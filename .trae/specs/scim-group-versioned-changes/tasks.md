# SCIM 组变更的版本化与可恢复协调 — 实施计划

每个任务为可独立验证的纵向切片，测试与实现同任务交付。依赖顺序即推荐实施顺序。

## Task 1: 数据模型与可逆迁移

- **Status**: `completed`
- **Completion Evidence**:
  - TR-1.1/1.3: `pytest tests/db/test_scim_group_change_migration.py` → 11 passed, 7 skipped（postgres URI 未配置）；upgrade/downgrade/upgrade 往返、单 head、列/索引/唯一约束/FK CASCADE 断言通过。
  - TR-1.2: `pytest tests/scim/ tests/repository/test_group.py` → 345 passed；既有组读写不受新列影响。
  - 交付：`db/models/user.py`（SqlGroup.current_version）、`db/models/scim.py`（SqlScimGroupChange + 生命周期常量、SqlScimActivity.resource_version）、`db/models/__init__.py` 导出、迁移 `b9c0d1e2f3a4_scim_group_changes.py`（down=e1f2a3b4c5d6）、测试 `tests/db/test_scim_group_change_migration.py`。
  - black 160 检查 5 个文件全部 unchanged。
- **Priority**: high
- **Depends On**: None
- **Description**:
  - 在 `db/models/user.py` 的 `SqlGroup` 增加可空 `current_version: Mapped[Optional[str]]`（String(255)），语义为「最近一次已完成目录版本」；新列不参与现有读取 JOIN。
  - 在 `db/models/scim.py` 新增 `SqlScimGroupChange`（表 `scim_group_changes`）：`id`、`group_id`（FK→groups.id，DB 层 `ondelete="CASCADE"`）、`external_id`(String 255)、`version`(String 255)、`base_version`(可空)、`old_name`、`new_name`、`ops_json`(Text，规范化操作与成员差异快照)、`status`(String 16：pending/applying/completed)、`result_json`(Text 可空)、`attempts`(Integer 默认 0)、`last_error`(String 500 可空)、`actor`(String 255 可空)、`token_id`(Integer 可空)、`created_at`/`updated_at`/`completed_at`(DateTime)。约束：`UniqueConstraint("external_id","version", name="uq_scim_group_changes_external_version")`；索引 `(group_id, status)` 与 `(status,)`（恢复扫描）。
  - 新 Alembic 版本（revision 新取，`down_revision = "e1f2a3b4c5d6"`）：SQLite 兼容方式加 `groups.current_version`（可空、无非常量 server default），建表/索引/约束；downgrade 反向 drop，顺序与 upgrade 对称。
  - 在 `db/models/__init__.py` 导出新模型。
- **Acceptance Criteria Addressed**: AC-11, AC-13
- **Test Requirements**:
  - `rule` TR-1.1: 新增 `tests/db/test_scim_group_change_migration.py`，在 SQLite 上 upgrade→downgrade→upgrade：表/列/唯一约束/索引存在性断言，downgrade 后 `scim_group_changes` 不存在且 `groups.current_version` 被移除；参照 `test_scim_activity_migration.py` 的夹具风格。
  - `rule` TR-1.2: upgrade 后既有 groups 行可正常读取且 `current_version is None`；建组/组详情现有测试不受影响（运行 `tests/scim/` 与 `tests/repository/test_group.py` 冒烟）。
  - `rule` TR-1.3: 迁移文件不使用 PostgreSQL 不兼容结构（无 server 端枚举、无 ALTER TYPE、方言无关 Text/DateTime）；走查 `alembic upgrade head` 在新建 SQLite 库成功。
- **Notes**: 迁移命名 `*_scim_group_changes.py`；revision id 用 12 位十六进制风格，与既有版本一致。

## Task 2: 版本化变更协调仓储（plan/apply/resume/recover）

- **Status**: `completed`
- **Completion Evidence**:
  - TR-2.1/2.2/2.3/2.4/2.5/2.6/2.7: 新增 `tests/repository/test_scim_group_change.py` 16 passed：pending 行先于组数据、注入故障回滚（原组名/成员/授权可用、attempts/last_error）、快照驱动 resume（group_id 不变、授权随改名延续、缓存即时生效）、未知成员/service account 无写入、enforce 他源 targeted remove 拒于规划前、同基版本一成一冲突、更旧版本冲突、同键 completed 回放、删除互斥与级联、applying 两类恢复及行级错误容忍、重名/externalId 冲突。
  - TR-2.8（rubric）: 自评 5 — 复用 `_remove_rows`/`_resolve_members`/`_members_by_group`/`_assert_external_id_free`/`evaluate_group_write` 与现有异常体系；不新增 store 实例；独立 Review 复核。
  - 交付：`repository/scim_group_change.py`、`repository/group.py`（删除互斥+显式级联、create_directory_group current_version、_group_detail current_version）、`sqlalchemy_store.py`（门面方法 + apply_scim_group_change 入 _GROUP_CUD_METHODS）。
  - 回归：`tests/repository/test_group.py` + `tests/scim/test_scim_groups.py` 93 passed；black 160 通过。
- **Priority**: high
- **Depends On**: Task 1
- **Description**:
  - 新增 `repository/scim_group_change.py`：
    - 数据类 `GroupChangePlan`（group_id、external_id、version、base_version、old_name、new_name、规范化 ops、member diff {added, removed_targets, replace_targets}、actor、token_id）与异常 `GroupVersionConflict(MlflowException)`（错误码映射 409，scimType 由路由层给 `versionConflict`）、`GroupChangeBlocked(MlflowException)`（开放变更阻断删除/重入）。
    - `plan_directory_group_change(session 边界由仓储管理, *, group_id|lookup, path_name, version, target_external_id, new_name, raw_ops, written_by, actor, token_id) -> GroupChangePlan`：单事务内完成全部只读预校验（成员解析、新名字符/保留字符/重名、externalId 占用、`evaluate_group_write` 组守卫、targeted remove 的他源行 enforce 预检）并写入 pending 行与 ops 快照；任何失败抛出且不留 completed、不改组数据。版本规则：整数按数值否则字符串序；版本不新于当前版本（严格小）→ `GroupVersionConflict`；相等 → 返回哨兵 `SAME_VERSION`（路由 no-op）；已有 `(external_id,version)` 记录 → 返回已有记录状态（completed/pending/applying）交路由决策。
    - `apply_directory_group_change(change_id, *, writer expectations) -> detail`：单事务：SELECT groups 行（PostgreSQL `with_for_update`，SQLite 写锁天然串行）；复核 managed_by 守卫、`current_version == base_version`（不等则抛 `GroupVersionConflict`）、目标名/externalId 仍空闲；置记录 applying；执行改名（`group.group_name`）与成员 ops（复用 `GroupRepository._remove_rows`/添加路径，保持 strict/sync 与 service-account 不可见语义）；`current_version=version`；记录置 completed 并写 result_json（组详情快照：名称、externalId、成员用户名/显示名/managed_by、时间戳）。提交返回 detail。
    - 应用失败：事务回滚保证组原状可用；在独立小事务把 pending 行 `attempts+1`、`last_error`（截断 500）；错误向上抛。
    - `get_change(external_id, version)`、`get_change_for_group(group_id, ...)`、`recover_interrupted_changes() -> dict`：applying→（组 current_version/名称已达目标：补 completed+快照；否则回 pending）；不应用 pending；每个异常单独捕获并汇总日志，不抛出。
    - `assert_no_open_change(group_id)`：供删除路径调用，存在 pending/applying → `GroupChangeBlocked`。
  - 在 `repository/group.py` 的 `delete_directory_group` 删除前调用互斥检查（仓储内注入或由 sqlalchemy_store 编排，保持单事务语义：检查与删除同事务）。
  - `sqlalchemy_store.py` 增加薄封装方法：`plan_directory_group_change`、`apply_directory_group_change`、`get_scim_group_change`、`recover_scim_group_changes`；把 apply 方法名加入 `_GROUP_CUD_METHODS`（缓存刷新）。删除互斥通过既有 `delete_directory_group` 路径生效。
- **Acceptance Criteria Addressed**: AC-1, AC-3, AC-4, AC-6, AC-12, AC-14
- **Test Requirements**:
  - `rule` TR-2.1（AC-1）: `tests/repository/test_scim_group_change.py`——版本化变更在组数据修改前存在 pending 行且字段齐全；在 apply 的成员写入步骤 monkeypatch 抛错后，pending 行存在、组名/成员/current_version 未变、attempts/last_error 已记录。
  - `rule` TR-2.2（AC-3）: 故障注入回滚后原组授权仍可解析（建组+组实验授权+成员）；随后同 (external_id,version) 调用 resume 路径完成：新名生效、group_id 不变、授权随组保留、新增成员有权、移除成员无权（调用真实权限解析并 flush 缓存）。
  - `rule` TR-2.3（AC-4）: 未知用户/service account 成员 → `UnknownMember`，组关系不变且无 completed 行；enforce 下 targeted remove 他源行 → 拒绝且无组数据变更。
  - `rule` TR-2.4（AC-6）: 两个会话基于同一 base_version 提交不同 version：恰好一成一败（`GroupVersionConflict`），库状态只反映胜者；更旧版本规划 → 冲突；相同版本 → SAME_VERSION 哨兵；已完成记录重复 plan → 取回 completed。
  - `rule` TR-2.5（AC-12）: pending/applying 存在时 `delete_directory_group` 抛 `GroupChangeBlocked` 且组未删；completed 后删除成功并级联清除变更记录。
  - `rule` TR-2.6（AC-9 的仓储部分）: `recover_interrupted_changes` 对两类 applying 行分别补 completed（含快照）与回 pending；行内异常不影响其他行恢复且函数不抛。
  - `rule` TR-2.7: 改名目标名被占用 / externalId 被他组占用 → RESOURCE_ALREADY_EXISTS，组原状不变；ops 快照驱动的 resume 不依赖原始请求体。
  - `rubric` TR-2.8（AC-14）: 代码分层维度；1-5；1=绕过 ownership 守卫或另开 store/事务破坏原子性，3=功能正确但守卫/语义重复实现，5=复用 `_remove_rows`、`evaluate_group_write`、session_maker 与现有异常体系；阈值 >=4；证据为代码走查。
- **Notes**: 不新增 store 单例；SQLite 不支持 FOR UPDATE 时 SQLAlchemy 静默跳过，靠写事务串行化，需在注释中说明。

## Task 3: SCIM 路由集成（版本解析、改名、幂等、审计/活动）

- **Status**: `completed`
- **Completion Evidence**:
  - 新增 `tests/scim/test_scim_group_versions.py` 19 passed，覆盖 TR-3.1~3.8：改名门槛矩阵（无版本 400/无 externalId 400/重名 409/PUT 成功/扩展对象 PATCH 成功/响应回显）、旧路径重放一体且审计仅一次、同 externalId+version PATCH 回放、stale 409 versionConflict、enforce 下 manual/oidc 组拒绝且无台账、未知成员 400 无写入无审计、HTTP 级 500→同键重试 200、删除互斥与级联、POST 种子版本、activity resource_version 仅在确定结果出现。
  - 交付：`models/scim.py`（DIRECTORY_GROUP_EXTENSION）、`routers/scim.py`（版本解析、plan/apply/replay 编排、group.renamed/version 审计、activity resource_version、displayName schema readWrite+扩展 schema）、`repository/scim_activity.py`（resource_version 全链路）、组仓储 by-id 查询与 ledger 兜底查找、apply 返回 settled_now。
  - TR-3.9（rubric）: 自评 4 — 版本化与遗留分支共享成员/守卫语义，错误映射集中于 `_raise_for_group_store_error`；独立 Review 复核。
  - 回归：全 `tests/scim/` + 两个仓储测试文件共 367 passed；black 160 通过。
- **Priority**: high
- **Depends On**: Task 2
- **Description**:
  - `models/scim.py`：新增扩展 URN 常量 `DIRECTORY_GROUP_EXTENSION = "urn:ietf:params:scim:schemas:extension:mlflow-oidc:2.0:Group"`；原始 body 解析辅助（pydantic extra=ignore 下从 raw dict 读取 `directoryVersion`，支持顶层与扩展对象；PATCH 无 path value 与 `replace path=directoryVersion`（可 URN 限定）两种形态）。
  - `routers/scim.py`：
    - 抽出组写编排函数：解析「有效 externalId」（PUT：body 结果值含清空语义但改名要求非空；PATCH：当前值或 externalId 变更结果）、版本、目标名（PUT displayName / PATCH replace displayName）。
    - 版本化分支（携带 directoryVersion）：路径 id 解析 404 时以 body externalId+version 查变更记录（completed→快照回放 200；pending/applying→接续 apply）；正常路径按「已完成回放 / pending 接续 / SAME_VERSION no-op / 新建 plan→apply」编排。冲突映射 `409 scimType=versionConflict`；blocked 删除映射 409；保持 400 invalidValue/mutability、409 uniqueness/mutability 的既有映射。
    - 未改名的版本化更新同一路径（new_name=old_name）。
    - 无版本分支：保持现有 `_apply_group_changes` 行为；改名（名称不同）在无版本或无有效 externalId 时仍 `400 mutability`。
    - POST `/Groups`：可选 `directoryVersion`，经 `create_directory_group` 同事务写 `current_version`（仓储小改：新增可选参数，默认 None）。
    - 响应渲染：`_to_scim_group` 在 current_version 非空时附扩展对象 `{DIRECTORY_GROUP_EXTENSION: {"directoryVersion": ...}}`；快照回放以**本次请求**为 base 渲染 location（最终名称）。
    - 审计：completed 提交后发 `group.renamed`（from/to/version）、`group.members_changed`（detail 增 version）、`group.external_id_set`（增 version）；仅在 pending→completed 的那次发，回放不发。
    - 活动：`scim_activity` 行支持 `resource_version`（仓储/模型/插入字段链路 + 路由 `_record_activity` 在请求 state 上取版本结果；冲突/拒入也记录版本；规划前 400/404 为空）。
    - DELETE：无变化的错误码外形；开放变更时 409（detail 指明进行中的目录变更，不泄露敏感内容）。
    - Schema 发现：Group schema 的 `displayName` mutability 改 `readWrite`，description 说明「仅当携带 directoryVersion 与 externalId 时服务器允许变更，否则 400 mutability」；新增扩展属性的文档可在 Schemas 输出中体现（至少在 docs 声明；若实现成本高可只在 description 注明自定义属性被接受）。
- **Acceptance Criteria Addressed**: AC-2, AC-4, AC-5, AC-7, AC-8, AC-10, AC-13, AC-14
- **Test Requirements**:
  - `rule` TR-3.1（AC-7）: 扩展 `tests/scim/test_scim_groups.py`——改名门槛矩阵 5 行（无版本 400/无 externalId 400/重名 409/PUT 成功/PATCH 成功），成功用例断言响应 id/displayName/location/扩展属性、externalId 稳定。
  - `rule` TR-3.2（AC-5）: 改名成功后向旧路径重发同 PUT → 200 同一体（新名 location），审计各事件仅 1 条；同 externalId+version 的 PATCH 重试同样回放；无版本请求打到旧名仍 404。
  - `rule` TR-3.3（AC-2）: enforce 下对 manual/oidc 组的版本化写（改名/成员/externalId）全部 409 mutability，库无 completed 记录；scim 组 200。
  - `rule` TR-3.4（AC-6）: 路由级版本冲突（monkeypatch/串行调用模拟交错）返回 409 versionConflict；更旧版本 409；同版本 200。
  - `rule` TR-3.5（AC-8）: 审计 fixture 断言 version 字段与「仅一次」；activity 表 resource_version：完成/回放/冲突有值，语法 400 与未知组 404 为空。
  - `rule` TR-3.6（AC-10/AC-13）: 既有无版本用例（Entra add/remove、Okta PUT、ownership 矩阵、delete、分页/filter/excludedAttributes）保持通过；GET 查询不新增 scim_group_changes 访问（可用 store spy/查询计数断言）。
  - `rule` TR-3.7（AC-4）: 版本化未知成员 → 400 invalidValue，关系与记录表无 completed；无审计。
  - `rule` TR-3.8（AC-12）: DELETE 开放变更 → 409；completed 后 DELETE → 204 且变更记录级联删除。
  - `rubric` TR-3.9（AC-14）: 错误语义与安全一致性维度；1-5；1=新旧分支产生权限差异或错误码不一致，3=可用但分支重复，5=版本化与遗留分支共享校验/审计且 deny-by-default 不变；阈值 >=4；证据为独立审查。
- **Notes**: ScimGroupInput 保持 extra=ignore；版本必须从原始 body 读取，避免 pydantic 吞掉。

## Task 4: 启动恢复接入

- **Status**: `completed`
- **Completion Evidence**:
  - TR-4.1/4.2: `tests/repository/test_scim_group_change_startup.py` 2 passed——applying 行 settled→completed、unsettled→pending、pending 不自动应用、恢复函数抛错被吞不阻断、恢复零审计事件（emit spy 为空）。
  - 交付：`app.py` `_recover_group_changes_at_startup()`，lifespan OIDC 注册后 best-effort 调用。
- **Priority**: medium
- **Depends On**: Task 3
- **Description**:
  - 在 `app.py` lifespan 启动段（OIDC 注册之后、yield 之前）以 `run_in_executor`/同步 best-effort 调用 `store.recover_scim_group_changes()`：捕获并记录所有异常，不影响 `_oidc_initialized` 与启动；日志输出来源于 Task 2 的汇总。
- **Acceptance Criteria Addressed**: AC-9
- **Test Requirements**:
  - `rule` TR-4.1: lifespan/应用工厂级测试（参照 `tests/middleware/` 或 app 相关现有测试风格；如无 app 夹具则直接测试启动钩子函数）：两类 applying 行被核对为预期状态，pending 不被自动应用，恢复函数抛错时启动流程仍完成且告警被记录。
  - `rule` TR-4.2: 启动恢复不发任何审计事件（audit spy 为空）。

## Task 5: 文档与既有断言更新

- **Status**: `completed`
- **Completion Evidence**:
  - TR-5.1: `test_scim_groups.py` schema 断言更新为 readWrite + 扩展 schema 列入 /Schemas；`test_put_cannot_rename` 与 PATCH displayName 参数化用例（无版本仍 400）原样通过；无新增 xfail/skip。
  - TR-5.2（rubric）: 自评 4 — `docs/scim.md` 标识符/Operations/PATCH 表、新增「Versioned changes and recovery」整节（版本序、409 versionConflict、幂等、重启、删除互斥）、删除三检查、Audit 与 activity 字段表均已同步。
- **Priority**: medium
- **Depends On**: Task 3
- **Description**:
  - 更新 `docs/scim.md` Groups：标识符章节（改名条件：directoryVersion + externalId；id/location 变化与旧路径重试语义）、Operations 表与 PATCH 表（版本属性两种传法、改名）、新增「版本化变更与恢复」小节（单调版本规则：整数/字符串序、409 versionConflict、幂等回放、重启核对、pending 接续）、Audit 小节（`group.renamed` 与 version 字段、activity resource_version）、删除互斥说明。
  - 更新因语义变化必须修改的既有用例：schema `displayName` mutability 断言（immutable→readWrite 及描述）、`test_put_cannot_rename`/PATCH 改名用例改为「无版本/无 externalId 仍 400」。
- **Acceptance Criteria Addressed**: AC-7, AC-10, NFR-6
- **Test Requirements**:
  - `rule` TR-5.1: 被修改的既有用例全部通过；未新增 xfail/skip；`grep` 确认 docs 不再声称改名一律 400。
  - `rubric` TR-5.2: 文档准确性维度；1-5；1=文档与实现矛盾，3=主要行为覆盖但恢复/冲突语义缺失，5=错误码、示例与边界完整；阈值 >=4；证据为审查对照。

## Task 6: 全量门禁验证

- **Status**: `completed`
- **Completion Evidence**:
  - TR-6.1: 全仓测试（除 hooks/e2e 单跑）**5784 passed, 213 skipped**；`tests/db/ + tests/repository/` 642 passed/80 skipped；`tests/scim/`+group-change+startup 367 passed；`tests/perf/` 51 passed；test_membership_ownership/middleware/test_app 等 532 passed；hooks 27 个文件逐文件独立运行，唯一失败 `test_artifact_proxy_coverage.py`（9 failed）经 `git stash` 干净树复现，确认为预存问题，与本次改动无关。
  - TR-6.2: `tests/perf/test_auth_path_baseline.py` 随 perf 套件通过——认证热路径零新增查询（特性仅在 SCIM 写路径；组读不 JOIN ledger，current_version 随 groups 行返回）。
  - black 160：所有改动文件 unchanged（仅顺手恢复了一个与本特性无关的预存格式文件）；pre-commit（black/密钥/空白等钩子）全部 Passed。
  - AC↔证据：AC-1/3/4/6/12→test_scim_group_change.py；AC-2/5/7/8/10/13→test_scim_group_versions.py + test_scim_groups.py；AC-9→test_scim_group_change_startup.py；AC-11→test_scim_group_change_migration.py；AC-14→rubric 4/5（见 review.md CP-U1）。
  - **独立审查 R1=FAIL → 修复 → R2=PASS**（review.md）：修复 F1 台账键跨组误绑（现行 externalId JOIN+组归属校验+externalId 复用链）、F2 CAS 败者 superseded 终态释放删除互斥、F3 改名保留字符校验、F4 快照回放、F6 模糊匹配唯一性、F7 flush 竞争错误映射、F8 plan 审计时点、F9 planner 撞键透明回退；迁移唯一键改为 (group_id,version)。新增回归：TestRenameValidation/TestExternalIdReuse/快照回放/冲突后删除 + 仓储 superseded/名称竞争/歧义用例。修复后目标套件 53 passed/4 skipped，scim+repository+db+perf 合计 1052 passed/80 skipped；最终受影响面 515 passed/4 skipped。
- **Priority**: high
- **Depends On**: Task 1, Task 2, Task 3, Task 4, Task 5
- **Description**:
  - 运行并记录：`pytest mlflow_oidc_auth/tests/scim/ mlflow_oidc_auth/tests/repository/test_group.py mlflow_oidc_auth/tests/repository/test_scim_group_change.py mlflow_oidc_auth/tests/db/ -k 'scim or group or migration'`、`pytest mlflow_oidc_auth/tests/perf/`、`black --line-length 160 --check mlflow_oidc_auth/`、`pre-commit run --all-files`（若环境可用）。
  - hooks 目录按 AGENTS.md 要求逐文件运行（如触及 hooks；本计划预计不触及，若触及则对应文件单独跑）。
  - 自证每条 AC 的证据归集到本任务 Completion Evidence；未通过项回修对应任务。
- **Acceptance Criteria Addressed**: AC-1..AC-14
- **Test Requirements**:
  - `rule` TR-6.1: 上述命令全部退出码 0，输出归档。
  - `rule` TR-6.2: 无新增到 AuthMiddleware 认证热路径的查询（`tests/perf/test_auth_path_baseline.py` 通过）。
  - `rubric` TR-6.3: 整体验收覆盖维度；1-5；阈值 >=4；证据为 AC↔测试映射表与命令输出。
