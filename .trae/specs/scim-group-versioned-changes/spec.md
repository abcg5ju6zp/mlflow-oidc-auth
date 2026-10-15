# SCIM 组变更的版本化与可恢复协调 — 产品需求文档

## Overview

- **Summary**: 为 SCIM 2.0 `PUT/PATCH /Groups/{id}` 的组变更（含此前被禁止的组重命名）引入持久化的「目录版本 + externalId」协调机制：每次版本化变更先落一份包含原名称、目标名称、成员差异和基版本的变更记录，再在单事务内原子完成改名、成员增删与版本推进；请求按 `(externalId, version)` 幂等，按版本冲突而不是互相覆盖；崩溃/重启后可核对、可接续。
- **Purpose**: 消除组变更与管理员权限修改、SCIM 重试、服务重启交错时的部分生效状态——组先改名而成员清理失败导致旧成员继续访问、重试打到已改名对象、并发 PATCH 互相覆盖。
- **Target Users**: 通过 SCIM 对接的企业目录（Entra/Okta 等）；负责恢复的 MLflow 管理员；依赖组成员关系获得授权的最终用户。

## Goals

- 支持目录通过 SCIM PUT/PATCH 安全地重命名组，并与成员替换在同一原子变更内完成。
- 每次版本化组变更可持久追踪：目录版本、externalId、原名称、目标名称、成员差异、基版本。
- 只有通过现有 `managed_by` 组守卫 **且** 版本匹配当前状态的请求才能推进。
- 失败语义明确：成员解析失败不改动任何关系；应用阶段失败回滚到原组可用状态，变更保持可接续；响应丢失按 externalId + 版本返回已完成结果。
- 并发 PATCH 串行化：后到者得到版本冲突，而不是覆盖先到者。
- 审计与活动记录只在最终结果确定后引用同一版本，且重试/回放不重复审计。
- 重启可核对并接续未完成变更。
- 不改变现有行为：SCIM 读取、不带版本的成员更新与普通单次替换、手工/他源组隔离。

## Non-Goals

- 不改变用户（`/Users`）侧 SCIM 语义。
- 不引入嵌套组成员、SCIM Bulk、ETag/HTTP 条件头（`If-Match`）支持。
- 不做跨实例的分布式锁或目录主动通知；多副本一致性由数据库约束与行锁保证。
- 不自动迁移/改写历史审计与活动数据。
- 不改变登录侧（OIDC/SAML claims）的组同步策略；组以稳定 `group_id` 为外键，改名对登录同步透明。
- 不在启动时自动重放 pending 变更（仅核对 applying 状态；推进由同键重试驱动）。

## Background & Context

- 现状（`mlflow_oidc_auth/routers/scim.py`、`repository/group.py`）：
  - 组的 SCIM `id` 即组名；`displayName` 被视为不可变，PUT/PATCH 改名返回 `400 mutability`（见 `docs/scim.md` Groups 章节与 `tests/scim/test_scim_groups.py`）。
  - `GroupRepository.apply_group_changes` 已在单事务内按序执行 add/remove/replace 成员操作，含 externalId 唯一校验与 managed_by 组守卫；并发成员插入靠 IntegrityError 转 409。
  - 成员关系（`user_groups`）与全部组权限表（实验、模型、Prompt、Scorer、Gateway、Workspace、MCP、regex 等）均以稳定的整数 `groups.id` 为外键；库内没有按组名字符串引用组的授权表，因此改名本身不需要迁移授权行。
  - 组写后由 `sqlalchemy_store.py` 的 `_GROUP_CUD_METHODS` 统一刷新 permission/workspace 缓存。
- 已确认的设计决策（用户选择）：
  1. 目录版本通过**自定义 JSON 属性**随请求体传入（非 HTTP 头）。
  2. 版本由**目录提供、按 externalId 单调**；`(externalId, version)` 是一次变更的幂等键；落后版本冲突。
  3. 重命名**必须携带 externalId 与版本**，且通过现有 managed_by 组守卫；否则维持 `400 mutability`。
  4. 重启时只**核对** applying 状态（不自动重放）；pending 变更由携带相同 `(externalId, version)` 的重试请求惰性接续。

## Functional Requirements

### 请求表达

- **FR-1 版本属性**：PUT 的 Group body 与 PATCH 操作可携带目录版本。接受两种写法：顶层 `directoryVersion` 字符串；或扩展 schema `urn:ietf:params:scim:schemas:extension:mlflow-oidc:2.0:Group` 的对象属性 `directoryVersion`（PATCH 无 path 的 value 内同理；亦接受 `replace` 该属性路径）。版本为去空白后非空、≤255 字符的字符串。读取响应在组持有当前版本时回显同一属性（扩展对象形式）。
- **FR-2 版本必伴 externalId**：任何携带 `directoryVersion` 的写请求必须能确定非空的目标 externalId（组当前持有，或本次 PUT/PATCH 设置的结果值）；否则 `400 invalidValue`，不产生写入。PUT 改 externalId 时，幂等键取**结果** externalId。
- **FR-3 改名表达**：PUT body 的 `displayName`（或 PATCH `replace displayName`）与路径 id 不同即改名。改名仅在「携带版本且目标 externalId 非空」时允许；否则维持现状 `400 mutability`。新名沿用现有组名校验（字符、保留字符 `/ ? # %`、≤255），重名 `409 uniqueness`。
- **FR-4 成员操作表达**：成员 add/remove/replace 的解析、顺序与 ownership 语义与现状完全一致（targeted remove 在 enforce 下整单回滚；replace 为 sync，永不删除他源成员行）。

### 规划与持久化（plan）

- **FR-5 变更记录表**：新增 `scim_group_changes` 表（迁移见 NFR-2），版本化变更在任何组数据写入前先持久化一行，至少包含：所属 `group_id`（外键，组删除时级联清除）、结果 `external_id`、`version`、`base_version`（规划时组的当前版本）、`old_name`、`new_name`、规范化后的操作快照与成员差异（add/remove/replace 的用户名集合）、`status`（`pending`/`applying`/`completed`）、响应数据快照（完成时）、`attempts`、`last_error`、actor（token 名）、`created_at`/`updated_at`/`completed_at`。`(external_id, version)` 唯一。
- **FR-6 规划阶段全量预校验**：组成员存在性（service account 不可见）、目标组名空闲、externalId 未被他组占用、managed_by 组守卫（enforce/report/off 现状语义）、成员 ownership 预检（targeted remove 命中他源行在 enforce 下拒绝）全部在 pending 行落库前完成。任何预校验失败：**无组数据变更、无 completed 记录、无审计事件**，返回与现状一致的 400/409。
- **FR-7 未改名的版本化更新**：携带版本但不改名时走同一套 plan/apply；差异中 `new_name = old_name`。

### 应用（apply，单事务可恢复）

- **FR-8 单事务原子应用**：一次 apply 在一个数据库事务内完成：锁定组行 → 再次校验 managed_by 与 `current_version == base_version` → 改名（如有）→ 按快照执行成员增删（沿用现有 guard 语义）→ `groups.current_version = version` → 变更记录置 `completed` 并保存响应快照。提交后才发审计、刷缓存。
- **FR-9 引用一致**：改名后成员关系与全部组授权因 `group_id` 稳定而持续有效；改名+成员变更提交后，被删成员立即失去该组授权，新增成员立即获得，权限缓存被失效（复用 `_GROUP_CUD_METHODS` 机制）。
- **FR-10 应用失败回滚**：apply 事务中任何步骤失败（含模拟的权限/存储错误）整体回滚——组仍以原名、原成员关系、原授权可用；变更记录保持 `pending`，`attempts+1` 并记录 `last_error`；本次请求返回可重试错误（5xx，SCIM 错误体），不产生「完成」审计。
- **FR-11 接续与幂等回放**：
  - 相同 `(externalId, version)` 重试且记录已 `completed`：用保存的快照以本次请求渲染（location 指向最终名称）返回 200，**不再写数据、不再发审计**。
  - 记录为 `pending/applying`：在同一守卫与版本规则下继续完成该变更（重放 apply），完成后正常审计一次。
  - 组已改名后按旧路径 `PUT/PATCH /Groups/{旧名}` 重试：路径解析 404 时，允许用请求体中的 externalId+version 命中既有记录完成回放/接续。
  - `version == 组当前版本` 且无变更记录：视为同版本重述，no-op 返回当前组 200。
- **FR-12 版本冲突**：规划时版本严格新于当前版本方可新建变更（两者均为整数时按整数比较，否则按字符串序；相等见 FR-11）。apply 的 CAS 条件失败（同基版本的并发 PATCH、期间出现更新版本）返回 `409`、scimType `versionConflict`，先提交者生效，无任何部分覆盖。
- **FR-13 手工/他源隔离不放松**：版本化不绕过任何现有守卫：enforce 下对非 `scim` 拥有组的版本化写仍 `409 mutability` 且不产生 completed 记录；他源 membership 的 targeted remove 仍整单拒绝。
- **FR-14 POST 兼容与初始版本**：`POST /Groups` 可选择接受 `directoryVersion`，在建组事务内写入 `groups.current_version`；不携带时行为与现状逐字节一致。POST 的重试仍按现有 409/读取语义，不依赖变更记录表。

### 审计、活动与恢复

- **FR-15 审计一次、引用同版本**：版本化变更只在 completed 提交后发审计：新事件 `group.renamed`（detail: `from`/`to`/`version`），`group.members_changed` 与 `group.external_id_set` 的 detail 增加 `version`；回放（FR-11）不重复发事件。
- **FR-16 活动记录版本列**：`scim_activity` 增加可空 `resource_version`：仅当请求最终对应到某版本化变更的确定结果（完成、回放、冲突、拒入）时写入该版本；规划前失败（400 语法、404）保持为空。
- **FR-17 启动核对**：应用 lifespan 启动时以 best-effort、不阻塞启动的方式执行一次恢复：`applying` 行若组当前版本/名称已等于目标则补记为 `completed`（含快照），否则置回 `pending` 等待同键重试；不自动执行 pending。恢复过程记录日志，不发审计事件。
- **FR-18 组删除与开放变更**：组删除（SCIM DELETE）遇该组存在非 completed 变更记录时拒绝（`409`，指明存在进行中的目录变更），避免删除与接续交错。

## Non-Functional Requirements

- **NFR-1 兼容**：不带 `directoryVersion` 的请求走现有代码路径与现有测试期望；SCIM 读取的查询形态不增加 JOIN（`current_version` 随 `groups` 行读取）。认证热路径（AuthMiddleware 查询预算）不受影响——本特性全部位于 SCIM 写路径。
- **NFR-2 迁移**：新 Alembic 版本（继 `e1f2a3b4c5d6` 之后）新增 `groups.current_version`（可空，SQLite 加列约束兼容）与 `scim_group_changes` 表及索引；downgrade 完整回退；迁移测试在 SQLite 上前后向通过，PostgreSQL 方言不使用不兼容语法。
- **NFR-3 并发正确**：并发正确性由数据库保证——唯一约束 `(external_id, version)`、组行锁/版本 CAS、名称与 externalId 唯一约束；不依赖进程内锁。
- **NFR-4 代码约定**：遵循仓库 AGENTS.md——store 单例、FastAPI 路由集中于 `routers/scim.py`、Black 160、公共签名类型标注与 Google docstring、ORM `Sql` 前缀、不记录令牌/正文。
- **NFR-5 安全**：deny-by-default 不放松；变更记录与日志不保存请求/响应正文以外的敏感物（仅用户名、组名、版本、externalId、错误短消息，截断长度同 scim_activity 约定）；新失败路径不得授予额外访问。
- **NFR-6 文档**：更新 `docs/scim.md` Groups 章节（版本属性、改名条件、冲突 scimType、恢复语义、审计事件）。

## Constraints

- **Technical**: Python / FastAPI / Flask / SQLAlchemy；SQLAlchemy ORM 事务；SQLite 与 PostgreSQL 双支持；MLflow ≥ 3.16.0 插件边界，不改 MLflow core。
- **Business**: 安全边界变更需保守——改名默认仍不可达（无版本/externalId 即维持 400）；既有部署零配置行为不变。
- **Dependencies**: 现有 `GroupRepository`、`ownership` 守卫、`scim_activity` 机制、lifespan 启动钩子、alembic 链头 `e1f2a3b4c5d6`。

## Assumptions

- 目录保证同一 externalId 下版本单调；插件对「整数版本按数值、否则按字符串序」判定新旧，该规则在文档中声明。
- 目标 externalId 在 PUT 改 externalId 的场景即可作为重试关联键（目录会原样重发整个 body）。
- 同一 externalId 同时只由一个目录/令牌驱动；令牌间隔离仍由现有 SCIM 令牌模型承担。
- 变更记录为运维可查的持久台账，不做保留期清理（区别于可清扫的 scim_activity）。
- 版本化读响应回显 `directoryVersion` 为便利属性，不改变 ETag 不支持的 ServiceProviderConfig 声明。

## Acceptance Criteria

### AC-1: 版本化变更在写入前完整持久化

- **Type**: `rule`
- **Given**: 一个 scim 拥有且带 externalId `E` 的组；PUT/PATCH 携带 `directoryVersion: "2"`、新成员差异
- **When**: 请求通过预校验
- **Then**: 任何组数据被修改前，`scim_group_changes` 存在一行，含 externalId `E`、version `2`、base_version（组当前值）、old/new name 与 add/remove 成员差异，初始 `pending`
- **Pass Condition**: 直接查表断言字段齐全且状态先于组数据变更（可通过应用阶段注入故障验证 pending 行已存在而组未变）
- **Evidence**: `pytest mlflow_oidc_auth/tests/scim/ mlflow_oidc_auth/tests/repository/` 新增用例

### AC-2: managed_by 与版本双匹配才能推进

- **Type**: `rule`
- **Given**: enforce 模式
- **When**: 对 manual 或 `oidc:*` 拥有的组发起携带版本的 PUT/PATCH（含改名）
- **Then**: 返回 `409 mutability`，组名/成员/版本均不变，无 completed 记录
- **Pass Condition**: 响应与库状态双重断言；scim 拥有的组同请求 200
- **Evidence**: 新增 SCIM 负面授权测试

### AC-3: 改名与成员变更是单事务原子结果

- **Type**: `rule`
- **Given**: scim 组 `eng`（externalId、成员 ALICE、组上有实验授权）
- **When**: 版本化 PUT 把 `displayName` 改为 `eng-new`、成员替换为 BOB，且在 apply 事务提交前注入失败
- **Then**: 组仍名为 `eng`、成员仍为 ALICE、授权仍可用；记录为 pending；无完成审计
- **When（恢复）**: 以相同 externalId+version 重试且无注入
- **Then**: 组改名为 `eng-new`、成员为 BOB；BOB 经该组立即持有授权，ALICE 立即失去；缓存无需等待 TTL
- **Pass Condition**: 故障注入 + 真实授权解析断言；`pytest` 通过
- **Evidence**: repository 级故障注入测试 + SCIM 路由测试

### AC-4: 成员解析失败不改动现有关系

- **Type**: `rule`
- **Given**: 组成员为 ALICE
- **When**: 版本化请求命名不存在的用户或 service account
- **Then**: `400 invalidValue`；成员关系不变；无组数据写入；不产生 completed 记录；无审计
- **Pass Condition**: 响应、成员关系、记录表三处断言
- **Evidence**: SCIM 测试

### AC-5: 响应丢失按 externalId+版本返回已完成结果

- **Type**: `rule`
- **Given**: 版本化改名+成员变更已完成 200（模拟响应丢失）
- **When**: 目录向**旧路径** `/Groups/eng` 重发完全相同的 PUT，或对同 externalId+version 重发 PATCH
- **Then**: 返回 200 与首次一致的资源体（id/displayName/location 均为 `eng-new`），不重复写数据、不重复发 `group.renamed`/`group.members_changed`
- **Pass Condition**: 第二次响应体比对一致；审计事件计数仍为 1；组成员与版本不变
- **Evidence**: SCIM 路由测试 + 审计抓取 fixture

### AC-6: 并发与陈旧 PATCH 按版本冲突

- **Type**: `rule`
- **Given**: 组当前版本 1，两个同时到达的版本化 PATCH（version 2 与另一个 version 2′，基版本均为 1）
- **When**: 两者交错执行
- **Then**: 恰好一个 200 提交，另一个 `409 versionConflict` 且无部分覆盖
- **And**: 版本 2 已完成后重放版本 1（更旧）的请求 → `409 versionConflict`；重放完全相同的版本 2 → 200 回放
- **Pass Condition**: 并发/串行两种交错的确定性结果（屏障或行锁级测试）
- **Evidence**: repository 并发测试（线程/会话级）+ 路由测试

### AC-7: 改名门槛与标识规则

- **Type**: `rule`
- **Given/When/Then 矩阵**:
  1. 改名但无版本 → `400 mutability`（现状保持）
  2. 改名有版本但组无 externalId 且本次不设置 → `400 mutability`
  3. 改名 + 版本 + externalId，新名已被他组占用 → `409 uniqueness`
  4. 改名 + 版本 + externalId 正常 → 200，响应 id/displayName/meta.location 为新名，externalId 关联不变
  5. PATCH `replace displayName` 同样适用 1–4
- **Pass Condition**: 矩阵逐行断言
- **Evidence**: SCIM 测试

### AC-8: 审计与活动只在结果确定后引用同一版本

- **Type**: `rule`
- **When**: 任一版本化变更经历「失败 → 重试成功 → 回放」
- **Then**: `group.renamed`/`group.members_changed`/`group.external_id_set` 各至多一条且 detail.version 等于完成版本；每次 HTTP 请求的 scim_activity 行仅在结果确定时带 `resource_version`（失败的规划请求为空）
- **Pass Condition**: audit fixture 与 activity 表断言
- **Evidence**: SCIM 审计/活动测试

### AC-9: 重启核对未完成变更

- **Type**: `rule`
- **Given**: 库中存在 `applying` 行（模拟崩溃）：其一目标状态已落库，其一未落库
- **When**: 执行启动恢复函数（lifespan 调用同一函数）
- **Then**: 前者补记 completed + 快照；后者回到 pending；不自动应用任何 pending；不发审计；异常不阻断启动
- **Pass Condition**: 状态转换断言 + 启动路径 best-effort 断言
- **Evidence**: repository 恢复测试 + app lifespan 测试

### AC-10: 无版本路径与手工组隔离保持兼容

- **Type**: `rule`
- **When**: 不带 `directoryVersion` 的现有 PUT/PATCH/POST/DELETE/GET 全部操作
- **Then**: 行为与现状一致（现有测试除显式改名相关断言外不修改即通过；改名仍 400）；enforce 下他源组与他源成员行的拒绝矩阵不变
- **Pass Condition**: `pytest mlflow_oidc_auth/tests/scim/` 全绿（含按新语义更新的既有用例），无 xfail/skip 新增安全豁免
- **Evidence**: 既有测试套件

### AC-11: 迁移可逆且双后端兼容

- **Type**: `rule`
- **When**: 对最新 head 执行 upgrade→downgrade→upgrade（SQLite 测试库）
- **Then**: 列/表/索引/唯一约束正确创建与删除，数据不丢失；SQL 无 PostgreSQL 不兼容结构
- **Pass Condition**: 新增迁移测试通过，且参照既有迁移测试约定覆盖前后向
- **Evidence**: `pytest mlflow_oidc_auth/tests/db/`

### AC-12: 删除开放变更加互斥

- **Type**: `rule`
- **Given**: 组存在 pending/applying 变更记录
- **When**: SCIM DELETE 该组
- **Then**: `409` 且组不删除；记录 completed 后删除成功（沿用现有删除级联与守卫）
- **Pass Condition**: 两阶段断言
- **Evidence**: SCIM 测试

### AC-13: 读取路径无额外查询负担

- **Type**: `rule`
- **When**: GET /Groups（列表/单读/分页/filter）
- **Then**: 不 JOIN 变更记录表；`current_version` 随 groups 行返回；查询数量与现状同级
- **Pass Condition**: 既有查询计数/分页测试保持通过
- **Evidence**: tests/scim + tests/perf 相关套件

### AC-14: 实现与仓库约定及安全姿态的一致性

- **Type**: `rubric`
- **Dimension**: 代码质量与安全契合度
- **Scale**: 1-5
- **Anchors**: 1 = 绕过守卫/新增 store 实例/破坏事务边界或缓存契约；3 = 功能正确但分层混乱、错误语义不一致；5 = 复用现有 ownership/缓存/活动机制，错误码与审计语义统一，类型标注与 docstring 完整，无秘密入库
- **Pass Threshold**: >= 4
- **Evidence**: 独立审查代码走查 + `pre-commit run --all-files`（black/flake8/mypy 适用范围）

## Open Questions

- 无（四个关键设计决策已经用户确认；其余按 Assumptions 落地，可在评审中推翻）。
