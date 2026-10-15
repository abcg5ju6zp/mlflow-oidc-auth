# 服务账号来源变更：带身份代际的可恢复操作 实施计划

## 背景与调研结论

管理员通过 `PUT /users/{username}/service-account-source` 把内部服务账号切到外部 OIDC 来源（如 Kubernetes 工作负载身份）。当前实现位于 [service_accounts.py](file:///Users/huangding/Documents/new-SWE/0910142/project-11/mlflow_oidc_auth/utils/service_accounts.py) 的 `apply_source()`，它是**一次性、无阶段记录**的过程：

1. `store.set_service_account_source()` **先发布新来源**；
2. 再 unlink 身份；
3. 再 `delete_user_tokens()` + `revoke_all_auth_sessions()`；
4. 链接新 subject；
5. `flush_bearer_identity_cache()`（永不抛错，失败被吞）；
6. 审计事件由路由层在函数返回后发出。

缺陷（与用户描述对应）：

- 撤销在来源写入**之后**：撤销/审计失败时，数据库显示外部托管，旧令牌仍有效；
- 无代际/阶段记录：响应丢失或进程重启后，无法判断哪些阶段已完成，无法续做；
- 缓存失效失败不可观测、不可补做；
- 切换期间没有"先阻断新本地凭据签发"的固定点。

关键现状（实现须保持）：

- `users.service_account_source`：`internal` 或 OIDC provider id（迁移 `e1f2a3b4c5d6`，当前 alembic head）；普通人账号为 NULL。
- 认证热路径 [auth_middleware.py](file:///Users/huangding/Documents/new-SWE/0910142/project-11/mlflow_oidc_auth/middleware/auth_middleware.py) 的 `_service_account_denial()` 从**每个请求本来就读取的 profile 行**取 source（预算 2 条 SQL，禁止新增查询）。
- 令牌签发：`UserTokenRepository.create/replace`（`_lock_user` 对 users 行 `FOR UPDATE`，SQLite 用 no-op write 取库锁），外部服务账号由路由层 `_refuse_tokens_for_external_service_account()` 拒绝（409）。
- 会话撤销：`AuthSessionRepository.revoke_all_for_user()`；缓存：`utils/bearer_identity_cache.py`（本地/Redis 后端，整缓存 clear，TTL 兜底）。
- store 是透明懒加载代理，新增 repo 属性自动透传，无需改门面。
- 用户删除在 [repository/user.py](file:///Users/huangding/Documents/new-SWE/0910142/project-11/mlflow_oidc_auth/repository/user.py) `delete()` 中显式清理所有依赖表，新表须同样清理。
- 现有行为约束：来源**未改变**的 PUT 仍会做身份对账（unlink 残留身份、link 指定 subject），但不撤销令牌；外部账号拒绝签发令牌；建账号时来源直接落库、无旧凭据，不应走变更流程。

## 目标语义（分阶段状态机）

每次来源变更生成一条带 `generation`（每账号递增）的过渡记录，阶段顺序：

1. **pinned（固定）**：持久化目标来源 + 目标主体映射；该账号新的本地凭据签发被拒绝（fail closed）。旧来源属性仍有效。
2. **revoked（已撤销）**：删除该账号全部访问令牌、撤销全部服务端会话，计数落库。
3. **published（已发布）**：写入 `users.service_account_source`，完成身份 unlink/link 对账。
4. **completed（已完成）**：认证缓存失效成功 + 审计发出后，收尾。

失败与恢复语义：

- 令牌/会话撤销失败：记录停在 `pinned`，来源**不得显示为已完成**（source 列仍是旧值），接口返回 503 + generation/phase，可重试。
- 发布后缓存失效失败：记录停在 `published`；恢复时**只补缓存失效与审计**，不重复撤销。
- 响应丢失/重启：以 generation 读回阶段，跳过已完成阶段，从首个未完成阶段幂等续做；启动时自动扫描所有未完成记录。
- 同一目标重复请求：复用同一 generation 续做（幂等），不新增代际；进行中请求**不同**目标：409，拒绝并保留原身份。
- 主体冲突（subject 已绑其他账号）：在 pin 之前拒绝，409，原身份不动。
- 切回 internal 不恢复旧令牌（每次变更都撤销，撤销不可恢复）。
- 兼容性：普通人账号、来源未改变的服务账号 PUT（身份对账保留、不撤销令牌）、外部账号拒绝签发（409）、内部账号正常签发令牌，全部不变。

## 新增持久化模型

新表 `service_account_source_transitions`（历史记录保留，兼作代际来源；完成行不删）：

| 列 | 说明 |
|---|---|
| `id` PK | |
| `user_id` FK→users.id, indexed | 用户删除时随级联/显式删除清理 |
| `generation` int | 每账号从 1 递增；`UNIQUE(user_id, generation)` |
| `target_source` varchar(255) | `internal` 或 provider id |
| `target_subject` varchar(255) NULL | 固定的主体映射（可空） |
| `phase` varchar(32), indexed | `pinned`/`revoked`/`published`/`completed` |
| `revoked_tokens` int default 0 | 本次观察到的删除计数 |
| `revoked_sessions` int default 0 | |
| `actor` varchar(255) NULL | 发起管理员；启动恢复记 `system:startup-recovery` |
| `created_at` / `updated_at` / `completed_at` NULL | |

为什么用独立表而非 users 加列：热路径（每请求认证）不需要感知 pending，独立表对认证路径**零新增查询**；pending 检查只发生在低频的管理员令牌签发路径。

## 修改文件与模块

- `mlflow_oidc_auth/db/models/service_account_source.py`（新建）：`SqlServiceAccountSourceTransition`。
- `mlflow_oidc_auth/db/models/__init__.py`：导出新模型。
- `mlflow_oidc_auth/db/migrations/versions/<新revision>_service_account_source_transitions.py`（新建）：`down_revision="e1f2a3b4c5d6"`；建表 + 索引/唯一约束；downgrade drop table。SQLite 批处理风格，与既有迁移一致。
- `mlflow_oidc_auth/repository/service_account_transition.py`（新建）：`ServiceAccountTransitionRepository` + 轻量 dataclass。
- `mlflow_oidc_auth/repository/__init__.py`：导出。
- `mlflow_oidc_auth/sqlalchemy_store.py`：实例化 `self.service_account_transition_repo`。
- `mlflow_oidc_auth/repository/user.py`：`delete()` 级联删除新表行。
- `mlflow_oidc_auth/repository/user_token.py`：`_insert()` 纵深防御——持锁事务内查到该用户存在未完成过渡即拒绝（INVALID_STATE）。
- `mlflow_oidc_auth/utils/bearer_identity_cache.py`：新增 `invalidate_bearer_identity_cache() -> bool`（失败返回 False，不抛）；`flush_bearer_identity_cache()` 保留为吞错包装。
- `mlflow_oidc_auth/utils/service_accounts.py`：重写为分阶段状态机 + 恢复入口 + 异常类型。
- `mlflow_oidc_auth/routers/users.py`：PUT 端点传 actor、映射新异常、响应携带 generation/status；签发拒绝增加 pending 检查；建账号路径改为直接 link subject（不走过渡）。
- `mlflow_oidc_auth/app.py`：lifespan startup 调用恢复扫描（try/except + 日志，不阻断启动）。
- 测试：新迁移测试、新状态机测试、路由测试；既有测试保持通过。

## 实施步骤（依赖序）

1. **模型 + 迁移**：新增 ORM 模型与 alembic 迁移，注册导出；编写迁移往返测试（SQLite；Postgres 按既有 conftest 约定）。
2. **过渡仓储**：
   - `begin(username, target_source, target_subject, actor) -> (transition, resumed)`：单事务内锁定 users 行（PG `FOR UPDATE`/SQLite no-op write）；校验是服务账号；取最新一条：未完成且同目标→返回续做；未完成不同目标→`INVALID_STATE`；否则 generation+1 插入 `pinned`。
   - `mark_revoked(tid, tokens, sessions)`、`mark_published(tid)`、`mark_completed(tid)`：用**条件 UPDATE**（`WHERE phase=前一阶段`）推进，rowcount=0 表示已被其他副本抢先，调用方重读。
   - `get_active(username)`、`list_incomplete()`（join users 取 username）、`get(tid)`。
3. **状态机（utils/service_accounts.py）**：
   - 保留 `INTERNAL_SOURCE`/`is_external`/`selectable_sources`/`validate_source` 不变。
   - 新增阶段常量与 `ServiceAccountTransitionError`（携带 username/generation/phase，区分 `revocation_failed`/`publication_failed`/`finalization_pending`）。
   - `apply_source(username, source, subject, *, actor=None) -> dict`：
     a. profile + `validate_source`；主体冲突预检（pin 之前）；
     b. **来源未改变**：不建过渡、不撤销凭据，仅执行既有身份对账 + 缓存失效（完全保持现行为）；
     c. 来源改变：`begin()` 得到代际；按记录阶段幂等推进：
        - pinned：`delete_user_tokens`/`revoke_all_auth_sessions`，异常→抛 TransitionError（行留 pinned）；成功带计数 `mark_revoked`；
        - revoked：`set_service_account_source` + 身份 unlink/link（迁移现有逻辑），异常→留 revoked；成功 `mark_published`；
        - published：`invalidate_bearer_identity_cache()`；失败→不审计、留 published 并返回 `finalization_pending`；成功→发审计事件（含 generation、from/to、subject_bound、计数、resumed 标记）→`mark_completed`；
     d. 返回 `{generation, source, subject_bound, recovered, status, revoked_tokens, revoked_sessions}`。
   - `recover_incomplete(actor="system:startup-recovery")`：扫描未完成记录逐条续做，单条失败只记日志，返回汇总计数。
4. **签发阻断**：路由 `_refuse_tokens_for_external_service_account()` 增加未完成过渡检查（409，"source change in progress"）；`UserTokenRepository._insert()` 在持锁事务内做同样拒绝（防任何旁路）。
5. **路由适配（users.py）**：
   - PUT：传 `actor=admin_username`；路由层不再另发审计；映射 ValueError→400、INVALID_PARAMETER→409（非服务账号）、RESOURCE_ALREADY_EXISTS→409（主体冲突）、INVALID_STATE→409（变更进行中）、TransitionError→503（body 含 generation/phase，提示同请求重试续做）；200 body 增加 `generation`、`status`（`completed`/`finalization_pending`）。
   - 建账号：外部账号创建后直接 `user_identity_repo.link(..., allow_additional_provider=True)`（link 内含缓存失效），失败仍删账号回滚。
6. **启动恢复**：app lifespan 调用 `recover_incomplete()`，异常只告警。
7. **测试**（见下），运行针对性 pytest 与 pre-commit/black。

## 依赖与注意事项

- 多副本：begin 与令牌签发都锁 users 行实现串行化；阶段推进用条件 UPDATE 防双副本竞争；各阶段操作本身幂允许多次执行。
- 审计至多一次语义不保证（崩溃于审计与 mark_completed 之间会重复一条）；detail 携带 generation 可去重，属可接受。
- 撤销计数在"删除已提交、mark 前崩溃"时续做观察到 0：审计 detail 如实记录本尝试计数并带 `resumed=true`，安全属性（无旧凭据存活）不受影响。
- 本地内存缓存只清本副本，其他副本靠 TTL——与现状一致，不恶化；Redis 后端为共享清除。
- 认证热路径零新增查询（pending 不进 middleware/profile）；新增存在性查询仅在低频签发路径。
- Kubernetes 来源账号、SAML 不受影响；`kubernetes` 保留为不可选来源。

## 验证

- `pytest mlflow_oidc_auth/tests/db/test_service_account_transition_migration.py`（新增，含 downgrade 往返）
- `pytest mlflow_oidc_auth/tests/test_service_account_source_transition.py`（新增）：
  - internal→external 成功：四阶段顺序、令牌/会话已撤销、source 最后才发布、审计含 generation；
  - external→internal→再 external：旧令牌不恢复；身份 unlink/link 正确；
  - 注入失败：撤销失败留 pinned、source 仍旧、重试后续做完成；发布后缓存失败留 published、重试只调缓存+审计（断言撤销函数未再被调用）；发布失败留 revoked、重试完成；
  - 代际幂等：同目标重试复用 generation；异目标 409 且原身份保留；
  - 主体冲突 pin 前 409、无过渡行；
  - pending 期间两个签发入口均被拒（repo 抛 INVALID_STATE、路由 409）；
  - 未改变来源 PUT：无过渡行、令牌不撤销、subject 对账照常；
  - 普通人账号 409；外部账号签发 409；内部账号签发正常；
  - `recover_incomplete()` 对 pinned/published 残留行的恢复（模拟重启）。
- `pytest mlflow_oidc_auth/tests/middleware/test_bearer_identity_binding.py`（既有用例全绿，含路由 200/409 行为）
- `pytest mlflow_oidc_auth/tests/repository/test_user_token.py mlflow_oidc_auth/tests/routers/test_users.py mlflow_oidc_auth/tests/test_user_tokens_api.py`
- `black --line-length 160 mlflow_oidc_auth/` 与针对性 `pre-commit run`（只跑触及文件）

## 风险

- **阶段跨事务非原子**：各步分属不同 repo 会话；以阶段标记 + 幂等续做覆盖，条件 UPDATE 防并发双推进。
- **503 被客户端当作终态**：响应体明确携带 generation/phase 与"同请求重试即续做"语义；启动扫描兜底。
- **迁移在大表上的行为**：新表无回填、无 users 列变更，升级即时完成；downgrade 直接 drop。
- **误削弱安全检查的风险**：pending 期间签发拒绝为新增 fail-closed 路径；middleware 判定逻辑不改；配套拒绝测试。
