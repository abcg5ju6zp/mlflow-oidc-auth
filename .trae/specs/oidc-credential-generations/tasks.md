# OIDC 提供方凭据代际化轮换 - 实施计划

任务为依赖有序的纵向切片；每个任务自带可执行验证要求。除任务 7 的文档更新外，每个任务都包含代码与测试。

## Task 1: 凭据加密 vault 与新增配置项
- **Status**: `pending`
- **Priority**: high
- **Depends On**: None
- **Description**:
  - 新增 `mlflow_oidc_auth/credentials/` 包与 `credentials/vault.py`：`CredentialVault` 仿 `session/token_vault.py`，HKDF info 为独立标签 `mlflow-oidc-auth/provider-credentials/v1`；支持专用 `OIDC_CREDENTIAL_ENCRYPTION_KEY`（逗号分隔多 Fernet key，首把加密、全部可解密），缺省由 `SECRET_KEY` 派生；`get_credential_vault()` 按 key 材料缓存；明文不入异常/日志/repr。
  - `config.py` 新增：`OIDC_CREDENTIAL_ENCRYPTION_KEY`（启动校验，复用校验逻辑）、`OIDC_CREDENTIAL_GENERATION_RETENTION_SECONDS`（缺省 = `SESSION_COOKIE_MAX_AGE_SECONDS` 或 14 天 + 900 秒）、`OIDC_CREDENTIAL_VALIDATION_TIMEOUT_SECONDS`（缺省 10）。
  - 不改动 `session/token_vault.py` 任何行为。
- **Acceptance Criteria Addressed**: AC-1, AC-15, AC-16
- **Test Requirements**:
  - `rule` TR-1.1: vault 加密-解密往返正确；错误 key/篡改密文返回 None 且不抛出；多 key 中旧 key 可解密；`pytest mlflow_oidc_auth/tests/session/`（既有）零改动通过。证据：新增 `tests/credentials/test_credential_vault.py` 与既有 session vault 测试输出。
  - `rule` TR-1.2: 配置项缺省值与非法专用 key 启动报错（不回显值）。证据：新增配置测试断言。
- **Notes**: 测试目录新增 `tests/credentials/__init__.py`。

## Task 2: 代际表、迁移与仓储
- **Status**: `pending`
- **Priority**: high
- **Depends On**: Task 1
- **Description**:
  - 新增 `db/models/credential.py::SqlOidcCredentialGeneration`：`id` PK、`provider_id`、`generation_id`（String(64)）、`client_id`、`encrypted_secret`（Text 可空）、`discovery_url`、`client_settings_json`（Text：scope/pkce/verify/public_client/静态 redirect_uri 快照）、`fingerprint`（String(64)，SHA-256 hex）、`status`（String(16)：active/retired）、`effective_at`、`retired_at` 可空、`retain_until` 可空、`created_at`；唯一约束 `(provider_id, generation_id)`；部分唯一索引"每提供方至多一个 active"（SQLite `sqlite_where` + PostgreSQL `postgresql_where`）；普通索引 `(provider_id, status)`、`retain_until`。
  - `db/models/identity.py` 两个模型各增可空 `credential_generation_id: String(64)`（不加外键），并在 `db/models/__init__.py` 导出新模型。
  - 新 Alembic 修订（down_revision = `e1f2a3b4c5d6`）：建表 + 两个可空列 + 索引；downgrade 反向（`batch_alter_table`）。
  - 新增 `repository/credential_generation.py`：不可变实体 `CredentialGeneration`（含 settings dict 解析）；方法包括 `bootstrap_from_config`（仅在无行时插入活动行，竞态冲突时采用）、`get_active(provider_id)`、`get(generation_id)`（跨提供方需带 provider 过滤的解析接口）、`list_generations(provider_id)`、`rotate(...)`（单事务：唯一 active 冲突重读、插新、退役旧、按规则物理清除旧行）、`prune_retired(...)`、引用计数（存活 `auth_sessions` 行数、未消费 `auth_state` 行数，均按 generation id）、`invalidate_cache` 钩子不需要（缓存放服务层）。进程内 per-provider `threading.Lock`（仿 `_KeyedLocks` 思路，可复用其实现）。
  - `repository/__init__.py`、`sqlalchemy_store.py`、`store.py` 接线（store 单例上暴露门面方法；只读方法允许 read_only session）。
- **Acceptance Criteria Addressed**: AC-1, AC-6, AC-9, AC-10, AC-14
- **Test Requirements**:
  - `rule` TR-2.1: 迁移在 SQLite 上 upgrade/downgrade 成功；升级后旧 state/session 行可读、新列可空；downgrade 后新表/列不存在。证据：新增 `tests/db/test_credential_generations_migration.py` 通过。
  - `rule` TR-2.2: 仓储行为：bootstrap 幂等（并发式二次调用采用同一行）；rotate 后唯一 active、旧行 retain_until 正确；同活动指纹插入被唯一约束拒绝并可重读采用；物理清除删除密文行；引用计数统计正确。证据：新增 `tests/repository/test_credential_generation.py`。
  - `rule` TR-2.3: 实体/仓储任何输出不携带明文 secret（encrypted_secret 字段不进实体 repr）。证据：测试 repr/序列化结果不含明文子串。
- **Notes**: DateTime 一律 naive UTC，与现有模型一致。

## Task 3: 代际化 authlib 客户端注册、解析与 JWKS 缓存失效
- **Status**: `pending`
- **Priority**: high
- **Depends On**: Task 2
- **Description**:
  - `oauth.py` 改造（保持模块 docstring 同步更新）：
    - 确定性客户端名：由（provider_id, generation_id）派生（`default` 前缀 `oidc`，其余 slugify provider id，规则与 `_secret_env_key` 一致）；同一代际任意进程同名。
    - 新增 `register_generation_client(generation: CredentialGeneration)`：从代际固定字段注册 authlib 客户端（含 scope/verify/pkce/redirect 快照语义，公共客户端无 secret），注册后进程内记忆 `generation_id -> client` 与 `provider_id -> active generation_id`。
    - `get_active_client(provider_id)`：活动代际客户端（必要时从 DB 引导，见 Task 5 的引导函数；本任务先调用仓储 bootstrap + 设置构造）。
    - `get_generation_client(provider_id, generation_id)`：按代际行注册/取回；行缺失返回 None。
    - `get_client(provider_id)` 保留为公开兼容面，语义改为"活动代际客户端"；`ensure_client_registered`/`ensure_all_clients_registered` 改为引导 + 注册活动代际；`is_oidc_configured` 语义不变。
    - `reset_oauth()` 同时清空代际记忆与注册态。
  - 处理遗留名 `oidc`：内部调用点（`routers/auth.py` 等）全部改为解析器，不再依赖 `oauth.oidc` 指向活动客户端；`oauth.oidc` 如仍被遗留外部面需要，仅作为 default 活动代际的只读属性访问器（模块包装），不为其注册可变客户端。实现时先全仓 grep `oauth.oidc` 调用点逐一迁移。
  - `auth.py` 新增 `invalidate_provider_jwks_cache(provider_id)`：驱逐 `_provider_jwks_cache` 中该提供方全部键；`default` 提供方额外清空扁平 `_jwks_cache`。不触碰其他提供方。
- **Acceptance Criteria Addressed**: AC-2, AC-9, AC-12, AC-15, AC-16
- **Test Requirements**:
  - `rule` TR-3.1: 同一代际在两个全新解析器实例上派生出相同客户端名与相同注册配置（client id、server_metadata_url、secret 存在性、client_kwargs）；不同代际客户端实例不同、metadata/JWKS 缓存相互独立。证据：新增 `tests/test_oauth_generations.py`。
  - `rule` TR-3.2: `get_client`/`ensure_*`/`is_oidc_configured`/`reset_oauth` 既有兼容测试通过；`pytest mlflow_oidc_auth/tests/test_oauth.py mlflow_oidc_auth/tests/test_auth_module.py` 通过（若既有测试断言内部注册结构，按行为等价更新）。
  - `rule` TR-3.3: JWKS 失效只影响目标提供方：预置 A/B 缓存，失效 A 后 B 仍命中。证据：新增 auth 缓存单测。
- **Notes**: `_client_settings` 的凭据组装逻辑需要同时服务"当前配置引导"与"代际快照注册"，重构为可复用纯函数。

## Task 4: 登录、回调、会话与代际绑定
- **Status**: `pending`
- **Priority**: high
- **Depends On**: Task 3
- **Description**:
  - `repository/auth_state.py`：`create()` 增 `credential_generation_id` 参数写入；`AuthAttempt` 携带该字段；`consume()` 返回。
  - `repository/auth_session.py`：`create()` 增 `credential_generation_id`；`ResolvedSession` 携带；登出/刷新读取路径带出。
  - `routers/auth.py`：
    - `_begin_login`：解析活动代际客户端（失败沿用现有 500 形态）；`create_auth_state(..., credential_generation_id=active_gen.id)`；授权重定向使用该客户端。
    - `_process_oidc_callback_fastapi`：消费 state 后按 `(provider, generation_id)` 取代际行；行缺失或 `status`/`retain_until` 不满足 → 固定错误"登录已过期，请重新登录"，零网络外呼；兑换只使用该代际客户端恰好一次；任何异常路径不尝试其他代际（删除 `_client_for_exchange` 的隐式回退语义，改为显式代际解析；default 遗留路径同样必须有代际——引导保证）。
    - `_open_server_session`/store.create_auth_session 写入代际 id；pending SessionTokens 路径同样记录。
    - `_client_for_refresh` 与撤销/end-session 客户端选择：优先会话代际客户端；代际已被清除时回退活动代际（仅刷新/撤销，best-effort 语义不变）；`_logout_context` 带出代际 id。
    - userinfo 调用继续使用兑换客户端（本就是同代际）。
  - store 门面方法签名更新；全部既有调用方修正。
- **Acceptance Criteria Addressed**: AC-2, AC-3, AC-4, AC-5, AC-11, AC-15
- **Test Requirements**:
  - `rule` TR-4.1: 登录写出 state 代际字段，授权客户端为活动代际；轮换后回调使用旧代际客户端恰好一次、新代际零调用、无二次外呼。证据：扩展/新增 `tests/routers/test_provider_login.py` 同目录新测试文件。
  - `rule` TR-4.2: 代际缺失与超期两条路径零 token 外呼并返回固定错误；兑换异常不触碰其他代际客户端。证据：负向测试。
  - `rule` TR-4.3: 会话刷新/撤销在代际保留时用旧客户端、清除后回退活动客户端；登出失败仍 best-effort。证据：扩展 routers/auth 会话测试。
  - `rule` TR-4.4: 既有 `tests/repository/test_auth_state.py`、`test_auth_session.py` 与 `tests/routers/test_auth.py` 全部通过（按新参数补齐）。
- **Notes**: 回调错误走现有 `/oidc/ui/auth?error=` 形态，新增固定错误标识，不改前端契约以外的内容。

## Task 5: 凭据轮换服务（重读、探测、协调、清理与恢复）
- **Status**: `pending`
- **Priority**: high
- **Depends On**: Task 4
- **Description**:
  - 新增 `credentials/generations.py` 服务：
    - `snapshot_provider_credentials(provider_id)`：经配置链读取该提供方当前 client_id/secret/public/discovery/回调静态项与 client_kwargs，产出材料与指纹（SHA-256 over 规范化 JSON；secret 参与哈希但不记录）。
    - `validate_new_credentials(snapshot, timeout)`：先 `load_server_metadata()`（新 discovery URL，超时 `OIDC_CREDENTIAL_VALIDATION_TIMEOUT_SECONDS`）；机密客户端再以临时 authlib 客户端调用 `fetch_access_token(grant_type="client_credentials")`：401/`invalid_client`/网络超时 → `invalid`；`invalid_grant`/`unauthorized_client`/`unsupported_grant_type` → `accepted`；公共客户端跳过探测。
    - `publish_refresh(provider_id) -> RefreshResult`：进程内 per-provider 锁 → `config_manager.refresh()` → 重读指纹 → 与活动代际相同返回 `unchanged`；不同则验证 → 失败返回 `failed`（审计 `auth.credential_refresh_failed`，活动不变）→ 通过则仓储单事务 rotate+prune（保留期取配置）；提交后注册新代际客户端、切换活动指向、驱逐该提供方 JWKS 缓存；任一步骤异常结果不得为成功，审计失败。
    - `bootstrap_provider(provider_id)` 与 `bootstrap_all()`：无行则从当前配置建立活动代际（不探测），供 `ensure_*` 与 lifespan 使用；启动时执行一次 prune（best-effort，仅记录日志）。
    - 冲突采用：rotate 遇唯一约束冲突时重读活动行，指纹相同则采用并返回 `unchanged`/`rotated`（幂等），否则返回冲突失败。
    - 进程内活动代际缓存，以 DB 行为准可重建；提供 `reset` 仅测试用。
  - `app.py` lifespan：启动引导所有已配置 OIDC 提供方代际并注册客户端（替换/包裹现有 `ensure_all_clients_registered` 输出，健康状态语义保持）。
  - 审计：`auth.credential_refresh`（rotated/unchanged）、`auth.credential_refresh_failed`（invalid_credentials/cleanup_failed/conflict），detail 不含密钥；指纹只出短前缀（前 8 字符）。
- **Acceptance Criteria Addressed**: AC-6, AC-7, AC-8, AC-9, AC-10, AC-12, AC-16
- **Test Requirements**:
  - `rule` TR-5.1: 无变化 → unchanged 且无行变化；401/invalid_client 与超时两分支 → failed、活动不变、有审计；授权型 400 错误 → rotated。证据：新增 `tests/credentials/test_generation_service.py`（替身 IdP/HTTP）。
  - `rule` TR-5.2: 注入清理失败 → 结果非完成、活动代际不变；并发同材料双调用仅一个新代际且双方结果一致；清空内存状态后恢复出相同活动/退役集合与同名客户端。证据：服务并发/恢复测试。
  - `rule` TR-5.3: rotated 后仅目标提供方 JWKS 缓存被驱逐、活动指向切换；其他提供方无变化。证据：与 TR-3.3 互补的服务级测试。
  - `rule` TR-5.4: 提前清除：退役超过 state TTL 且零 state/会话引用的代际被物理删除；仍被引用或未超期的保留。证据：仓储+服务测试。
  - `rubric` TR-5.5: 并发正确性与失败模式完备性；1-5；锚点：1=存在产生重复活动行或失败后活动被替换的路径，3=主路径正确但恢复/冲突分支缺测，5=所有分支（不变/成功/验证失败/清理失败/冲突/重启）均有代码与测试；阈值 >=4；证据：评审与测试覆盖矩阵。
- **Notes**: 探测客户端必须是一次性的、不进入代际注册表；日志只记异常类型与提供方 id。

## Task 6: 管理员凭据代际 API
- **Status**: `pending`
- **Priority**: high
- **Depends On**: Task 5
- **Description**:
  - 新增 `routers/oidc_credentials.py`，前缀仿现有管理端约定（`/api/2.0/mlflow/oidc/credentials`，经 `_get_rest_path`）：
    - `POST /providers/{provider_id}/refresh`：`Depends(check_admin_permission)`；调用 `publish_refresh`；200 返回 `{provider_id, result: unchanged|rotated, active_generation: {id, effective_at, fingerprint_prefix}, retired: [...]}`；验证失败 422/502 稳定分类（不泄露内部细节），清理/冲突失败 500；未知提供方 404。
    - `GET /providers/{provider_id}/generations`：返回非密元数据列表（id、status、effective_at、retired_at、retain_until、fingerprint_prefix、client_id、discovery_url）。
  - 在 `routers/__init__.py` 注册（纳入 get_all_routers，自动获得 ajax 孪生）；确认路由被 validator 策略覆盖的方式与现有 FastAPI 管理路由一致（依赖门即授权）。
- **Acceptance Criteria Addressed**: AC-13
- **Test Requirements**:
  - `rule` TR-6.1: 未认证请求被拒（与现有管理端点同形态）、非管理员 403、管理员 200；未知提供方 404；任何响应体/日志不含 secret 明文，指纹仅短前缀。证据：新增 `tests/routers/test_oidc_credentials.py`（含负向越权用例）。
  - `rule` TR-6.2: refresh 端点对 unchanged/rotated/failed 三类服务结果返回稳定状态码与 JSON 结构。证据：同上。
- **Notes**: 遵循仓库"新 FastAPI 路由必须有依赖门"与 application/problem+json 之外的既有错误形态约定（以现有 routers 为准，不引入新错误格式）。

## Task 7: 文档更新与全量门禁
- **Status**: `pending`
- **Priority**: medium
- **Depends On**: Task 6
- **Description**:
  - 更新既有 `docs/configuration-providers.md`（与必要时 `docs/configuration.md`）：说明代际语义、轮换窗口行为、保留期配置、新环境变量、管理员端点与稳定错误；不新建文档文件。
  - 运行并记录：Black 160 格式化；目标测试集 + perf 基线 + hooks 逐文件；迁移升降级；最后跑全量 `pytest mlflow_oidc_auth/tests/`（hooks 目录按 Gotcha 逐文件）。
- **Acceptance Criteria Addressed**: AC-15, AC-16
- **Test Requirements**:
  - `rule` TR-7.1: `black --line-length 160 --check mlflow_oidc_auth/` 通过；全量测试通过（含 perf 基线），失败项附输出。证据：命令输出记录于 Completion Evidence。
  - `rubric` TR-7.2: 文档与实现一致性（变量名、端点、错误码、默认值）；1-5；锚点：1=文档与代码多处不符，3=主流程准确但缺边界说明，5=覆盖正常/轮换/失败/保留期且与代码逐项一致；阈值 >=4；证据：评审对照。
