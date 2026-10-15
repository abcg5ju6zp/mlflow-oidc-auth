# OIDC 提供方凭据代际化轮换 - 产品需求文档

## Overview

- **Summary**: 为每个身份提供方（OIDC IdP）的客户端凭据引入可识别、可持久化、可恢复的"配置代际"（credential generation）。登录发起时固定代际，回调只能由同一代际完成 code 兑换；凭据轮换经共享状态协调发布新一代际，旧代际在保留期内仅为在途登录与存量会话服务，多 worker / 响应丢失 / 重启后恢复出完全一致的代际集合，且绝不产生互相冲突的 OAuth 客户端。
- **Purpose**: 消除密钥轮换窗口内"旧 state + 新密钥"导致的 `invalid_client`、盲目重试二次消费一次性 code、多进程读取新值时机不一致等故障，并保证一次失败的轮换（新密钥无效、旧密钥清理失败）不会破坏当前活动配置。
- **Target Users**: 平台运维人员（轮换密钥、触发刷新、观察结果）；通过浏览器登录的最终用户（轮换窗口内登录不中断、失败有稳定错误）；部署的所有 worker 进程。

## Goals

- 每次凭据刷新发布为可识别代际，代际固定 client id、client secret、发现地址、回调相关设置与生效时间。
- 登录与回调用代际严格配对：同代际兑换、一次性、失败不试探其他密钥。
- 轮换协议多 worker 安全：串行化、幂等、可从共享 DB 状态恢复，验证失败不替换活动代际，旧代纪清理失败不报完成。
- 旧代际按保留期退役，仅服务在途登录与需刷新/撤销的旧会话；超期拒绝新登录。
- 客户端元数据与缓存随代际按提供方切换，不影响其他提供方。
- 静态部署、单进程、无凭据变化、现有会话令牌加密、普通登录/退出行为保持不变。

## Non-Goals

- 不替代、不代理外部密钥系统（Kubernetes Secret、Vault、云密钥服务）中的密钥删除/轮换动作；旧密钥在外部系统的生命周期由运维负责。本特性只管理密钥在本插件内的代际表示与清除。
- 不改变 bearer 令牌（含 Kubernetes 服务账号令牌、SAML）的验证路径；代际仅覆盖交互式 OIDC 客户端凭据。
- 不新增 CLI 刷新命令（刷新入口为管理员 API 与内部 Python 服务函数；已确认）。
- 不做代际的自动定时轮换/定时刷新（刷新由运维显式触发；保留期清理在刷新时与启动时执行）。
- 不改变 MLflow 核心行为、不引入新框架。

## Background & Context

现状（代码调研证据）：

- `oauth.py` 为每个提供方惰性注册唯一一个 authlib 客户端（`default` 提供方占用遗留名 `oidc`），密钥在注册时经 `config_manager` 解析一次，`_registered` 标志阻止重建。
- `config.AppConfig.refresh()` 与 `ConfigManager.refresh()` 已存在（K8s provider 会重新读取挂载文件），但应用运行期**没有任何调用点**；即使调用，已注册客户端仍持有旧密钥。
- 登录在 `routers/auth.py::_begin_login` 中经 `store.create_auth_state(provider_id, ...)` 建一行在途状态；回调 `consume_auth_state` 只取回 `provider_id`，随后 `_client_for_exchange` 取"当前"客户端兑换。authlib 把 nonce/PKCE verifier/redirect_uri 按 state 存在签名 cookie 中（`StarletteAppMixin.save_authorize_data`），与客户端实例无关——因此回调侧唯一需要固定的是"用哪一个客户端（哪一份凭据）兑换"。
- authlib 客户端按注册名缓存于 `OAuth._clients`，每个实例持有独立 `server_metadata` 与 JWKS 缓存；注册名确定即可在任意 worker 上重建同一客户端。
- 可复用设施：DB 仓储 + SQLite/Postgres 跨进程行锁模式（`repository/auth_session.py::refresh_guard`，进程内 `_KeyedLocks` + `SELECT ... FOR UPDATE`）；Fernet 静态加密（`session/token_vault.py`，HKDF 用途隔离）；每提供方 bearer JWKS 缓存（`auth.py::_provider_jwks_cache`，键含 `(provider_id, url)`）；管理员依赖 `dependencies.check_admin_permission`；Alembic 迁移链当前 head 为 `e1f2a3b4c5d6`。
- 在途 state 有效期 15 分钟（`DEFAULT_STATE_LIFETIME_SECONDS`）；会话默认存活 14 天（`DEFAULT_SESSION_LIFETIME_SECONDS` / `SESSION_COOKIE_MAX_AGE_SECONDS`）。

## Functional Requirements

### 代际模型与共享存储

- **FR-1（代际内容）**: 系统为每个 OIDC 提供方维护零个或一个 `active` 代际与零到多个 `retired` 代际，持久化于共享 DB 新表。每个代际不可变地固定：提供方 id、代际 id、client id、加密后的 client secret（公共客户端为空）、discovery URL、回调/客户端设置快照（静态 `OIDC_REDIRECT_URI`、scope、PKCE 方法、TLS verify、public_client 标志）、指纹、状态、生效时间、退役时间、保留截止时间、创建时间。
- **FR-2（密钥静态加密）**: client secret 以独立用途标签经 Fernet 加密后入库；支持专用密钥 `OIDC_CREDENTIAL_ENCRYPTION_KEY`（缺省时由 `SECRET_KEY` 经 HKDF 以独立 info 派生）；任何日志、审计、API 响应不得出现明文 secret，指纹最多暴露短前缀。现有 `token_vault`（会话令牌加密）实现与行为不变。
- **FR-3（启动引导）**: 当提供方在 DB 中没有任何代际行时（全新部署或升级后首次运行），从当前配置链惰性建立一个 `active` 代际，不做 IdP 探测（与今天启动注册的语义一致）；已有行时一律以 DB 为准，不隐式新建。

### 登录/回调代际绑定

- **FR-4（登录固定代际）**: 发起登录时解析该提供方当前 `active` 代际（并确保其 authlib 客户端已注册）；在 `auth_state` 行上记录所用代际 id；授权重定向只使用该代际的客户端。`retired` 或已过保留期的代际不得用于发起登录。
- **FR-5（回调同代际一次性兑换）**: 回调消费 state 后，只按行上的代际 id 解析客户端并兑换 code 一次。兑换失败返回与现有回调一致的稳定错误，**绝不**尝试活动代际或任何其他代际的密钥，绝不重试兑换（code 单次使用原则与现有 `_authorize_access_token_with_key_refresh` 不重试的既有结论保持一致）。
- **FR-6（代际缺失/超期）**: 回调时代际行不存在或已过保留截止时间，不发起任何 token 请求，返回固定错误（登录已过期，请重新登录）。
- **FR-7（会话记录代际）**: 登录成功建立的 `auth_sessions` 行记录本次登录的代际 id（可空字符串列，不加外键约束，使代际可独立清除）。

### 轮换协议

- **FR-8（刷新入口与串行化）**: 提供按提供方的刷新服务函数与管理员 HTTP API（见 FR-14）。刷新在单进程内以提供方为键加锁；在支持行锁的数据库上再以提供方状态行为锁跨进程串行化（沿用 `refresh_guard` 的双层锁与 SQLite 退化模式）。
- **FR-9（配置重读与无变化幂等）**: 刷新先调用 `config_manager.refresh()`，随后仅重读目标提供方的凭据材料并计算指纹；与该提供方当前 `active` 代际指纹相同（含活动代际不存在且新材料无法构成有效配置的情形按现状处理）则不新增、不切换，返回 `unchanged`。刷新不重算、不切换任何其他提供方的代际。
- **FR-10（先验证后切换，已确认策略）**: 指纹变化时，切换前必须：(a) 成功拉取新发现地址的 discovery 文档（含 issuer/token endpoint，限时）；(b) 机密客户端向 token endpoint 发起 `grant_type=client_credentials` 探测——HTTP 401/`invalid_client` 或网络/超时错误判定为验证失败；`invalid_grant`/`unauthorized_client`/`unsupported_grant_type` 判定为"凭据已通过客户端认证、授权类型未启用"，验证通过；公共客户端（PKCE）跳过 (b)。验证失败时不得替换活动代际、不得写入新代际行，返回失败并审计。
- **FR-11（单事务切换与清理原子性）**: 验证通过后，在单个 DB 事务内完成：插入新 `active` 行、将原活动行置为 `retired` 并写退役时间与保留截止时间、物理删除（含密文列）所有已过保留截止时间、或已退役超过在途 state 有效期（15 分钟）且无在途 state、无存活会话引用的旧代际。任一步失败整体回滚，活动代际不变，刷新结果不得报告完成。
- **FR-12（保留期语义）**: 旧代际保留截止时间默认为 `SESSION_COOKIE_MAX_AGE_SECONDS`（缺省 14 天）+ 在途 state 有效期（15 分钟），可由 `OIDC_CREDENTIAL_GENERATION_RETENTION_SECONDS` 覆盖。保留期内：在途登录的回调兑换、该代际会话的 refresh token 刷新与 RFC 7009 撤销继续可用该代际客户端。超过保留期：拒绝新登录与回调；会话刷新/撤销回退该提供方活动代际（best effort，沿用现有"失败只记录日志/审计、不阻断退出"的语义）。
- **FR-13（并发/丢失/重启一致）**: 同一目标材料的并发刷新只产生一个新代际：锁内重读 + 指纹比对 +（提供方 id、活动状态）唯一约束兜底；冲突方采用已提交代际并返回其结果。刷新响应丢失后重试得到相同结果（幂等）。任一 worker 重启后从代际行惰性重建客户端，注册名由（提供方 id、代际 id）确定性派生，同一代际在任意进程中同名同配置，不同代际天然是不同客户端——不存在互相冲突的 OAuth 客户端。
- **FR-14（管理员 API）**: 新增 admin-only 路由：`POST .../oidc/credentials/providers/{provider_id}/refresh`（返回 `unchanged`/`rotated`/`failed` 稳定 JSON，含代际 id 与时间戳、失败原因分类，不含任何密钥），`GET .../oidc/credentials/providers/{provider_id}/generations`（仅非密元数据与指纹短前缀）。未知提供方返回 404；未认证与非管理员被拒绝。
- **FR-15（缓存随代际切换、按提供方隔离）**: 提交切换后，进程内活动代际指向新客户端；该客户端持有独立的 authlib server_metadata/JWKS 缓存。同时仅驱逐目标提供方的 bearer JWKS 缓存条目（`default` 提供方同时驱逐部署级扁平缓存）；其他提供方的代际、客户端与缓存条目不受任何影响。
- **FR-16（审计）**: 轮换成功、无变化、验证失败、清理失败均发出审计事件，字段含提供方 id、结果分类、代际 id（成功时），不含量级化密钥信息。

### 兼容性

- **FR-17（行为不变项）**: 未发生凭据变化时刷新为无操作；单进程 + SQLite 部署完整可用；静态环境变量部署行为不变；`oauth.py` 的遗留调用面（`get_client(provider_id)` 返回活动代际客户端、`default` 的遗留客户端名解析、`ensure_*`/`reset_oauth`）对既有调用方与测试保持兼容；现有会话令牌加密机制不变；普通登录、登出（含 RP-initiated logout 与令牌撤销）流程不变。
- **FR-18（迁移）**: 新表与两个新可空列（`auth_state.credential_generation_id`、`auth_sessions.credential_generation_id`）经 Alembic 迁移落地，可在 SQLite 上正向与反向执行；存量行不受影响。

## Non-Functional Requirements

- **NFR-1（安全）**: 默认拒绝：任何代际解析失败（行缺失、状态不符、超期、提供方不匹配）均按失败处理，不存在"回退到别的密钥试试"的路径；密钥明文不入库、不入日志/API/审计；新端点默认拒绝非管理员。
- **NFR-2（性能）**: 不向已被基线测试保护的每请求认证路径（`AuthMiddleware`，2 条语句预算）增加查询。代际解析只发生在登录、回调、会话刷新等一次性流程；活动代际在进程内缓存，单次登录/回调相对现状至多增加 1 条 DB 语句。
- **NFR-3（可靠）**: 全部状态转换可重入、幂等；SQLite 与 PostgreSQL 行为一致（行锁能力差异按既有模式退化）；刷新探测有超时边界。
- **NFR-4（可观测）**: 结果可从 HTTP 响应与审计日志判定；代际状态端点可供运维核对。
- **NFR-5（测试）**: 每个新分支有单元/集成测试，包含越权负向测试与轮换窗口的跨代际登录测试；迁移含升降级测试；既有测试套件保持通过。

## Constraints

- **Technical**: Python / FastAPI / Flask / SQLAlchemy；ORM 模型 `Sql` 前缀；Black 160；Google/Sphinx docstrings；类型标注；存储单例 `store`；新 API 必须是 FastAPI router 并在 `routers/__init__.py` 注册、以 `Depends()` 鉴权；迁移可升降级并兼容 SQLite/PostgreSQL；不得为让测试通过而弱化任何检查。
- **Business**: 多租户隔离是核心价值；本特性是安全边界变更，任何"失败时换一把钥匙再试"的宽松逻辑均不可接受。
- **Dependencies**: 仅依赖现有库（authlib 1.8、cryptography/Fernet、SQLAlchemy/Alembic、现有 HTTP 客户端栈）；IdP 探测语义依赖 OAuth 2.0 标准错误码，Keycloak 等常见 IdP 的 401 与 400 区分是该策略成立的基础。

## Assumptions

- 密钥轮换时 client id 通常保持不变，但模型允许其改变；发现地址与回调设置也允许随代际改变（指纹涵盖全部固定字段）。
- 不支持 `client_credentials` 探测或网络不可达的场景按 FR-10 处理（显式 401/网络错误失败；授权类 400 错误通过）；不为绕过验证提供开关。
- 外部密钥系统中旧密钥的实际删除由运维/外部平台负责；"旧密钥删除失败"在本特性内指插件内旧代际密文与行的清除失败。
- 回调 URL 本身按请求动态计算并已由 authlib 按 state 固定在 cookie 中；代际快照固定的是静态 `OIDC_REDIRECT_URI` 与影响客户端构造的设置，不固定每次请求的动态来源地址。
- 代际 id 为随机不可猜测标识（不携带身份信息），代际顺序由状态与时间戳表达。

## Acceptance Criteria

### AC-1: 代际内容完整且密钥加密持久化
- **Type**: `rule`
- **Given**: 一个配置完成的 OIDC 提供方
- **When**: 系统为其建立活动代际后直接查询 DB
- **Then**: 代际行包含提供方 id、代际 id、client id、密文 client secret、discovery URL、回调/客户端设置快照、指纹、状态 `active`、生效时间；密文列不等于明文 secret，且经凭据 vault 可正确往返解密
- **Pass Condition**: 仓储测试断言上述字段存在、密文不含明文子串、解密值与原始 secret 相等；`token_vault` 相关测试零改动通过
- **Evidence**: `pytest mlflow_oidc_auth/tests/repository/ mlflow_oidc_auth/tests/session/`

### AC-2: 登录记录并使用活动代际
- **Type**: `rule`
- **Given**: 提供方存在活动代际 G1
- **When**: 请求 `/login/{provider}`
- **Then**: 创建的 `auth_state` 行携带 G1 的代际 id，且授权重定向由 G1 对应的 authlib 客户端发起
- **Pass Condition**: 测试观察 state 行代际字段 == G1，且发起授权的客户端注册名与 G1 确定性派生名一致
- **Evidence**: 新增 routers 登录代际绑定测试

### AC-3: 回调用同一代际兑换且只用一次
- **Type**: `rule`
- **Given**: 在途 state 绑定 G1，轮换后活动代际为 G2
- **When**: 回调到达
- **Then**: code 仅提交给 G1 的 token endpoint/客户端一次，G2 客户端不被调用
- **Pass Condition**: 测试以替身客户端断言 G1 收到恰好一次兑换调用、G2 零调用，且无第二次 token 请求
- **Evidence**: 新增跨代际回调测试

### AC-4: 兑换失败返回稳定错误且不试探其他密钥
- **Type**: `rule`
- **Given**: 在途 state 绑定 G1，G1 客户端兑换抛出 `invalid_client`
- **When**: 回调处理该异常
- **Then**: 重定向到固定的认证错误页（与既有兑换失败错误形态一致），不调用任何其他代际客户端，不重试
- **Pass Condition**: 测试断言其他代际客户端零调用、响应为既有稳定错误形态
- **Evidence**: 新增负向测试

### AC-5: 缺失或超期代际的回调被稳定拒绝
- **Type**: `rule`
- **Given**: state 绑定的代际行已被物理删除，或当前时间超过其保留截止时间
- **When**: 回调到达
- **Then**: 不发起任何 token 网络请求，重定向到"登录已过期，请重新登录"固定错误
- **Pass Condition**: 替身 HTTP 客户端断言零外呼；响应错误码固定
- **Evidence**: 新增测试

### AC-6: 无凭据变化的刷新幂等
- **Type**: `rule`
- **Given**: 活动代际 G1 的指纹与当前配置一致
- **When**: 单次或并发多次调用刷新
- **Then**: 不新增代际行、活动代际仍为 G1、返回 `unchanged`；并发场景下代际表仍只有一个活动行
- **Pass Condition**: 测试断言行数/活动 id 不变、响应状态为 unchanged
- **Evidence**: 新增轮换服务测试

### AC-7: 新密钥验证失败不替换活动代际
- **Type**: `rule`
- **Given**: 配置中新 secret 的发现文档可达但凭据探测返回 401/`invalid_client`（另一用例：网络超时）
- **When**: 调用刷新
- **Then**: 不插入新代际、活动代际保持 G1、响应为失败分类、发出失败审计事件
- **Pass Condition**: 测试断言活动行未变、无 active 新行、审计事件被记录；401 与超时两个分支均覆盖
- **Evidence**: 新增测试

### AC-8: 旧代际清理失败时刷新不报告完成
- **Type**: `rule`
- **Given**: 新密钥验证通过，但事务内旧代际清除/退役写入被注入失败
- **When**: 调用刷新
- **Then**: 事务回滚、活动代际仍为 G1（或响应明确为非完成状态且活动未被替换），响应/审计不得呈现成功
- **Pass Condition**: 注入失败后断言活动代际不变且刷新结果为失败
- **Evidence**: 新增测试

### AC-9: 并发刷新、响应丢失与重启恢复出相同代际
- **Type**: `rule`
- **Given**: 两个 worker（模拟为共享同一 DB 的两个独立进程内缓存/解析器实例）
- **When**: 并发执行同一目标材料的刷新；随后清空两个实例的内存状态模拟重启
- **Then**: 只产生一个新代际（冲突方采用），两实例重建出相同的活动/退役代际集合与同名、同配置客户端
- **Pass Condition**: 测试断言代际行数一致、活动 id 相同、两实例客户端注册名与 client id/secret 配置一致、不存在同代际两个不同客户端
- **Evidence**: 新增并发/恢复测试（SQLite 下行锁退化路径与唯一约束兜底均被执行）

### AC-10: 旧代际保留与到期语义
- **Type**: `rule`
- **Given**: G1 已退役，保留截止时间为 T
- **When**: 分别在 T 前与 T 后处理：在途回调、该代际会话刷新/撤销、新登录请求；并构造无在途 state 且无存活会话引用的旧代际
- **Then**: T 前回调兑换/刷新/撤销使用 G1；T 后新登录与回调被拒绝；超在途 state 有效期且零引用的旧代际在下次刷新/启动时被物理清除（密文一并删除）
- **Pass Condition**: 时间与引用两类用例分别断言客户端选择与行删除结果
- **Evidence**: 新增保留期/清除测试

### AC-11: 会话刷新与撤销跟随代际
- **Type**: `rule`
- **Given**: 会话行记录 G1，轮换后活动代为 G2
- **When**: 会话过期触发刷新、用户登出触发 RFC 7009 撤销
- **Then**: G1 仍保留时使用 G1 客户端；G1 被清除后回退 G2（失败仍 best-effort 不阻断登出）；回调路径在任何情况下不做此回退
- **Pass Condition**: 测试断言两阶段客户端选择，且 AC-5 的回调零回退保持成立
- **Evidence**: 新增会话代际测试

### AC-12: 缓存与元数据按提供方隔离切换
- **Type**: `rule`
- **Given**: 提供方 A、B 均有活动代际且各自 JWKS 缓存有条目
- **When**: 仅刷新 A
- **Then**: A 的 bearer JWKS 缓存条目被驱逐、新登录得到独立元数据缓存的新客户端；B 的代际行、客户端实例与缓存条目保持不变
- **Pass Condition**: 测试断言 B 缓存对象命中不变、B 客户端身份不变，A 缓存被驱逐
- **Evidence**: 新增缓存隔离测试

### AC-13: 管理员刷新/状态端点鉴权与响应安全
- **Type**: `rule`
- **Given**: 刷新与状态查询端点
- **When**: 未认证、非管理员、管理员分别访问；对未知提供方调用
- **Then**: 未认证/非管理员被拒绝（302 至登录或 403，与现有管理端点一致），管理员得到结构化响应，未知提供方 404；任何响应不含 client secret 明文
- **Pass Condition**: 负向 + 正向测试断言状态码与响应体字段（含指纹仅短前缀）
- **Evidence**: `pytest mlflow_oidc_auth/tests/routers/ -k credential`

### AC-14: 数据库迁移可升降级且兼容存量数据
- **Type**: `rule`
- **Given**: 迁移前数据库含存量 `auth_state`/`auth_sessions` 行
- **When**: 升级到新修订再降级回退
- **Then**: 升级后新表与两个可空列存在且存量行可读；代际仓储在空表上可引导；降级后表/列被移除且无报错（SQLite 以 batch 模式）
- **Pass Condition**: 迁移测试在 SQLite 上正向、反向均通过
- **Evidence**: 新增 `tests/db/test_credential_generations_migration.py`

### AC-15: 静态部署与既有行为无回归
- **Type**: `rule`
- **Given**: 未配置任何密钥系统、不触发刷新的默认部署
- **When**: 运行既有单元/路由/SAML 等测试与 perf 基线
- **Then**: 遗留 `oauth.oidc`/`get_client`/`ensure_*`/`reset_oauth` 语义、普通登录登出、会话令牌加密、每请求认证路径语句预算均不回退
- **Pass Condition**: 相关既有测试文件全部通过且 `test_auth_path_baseline.py` 通过
- **Evidence**: `pytest mlflow_oidc_auth/tests/ mlflow_oidc_auth/tests/perf/test_auth_path_baseline.py`（hooks 目录按既有约定逐文件运行）

### AC-16: 安全边界与代码质量评审
- **Type**: `rubric`
- **Dimension**: 密钥处理克制性（加密、零日志泄露、零回退试探）、默认拒绝完备性、错误稳定性、跨进程正确性、命名/注释/测试可读性
- **Scale**: 1-5
- **Anchors**: 1 = 存在密钥明文落日志/入库或回调可回退其他密钥；3 = 功能正确但存在两处以上可维护性或防御性缺口；5 = 所有密钥路径克制、所有失败模式 fail-closed 且有测试、结构与既有仓储/锁模式一致
- **Pass Threshold**: >= 4
- **Evidence**: 独立只读评审（security/code review）对照本 rubric 打分并给出证据

## Open Questions

- 无（三个关键决策点——验证策略、刷新入口、保留期限——已确认：发现文档+客户端凭据探测；管理员 API+内部函数；保留期默认对齐会话有效期并支持提前清除）。
