# OIDC 提供方凭据代际化轮换 - 独立审查

- **审查日期**: 2026-10-14
- **范围**: 实现对照 `.trae/specs/oidc-credential-generations/spec.md` 的全部变更
- **方式**: fresh-context 独立只读审查代理（静态阅读 + authlib 源码核对，未修改文件），随后由主流程按 findings 修复并复跑测试。

## 独立审查结论

**总体：pass。无 critical/high。** 识别 2 个 medium（F1 维护路径保留闸门、F2 真实并发证据）与若干 low（F4-F13）。

## Checkpoint

| CP | 内容 | 独立审查 | 修复后复核 |
| --- | --- | --- | --- |
| CP-R1 | 回调仅同代际兑换一次，不试探其他代际/提供方 | PASS | PASS（`tests/test_generation_bound_callback.py`） |
| CP-R2 | 代际缺失/超期零外呼、稳定错误、fail-closed | PASS | PASS |
| CP-R3 | 明文 secret 不入日志/API/审计/异常 | PASS | PASS |
| CP-R4 | 凭据 vault 与会话 token vault 隔离 | PASS | PASS（不同 HKDF info，专测） |
| CP-R5 | 管理端点鉴权充分、ajax 孪生同保护 | PASS | PASS |
| CP-R6 | 多 worker 唯一活动代际（索引+锁+采用） | PASS（运行证据弱=F2） | PASS（新增真实双线程测试；冲突异常改为 MlflowException 子类穿透托管 session） |
| CP-R7 | 切换/退役/清理单事务原子，失败回滚不报成功 | PASS | PASS |
| CP-R8 | 重启确定性重建、无冲突客户端 | PASS | PASS |
| CP-R9 | 保留/到期语义 | PARTIAL（F1） | PASS（维护路径新增 usable_at 闸门 + 专测） |
| CP-R10 | 缓存/元数据按提供方隔离 | PASS | PASS（驱逐加锁=F6） |
| CP-R11 | 先验证后切换、探测语义 | PASS（文本子串放行=F4） | PASS（仅结构化 error code/状态判定） |
| CP-R12 | 无轮换/静态/SAML/PKCE/登出/token 加密无回归 | PASS | PASS（全量套件） |
| CP-R13 | 迁移升降级/单 head/存量兼容 | PASS | PASS |
| CP-R14 | 新配置项、启动引导、不探测、sweep 容错 | PASS | PASS |
| CP-R15 | 认证热路径语句预算 | PASS | PASS（回调行读取合并为一次=F5；perf 基线通过） |
| CP-R16 | 审计覆盖成功/unchanged/失败 | PASS | PASS |
| CP-R17 | AC 证据完备性 | PARTIAL | PASS（补 F1/F2/F5/探测测试） |

## 发现与处置

- **F1（medium）会话刷新/撤销/end-session 未按 retain_until 判定** → 已修复：新增
  `usable_pinned_client(provider_id, generation_id)`（行存在且 `usable_at()` 才物化），
  `_client_for_refresh` 与 `_named_provider_end_session_url` 改用；回调仍严格 fail-closed
  不回退。测试：`TestSessionMaintenanceFollowsThePinnedGeneration`、
  `TestPinnedClientRetention`。
- **F2（medium）rotate 的唯一索引兜底缺真实并发执行；且托管 session 会把冲突包成
  MlflowException 导致服务层漏接** → 已修复：
  `ActiveGenerationConflict` 改为继承 `MlflowException(RESOURCE_ALREADY_EXISTS)` 原样穿透；
  flush 同时捕获 `OperationalError`（SQLite 写锁串行化）；新增真实双线程测试
  `TestConcurrentRotation.test_two_threads_publishing_the_same_material_leave_one_active`。
- **F4（low）探测错误用异常文本子串放行** → 已修复：只按结构化 `error` code 与 401/403
  状态判定，其余 fail-closed。
- **F5（low）冷 worker 回调用两次行读取** → 已修复：
  `generation_client(..., generation=row)` 复用已加载行，测试断言只读取一次并传入同一对象。
- **F6（low）JWKS 驱逐未持锁** → 已修复：在 `_provider_jwks_lock` 内驱逐。
- **F7（low）提交后物化异常会误报 500** → 已修复：提交后物化/采用包 try，失败仅日志，
  响应反映已提交结果。
- **F8（low）测试 helper 未真正切换 client_id** → 已修复：helper 显式参数，别名测试断言
  两代际 client id 不同。
- **F12（hardening）prune 的 EXISTS 未关联 provider_id** → 已修复：state/session 引用
  同时匹配 provider。
- F9（legacy 注册抖动，信息性，兑换路径不受影响，遗留面保留）、F10（滚动升级 15 分钟窗口
  fail-closed，已在文档发布说明语义中提示）、F11（保留期显式配 0 的语义符合 FR-11）、
  F13（首次刷新无活动行且配置无效返回 503 而非 unchanged；采取更响的语义，活动代际不变）
  作为记录保留，无需代码变更。

## AC 复核（独立审查 → 修复后）

| AC | 独立审查 | 修复后证据 |
| --- | --- | --- |
| AC-1 | PASS | `tests/repository/test_credential_generation.py`、`tests/credentials/test_credential_vault.py` |
| AC-2 | PASS | `routers/test_auth.py::test_login_success`、`test_provider_login.py::test_the_attempt_names_the_provider` |
| AC-3 | PASS | `test_the_callback_exchanges_with_the_pinned_generation_exactly_once`（G1=1/G2=0） |
| AC-4 | PASS | `test_a_failed_exchange_never_tries_another_generation` |
| AC-5 | PASS | `test_a_purged_generation...`、`..._past_its_retention_deadline...`、`..._without_a_generation_id...` |
| AC-6 | PARTIAL→PASS | `test_two_refresh_calls_with_the_same_material...` + `TestConcurrentRotation` 真实双线程 |
| AC-7 | PARTIAL→PASS | invalid_client/三类授权码/发现超时/无 token endpoint/公共客户端零探测 |
| AC-8 | PASS | `test_rotation_rolls_back...` + `test_a_failed_rotation_transaction...` |
| AC-9 | PARTIAL→PASS | 冲突穿透修复 + 双线程 + 重启重建测试 |
| AC-10 | PASS（F1 备注）→PASS | 仓储 6 例 + `TestPinnedClientRetention` |
| AC-11 | PASS（F1 备注）→PASS | `TestSessionMaintenanceFollowsThePinnedGeneration` 5 例（含过期回退） |
| AC-12 | PASS | `test_credential_jwks_cache.py` 3 例 + 服务层 A/B 隔离 |
| AC-13 | PASS | `tests/routers/test_oidc_credentials.py` 12 例 |
| AC-14 | PASS | `tests/db/test_credential_generations_migration.py`（SQLite 正反向） |
| AC-15 | PASS | 全量套件（hooks 逐文件）+ `tests/perf/test_auth_path_baseline.py` |
| AC-16 | PASS（4/5）→ PASS | 所有 fail-closed 路径有测试；密钥克制；结构一致 |

## 证据

- 独立审查全文（含 checkpoint 详述与未排查项声明）保存在本次会话记录中；代理以
  general_purpose_task 调用，未写入工作区。
- 修复后命令证据：受影响面 1815 项通过；全量套件（除 hooks 既有环境失败）与 perf 基线通过；
  hooks 目录唯一失败为 `test_artifact_proxy_coverage.py` 的 file: URI 解析，在 pristine 树
  同样失败（本机 fastapi/mlflow 版本与项目 pin 不一致 + pytest-flask 插件干扰，非本次变更）。

## Review History

### R1 - 2026-10-14 - 独立只读审查
- Result: pass（无 critical/high）
- Findings: F1..F13（见上），其中 F1/F2/F4/F5/F6/F7/F8/F12 已修复并补测试，其余记录保留。
- Checkpoint: CP-R1..CP-R17 见上表。
