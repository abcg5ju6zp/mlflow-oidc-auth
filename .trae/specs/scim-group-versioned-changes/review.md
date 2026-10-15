# Independent Review — SCIM 组变更版本化与可恢复协调

- Review R1（fresh context, read-only general-purpose agent）：**FAIL** → F1/F2/F3 major + F4/F7/F8/F9 次要发现。
- Remediation：全部修复并新增回归测试（见 tasks.md Task 6 与本文档历史）。
- Review R2（fresh context, read-only）：**PASS**（131 passed/4 skipped 目标套件；扩大回归 843 passed/8 skipped）；F7/F9 并发分支由复审临时脚本实证（SQLite 写锁模型无法仓内跨事务复现），无阻断项。

## Checkpoints

- [x] **CP-R1（AC-1）变更先持久化**：plan 单事务内完成只读校验后写 pending 行（externalId/version/base/old/new/ops/diff），任何组数据写入前台账已存在。证据：`repository/scim_group_change.py` plan；`tests/repository/test_scim_group_change.py::TestPlan`。
- [x] **CP-R2（AC-2）managed_by+版本双闸门**：plan 与 apply（行锁后）各过一次 `evaluate_group_write`；targeted remove 规划前只读预检；enforce 下 manual/oidc 组 409 mutability 无 completed 行。证据：`TestOwnership`（scim）与仓储 enforce 用例。
- [x] **CP-R3（AC-3）单事务原子结果**：applying→改名→成员 ops→current_version→completed/快照在同一受管事务；故障回滚原名/成员/授权可用，同键 resume 完成；授权随稳定 group_id 延续，缓存经 `_GROUP_CUD_METHODS` 提交后刷新。证据：`test_failed_apply_keeps_the_original_group_usable_then_resumes_from_snapshot`。
- [x] **CP-R4（AC-4）成员解析失败零写入**：未知用户/service account 在规划阶段拒绝，无台账、无关系变更、无完成审计。证据：`TestPlan::test_unknown_member_*`、`TestOwnership::test_unknown_member_applies_nothing`。
- [x] **CP-R5（AC-5）externalId+版本幂等回放**：completed 记录回放**落定快照**（非活态），旧路径重放通过（组归属/旧名校验 + externalId 现行持有者 JOIN，杜绝跨组误绑，externalId 复用启动新链），审计仅一次。证据：R2 复核 + `TestIdempotentReplay`、`TestExternalIdReuse`。
- [x] **CP-R6（AC-6）版本冲突不覆盖**：唯一 `(group_id,version)`、组行锁（PG FOR UPDATE/SQLite 写串行）、base CAS；败者转 `superseded` 终态，旧版本 409，同版本回放 200。证据：`TestVersionConflicts`、`test_repeated_version_after_a_newer_one_is_a_conflict`。
- [x] **CP-R7（AC-7）改名门槛矩阵**：无版本/无 externalId → 400 mutability；保留字符 `/ ? # %`（PUT/PATCH 全形态）→ 400 invalidValue；重名 409；成功时 id/location 为新名。证据：`TestRenameGate`、`TestRenameValidation`。
- [x] **CP-R8（AC-8）审计/活动引用同版本且仅一次**：settled_now 才发 `group.renamed`/`group.members_changed`/`group.external_id_set`（含 version），回放零审计；scim_activity.resource_version 仅在确定结果出现。证据：`TestIdempotentReplay` 审计计数、`TestActivityVersion`。
- [x] **CP-R9（AC-9）重启核对**：applying  settled→completed（快照）/未达→pending；不自动应用 pending；逐行容错；lifespan best-effort 不阻断启动；零审计。证据：`test_scim_group_change_startup.py` 2 passed。
- [x] **CP-R10（AC-10）兼容与隔离**：无版本走旧路径，既有 Entra/Okta/ownership/delete/分页套件不改行为；无新增 xfail/skip；`tests/scim/` 全绿。
- [x] **CP-R11（AC-11）迁移可逆双后端**：b9c0d1e2f3a4 加 groups.current_version、scim_activity.resource_version、scim_group_changes（唯一 group_id+version、非唯一 external+version 索引、FK CASCADE）；upgrade→downgrade→upgrade 通过；无 PG 不兼容 DDL。
- [x] **CP-R12（AC-12）删除互斥**：同事务检查 pending/applying → 409；superseded 不阻塞；completed 后删除成功并显式清除台账（SQLite 不依赖 FK PRAGMA）。证据：`TestDeleteMutex` 三用例。
- [x] **CP-R13（AC-13）读路径零负担**：GET 不 JOIN 台账，current_version 随 groups 行返回；perf 套件（含 auth 热路径基线）全绿。
- [x] **CP-U1（AC-14, rubric ≥4）代码/安全契合度：4/5**。复用 `_remove_rows`/`_resolve_members`/`_members_by_group`/`_assert_external_id_free`/ownership 守卫/受管会话/缓存装饰器；错误映射集中；无秘密入库（last_error 截断、错误体不含 SQL 文本——F7 已修）；扣分项为两处分发分支的复杂度（经两轮安全走查可接受）。
- [x] **CP-U2（NFR-6/TR-5.2, rubric ≥4）文档准确性：4/5**：docs/scim.md 覆盖改名条件、版本序、versionConflict、幂等快照、externalId 复用、superseded、重启恢复、删除互斥、审计与 activity 字段。

## Evidence

- 目标套件（修复后）：`tests/scim/test_scim_group_versions.py`（26 用例）、`tests/repository/test_scim_group_change.py`（20 用例）、`test_scim_group_change_startup.py`（2）、`test_scim_group_change_migration.py`（SQLite 11 passed / PG 4 skipped）。
- 扩大回归：`tests/scim/ + tests/repository/ + tests/db/ + tests/perf/` = 1052 passed, 80 skipped；全仓（除 hooks/e2e）5784 passed, 213 skipped；hooks 27 文件独立运行，唯一失败 `test_artifact_proxy_coverage.py` 经干净树复现为预存问题。
- 静态：black 160 改动文件全部 unchanged；pre-commit（black/密钥/空白）Passed。
- R2 临时脚本实证（未落盘）：F7 末次 flush 映射、F9 planner 竞争回退、rename+externalId 双改双次重试、四种 PATCH 保留字符形态、enforce 拒绝矩阵、superseded 后删除。

## Findings & resolution

| ID | Severity | 问题 | 处置 |
|---|---|---|---|
| F1 | major | 台账 (externalId,version) 未绑定路径组，externalId 复用回放他组资源 | 已修复：现行 externalId JOIN + 组归属/旧名双重校验；`TestExternalIdReuse` |
| F2 | major | CAS 败者行永久 pending，阻塞 DELETE | 已修复：`superseded` 终态 + 互斥只挡 pending/applying；仓储/路由回归 |
| F3 | major | 版本化改名漏 `/ ? # %` 校验 | 已修复：编排器统一拦截 400 invalidValue；4 参数测试 |
| F4 | minor | 回放返回活态而非快照 | 已修复：record_result_detail 快照渲染（时间戳往返）；快照测试 |
| F6 | minor | (version,old_name) 模糊匹配歧义 | 已修复：恰好唯一才命中；歧义测试 |
| F7 | minor | flush 竞争映射 409 mutability 且可能带 SQL 文本 | 已修复：RESOURCE_ALREADY_EXISTS 映射；复审脚本实证 |
| F8 | suggestion | report 模式 plan 即发允许类冲突审计 | 已修复：仅 apply 提交后发一次，拒绝类仍在 plan 记录 |
| F9 | suggestion | 同键并发 planner 收 409 | 已修复：flush 撞键回滚重查返回既有行；复审脚本实证 |
| — | nit | `get_open_change_for_group` 死代码 | 已删除 |
| — | 已知 | `tests/hooks/test_artifact_proxy_coverage.py` 9 failed | 干净树复现，预存问题，与本变更无关 |

## Review History

- **R1**：FAIL（3 major + 4 minor/suggestion），独立只读代理，证据含三段端到端复现脚本。
- **R2**：PASS，独立只读代理逐项核验修复、回归 131+843 通过，未发现新安全缺陷；非阻断建议（F7/F9 仓内直接测试）受限于 SQLite 跨事务写锁模型，以脚本实证替代。
