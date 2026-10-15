"""Versioned, recoverable SCIM group changes (directory rename + membership sync).

A versioned write is a two-phase, crash-safe choreography around one
:class:`~mlflow_oidc_auth.db.models.SqlScimGroupChange` row:

1. :meth:`ScimGroupChangeRepository.plan` validates *everything* read-only — the group owner
   guard, the member names, the target name and external id, the targeted-removal ownership
   guard, and the directory version ordering — and only then writes the ``pending`` row with the
   normalized operations snapshot. A failed plan changes no group data and leaves no audit.
2. :meth:`ScimGroupChangeRepository.apply` performs the rename, the membership operations and
   the ``current_version`` bump in **one** transaction, taking the group row lock and
   re-checking the owner guard and the optimistic-concurrency base. Any failure rolls that
   transaction back: the group stays at its old name, membership and grants, while the row stays
   ``pending`` (attempt/error recorded) for a retry carrying the same ``(external_id, version)``.
   Commit is what flips the row to ``completed`` with the response snapshot.

Because memberships and every group permission reference the stable ``groups.id``, a rename
inside that transaction migrates no grant rows — it cannot leave a grant pointing at a name that
does not exist.
"""

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from mlflow.exceptions import MlflowException
from mlflow.protos.databricks_pb2 import INVALID_STATE, RESOURCE_ALREADY_EXISTS, RESOURCE_DOES_NOT_EXIST
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from mlflow_oidc_auth.config import config
from mlflow_oidc_auth.db.models import (
    GROUP_CHANGE_APPLYING,
    GROUP_CHANGE_COMPLETED,
    GROUP_CHANGE_PENDING,
    GROUP_CHANGE_SUPERSEDED,
    SqlGroup,
    SqlScimGroupChange,
    SqlUser,
    SqlUserGroup,
)
from mlflow_oidc_auth.logger import get_logger
from mlflow_oidc_auth.ownership import evaluate_group_write
from mlflow_oidc_auth.repository.group import (
    MembershipConflict,
    MembershipOutcome,
    MembershipRefused,
    GroupRepository,
    GroupWriteRefused,
    UnknownMember,
    _evaluate_removal,
    audit_group_conflict,
    audit_membership_conflicts,
)
from mlflow_oidc_auth.repository.utils import get_group

logger = get_logger()

#: Operations snapshot / wire format version inside ``ops_json``.
OPS_SNAPSHOT_VERSION = 1


@dataclass(frozen=True)
class GroupChangeRecord:
    """Plain fields of one ``scim_group_changes`` row, safe to read after its session closed."""

    id: int
    group_id: int
    external_id: str
    version: str
    base_version: Optional[str]
    old_name: str
    new_name: str
    status: str
    ops: List[Tuple[str, Optional[List[str]]]]
    planned_diff: Dict[str, List[str]]
    from_external_id: Optional[str]
    result: Optional[dict]
    attempts: int
    last_error: Optional[str]
    actor: Optional[str]
    token_id: Optional[int]

    @property
    def is_completed(self) -> bool:
        return self.status == GROUP_CHANGE_COMPLETED

    @property
    def is_open(self) -> bool:
        return self.status in (GROUP_CHANGE_PENDING, GROUP_CHANGE_APPLYING)


class SameVersion(MlflowException):
    """The request re-asserts the group's current version with no change record: a no-op replay.

    An ``MlflowException`` subclass (rather than a plain exception) so the managed-session wrapper
    rolls the read-only plan transaction back and re-raises it unconverted.
    """

    def __init__(self, group_id: int):
        super().__init__(f"directory version already current for group {group_id}", INVALID_STATE)
        self.group_id = group_id


class GroupVersionConflict(MlflowException):
    """The request's base version no longer matches the group's current version.

    A concurrent versioned write committed first, or the request carries a version older than
    the one the group is on. The client must re-read and retry; nothing was applied.
    """

    def __init__(self, message: str):
        super().__init__(message, INVALID_STATE)


class GroupChangeBlocked(MlflowException):
    """A group mutation is blocked while a directory change for it has not settled."""

    def __init__(self, group_name: str):
        super().__init__(
            f"Group '{group_name}' has an in-progress directory change; retry after it settles",
            INVALID_STATE,
        )
        self.group_name = group_name


def compare_versions(candidate: str, current: Optional[str]) -> int:
    """Order two directory versions, mirroring the rule the SCIM docs publish.

    Integer versions (both parseable) compare numerically; anything else compares lexicographically.
    ``None`` (the group never saw a version) sorts before every non-empty version.

    Returns:
        int: ``-1``/``0``/``1`` as :func:`operator.eq`-style ordering.
    """
    if current is None:
        return 1
    if candidate == current:
        return 0
    try:
        a, b = int(candidate), int(current)
    except (TypeError, ValueError):
        return -1 if candidate < current else 1
    return -1 if a < b else (1 if a > b else 0)


def _evaluate_targeted_removals(rows, outcome: MembershipOutcome, *, written_by: str) -> None:
    """Evaluate strict targeted removals **without deleting anything** — the plan-time precheck.

    Mirrors the strict branch of :meth:`GroupRepository._remove_rows` so an ``enforce`` refusal is
    decided before the ledger row exists; under ``report``/``off`` every row is allowed and this
    records nothing.
    """
    refused_here = False
    for row, user, group_name in rows:
        decision = _evaluate_removal(row, user, written_by, False)
        if decision.conflict:
            outcome.conflicts.append(MembershipConflict(user.username, group_name, decision))
        if not decision.allowed:
            refused_here = True
    if refused_here:
        raise MembershipRefused(outcome, written_by)


def _iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    return parsed.replace(tzinfo=None) if parsed.tzinfo is not None else parsed


def _record(row: SqlScimGroupChange, *, include_result: bool) -> GroupChangeRecord:
    payload = json.loads(row.ops_json)
    result = None
    if include_result and row.result_json:
        result = json.loads(row.result_json)
    return GroupChangeRecord(
        id=row.id,
        group_id=row.group_id,
        external_id=row.external_id,
        version=row.version,
        base_version=row.base_version,
        old_name=row.old_name,
        new_name=row.new_name,
        status=row.status,
        ops=[(kind, list(users) if users is not None else None) for kind, users in payload.get("ops", [])],
        planned_diff={k: list(v) for k, v in payload.get("planned_diff", {}).items()},
        from_external_id=payload.get("from_external_id"),
        result=result,
        attempts=int(row.attempts or 0),
        last_error=row.last_error,
        actor=row.actor,
        token_id=row.token_id,
    )


class ScimGroupChangeRepository:
    """Plan, apply, replay and recover the versioned group-change ledger."""

    def __init__(self, session_maker):
        self._Session: Callable[..., Session] = session_maker

    # ------------------------------------------------------------------ reads

    def get_change(self, external_id: str, version: str) -> Optional[GroupChangeRecord]:
        """The ledger row for a directory's ``(externalId, version)`` key, or None."""
        with self._Session() as session:
            row = self._row_by_key(session, external_id, version)
            return _record(row, include_result=True) if row is not None else None

    def find_change(self, *, version: str, old_name: Optional[str] = None, group_id: Optional[int] = None) -> Optional[GroupChangeRecord]:
        """Find a change for a retry that no longer carries a resolvable path/externalId.

        A PATCH rename retried against the old name after the response was lost may carry neither
        the new name nor the externalId. ``(version, old_name)`` then locates the ledger row — but
        a version string can repeat across directories, so this returns a row only when the match
        is *unambiguous* (exactly one); any collision resolves to None and the caller 404s.
        ``group_id`` narrows further when known.
        """
        with self._Session() as session:
            query = session.query(SqlScimGroupChange).filter(SqlScimGroupChange.version == version)
            if old_name is not None:
                query = query.filter(SqlScimGroupChange.old_name == old_name)
            if group_id is not None:
                query = query.filter(SqlScimGroupChange.group_id == group_id)
            rows_found = query.order_by(SqlScimGroupChange.id.desc()).all()
            return _record(rows_found[0], include_result=True) if len(rows_found) == 1 else None

    @staticmethod
    def _row_by_key(session: Session, external_id: str, version: str, group_id: Optional[int] = None) -> Optional[SqlScimGroupChange]:
        """Look a change up by the group's **current** external id and version.

        Joining ``groups`` (rather than trusting the ledger's historical ``external_id``) is what
        keeps idempotency correct when an external id is reused after a group moves off it: a
        ledger row left by a previous holder no longer joins, and the current holder's row does.
        ``(group_id, version)`` is unique and a live external id is unique among groups, so at most
        one row matches; ``group_id`` narrows further when the caller already resolved the group.
        """
        query = (
            session.query(SqlScimGroupChange)
            .join(SqlGroup, SqlGroup.id == SqlScimGroupChange.group_id)
            .filter(SqlGroup.external_id == external_id, SqlScimGroupChange.version == version)
        )
        if group_id is not None:
            query = query.filter(SqlScimGroupChange.group_id == group_id)
        return query.one_or_none()

    # ------------------------------------------------------------------ plan

    def plan(
        self,
        group_name: str,
        *,
        version: str,
        target_external_id: str,
        new_name: str,
        operations: Sequence[Tuple[str, Optional[Sequence[str]]]],
        written_by: str,
        actor: Optional[str] = None,
        token_id: Optional[int] = None,
    ) -> GroupChangeRecord:
        """Validate the whole change set and persist its ``pending`` row.

        See module docs for the ordering: a duplicate key is handed back (caller replays or
        resumes), a same-version re-assertion raises :class:`SameVersion`, an older version raises
        :class:`GroupVersionConflict`.

        Parameters:
            group_name: The group the request path addresses (its current name).
            version: The directory's monotonic version for this change.
            target_external_id: The non-empty external id the group has after the change. The
                idempotency key uses it, so PUT changing the external id keys on the new value.
            new_name: The group's name after the change; equal to ``group_name`` for member-only
                changes.
            operations: Normalized ``(kind, usernames)`` tuples, same shape as
                :meth:`GroupRepository.apply_group_changes`.
            written_by: The owning source (``scim`` for the SCIM API).
            actor: Who names the audit trail (token actor).
            token_id: The authenticating SCIM token's row id.

        Returns:
            GroupChangeRecord: The fresh ``pending`` row, or the existing row for the same key.

        Raises:
            MlflowException: ``RESOURCE_DOES_NOT_EXIST`` for an unknown group;
                :class:`UnknownMember`; :class:`MembershipRefused`; :class:`GroupWriteRefused`;
                ``RESOURCE_ALREADY_EXISTS`` for a taken name/external id;
                :class:`GroupVersionConflict` for a stale version.
        """
        normalized: List[Tuple[str, Optional[List[str]]]] = [(kind, list(usernames) if usernames is not None else None) for kind, usernames in operations]
        try:
            with self._Session(read_only=False) as session:
                group = get_group(session, group_name)
                group_decision = evaluate_group_write(group.managed_by, written_by, enforcement=config.MANAGED_BY_ENFORCEMENT)
                if not group_decision.allowed:
                    raise GroupWriteRefused(group.group_name, group_decision, written_by)

                # Idempotency correlation is (group, version): the same version re-presented for
                # this group returns its settled/open ledger row; historical rows of another group
                # that used the same externalId never match.
                duplicate = (
                    session.query(SqlScimGroupChange).filter(SqlScimGroupChange.group_id == group.id, SqlScimGroupChange.version == version).one_or_none()
                )
                if duplicate is not None:
                    return _record(duplicate, include_result=True)

                if compare_versions(version, group.current_version) == 0:
                    raise SameVersion(group.id)
                if compare_versions(version, group.current_version) < 0:
                    raise GroupVersionConflict(f"directory version {version!r} is older than the group's current version {group.current_version!r}")

                if new_name != group.group_name:
                    if session.query(SqlGroup.id).filter(SqlGroup.group_name == new_name).first() is not None:
                        raise MlflowException(f"Group '{new_name}' exists", RESOURCE_ALREADY_EXISTS)
                GroupRepository._assert_external_id_free(session, target_external_id, group.id)

                planned_diff = self._planned_diff(session, group, normalized, written_by=written_by)
                payload = {
                    "v": OPS_SNAPSHOT_VERSION,
                    "ops": normalized,
                    "planned_diff": planned_diff,
                    "from_external_id": group.external_id,
                }
                row = SqlScimGroupChange(
                    group_id=group.id,
                    external_id=target_external_id,
                    version=version,
                    base_version=group.current_version,
                    old_name=group.group_name,
                    new_name=new_name,
                    ops_json=json.dumps(payload, separators=(",", ":")),
                    status=GROUP_CHANGE_PENDING,
                    actor=actor,
                    token_id=token_id,
                )
                session.add(row)
                try:
                    session.flush()
                except IntegrityError:
                    # A concurrent planner won (group_id, version): its row is the change. Start a
                    # fresh transaction inside this same request and hand the existing row back so
                    # the caller replays or resumes instead of failing the duplicate.
                    session.rollback()
                    existing = (
                        session.query(SqlScimGroupChange).filter(SqlScimGroupChange.group_id == group.id, SqlScimGroupChange.version == version).one_or_none()
                    )
                    if existing is not None:
                        return _record(existing, include_result=True)
                    raise
                record = _record(row, include_result=False)
        except GroupWriteRefused as refused:
            audit_group_conflict(refused.group_name, refused.decision, written_by, actor=actor, operation="group.write")
            raise
        except MembershipRefused as refused:
            audit_membership_conflicts(MembershipOutcome(conflicts=refused.outcome.refused), written_by, actor=actor)
            raise
        # Note: no conflict audit here for a merely *allowed* (report/off) cross-owner plan: nothing
        # is written until apply commits, where the post-commit conflict audit is emitted once.
        return record

    @staticmethod
    def _planned_diff(session: Session, group: SqlGroup, operations: Sequence[Tuple[str, Optional[List[str]]]], *, written_by: str) -> Dict[str, List[str]]:
        """The intended add/remove sets against planning-time membership, plus pre-validation.

        Read-only by construction: every named member is resolved here (an unknown user or service
        account fails the plan before the ledger row exists), and a targeted (``remove``) operation
        is run through the ownership guard in evaluate-only mode so an ``enforce`` refusal lands
        before anything is written. A ``replace`` is a sync and never refuses here — its foreign
        rows are kept, as in the legacy path.
        """
        added: List[str] = []
        removed: List[str] = []

        def current() -> Dict[int, Tuple[SqlUserGroup, SqlUser]]:
            return {
                user.id: (row, user)
                for row, user in session.query(SqlUserGroup, SqlUser)
                .join(SqlUser, SqlUser.id == SqlUserGroup.user_id)
                .filter(SqlUserGroup.group_id == group.id, SqlUser.is_service_account.is_(False))
                .order_by(SqlUserGroup.id)
                .all()
            }

        precheck = MembershipOutcome()
        for kind, usernames in operations:
            members = current()
            if kind == "add":
                for user in GroupRepository._resolve_members(session, usernames or [], include_service_accounts=False):
                    if user.id not in members:
                        added.append(user.username)
            elif kind == "remove":
                if usernames is None:
                    targets = list(members.values())
                else:
                    ids = {user.id for user in GroupRepository._resolve_members(session, usernames, include_service_accounts=False)}
                    targets = [members[i] for i in members if i in ids]
                removed.extend(user.username for _, user in targets)
                _evaluate_targeted_removals([(row, user, group.group_name) for row, user in targets], precheck, written_by=written_by)
            elif kind == "replace":
                wanted = GroupRepository._resolve_members(session, usernames or [], include_service_accounts=False)
                wanted_ids = {user.id for user in wanted}
                added.extend(user.username for user in wanted if user.id not in members)
                removed.extend(user.username for uid, (_, user) in members.items() if uid not in wanted_ids)
            else:
                raise MlflowException(f"Unknown membership operation {kind!r}", INVALID_STATE)
        return {"added": sorted(set(added)), "removed": sorted(set(removed))}

    # ------------------------------------------------------------------ apply

    def apply(
        self,
        change_id: int,
        *,
        written_by: str,
        actor: Optional[str] = None,
    ) -> Tuple[MembershipOutcome, dict, GroupChangeRecord, bool]:
        """Drive a ``pending``/``applying`` change to completion in one transaction.

        Returns:
            ``(outcome, detail, record, settled_now)`` — membership outcome for the audit, the
            completed group detail, the completed ledger record, and whether **this call** made the
            transition to completed. A replay of an already-completed row returns
            ``settled_now=False`` and an empty outcome, so the caller emits completion audit events
            exactly once.

        Raises:
            MlflowException: Any validation/conflict that refused or rolled the apply back. The
                ledger row stays ``pending`` with its attempt recorded.
        """
        outcome = MembershipOutcome()
        group_decision = None
        try:
            with self._Session(read_only=False) as session:
                change = session.get(SqlScimGroupChange, change_id)
                if change is None:
                    raise MlflowException(f"Group change {change_id} not found", RESOURCE_DOES_NOT_EXIST)
                if change.status == GROUP_CHANGE_COMPLETED:
                    payload = json.loads(change.result_json)
                    return MembershipOutcome(), payload["detail"], _record(change, include_result=True), False
                if change.status == GROUP_CHANGE_SUPERSEDED:
                    # The request lost an earlier race; its answer is permanently 409, and the row
                    # stays terminal so it neither retries nor blocks the group's delete.
                    raise GroupVersionConflict(f"directory version {change.version!r} was superseded for group {change.new_name!r}")
                payload = json.loads(change.ops_json)

                group = self._locked_group(session, change.group_id)
                group_decision = evaluate_group_write(group.managed_by, written_by, enforcement=config.MANAGED_BY_ENFORCEMENT)
                if not group_decision.allowed:
                    raise GroupWriteRefused(group.group_name, group_decision, written_by)

                # Optimistic concurrency: only the request planned on the group's current version
                # advances. A concurrent versioned commit changes this first and wins; this row
                # becomes terminal (superseded) below so a lost race cannot block the group later.
                if (group.current_version or None) != (change.base_version or None):
                    raise GroupVersionConflict(
                        f"group version changed since the request was planned: base {change.base_version!r}, now {group.current_version!r}"
                    )
                if change.new_name != group.group_name:
                    if session.query(SqlGroup.id).filter(SqlGroup.group_name == change.new_name).first() is not None:
                        raise MlflowException(f"Group '{change.new_name}' exists", RESOURCE_ALREADY_EXISTS)
                GroupRepository._assert_external_id_free(session, change.external_id, group.id)

                change.status = GROUP_CHANGE_APPLYING
                session.flush()

                if change.new_name != group.group_name:
                    group.group_name = change.new_name
                if (group.external_id or None) != (change.external_id or None):
                    group.external_id = change.external_id or None

                self._apply_ops(session, group, payload["ops"], outcome, written_by=written_by)

                if change.new_name != change.old_name or outcome.changed or (group.external_id or None) != (payload.get("from_external_id") or None):
                    group.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
                group.current_version = change.version

                detail = GroupRepository._group_detail(group)
                detail["members"] = GroupRepository._members_by_group(session, [group.id], include_service_accounts=False)[group.id]
                snapshot = {
                    "detail": detail,
                    "outcome": {
                        "added": [[u, g] for u, g in outcome.added],
                        "removed": [[u, g] for u, g in outcome.removed],
                        "kept": [c.username for c in outcome.conflicts if c.kept],
                    },
                }
                change.status = GROUP_CHANGE_COMPLETED
                change.result_json = json.dumps(snapshot, default=_iso, separators=(",", ":"))
                change.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
                try:
                    session.flush()
                except IntegrityError as e:
                    # Last-race: another writer took the name or external id between the re-check
                    # and this commit. Surface it as the same 409 uniqueness a plan-time clash gets
                    # instead of a generic 400 carrying SQL text.
                    raise MlflowException(
                        f"Group '{change.new_name}' or external id {change.external_id!r} is no longer available",
                        RESOURCE_ALREADY_EXISTS,
                    ) from e
                record = _record(change, include_result=True)
        except GroupWriteRefused as refused:
            self._record_attempt(change_id, refused)
            audit_group_conflict(refused.group_name, refused.decision, written_by, actor=actor, operation="group.write")
            raise
        except MembershipRefused as refused:
            self._record_attempt(change_id, refused)
            audit_membership_conflicts(MembershipOutcome(conflicts=refused.outcome.refused), written_by, actor=actor)
            raise
        except GroupVersionConflict:
            # A lost version race is terminal, not retryable: mark superseded (below) so the row
            # stops blocking the group's delete, then hand the 409 to the caller unchanged.
            self._record_attempt(change_id, None, supersede=True)
            raise
        except Exception as exc:
            self._record_attempt(change_id, exc)
            raise
        if group_decision is not None and group_decision.conflict:
            audit_group_conflict(record.new_name, group_decision, written_by, actor=actor, operation="group.write")
        audit_membership_conflicts(outcome, written_by, actor=actor)
        return outcome, record_result_detail(record), record, True

    @staticmethod
    def _locked_group(session: Session, group_id: int) -> SqlGroup:
        """The group row, row-locked where the backend supports it.

        PostgreSQL takes ``FOR UPDATE``; SQLite ignores it (a write transaction there is already
        serialized by its database-level lock), so optimistic-concurrency checks stay correct on
        both.
        """
        query = session.query(SqlGroup).filter(SqlGroup.id == group_id)
        if session.bind.dialect.name == "postgresql":
            query = query.with_for_update()
        group = query.one_or_none()
        if group is None:
            raise MlflowException(f"Group id {group_id} not found", RESOURCE_DOES_NOT_EXIST)
        return group

    @staticmethod
    def _apply_ops(session: Session, group: SqlGroup, operations, outcome: MembershipOutcome, *, written_by: str) -> None:
        """The same add/remove/replace semantics as :meth:`GroupRepository.apply_group_changes`."""

        def current():
            return {
                user.id: (row, user)
                for row, user in session.query(SqlUserGroup, SqlUser)
                .join(SqlUser, SqlUser.id == SqlUserGroup.user_id)
                .filter(SqlUserGroup.group_id == group.id, SqlUser.is_service_account.is_(False))
                .order_by(SqlUserGroup.id)
                .all()
            }

        for kind, usernames in operations:
            members = current()
            if kind == "add":
                for user in GroupRepository._resolve_members(session, usernames or [], include_service_accounts=False):
                    if user.id not in members:
                        session.add(SqlUserGroup(user_id=user.id, group_id=group.id, managed_by=written_by))
                        outcome.added.append((user.username, group.group_name))
            elif kind == "remove":
                if usernames is None:
                    targets = list(members.values())
                else:
                    ids = {user.id for user in GroupRepository._resolve_members(session, usernames, include_service_accounts=False)}
                    targets = [members[i] for i in members if i in ids]
                rows = [(row, user, group.group_name) for row, user in targets]
                GroupRepository._remove_rows(session, rows, outcome, written_by=written_by, admin_override=False, strict=True)
            elif kind == "replace":
                wanted = GroupRepository._resolve_members(session, usernames or [], include_service_accounts=False)
                wanted_ids = {user.id for user in wanted}
                rows = [(row, user, group.group_name) for uid, (row, user) in members.items() if uid not in wanted_ids]
                GroupRepository._remove_rows(session, rows, outcome, written_by=written_by, admin_override=False, strict=False, sync=True)
                for user in wanted:
                    if user.id not in members:
                        session.add(SqlUserGroup(user_id=user.id, group_id=group.id, managed_by=written_by))
                        outcome.added.append((user.username, group.group_name))
            else:
                raise MlflowException(f"Unknown membership operation {kind!r}", INVALID_STATE)
            try:
                session.flush()
            except IntegrityError as e:
                raise MlflowException(f"Membership of '{group.group_name}' changed concurrently; retry", RESOURCE_ALREADY_EXISTS) from e

    def _record_attempt(self, change_id: int, exc: Optional[BaseException], *, supersede: bool = False) -> None:
        """Record a rolled-back apply attempt.

        A normal failure returns the row to ``pending`` (retryable; the original group stayed
        usable); a lost version race closes it as ``superseded`` (terminal — it must never block a
        group delete). Best effort, in its own transaction so the original rollback stands.
        """
        try:
            with self._Session(read_only=False) as session:
                row = session.get(SqlScimGroupChange, change_id)
                if row is None or row.status in (GROUP_CHANGE_COMPLETED, GROUP_CHANGE_SUPERSEDED):
                    return
                row.status = GROUP_CHANGE_SUPERSEDED if supersede else GROUP_CHANGE_PENDING
                row.attempts = int(row.attempts or 0) + 1
                row.last_error = (f"{type(exc).__name__}: {exc}" if exc is not None else "superseded by a newer directory version")[:500]
        except Exception:
            logger.warning("Could not record failed group-change attempt %d", change_id, exc_info=True)

    # -------------------------------------------------------------- recovery

    def recover_interrupted_changes(self) -> Dict[str, int]:
        """Reconcile ``applying`` rows left by a crashed process. Best effort, never raises.

        A row whose group already carries its version and name committed (the apply transaction
        is atomic, so that means membership landed too) is completed with a fresh snapshot; any
        other ``applying`` row returns to ``pending`` for the directory's same-key retry.
        ``pending`` rows are never auto-applied.

        Returns:
            dict: ``{"completed": n, "pending": n, "failed": n}`` counts.
        """
        summary = {"completed": 0, "pending": 0, "failed": 0}
        try:
            with self._Session(read_only=False) as session:
                rows = session.query(SqlScimGroupChange).filter(SqlScimGroupChange.status == GROUP_CHANGE_APPLYING).order_by(SqlScimGroupChange.id).all()
                for row in rows:
                    try:
                        group = session.get(SqlGroup, row.group_id)
                        settled = group is not None and (group.current_version or None) == (row.version or None) and group.group_name == row.new_name
                        if settled:
                            detail = GroupRepository._group_detail(group)
                            detail["members"] = GroupRepository._members_by_group(session, [group.id], include_service_accounts=False)[group.id]
                            row.result_json = json.dumps({"detail": detail, "recovered": True}, default=_iso, separators=(",", ":"))
                            row.status = GROUP_CHANGE_COMPLETED
                            row.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
                            summary["completed"] += 1
                        else:
                            row.status = GROUP_CHANGE_PENDING
                            row.attempts = int(row.attempts or 0) + 1
                            row.last_error = "interrupted apply reconciled at startup; awaiting retry"[:500]
                            summary["pending"] += 1
                    except Exception:
                        summary["failed"] += 1
                        logger.warning("Could not reconcile scim_group_changes row %d", row.id, exc_info=True)
        except Exception:
            logger.warning("SCIM group-change recovery did not run", exc_info=True)
            summary["failed"] += 1
        if any(summary.values()):
            logger.info("SCIM group-change recovery: %s", summary)
        return summary


def record_result_detail(record: GroupChangeRecord) -> dict:
    """The group-detail dict from a completed record's result snapshot."""
    detail = dict(record.result["detail"])
    detail["created_at"] = _parse_iso(detail.get("created_at"))
    detail["updated_at"] = _parse_iso(detail.get("updated_at"))
    return detail
