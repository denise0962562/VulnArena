"""Put a finished drill back into either state.

The range is memory-only, so a snapshot is just "which defects were on" plus "what
the gateway policy looked like before the patch". Restoring is therefore a few
attribute writes, not a database rollback.
"""

from vulnarena.arena.contracts import ArenaSession, ArenaSnapshot, ArenaStatus
from vulnarena.arena.events import ArenaEvent
from vulnarena.arena.runtime import ArenaRuntime
from vulnarena.procure.app import ProcureState
from vulnarena.procure.models import DefectFlag


async def _write_policy(runtime: ArenaRuntime, session_id: str, snapshot: ArenaSnapshot) -> None:
    store = runtime.policy_store
    if store is None or snapshot.policy is None:
        return
    policy = snapshot.policy.model_copy(update={"session_id": session_id})
    await store.save(policy)
    runtime.forget(session_id)


def _apply_flags(state: ProcureState, defects: list[str]) -> None:
    wanted = set(defects)
    for flag in DefectFlag:
        state.set_flag(flag, flag.value in wanted)


async def restore_vulnerable(
    state: ProcureState, runtime: ArenaRuntime, session: ArenaSession
) -> ArenaSession:
    """Undo the patch: defects back on, gateway back to its weak baseline."""
    snapshot = session.snapshot
    if snapshot is None:
        raise ValueError("session has no snapshot")
    _apply_flags(state, snapshot.defects)
    await _write_policy(runtime, session.session_id, snapshot)
    session.status = ArenaStatus.BREACH_CONFIRMED
    await runtime.emit(
        ArenaEvent(
            session_id=session.session_id,
            stage="RESTORE",
            kind="restored",
            message="靶场已复原到未修复状态",
            data={"defects": snapshot.defects},
        )
    )
    return session


async def apply_patch(
    state: ProcureState, runtime: ArenaRuntime, session: ArenaSession
) -> ArenaSession:
    """Re-apply the defence: defects off, patch rule back into the policy."""
    snapshot = session.snapshot
    if snapshot is None:
        raise ValueError("session has no snapshot")
    _apply_flags(state, [])
    patched = snapshot
    rules = list(session.patch.rules) if session.patch is not None else []
    if not rules and session.patch is not None and session.patch.rule is not None:
        rules = [session.patch.rule]
    if rules and snapshot.policy is not None:
        merged_rules = list(snapshot.policy.blocked_patterns)
        seen = {rule.regex for rule in merged_rules}
        merged_rules.extend(rule for rule in rules if rule.regex not in seen)
        merged = snapshot.policy.model_copy(update={"blocked_patterns": merged_rules})
        patched = snapshot.model_copy(update={"policy": merged})
    await _write_policy(runtime, session.session_id, patched)
    passed = session.regression is not None and session.regression.passed
    session.status = ArenaStatus.VERIFIED if passed else ArenaStatus.REGRESSION_FAILED
    await runtime.emit(
        ArenaEvent(
            session_id=session.session_id,
            stage="RESTORE",
            kind="patched",
            message="靶场已回到已修复状态",
            data={"rule_ids": [rule.id for rule in rules]},
        )
    )
    return session
