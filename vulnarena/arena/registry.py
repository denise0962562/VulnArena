"""Active session cache backed by durable PostgreSQL report snapshots."""

from vulnarena.arena.contracts import ArenaSession


class SessionRegistry:
    def __init__(self) -> None:
        self._sessions: dict[str, ArenaSession] = {}
        self.db = None

    async def attach(self, db):
        from vulnarena.arena.contracts import ArenaStatus
        from vulnarena.arena.persistence import load_reports
        from vulnarena.schemas import utcnow

        self.db = db
        reports = await load_reports(db)
        for key, payload in reports.items():
            if not key.startswith("session:"):
                continue
            session = ArenaSession.model_validate(payload)
            if session.finished_at is None:
                session.status = ArenaStatus.INTERRUPTED
                session.finished_at = utcnow()
                session.fallback_reason = "服务重启，演练中断；历史报告保留，沙盒需重新建立。"
            self.put(session)
            await self.save(session)
        return reports.get("selfplay:latest", {})

    async def save(self, session):
        self.put(session)
        if self.db is not None:
            from vulnarena.arena.persistence import save_report

            await save_report(
                self.db, "session:" + session.session_id, session.model_dump(mode="json")
            )

    def put(self, session: ArenaSession) -> None:
        self._sessions[session.session_id] = session

    def get(self, session_id: str) -> ArenaSession | None:
        return self._sessions.get(session_id)

    def all(self) -> list[ArenaSession]:
        return list(self._sessions.values())

    def recent(self, limit: int = 20) -> list[dict[str, object]]:
        ordered = sorted(self._sessions.values(), key=lambda item: item.started_at, reverse=True)
        return [
            {
                "session_id": session.session_id,
                "status": session.status.value,
                "agent_mode": session.agent_mode,
                "model_calls": session.model_calls,
                "fallback_reason": session.fallback_reason,
                "defects": session.defects,
                "started_at": session.started_at.isoformat(),
                "finished_at": session.finished_at.isoformat() if session.finished_at else None,
            }
            for session in ordered[:limit]
        ]
