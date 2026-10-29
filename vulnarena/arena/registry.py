"""In-process registry of arena sessions.

The report table arrives with PostgreSQL persistence in a later phase; the page
only needs the latest sessions to survive a browser refresh.
"""

from vulnarena.arena.contracts import ArenaSession


class SessionRegistry:
    def __init__(self) -> None:
        self._sessions: dict[str, ArenaSession] = {}

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
                "defects": session.defects,
                "started_at": session.started_at.isoformat(),
                "finished_at": session.finished_at.isoformat() if session.finished_at else None,
            }
            for session in ordered[:limit]
        ]
