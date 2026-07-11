import json
from pathlib import Path

import psycopg

from halcyon.store import MODULE_RESET, Event

_SCHEMA = (Path(__file__).parent / "schema.sql").read_text()


def init_schema(dsn: str) -> None:
    with psycopg.connect(dsn) as conn:
        conn.execute(_SCHEMA)
        conn.commit()


class PostgresStore:
    def __init__(self, dsn: str) -> None:
        self._dsn = dsn

    def append_event(
        self, session_id: str, module: str, event_type: str, actor: str, details: dict
    ) -> None:
        with psycopg.connect(self._dsn) as conn:
            conn.execute(
                "INSERT INTO audit_log (session_id, module, event_type, actor, details) "
                "VALUES (%s, %s, %s, %s, %s)",
                (session_id, module, event_type, actor, json.dumps(details or {})),
            )
            conn.commit()

    def events_since_reset(self, session_id: str, module: str) -> list[Event]:
        with psycopg.connect(self._dsn) as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(id), 0) FROM audit_log "
                "WHERE session_id=%s AND module=%s AND event_type=%s",
                (session_id, module, MODULE_RESET),
            ).fetchone()
            last_reset = row[0] if row else 0
            rows = conn.execute(
                "SELECT session_id, module, event_type, actor, details, id "
                "FROM audit_log WHERE session_id=%s AND module=%s AND id>%s "
                "AND event_type<>%s ORDER BY id",
                (session_id, module, last_reset, MODULE_RESET),
            ).fetchall()
        return [Event(r[0], r[1], r[2], r[3], r[4], r[5]) for r in rows]

    def write_reset_marker(self, session_id: str, module: str) -> None:
        self.append_event(session_id, module, MODULE_RESET, session_id, {})

    def get_progress(self, session_id: str, module: str) -> tuple[bool, bool]:
        with psycopg.connect(self._dsn) as conn:
            row = conn.execute(
                "SELECT core, stretch FROM progress WHERE session_id=%s AND module=%s",
                (session_id, module),
            ).fetchone()
        return (row[0], row[1]) if row else (False, False)

    def upsert_progress(
        self, session_id: str, module: str, core: bool, stretch: bool
    ) -> None:
        with psycopg.connect(self._dsn) as conn:
            conn.execute(
                "INSERT INTO progress (session_id, module, core, stretch, updated_at) "
                "VALUES (%s, %s, %s, %s, now()) "
                "ON CONFLICT (session_id, module) DO UPDATE SET "
                "core=EXCLUDED.core, stretch=EXCLUDED.stretch, updated_at=now()",
                (session_id, module, core, stretch),
            )
            conn.commit()

    def ping(self) -> bool:
        try:
            with psycopg.connect(self._dsn, connect_timeout=3) as conn:
                conn.execute("SELECT 1")
            return True
        except psycopg.Error:
            return False
