from dataclasses import dataclass, field
from typing import Protocol

MODULE_RESET = "module_reset"


@dataclass
class Event:
    session_id: str
    module: str
    event_type: str
    actor: str
    details: dict
    id: int = 0


class Store(Protocol):
    def append_event(
        self, session_id: str, module: str, event_type: str, actor: str, details: dict
    ) -> None: ...
    def events_since_reset(self, session_id: str, module: str) -> list[Event]: ...
    def write_reset_marker(self, session_id: str, module: str) -> None: ...
    def get_progress(self, session_id: str, module: str) -> tuple[bool, bool]: ...
    def upsert_progress(
        self, session_id: str, module: str, core: bool, stretch: bool
    ) -> None: ...
    def ping(self) -> bool: ...


@dataclass
class InMemoryStore:
    _events: list[Event] = field(default_factory=list)
    _progress: dict[tuple[str, str], tuple[bool, bool]] = field(default_factory=dict)
    _seq: int = 0

    def append_event(
        self, session_id: str, module: str, event_type: str, actor: str, details: dict
    ) -> None:
        self._seq += 1
        self._events.append(
            Event(session_id, module, event_type, actor, dict(details or {}), self._seq)
        )

    def events_since_reset(self, session_id: str, module: str) -> list[Event]:
        rel = [e for e in self._events if e.session_id == session_id and e.module == module]
        last_reset = max(
            (e.id for e in rel if e.event_type == MODULE_RESET), default=0
        )
        return [e for e in rel if e.id > last_reset and e.event_type != MODULE_RESET]

    def write_reset_marker(self, session_id: str, module: str) -> None:
        self.append_event(session_id, module, MODULE_RESET, session_id, {})

    def get_progress(self, session_id: str, module: str) -> tuple[bool, bool]:
        return self._progress.get((session_id, module), (False, False))

    def upsert_progress(
        self, session_id: str, module: str, core: bool, stretch: bool
    ) -> None:
        self._progress[(session_id, module)] = (core, stretch)

    def ping(self) -> bool:
        return True
