import re
from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class Chunk:
    id: str
    text: str
    provenance: str  # "trusted" | "user"
    access: str = "public"  # "public" | "restricted"
    owner_session: str = ""


def _tokens(s: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", s.lower()))


class KnowledgeBase(Protocol):
    def add(self, text: str, provenance: str, access: str = "public",
            owner_session: str = "") -> Chunk: ...
    def retrieve(self, query: str, session_id: str, k: int = 3) -> list[Chunk]: ...
    def seed(self, fixtures: list[dict]) -> None: ...
    def clear(self) -> None: ...


@dataclass
class InMemoryKB:
    _chunks: list[Chunk] = field(default_factory=list)
    _seq: int = 0

    def add(self, text: str, provenance: str, access: str = "public",
            owner_session: str = "") -> Chunk:
        self._seq += 1
        c = Chunk(f"c{self._seq}", text, provenance, access, owner_session)
        self._chunks.append(c)
        return c

    def retrieve(self, query: str, session_id: str, k: int = 3) -> list[Chunk]:
        q = _tokens(query)
        scored = [(len(q & _tokens(c.text)), c) for c in self._chunks]
        scored = [(s, c) for s, c in scored if s > 0]
        scored.sort(key=lambda t: (-t[0], t[1].id))
        return [c for _, c in scored[:k]]

    def seed(self, fixtures: list[dict]) -> None:
        for f in fixtures:
            self.add(f["text"], f.get("provenance", "trusted"),
                     f.get("access", "public"), f.get("owner_session", ""))

    def clear(self) -> None:
        self._chunks = []
        self._seq = 0
