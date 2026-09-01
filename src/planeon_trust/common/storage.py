"""Atomic redacted decision, audit, and internal-outbox storage contract."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


FORBIDDEN_FIELDS = frozenset(
    {
        "token", "jwt", "claims", "authorization", "attributes", "input",
        "policySource", "prompt", "modelOutput", "businessPayload",
    }
)


class StorageDenied(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class StorageSnapshot:
    decisions: tuple[Mapping[str, object], ...]
    audits: tuple[Mapping[str, object], ...]
    outbox: tuple[Mapping[str, object], ...]


def _redacted(value: object) -> bool:
    if isinstance(value, Mapping):
        return not any(key in FORBIDDEN_FIELDS or not _redacted(item) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return all(_redacted(item) for item in value)
    return True


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


class AtomicMemoryStore:
    def __init__(self) -> None:
        self._decisions: list[Mapping[str, object]] = []
        self._audits: list[Mapping[str, object]] = []
        self._outbox: list[Mapping[str, object]] = []
        self._lock = threading.Lock()
        self.fail_next_commit = False

    def record(self, decision: Mapping[str, object], audit: Mapping[str, object], outbox: Mapping[str, object]) -> None:
        if not all(_redacted(record) for record in (decision, audit, outbox)):
            raise StorageDenied("sensitive storage field refused")
        with self._lock:
            next_decisions = [*self._decisions, _freeze(decision)]
            next_audits = [*self._audits, _freeze(audit)]
            next_outbox = [*self._outbox, _freeze(outbox)]
            if self.fail_next_commit:
                self.fail_next_commit = False
                raise StorageDenied("injected atomic commit failure")
            self._decisions, self._audits, self._outbox = next_decisions, next_audits, next_outbox

    def snapshot(self) -> StorageSnapshot:
        with self._lock:
            return StorageSnapshot(tuple(self._decisions), tuple(self._audits), tuple(self._outbox))
