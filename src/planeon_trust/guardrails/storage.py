"""Atomic metadata-only guardrail decision and evidence storage."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Sequence


FORBIDDEN_FIELDS = frozenset(
    {
        "authorization",
        "claims",
        "content",
        "contentValue",
        "jwt",
        "modelOutput",
        "password",
        "privateKey",
        "prompt",
        "rawContent",
        "redactedContent",
        "secret",
        "subjectId",
        "token",
    }
)


class GuardrailStorageDenied(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class GuardrailStorageSnapshot:
    decisions: tuple[Mapping[str, object], ...]
    audits: tuple[Mapping[str, object], ...]
    evidence: tuple[Mapping[str, object], ...]
    outbox: tuple[Mapping[str, object], ...]


def _safe_shape(value: object) -> bool:
    if isinstance(value, Mapping):
        return not any(key in FORBIDDEN_FIELDS or not _safe_shape(item) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return all(_safe_shape(item) for item in value)
    return True


def _contains(value: object, protected: str) -> bool:
    if isinstance(value, str):
        return protected in value
    if isinstance(value, Mapping):
        return any(_contains(key, protected) or _contains(item, protected) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return any(_contains(item, protected) for item in value)
    return False


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


class GuardrailMemoryStore:
    def __init__(self) -> None:
        self._decisions: list[Mapping[str, object]] = []
        self._audits: list[Mapping[str, object]] = []
        self._evidence: list[Mapping[str, object]] = []
        self._outbox: list[Mapping[str, object]] = []
        self._lock = threading.Lock()
        self.fail_next_commit = False

    def record(
        self,
        decision: Mapping[str, object],
        audit: Mapping[str, object],
        evidence: Mapping[str, object],
        outbox: Mapping[str, object],
        *,
        protected_values: Sequence[str],
    ) -> None:
        records = (decision, audit, evidence, outbox)
        if not all(_safe_shape(record) for record in records):
            raise GuardrailStorageDenied("sensitive storage field refused")
        protected = tuple(value for value in protected_values if isinstance(value, str) and len(value) >= 16)
        if any(_contains(record, value) for record in records for value in protected):
            raise GuardrailStorageDenied("protected content storage refused")
        with self._lock:
            next_decisions = [*self._decisions, _freeze(decision)]
            next_audits = [*self._audits, _freeze(audit)]
            next_evidence = [*self._evidence, _freeze(evidence)]
            next_outbox = [*self._outbox, _freeze(outbox)]
            if self.fail_next_commit:
                self.fail_next_commit = False
                raise GuardrailStorageDenied("injected atomic commit failure")
            self._decisions = next_decisions
            self._audits = next_audits
            self._evidence = next_evidence
            self._outbox = next_outbox

    def snapshot(self) -> GuardrailStorageSnapshot:
        with self._lock:
            return GuardrailStorageSnapshot(
                tuple(self._decisions),
                tuple(self._audits),
                tuple(self._evidence),
                tuple(self._outbox),
            )
