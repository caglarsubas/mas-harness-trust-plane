"""Tenant-keyed bounded metadata-only policy decision cache."""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(frozen=True, slots=True)
class CacheKey:
    organization_id: str
    subject_digest: str
    request_digest: str
    policy_digest: str


@dataclass(frozen=True, slots=True)
class CachedOutcome:
    reason_code: str
    obligations: tuple[str, ...]
    expires_at: datetime


class DecisionCache:
    def __init__(self, maximum_entries: int = 1024, maximum_ttl_seconds: int = 30) -> None:
        if not 1 <= maximum_entries <= 1024 or not 1 <= maximum_ttl_seconds <= 30:
            raise ValueError("cache bounds exceed TRUST-001")
        self._maximum_entries = maximum_entries
        self._maximum_ttl = maximum_ttl_seconds
        self._items: OrderedDict[CacheKey, CachedOutcome] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: CacheKey, *, now: datetime) -> CachedOutcome | None:
        with self._lock:
            value = self._items.get(key)
            if value is None:
                return None
            if now >= value.expires_at:
                del self._items[key]
                return None
            self._items.move_to_end(key)
            return value

    def put(self, key: CacheKey, *, reason_code: str, obligations: tuple[str, ...], now: datetime, ttl_seconds: int) -> None:
        if reason_code != "ALLOW" or not 1 <= ttl_seconds <= self._maximum_ttl:
            return
        value = CachedOutcome(reason_code, obligations, now + timedelta(seconds=ttl_seconds))
        with self._lock:
            self._items[key] = value
            self._items.move_to_end(key)
            while len(self._items) > self._maximum_entries:
                self._items.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def snapshot(self) -> tuple[tuple[CacheKey, CachedOutcome], ...]:
        with self._lock:
            return tuple(self._items.items())
