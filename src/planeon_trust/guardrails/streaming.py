"""Tenant-keyed bounded streaming state over the SDK-006 stream contract."""

from __future__ import annotations

import hashlib
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

from planeon_harness.guardrail import GuardrailOutcome, GuardrailResult, GuardrailStage, GuardrailStream

from planeon_trust.common.time import require_now

from .profiles import VerifiedGuardrailProfile


MAXIMUM_OPEN_STREAMS_PER_TENANT = 128
IDLE_TTL = timedelta(seconds=60)


class StreamState(str, Enum):
    OPEN = "OPEN"
    TERMINATED = "TERMINATED"
    FINISHED = "FINISHED"
    EXPIRED = "EXPIRED"


class StreamDenied(PermissionError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(f"guardrail stream denied: {reason_code}")
        self.reason_code = reason_code


@dataclass(slots=True)
class _Session:
    stream_id: str
    organization_id: str
    profile_id: str
    profile_digest: str
    stream: GuardrailStream
    state: StreamState
    next_sequence: int
    last_seen: datetime
    buffered_bytes: int
    content_hasher: object
    closed_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class StreamSnapshot:
    stream_id: str
    organization_id: str
    profile_id: str
    profile_digest: str
    state: StreamState
    next_sequence: int
    buffered_bytes: int


@dataclass(frozen=True, slots=True)
class StreamEvaluation:
    result: GuardrailResult
    snapshot: StreamSnapshot
    content_digest: str
    content_bytes: int


class GuardrailStreamRegistry:
    def __init__(self) -> None:
        self._sessions: dict[tuple[str, str], _Session] = {}
        self._lock = threading.RLock()

    def create(self, organization_id: str, verified: VerifiedGuardrailProfile, *, now: datetime) -> StreamSnapshot:
        current = require_now(now)
        if verified.organization_id != organization_id or verified.profile.stage is not GuardrailStage.STREAMING:
            raise StreamDenied("STREAM_PROFILE_REQUIRED")
        with self._lock:
            self._expire_and_prune(current)
            open_count = sum(
                session.organization_id == organization_id and session.state is StreamState.OPEN
                for session in self._sessions.values()
            )
            if open_count >= MAXIMUM_OPEN_STREAMS_PER_TENANT:
                raise StreamDenied("STREAM_CAPACITY_EXCEEDED")
            stream_id = f"stream.{uuid.uuid4().hex}"
            session = _Session(
                stream_id=stream_id,
                organization_id=organization_id,
                profile_id=verified.profile.profile_id,
                profile_digest=verified.profile_digest,
                stream=verified.client().stream(),
                state=StreamState.OPEN,
                next_sequence=1,
                last_seen=current,
                buffered_bytes=0,
                content_hasher=hashlib.sha256(),
            )
            self._sessions[(organization_id, stream_id)] = session
            return self._snapshot(session)

    def push(
        self,
        organization_id: str,
        stream_id: str,
        sequence: object,
        content: object,
        *,
        expected_profile_digest: str,
        now: datetime,
    ) -> StreamEvaluation:
        current = require_now(now)
        if type(sequence) is not int or sequence < 1 or not isinstance(content, str) or not content:
            raise StreamDenied("STREAM_REQUEST_MALFORMED")
        with self._lock:
            session = self._lookup(organization_id, stream_id, current)
            self._require_open(session, expected_profile_digest)
            if sequence != session.next_sequence:
                raise StreamDenied("STREAM_SEQUENCE_INVALID")
            candidate_hasher = session.content_hasher.copy()
            candidate_hasher.update(content.encode("utf-8"))
            candidate_bytes = session.buffered_bytes + len(content.encode("utf-8"))
            result = session.stream.push(content)
            session.next_sequence += 1
            session.last_seen = current
            if result.outcome in {
                GuardrailOutcome.DENY,
                GuardrailOutcome.QUARANTINE,
                GuardrailOutcome.ERROR_FAIL_CLOSED,
            }:
                session.state = StreamState.TERMINATED
                session.closed_at = current
                session.buffered_bytes = 0
                session.content_hasher = hashlib.sha256()
            else:
                session.buffered_bytes = candidate_bytes
                session.content_hasher = candidate_hasher
            return StreamEvaluation(
                result,
                self._snapshot(session),
                f"sha256:{candidate_hasher.hexdigest()}",
                candidate_bytes,
            )

    def finish(
        self,
        organization_id: str,
        stream_id: str,
        sequence: object,
        *,
        expected_profile_digest: str,
        now: datetime,
    ) -> StreamEvaluation:
        current = require_now(now)
        if type(sequence) is not int or sequence < 1:
            raise StreamDenied("STREAM_REQUEST_MALFORMED")
        with self._lock:
            session = self._lookup(organization_id, stream_id, current)
            self._require_open(session, expected_profile_digest)
            if sequence != session.next_sequence:
                raise StreamDenied("STREAM_SEQUENCE_INVALID")
            content_digest = f"sha256:{session.content_hasher.hexdigest()}"
            content_bytes = session.buffered_bytes
            result = session.stream.finish()
            session.next_sequence += 1
            session.last_seen = current
            session.closed_at = current
            session.state = StreamState.FINISHED
            session.buffered_bytes = 0
            session.content_hasher = hashlib.sha256()
            return StreamEvaluation(result, self._snapshot(session), content_digest, content_bytes)

    def profile_for(self, organization_id: str, stream_id: str, *, now: datetime) -> str:
        current = require_now(now)
        with self._lock:
            return self._lookup(organization_id, stream_id, current).profile_id

    def expire_profile(self, organization_id: str, profile_id: str) -> None:
        with self._lock:
            for session in self._sessions.values():
                if (
                    session.organization_id == organization_id
                    and session.profile_id == profile_id
                    and session.state is StreamState.OPEN
                ):
                    self._close_content(session)
                    session.state = StreamState.EXPIRED
                    session.closed_at = session.last_seen

    def snapshots(self) -> tuple[StreamSnapshot, ...]:
        with self._lock:
            return tuple(self._snapshot(item) for item in self._sessions.values())

    def _lookup(self, organization_id: str, stream_id: object, now: datetime) -> _Session:
        if not isinstance(stream_id, str) or not stream_id.startswith("stream."):
            raise StreamDenied("STREAM_NOT_FOUND")
        self._expire_and_prune(now)
        session = self._sessions.get((organization_id, stream_id))
        if session is None:
            raise StreamDenied("STREAM_NOT_FOUND")
        if session.state is StreamState.EXPIRED:
            raise StreamDenied("STREAM_EXPIRED")
        if session.state is StreamState.TERMINATED:
            raise StreamDenied("STREAM_TERMINATED")
        if session.state is StreamState.FINISHED:
            raise StreamDenied("STREAM_FINISHED")
        return session

    @staticmethod
    def _require_open(session: _Session, expected_profile_digest: str) -> None:
        if session.profile_digest != expected_profile_digest:
            raise StreamDenied("STREAM_PROFILE_CHANGED")
        if session.state is not StreamState.OPEN:
            raise StreamDenied(f"STREAM_{session.state.value}")

    def _expire_and_prune(self, now: datetime) -> None:
        for session in self._sessions.values():
            if session.state is StreamState.OPEN and now - session.last_seen >= IDLE_TTL:
                self._close_content(session)
                session.state = StreamState.EXPIRED
                session.closed_at = now
        stale = [
            key
            for key, session in self._sessions.items()
            if session.closed_at is not None and now - session.closed_at >= IDLE_TTL * 2
        ]
        for key in stale:
            del self._sessions[key]

    @staticmethod
    def _close_content(session: _Session) -> None:
        try:
            session.stream.finish()
        except Exception as exc:
            raise StreamDenied("STREAM_CLEAR_FAILED") from exc
        session.buffered_bytes = 0
        session.content_hasher = hashlib.sha256()

    @staticmethod
    def _snapshot(session: _Session) -> StreamSnapshot:
        return StreamSnapshot(
            stream_id=session.stream_id,
            organization_id=session.organization_id,
            profile_id=session.profile_id,
            profile_digest=session.profile_digest,
            state=session.state,
            next_sequence=session.next_sequence,
            buffered_bytes=session.buffered_bytes,
        )
