"""Authenticated guardrail evaluation, evidence, and stream orchestration."""

from __future__ import annotations

import re
import uuid
from datetime import datetime

from planeon_harness.guardrail import GuardrailContractError, GuardrailOutcome, GuardrailResult, GuardrailStage

from planeon_trust.common.canonical import digest_json, opaque_digest
from planeon_trust.common.identity import IdentityDenied, IdentityVerifier, TenantIdentity, contains_tenant_identity
from planeon_trust.common.time import render_timestamp, require_now

from .profiles import GuardrailProfileManager, ProfileDenied, VerifiedGuardrailProfile
from .storage import GuardrailMemoryStore, GuardrailStorageDenied
from .streaming import GuardrailStreamRegistry, StreamDenied, StreamEvaluation, StreamSnapshot


EVALUATION_SCHEMA = "harness.planeon.ai/guardrail-evaluation/v1alpha1"
STREAM_SCHEMA = "harness.planeon.ai/guardrail-stream/v1alpha1"
OUTBOX_SCHEMA = "harness.planeon.ai/internal-outbox/v1alpha1"
EVIDENCE_API_VERSION = "harness.planeon.ai/v1alpha1"
_STABLE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$")


class GuardrailServiceDenied(PermissionError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(f"guardrail service denied: {reason_code}")
        self.reason_code = reason_code


def _profile_id(value: object) -> str:
    if not isinstance(value, str) or len(value) > 128 or _STABLE_ID.fullmatch(value) is None:
        raise GuardrailServiceDenied("REQUEST_MALFORMED")
    return value


def _request(raw: object, fields: set[str]) -> dict[str, object]:
    if not isinstance(raw, dict) or set(raw) != fields or contains_tenant_identity(raw):
        raise GuardrailServiceDenied("CALLER_TENANT_FORBIDDEN" if contains_tenant_identity(raw) else "REQUEST_MALFORMED")
    return raw


class GuardrailService:
    def __init__(
        self,
        *,
        identity: IdentityVerifier,
        profiles: GuardrailProfileManager,
        streams: GuardrailStreamRegistry,
        store: GuardrailMemoryStore,
    ) -> None:
        self.identity = identity
        self.profiles = profiles
        self.streams = streams
        self.store = store

    def ready(self, organization_id: str, *, now: datetime) -> bool:
        try:
            return self.profiles.ready(organization_id, now=now)
        except ValueError:
            return False

    def evaluate(self, bearer_token: object, raw: object, *, now: datetime) -> dict[str, object]:
        current = require_now(now)
        admitted = self._admit(bearer_token, current)
        request = _request(raw, {"profileId", "content"})
        profile_id = _profile_id(request["profileId"])
        content = request["content"]
        if not isinstance(content, str):
            raise GuardrailServiceDenied("REQUEST_MALFORMED")
        verified = self._active(admitted.organization_id, profile_id, current)
        if verified.profile.stage is GuardrailStage.STREAMING:
            raise GuardrailServiceDenied("STREAM_ROUTE_REQUIRED")
        try:
            result = verified.client().evaluate(content)
        except GuardrailContractError as exc:
            raise GuardrailServiceDenied(exc.code) from exc
        return self._record(admitted, verified, result, opaque_digest(content), len(content.encode("utf-8")), current, (content,))

    def create_stream(self, bearer_token: object, raw: object, *, now: datetime) -> dict[str, object]:
        current = require_now(now)
        admitted = self._admit(bearer_token, current)
        request = _request(raw, {"profileId"})
        profile_id = _profile_id(request["profileId"])
        verified = self._active(admitted.organization_id, profile_id, current)
        try:
            snapshot = self.streams.create(admitted.organization_id, verified, now=current)
        except StreamDenied as exc:
            raise GuardrailServiceDenied(exc.reason_code) from exc
        return self._stream_created(snapshot)

    def push_stream(
        self,
        bearer_token: object,
        stream_id: object,
        raw: object,
        *,
        now: datetime,
    ) -> dict[str, object]:
        current = require_now(now)
        admitted = self._admit(bearer_token, current)
        request = _request(raw, {"sequence", "content"})
        content = request["content"]
        if not isinstance(content, str) or not content:
            raise GuardrailServiceDenied("STREAM_REQUEST_MALFORMED")
        try:
            profile_id = self.streams.profile_for(admitted.organization_id, str(stream_id), now=current)
            verified = self._active(admitted.organization_id, profile_id, current)
            evaluation = self.streams.push(
                admitted.organization_id,
                str(stream_id),
                request["sequence"],
                content,
                expected_profile_digest=verified.profile_digest,
                now=current,
            )
        except StreamDenied as exc:
            raise GuardrailServiceDenied(exc.reason_code) from exc
        result = self._record(
            admitted,
            verified,
            evaluation.result,
            evaluation.content_digest,
            evaluation.content_bytes,
            current,
            (content,),
        )
        return self._stream_evaluation(evaluation, result)

    def finish_stream(
        self,
        bearer_token: object,
        stream_id: object,
        raw: object,
        *,
        now: datetime,
    ) -> dict[str, object]:
        current = require_now(now)
        admitted = self._admit(bearer_token, current)
        request = _request(raw, {"sequence"})
        try:
            profile_id = self.streams.profile_for(admitted.organization_id, str(stream_id), now=current)
            verified = self._active(admitted.organization_id, profile_id, current)
            evaluation = self.streams.finish(
                admitted.organization_id,
                str(stream_id),
                request["sequence"],
                expected_profile_digest=verified.profile_digest,
                now=current,
            )
        except StreamDenied as exc:
            raise GuardrailServiceDenied(exc.reason_code) from exc
        result = self._record(
            admitted,
            verified,
            evaluation.result,
            evaluation.content_digest,
            evaluation.content_bytes,
            current,
            (),
        )
        return self._stream_evaluation(evaluation, result)

    def _admit(self, bearer_token: object, now: datetime) -> TenantIdentity:
        try:
            return self.identity.verify(bearer_token, now=now)
        except IdentityDenied as exc:
            raise GuardrailServiceDenied(exc.reason_code) from exc

    def _active(self, organization_id: str, profile_id: str, now: datetime) -> VerifiedGuardrailProfile:
        try:
            return self.profiles.active(organization_id, profile_id, now=now)
        except ProfileDenied as exc:
            raise GuardrailServiceDenied(exc.reason_code) from exc

    def _record(
        self,
        admitted: TenantIdentity,
        verified: VerifiedGuardrailProfile,
        result: GuardrailResult,
        content_digest: str,
        content_bytes: int,
        now: datetime,
        protected_values: tuple[str, ...],
    ) -> dict[str, object]:
        decision_id = f"decision.guardrail.{uuid.uuid4().hex}"
        evaluated_at = render_timestamp(now)
        result_dict = result.to_dict()
        result_metadata = {key: value for key, value in result_dict.items() if key != "redactedContent"}
        released = result.outcome in {GuardrailOutcome.ALLOW, GuardrailOutcome.REDACT}
        decision = {
            "schemaVersion": EVALUATION_SCHEMA,
            "decisionId": decision_id,
            "organizationId": admitted.organization_id,
            "profileId": verified.profile.profile_id,
            "profileVersion": verified.profile.version,
            "profileDigest": verified.profile_digest,
            "stage": verified.profile.stage.value,
            "contentDigest": content_digest,
            "contentBytes": content_bytes,
            "result": result_metadata,
            "released": released,
            "evaluatedAt": evaluated_at,
        }
        evidence = self._evidence(decision, verified, result, now)
        audit = {
            "auditId": f"audit.guardrail.{decision_id.rsplit('.', 1)[1]}",
            "organizationId": admitted.organization_id,
            "decisionId": decision_id,
            "subjectDigest": opaque_digest(admitted.subject_id),
            "profileDigest": verified.profile_digest,
            "contentDigest": content_digest,
            "outcome": result.outcome.value,
            "reasonCode": result.reason_code,
            "released": released,
            "evidenceId": evidence["metadata"]["id"],
            "recordedAt": evaluated_at,
        }
        outbox = {
            "schemaVersion": OUTBOX_SCHEMA,
            "eventId": f"outbox.guardrail.{decision_id.rsplit('.', 1)[1]}",
            "eventType": "planeon.trust.guardrail-evaluation.recorded.v1alpha1",
            "classification": "INTERNAL_GUARDRAIL_METADATA_NOT_PUBLIC_LIFECYCLE_CLOUDEVENT",
            "organizationId": admitted.organization_id,
            "aggregateId": decision_id,
            "aggregateDigest": digest_json(decision),
            "evidenceId": evidence["metadata"]["id"],
            "recordedAt": evaluated_at,
        }
        redacted = result.redacted_content
        try:
            self.store.record(
                decision,
                audit,
                evidence,
                outbox,
                protected_values=(*protected_values, *((redacted,) if redacted is not None else ())),
            )
        except GuardrailStorageDenied as exc:
            raise GuardrailServiceDenied("AUDIT_COMMIT_FAILED") from exc
        return {
            "schemaVersion": EVALUATION_SCHEMA,
            "decisionId": decision_id,
            "profileDigest": verified.profile_digest,
            "contentDigest": content_digest,
            "contentBytes": content_bytes,
            "evaluatedAt": evaluated_at,
            "released": released,
            **result_dict,
            "evidenceRecord": evidence,
        }

    @staticmethod
    def _evidence(
        decision: dict[str, object],
        verified: VerifiedGuardrailProfile,
        result: GuardrailResult,
        now: datetime,
    ) -> dict[str, object]:
        suffix = str(decision["decisionId"]).rsplit(".", 1)[1]
        mapped_result = "PASS" if result.outcome is GuardrailOutcome.ALLOW else "WARN" if result.outcome is GuardrailOutcome.REDACT else "FAIL"
        return {
            "apiVersion": EVIDENCE_API_VERSION,
            "kind": "EvidenceRecord",
            "metadata": {"id": f"evidence.guardrail.{suffix}", "version": "1.0.0"},
            "spec": {
                "organizationId": verified.organization_id,
                "recordState": "RECEIVED",
                "axis": "SECURITY",
                "result": mapped_result,
                "subject": {
                    "kind": "resource.guardrail-profile",
                    "id": verified.profile.profile_id,
                    "digest": verified.profile_digest,
                },
                "producer": {"type": "SYSTEM", "id": "system.guardrail-service"},
                "producerAuthority": "PLATFORM",
                "evidenceDigest": digest_json(decision),
                "provenanceDigest": verified.profile_digest,
                "collectedAt": render_timestamp(now),
                "validUntil": render_timestamp(verified.expires_at),
                "controlIds": ["control.guardrail-evaluation"],
                "campaignGenerated": False,
            },
        }

    @staticmethod
    def _stream_created(snapshot: StreamSnapshot) -> dict[str, object]:
        return {
            "schemaVersion": STREAM_SCHEMA,
            "streamId": snapshot.stream_id,
            "profileId": snapshot.profile_id,
            "profileDigest": snapshot.profile_digest,
            "state": snapshot.state.value,
            "nextSequence": snapshot.next_sequence,
        }

    @staticmethod
    def _stream_evaluation(evaluation: StreamEvaluation, result: dict[str, object]) -> dict[str, object]:
        snapshot = evaluation.snapshot
        return {
            "schemaVersion": STREAM_SCHEMA,
            "streamId": snapshot.stream_id,
            "profileId": snapshot.profile_id,
            "profileDigest": snapshot.profile_digest,
            "state": snapshot.state.value,
            "nextSequence": snapshot.next_sequence,
            "evaluation": result,
        }
