"""Fail-closed policy decision orchestration."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any, Mapping

from .cache import CacheKey, DecisionCache
from .canonical import CanonicalError, digest_json, opaque_digest
from .identity import IdentityDenied, IdentityVerifier, contains_tenant_identity
from .opa import OpaClient, OpaDenied, OpaDecision
from .policy import PolicyDenied, PolicyManager, VerifiedPolicy
from .storage import AtomicMemoryStore, StorageDenied
from .time import render_timestamp, require_now


DECISION_SCHEMA = "harness.planeon.ai/policy-decision/v1alpha1"
OUTBOX_SCHEMA = "harness.planeon.ai/internal-outbox/v1alpha1"
MAX_REQUEST_DEPTH = 8
MAX_COLLECTION_ITEMS = 128


class DecisionDenied(PermissionError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(f"decision denied: {reason_code}")
        self.reason_code = reason_code


def _bounded_json(value: object, *, depth: int = 0) -> bool:
    if depth > MAX_REQUEST_DEPTH:
        return False
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, int) and not isinstance(value, bool):
        return -(2**53) < value < 2**53
    if isinstance(value, str):
        return len(value.encode("utf-8")) <= 4096
    if isinstance(value, list):
        return len(value) <= MAX_COLLECTION_ITEMS and all(_bounded_json(item, depth=depth + 1) for item in value)
    if isinstance(value, dict):
        return (
            len(value) <= MAX_COLLECTION_ITEMS
            and all(isinstance(key, str) and key and len(key) <= 128 for key in value)
            and all(_bounded_json(item, depth=depth + 1) for item in value.values())
        )
    return False


def validate_request(raw: object) -> dict[str, object]:
    if not isinstance(raw, dict) or set(raw) != {"action", "resource", "attributes", "mutation"}:
        raise DecisionDenied("REQUEST_MALFORMED")
    if contains_tenant_identity(raw):
        raise DecisionDenied("CALLER_TENANT_FORBIDDEN")
    action, resource, attributes, mutation = raw["action"], raw["resource"], raw["attributes"], raw["mutation"]
    if not isinstance(action, str) or not action or len(action) > 128:
        raise DecisionDenied("REQUEST_MALFORMED")
    if not isinstance(resource, dict) or set(resource) != {"kind", "id"}:
        raise DecisionDenied("REQUEST_MALFORMED")
    if not all(isinstance(resource[field], str) and resource[field] and len(resource[field]) <= 200 for field in ("kind", "id")):
        raise DecisionDenied("REQUEST_MALFORMED")
    if not isinstance(attributes, dict) or not _bounded_json(attributes):
        raise DecisionDenied("REQUEST_MALFORMED")
    if not isinstance(mutation, bool):
        raise DecisionDenied("REQUEST_MALFORMED")
    try:
        if len(__import__("json").dumps(raw, sort_keys=True, separators=(",", ":")).encode("utf-8")) > 65536:
            raise DecisionDenied("REQUEST_TOO_LARGE")
    except (TypeError, ValueError) as exc:
        raise DecisionDenied("REQUEST_MALFORMED") from exc
    return {"action": action, "resource": dict(resource), "attributes": dict(attributes), "mutation": mutation}


class DecisionService:
    def __init__(
        self,
        *,
        identity: IdentityVerifier,
        policies: PolicyManager,
        opa: OpaClient,
        cache: DecisionCache,
        store: AtomicMemoryStore,
    ) -> None:
        self.identity = identity
        self.policies = policies
        self.opa = opa
        self.cache = cache
        self.store = store

    def ready(self, *, organization_id: str, now: datetime) -> bool:
        try:
            self.policies.active(organization_id, now=now)
        except (PolicyDenied, ValueError):
            return False
        return self.opa.ready()

    def decide(self, bearer_token: object, raw_request: object, *, now: datetime) -> dict[str, object]:
        current = require_now(now)
        request = validate_request(raw_request)
        try:
            admitted = self.identity.verify(bearer_token, now=current)
            policy = self.policies.active(admitted.organization_id, now=current)
        except IdentityDenied as exc:
            raise DecisionDenied(exc.reason_code) from exc
        except PolicyDenied as exc:
            raise DecisionDenied(exc.reason_code) from exc
        try:
            request_digest = digest_json(request)
            subject_digest = opaque_digest(admitted.subject_id)
            key = CacheKey(admitted.organization_id, subject_digest, request_digest, policy.policy_digest)
            outcome: OpaDecision | None = None
            cache_hit = False
            if request["mutation"] is False:
                cached = self.cache.get(key, now=current)
                if cached is not None:
                    outcome = OpaDecision(True, cached.reason_code, cached.obligations, max(0, int((cached.expires_at - current).total_seconds())))
                    cache_hit = True
            if outcome is None:
                outcome = self.opa.evaluate(
                    {
                        "organizationId": admitted.organization_id,
                        "subjectId": admitted.subject_id,
                        "action": request["action"],
                        "resource": request["resource"],
                        "attributes": request["attributes"],
                        "mutation": request["mutation"],
                        "policyDigest": policy.policy_digest,
                    }
                )
                if outcome.allowed and request["mutation"] is False:
                    self.cache.put(
                        key,
                        reason_code=outcome.reason_code,
                        obligations=outcome.obligations,
                        now=current,
                        ttl_seconds=outcome.ttl_seconds,
                    )
        except OpaDenied as exc:
            outcome = OpaDecision(False, exc.reason_code, (), 0)
            cache_hit = False
        except Exception as exc:
            outcome = OpaDecision(False, "CACHE_FAILURE", (), 0)
            cache_hit = False
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
        response = self._response(admitted.organization_id, admitted.subject_id, request_digest, policy, outcome, current)
        decision_record = {
            "decisionId": response["decisionId"],
            "organizationId": admitted.organization_id,
            "subjectDigest": subject_digest,
            "requestDigest": request_digest,
            "policyDigest": policy.policy_digest,
            "allowed": outcome.allowed,
            "reasonCode": outcome.reason_code,
            "obligationIds": list(outcome.obligations),
            "evaluatedAt": response["evaluatedAt"],
            "expiresAt": response["expiresAt"],
        }
        audit = {
            "auditId": f"audit.{str(response['decisionId']).split('.', 1)[1]}",
            "organizationId": admitted.organization_id,
            "decisionId": response["decisionId"],
            "requestDigest": request_digest,
            "policyDigest": policy.policy_digest,
            "subjectDigest": subject_digest,
            "outcome": "ALLOW" if outcome.allowed else "DENY",
            "reasonCode": outcome.reason_code,
            "obligationIds": list(outcome.obligations),
            "cacheHit": cache_hit,
            "recordedAt": response["evaluatedAt"],
        }
        outbox = {
            "schemaVersion": OUTBOX_SCHEMA,
            "eventId": f"outbox.{str(response['decisionId']).split('.', 1)[1]}",
            "eventType": "planeon.trust.policy-decision.recorded.v1alpha1",
            "classification": "INTERNAL_DECISION_METADATA_NOT_PUBLIC_LIFECYCLE_CLOUDEVENT",
            "organizationId": admitted.organization_id,
            "aggregateId": response["decisionId"],
            "aggregateDigest": digest_json(decision_record),
            "recordedAt": response["evaluatedAt"],
        }
        try:
            self.store.record(decision_record, audit, outbox)
        except StorageDenied as exc:
            raise DecisionDenied("AUDIT_COMMIT_FAILED") from exc
        return response

    @staticmethod
    def _response(
        organization_id: str,
        subject_id: str,
        request_digest: str,
        policy: VerifiedPolicy,
        outcome: OpaDecision,
        now: datetime,
    ) -> dict[str, object]:
        ttl = outcome.ttl_seconds if outcome.allowed else 0
        expires = min(policy.expires_at, now + timedelta(seconds=max(1, ttl)))
        return {
            "schemaVersion": DECISION_SCHEMA,
            "decisionId": f"decision.{uuid.uuid4().hex}",
            "organizationId": organization_id,
            "subjectId": subject_id,
            "requestDigest": request_digest,
            "policyDigest": policy.policy_digest,
            "allowed": outcome.allowed,
            "reasonCode": None if outcome.allowed else outcome.reason_code,
            "obligations": list(outcome.obligations),
            "evaluatedAt": render_timestamp(now),
            "expiresAt": render_timestamp(expires),
        }
