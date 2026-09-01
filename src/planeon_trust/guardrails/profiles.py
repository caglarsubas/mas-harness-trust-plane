"""Signed tenant guardrail profiles with atomic activation and revocation."""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from planeon_harness.guardrail import FailMode, GuardrailClient, GuardrailProfile, GuardrailStage

from planeon_trust.common.canonical import (
    CanonicalError,
    b64url_decode,
    canonical_json,
    digest_bytes,
    digest_json,
    require_digest,
)
from planeon_trust.common.json_io import JsonContractError, load_regular_json, require_object
from planeon_trust.common.time import require_now, utc_timestamp

from .detectors import DetectorConfigurationError, DetectorSpec, build_detectors, parse_specs


ARTIFACT_SCHEMA = "harness.planeon.ai/signed-guardrail-profile-artifact/v1alpha1"
KEYSET_SCHEMA = "harness.planeon.ai/guardrail-profile-public-key-set/v1alpha1"
SIGNATURE_PURPOSE = "GUARDRAIL_PROFILE"
_STABLE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$")


class ProfileDenied(PermissionError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(f"guardrail profile denied: {reason_code}")
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class VerifiedGuardrailProfile:
    organization_id: str
    profile: GuardrailProfile
    detector_specs: tuple[DetectorSpec, ...]
    profile_digest: str
    effective_at: datetime
    expires_at: datetime
    supersedes_profile_digest: str | None
    signer_key_id: str

    def active_at(self, now: datetime) -> bool:
        return self.effective_at <= now < self.expires_at

    def client(self) -> GuardrailClient:
        return GuardrailClient(
            self.profile,
            build_detectors(self.profile.detector_ids, self.detector_specs),
        )


@dataclass(frozen=True, slots=True)
class GuardrailProfileState:
    active: VerifiedGuardrailProfile | None
    last_known_good: VerifiedGuardrailProfile | None
    revoked: frozenset[str]


def _stable_id(value: object, reason: str) -> str:
    if not isinstance(value, str) or len(value) > 128 or _STABLE_ID.fullmatch(value) is None:
        raise ProfileDenied(reason)
    return value


def _load_keyset(raw: object, organization_id: str, now: datetime) -> Mapping[str, Mapping[str, Any]]:
    document = require_object(raw, fields={"schemaVersion", "organizationId", "keys"}, label="guardrail key set")
    if document["schemaVersion"] != KEYSET_SCHEMA or document["organizationId"] != organization_id:
        raise ProfileDenied("TENANT_MISMATCH")
    if not isinstance(document["keys"], list) or not document["keys"]:
        raise ProfileDenied("SIGNER_UNKNOWN")
    result: dict[str, Mapping[str, Any]] = {}
    fields = {"keyId", "algorithm", "state", "purposes", "publicKey", "notBefore", "notAfter"}
    for raw_key in document["keys"]:
        key = require_object(raw_key, fields=fields, label="guardrail key")
        key_id = _stable_id(key["keyId"], "SIGNER_UNKNOWN")
        if key_id in result or key["algorithm"] != "ED25519":
            raise ProfileDenied("ALGORITHM_DENIED")
        if key["state"] not in {"PENDING", "ACTIVE", "RETIRED", "REVOKED"}:
            raise ProfileDenied("KEY_STATE_INVALID")
        purposes = key["purposes"]
        if not isinstance(purposes, list) or not purposes or len(purposes) != len(set(purposes)):
            raise ProfileDenied("KEY_PURPOSE_MISMATCH")
        b64url_decode(key["publicKey"], field="publicKey", size=32)
        not_before = utc_timestamp(key["notBefore"], "key.notBefore")
        not_after = utc_timestamp(key["notAfter"], "key.notAfter")
        if not_before >= not_after:
            raise ProfileDenied("KEY_STATE_INVALID")
        result[key_id] = MappingProxyType({**key, "_valid": not_before <= now < not_after})
    return MappingProxyType(result)


def verify_profile_artifact(
    artifact_path: Path,
    keyset_path: Path,
    *,
    now: datetime,
) -> VerifiedGuardrailProfile:
    current = require_now(now)
    try:
        artifact = require_object(
            load_regular_json(artifact_path),
            fields={"schemaVersion", "payload", "signature"},
            label="guardrail artifact",
        )
        if artifact["schemaVersion"] != ARTIFACT_SCHEMA:
            raise ProfileDenied("ARTIFACT_MALFORMED")
        payload = require_object(
            artifact["payload"],
            fields={
                "organizationId",
                "profile",
                "detectors",
                "profileDigest",
                "effectiveAt",
                "expiresAt",
                "supersedesProfileDigest",
            },
            label="guardrail payload",
        )
        signature = require_object(
            artifact["signature"],
            fields={"algorithm", "keyId", "purpose", "signedMessageDigest", "value"},
            label="guardrail signature",
        )
        organization_id = _stable_id(payload["organizationId"], "TENANT_MISMATCH")
        profile = GuardrailProfile.from_dict(payload["profile"])
        if profile.stage in {GuardrailStage.INPUT, GuardrailStage.RUNTIME} and profile.fail_mode is not FailMode.FAIL_CLOSED:
            raise ProfileDenied("FAIL_MODE_DENIED")
        specs = parse_specs(payload["detectors"])
        build_detectors(profile.detector_ids, specs)
        profile_subject = {
            "profile": profile.to_dict(),
            "detectors": [spec.to_dict() for spec in specs],
        }
        profile_digest = require_digest(payload["profileDigest"], "profileDigest")
        if digest_json(profile_subject) != profile_digest:
            raise ProfileDenied("PROFILE_DIGEST_MISMATCH")
        effective_at = utc_timestamp(payload["effectiveAt"], "effectiveAt")
        expires_at = utc_timestamp(payload["expiresAt"], "expiresAt")
        if effective_at >= expires_at:
            raise ProfileDenied("PROFILE_TIME_INVALID")
        if current < effective_at:
            raise ProfileDenied("PROFILE_NOT_YET_EFFECTIVE")
        if current >= expires_at:
            raise ProfileDenied("PROFILE_EXPIRED")
        predecessor = payload["supersedesProfileDigest"]
        if predecessor is not None:
            predecessor = require_digest(predecessor, "supersedesProfileDigest")
        message = canonical_json(payload)
        if digest_bytes(message) != require_digest(signature["signedMessageDigest"], "signedMessageDigest"):
            raise ProfileDenied("SIGNED_DIGEST_MISMATCH")
        if signature["algorithm"] != "ED25519":
            raise ProfileDenied("ALGORITHM_DENIED")
        if signature["purpose"] != SIGNATURE_PURPOSE:
            raise ProfileDenied("KEY_PURPOSE_MISMATCH")
        keys = _load_keyset(load_regular_json(keyset_path), organization_id, current)
        key = keys.get(signature["keyId"])
        if key is None:
            raise ProfileDenied("SIGNER_UNKNOWN")
        if key["state"] == "REVOKED":
            raise ProfileDenied("SIGNER_REVOKED")
        if key["state"] != "ACTIVE" or not key["_valid"]:
            raise ProfileDenied("SIGNER_NOT_ACTIVE")
        if SIGNATURE_PURPOSE not in key["purposes"]:
            raise ProfileDenied("KEY_PURPOSE_MISMATCH")
        try:
            Ed25519PublicKey.from_public_bytes(
                b64url_decode(key["publicKey"], field="publicKey", size=32)
            ).verify(
                b64url_decode(signature["value"], field="signature.value", size=64),
                message,
            )
        except InvalidSignature as exc:
            raise ProfileDenied("SIGNATURE_INVALID") from exc
        return VerifiedGuardrailProfile(
            organization_id=organization_id,
            profile=profile,
            detector_specs=specs,
            profile_digest=profile_digest,
            effective_at=effective_at,
            expires_at=expires_at,
            supersedes_profile_digest=predecessor,
            signer_key_id=str(signature["keyId"]),
        )
    except ProfileDenied:
        raise
    except (CanonicalError, DetectorConfigurationError, JsonContractError, KeyError, OSError, TypeError, ValueError) as exc:
        raise ProfileDenied("ARTIFACT_MALFORMED") from exc


def _semver(value: str) -> tuple[int, int, int]:
    major, minor, patch = value.split(".")
    return int(major), int(minor), int(patch)


class GuardrailProfileManager:
    def __init__(self, on_trust_change: Callable[[str, str], None] | None = None) -> None:
        self._states: dict[tuple[str, str], GuardrailProfileState] = {}
        self._lock = threading.RLock()
        self._on_trust_change = on_trust_change or (lambda _organization, _profile: None)

    def state(self, organization_id: str, profile_id: str) -> GuardrailProfileState:
        with self._lock:
            return self._states.get((organization_id, profile_id), GuardrailProfileState(None, None, frozenset()))

    def activate(self, artifact_path: Path, keyset_path: Path, *, now: datetime) -> VerifiedGuardrailProfile:
        candidate = verify_profile_artifact(artifact_path, keyset_path, now=now)
        key = (candidate.organization_id, candidate.profile.profile_id)
        with self._lock:
            previous = self.state(*key)
            if candidate.profile_digest in previous.revoked:
                raise ProfileDenied("PROFILE_REVOKED")
            if previous.active is None:
                if candidate.supersedes_profile_digest is not None:
                    raise ProfileDenied("PREDECESSOR_MISMATCH")
                next_state = GuardrailProfileState(candidate, None, previous.revoked)
            else:
                if _semver(candidate.profile.version) <= _semver(previous.active.profile.version):
                    raise ProfileDenied("VERSION_INVALID")
                if candidate.supersedes_profile_digest != previous.active.profile_digest:
                    raise ProfileDenied("PREDECESSOR_MISMATCH")
                next_state = GuardrailProfileState(candidate, previous.active, previous.revoked)
            self._states[key] = next_state
            self._on_trust_change(*key)
            return candidate

    def active(self, organization_id: str, profile_id: str, *, now: datetime) -> VerifiedGuardrailProfile:
        current = require_now(now)
        with self._lock:
            state = self.state(organization_id, profile_id)
            candidate = state.active
            if candidate is None:
                raise ProfileDenied("PROFILE_UNAVAILABLE")
            if candidate.profile_digest in state.revoked:
                raise ProfileDenied("PROFILE_REVOKED")
            if current < candidate.effective_at:
                raise ProfileDenied("PROFILE_NOT_YET_EFFECTIVE")
            if current >= candidate.expires_at:
                self._on_trust_change(organization_id, profile_id)
                raise ProfileDenied("PROFILE_EXPIRED")
            return candidate

    def revoke(self, organization_id: str, profile_id: str, profile_digest: str) -> None:
        require_digest(profile_digest, "profileDigest")
        with self._lock:
            state = self.state(organization_id, profile_id)
            revoked = frozenset((*state.revoked, profile_digest))
            active = None if state.active and state.active.profile_digest == profile_digest else state.active
            previous = None if state.last_known_good and state.last_known_good.profile_digest == profile_digest else state.last_known_good
            self._states[(organization_id, profile_id)] = GuardrailProfileState(active, previous, revoked)
            self._on_trust_change(organization_id, profile_id)

    def rollback(self, organization_id: str, profile_id: str, *, now: datetime) -> VerifiedGuardrailProfile:
        current = require_now(now)
        with self._lock:
            state = self.state(organization_id, profile_id)
            candidate = state.last_known_good
            if candidate is None or candidate.profile_digest in state.revoked or not candidate.active_at(current):
                raise ProfileDenied("LAST_KNOWN_GOOD_UNAVAILABLE")
            self._states[(organization_id, profile_id)] = GuardrailProfileState(candidate, None, state.revoked)
            self._on_trust_change(organization_id, profile_id)
            return candidate

    def ready(self, organization_id: str, *, now: datetime) -> bool:
        current = require_now(now)
        with self._lock:
            return any(
                key[0] == organization_id
                and state.active is not None
                and state.active.profile_digest not in state.revoked
                and state.active.active_at(current)
                for key, state in self._states.items()
            )
