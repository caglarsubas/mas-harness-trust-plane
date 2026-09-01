"""Signed policy verification, atomic activation, revocation, and rollback."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import CanonicalError, b64url_decode, canonical_json, digest_bytes, digest_json, require_digest
from .json_io import JsonContractError, load_regular_json, require_object
from .time import require_now, utc_timestamp


ARTIFACT_SCHEMA = "harness.planeon.ai/signed-policy-artifact/v1alpha1"
KEYSET_SCHEMA = "harness.planeon.ai/policy-public-key-set/v1alpha1"
ENTRYPOINT = "planeon/authz/decision"


class PolicyDenied(PermissionError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(f"policy denied: {reason_code}")
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class VerifiedPolicy:
    organization_id: str
    policy_id: str
    policy_digest: str
    bundle_version: int
    entrypoint: str
    module_digests: tuple[tuple[str, str], ...]
    data_digest: str
    effective_at: datetime
    expires_at: datetime
    supersedes_policy_digest: str | None
    signer_key_id: str

    def active_at(self, now: datetime) -> bool:
        return self.effective_at <= now < self.expires_at


@dataclass(frozen=True, slots=True)
class PolicyState:
    active: VerifiedPolicy | None
    last_known_good: VerifiedPolicy | None
    revoked: frozenset[str]


def _path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 240:
        raise PolicyDenied("MODULE_PATH_INVALID")
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or ".." in candidate.parts or value.startswith(".") or value.endswith("/"):
        raise PolicyDenied("MODULE_PATH_INVALID")
    if candidate.suffix != ".rego" or candidate.as_posix() != value:
        raise PolicyDenied("MODULE_PATH_INVALID")
    return value


def _regular_bytes(root: Path, relative: str, *, maximum: int) -> bytes:
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    try:
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        if resolved.parent != resolved_root and resolved_root not in resolved.parents:
            raise PolicyDenied("MODULE_PATH_INVALID")
        if candidate.is_symlink() or not candidate.is_file():
            raise PolicyDenied("MODULE_PATH_INVALID")
        data = candidate.read_bytes()
    except OSError as exc:
        raise PolicyDenied("MODULE_PATH_INVALID") from exc
    if not data or len(data) > maximum:
        raise PolicyDenied("MODULE_CONTENT_INVALID")
    return data


def _load_keyset(raw: object, organization_id: str, now: datetime) -> Mapping[str, Mapping[str, Any]]:
    document = require_object(raw, fields={"schemaVersion", "organizationId", "keys"}, label="policy key set")
    if document["schemaVersion"] != KEYSET_SCHEMA or document["organizationId"] != organization_id:
        raise PolicyDenied("TENANT_MISMATCH")
    if not isinstance(document["keys"], list) or not document["keys"]:
        raise PolicyDenied("SIGNER_UNKNOWN")
    keys: dict[str, Mapping[str, Any]] = {}
    fields = {"keyId", "algorithm", "state", "purposes", "publicKey", "notBefore", "notAfter"}
    for raw_key in document["keys"]:
        key = require_object(raw_key, fields=fields, label="policy key")
        key_id = key["keyId"]
        if not isinstance(key_id, str) or not key_id or key_id in keys:
            raise PolicyDenied("SIGNER_UNKNOWN")
        if key["algorithm"] != "ED25519":
            raise PolicyDenied("ALGORITHM_DENIED")
        if key["state"] not in {"PENDING", "ACTIVE", "RETIRED", "REVOKED"}:
            raise PolicyDenied("KEY_STATE_INVALID")
        if not isinstance(key["purposes"], list) or not key["purposes"] or len(key["purposes"]) != len(set(key["purposes"])):
            raise PolicyDenied("KEY_PURPOSE_MISMATCH")
        b64url_decode(key["publicKey"], field="publicKey", size=32)
        not_before = utc_timestamp(key["notBefore"], "key.notBefore")
        not_after = utc_timestamp(key["notAfter"], "key.notAfter")
        if not_before >= not_after:
            raise PolicyDenied("KEY_STATE_INVALID")
        keys[key_id] = MappingProxyType({**key, "_valid": not_before <= now < not_after})
    return MappingProxyType(keys)


def verify_policy_artifact(artifact_path: Path, keyset_path: Path, *, now: datetime) -> VerifiedPolicy:
    current = require_now(now)
    try:
        artifact = require_object(load_regular_json(artifact_path), fields={"schemaVersion", "payload", "signature"}, label="policy artifact")
        if artifact["schemaVersion"] != ARTIFACT_SCHEMA:
            raise PolicyDenied("ARTIFACT_MALFORMED")
        payload_fields = {
            "organizationId", "policyId", "policyDigest", "bundleVersion", "entrypoint",
            "modules", "dataDigest", "effectiveAt", "expiresAt", "supersedesPolicyDigest",
        }
        payload = require_object(artifact["payload"], fields=payload_fields, label="policy payload")
        signature = require_object(
            artifact["signature"],
            fields={"algorithm", "keyId", "purpose", "signedMessageDigest", "value"},
            label="policy signature",
        )
        organization_id, policy_id = payload["organizationId"], payload["policyId"]
        if not isinstance(organization_id, str) or not organization_id or not isinstance(policy_id, str) or not policy_id:
            raise PolicyDenied("ARTIFACT_MALFORMED")
        version = payload["bundleVersion"]
        if not isinstance(version, int) or isinstance(version, bool) or not 1 <= version <= 2_147_483_647:
            raise PolicyDenied("VERSION_INVALID")
        if payload["entrypoint"] != ENTRYPOINT:
            raise PolicyDenied("ENTRYPOINT_DENIED")
        modules = payload["modules"]
        if not isinstance(modules, list) or not modules:
            raise PolicyDenied("MODULE_CONTENT_INVALID")
        module_digests: list[tuple[str, str]] = []
        seen: set[str] = set()
        root = artifact_path.parent
        for raw_module in modules:
            module = require_object(raw_module, fields={"path", "sha256"}, label="policy module")
            path = _path(module["path"])
            if path in seen:
                raise PolicyDenied("MODULE_PATH_INVALID")
            seen.add(path)
            expected = require_digest(module["sha256"], "module.sha256")
            if digest_bytes(_regular_bytes(root, path, maximum=262144)) != expected:
                raise PolicyDenied("MODULE_DIGEST_MISMATCH")
            module_digests.append((path, expected))
        if module_digests != sorted(module_digests):
            raise PolicyDenied("MODULE_PATH_INVALID")
        data_digest = require_digest(payload["dataDigest"], "dataDigest")
        if digest_bytes(_regular_bytes(root, "data.json", maximum=262144)) != data_digest:
            raise PolicyDenied("DATA_DIGEST_MISMATCH")
        policy_subject = {
            "entrypoint": payload["entrypoint"],
            "modules": [{"path": path, "sha256": value} for path, value in module_digests],
            "dataDigest": data_digest,
        }
        policy_digest = require_digest(payload["policyDigest"], "policyDigest")
        if digest_json(policy_subject) != policy_digest:
            raise PolicyDenied("POLICY_DIGEST_MISMATCH")
        effective = utc_timestamp(payload["effectiveAt"], "effectiveAt")
        expires = utc_timestamp(payload["expiresAt"], "expiresAt")
        if effective >= expires or current < effective:
            raise PolicyDenied("POLICY_NOT_YET_EFFECTIVE")
        if current >= expires:
            raise PolicyDenied("POLICY_EXPIRED")
        predecessor = payload["supersedesPolicyDigest"]
        if predecessor is not None:
            predecessor = require_digest(predecessor, "supersedesPolicyDigest")
        message = canonical_json(payload)
        signed_digest = require_digest(signature["signedMessageDigest"], "signedMessageDigest")
        if digest_bytes(message) != signed_digest:
            raise PolicyDenied("SIGNED_DIGEST_MISMATCH")
        if signature["algorithm"] != "ED25519":
            raise PolicyDenied("ALGORITHM_DENIED")
        if signature["purpose"] != "POLICY_BUNDLE":
            raise PolicyDenied("KEY_PURPOSE_MISMATCH")
        keys = _load_keyset(load_regular_json(keyset_path), organization_id, current)
        key = keys.get(signature["keyId"])
        if key is None:
            raise PolicyDenied("SIGNER_UNKNOWN")
        if key["state"] == "REVOKED":
            raise PolicyDenied("SIGNER_REVOKED")
        if key["state"] != "ACTIVE" or not key["_valid"]:
            raise PolicyDenied("SIGNER_NOT_ACTIVE")
        if "POLICY_BUNDLE" not in key["purposes"]:
            raise PolicyDenied("KEY_PURPOSE_MISMATCH")
        try:
            Ed25519PublicKey.from_public_bytes(b64url_decode(key["publicKey"], field="publicKey", size=32)).verify(
                b64url_decode(signature["value"], field="signature.value", size=64), message
            )
        except InvalidSignature as exc:
            raise PolicyDenied("SIGNATURE_INVALID") from exc
        return VerifiedPolicy(
            organization_id=organization_id,
            policy_id=policy_id,
            policy_digest=policy_digest,
            bundle_version=version,
            entrypoint=ENTRYPOINT,
            module_digests=tuple(module_digests),
            data_digest=data_digest,
            effective_at=effective,
            expires_at=expires,
            supersedes_policy_digest=predecessor,
            signer_key_id=str(signature["keyId"]),
        )
    except PolicyDenied:
        raise
    except (CanonicalError, JsonContractError, OSError, KeyError, TypeError, ValueError) as exc:
        raise PolicyDenied("ARTIFACT_MALFORMED") from exc


class PolicyManager:
    def __init__(self, on_trust_change: Callable[[], None] | None = None) -> None:
        self._states: dict[str, PolicyState] = {}
        self._lock = threading.RLock()
        self._on_trust_change = on_trust_change or (lambda: None)

    def state(self, organization_id: str) -> PolicyState:
        with self._lock:
            return self._states.get(organization_id, PolicyState(None, None, frozenset()))

    def activate(self, artifact_path: Path, keyset_path: Path, *, now: datetime) -> VerifiedPolicy:
        candidate = verify_policy_artifact(artifact_path, keyset_path, now=now)
        with self._lock:
            previous = self.state(candidate.organization_id)
            if candidate.policy_digest in previous.revoked:
                raise PolicyDenied("POLICY_REVOKED")
            if previous.active is None:
                if candidate.bundle_version != 1 or candidate.supersedes_policy_digest is not None:
                    raise PolicyDenied("VERSION_INVALID")
                next_state = PolicyState(candidate, None, previous.revoked)
            else:
                if candidate.bundle_version != previous.active.bundle_version + 1:
                    raise PolicyDenied("VERSION_INVALID")
                if candidate.supersedes_policy_digest != previous.active.policy_digest:
                    raise PolicyDenied("PREDECESSOR_MISMATCH")
                next_state = PolicyState(candidate, previous.active, previous.revoked)
            self._states[candidate.organization_id] = next_state
            self._on_trust_change()
            return candidate

    def active(self, organization_id: str, *, now: datetime) -> VerifiedPolicy:
        current = require_now(now)
        with self._lock:
            state = self.state(organization_id)
            policy = state.active
            if policy is None:
                raise PolicyDenied("POLICY_UNAVAILABLE")
            if policy.policy_digest in state.revoked:
                raise PolicyDenied("POLICY_REVOKED")
            if current < policy.effective_at:
                raise PolicyDenied("POLICY_NOT_YET_EFFECTIVE")
            if current >= policy.expires_at:
                self._on_trust_change()
                raise PolicyDenied("POLICY_EXPIRED")
            return policy

    def revoke(self, organization_id: str, policy_digest: str) -> None:
        require_digest(policy_digest, "policyDigest")
        with self._lock:
            state = self.state(organization_id)
            revoked = frozenset((*state.revoked, policy_digest))
            active = None if state.active and state.active.policy_digest == policy_digest else state.active
            last = None if state.last_known_good and state.last_known_good.policy_digest == policy_digest else state.last_known_good
            self._states[organization_id] = PolicyState(active, last, revoked)
            self._on_trust_change()

    def rollback(self, organization_id: str, *, now: datetime) -> VerifiedPolicy:
        current = require_now(now)
        with self._lock:
            state = self.state(organization_id)
            candidate = state.last_known_good
            if candidate is None or candidate.policy_digest in state.revoked or not candidate.active_at(current):
                raise PolicyDenied("LAST_KNOWN_GOOD_UNAVAILABLE")
            self._states[organization_id] = PolicyState(candidate, None, state.revoked)
            self._on_trust_change()
            return candidate
