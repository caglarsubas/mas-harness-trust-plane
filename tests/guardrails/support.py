from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from planeon_trust.common.canonical import b64url_encode, canonical_json, digest_bytes, digest_json
from planeon_trust.common.identity import TenantIdentity
from planeon_trust.guardrails.profiles import ARTIFACT_SCHEMA, KEYSET_SCHEMA, SIGNATURE_PURPOSE, GuardrailProfileManager
from planeon_trust.guardrails.service import GuardrailService
from planeon_trust.guardrails.storage import GuardrailMemoryStore
from planeon_trust.guardrails.streaming import GuardrailStreamRegistry


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures" / "guardrails"
NOW = datetime(2026, 9, 1, 16, 0, 0, tzinfo=timezone.utc)
TOKEN_ONE = "local-test-token-one"
TOKEN_TWO = "local-test-token-two"


class FakeIdentity:
    def verify(self, token: object, *, now: datetime) -> TenantIdentity:
        if token == TOKEN_ONE:
            return TenantIdentity("acme.one", "user.one", "https://issuer.example.test", "sha256:" + "1" * 64)
        if token == TOKEN_TWO:
            return TenantIdentity("acme.two", "user.two", "https://issuer.example.test", "sha256:" + "2" * 64)
        from planeon_trust.common.identity import IdentityDenied

        raise IdentityDenied("TOKEN_MALFORMED")


class ProfileAuthority:
    def __init__(self, organization_id: str = "acme.one") -> None:
        self.organization_id = organization_id
        self.private = Ed25519PrivateKey.generate()
        self.temporary = tempfile.TemporaryDirectory(prefix="trust002-profiles-")
        self.root = Path(self.temporary.name)
        public = self.private.public_key().public_bytes_raw()
        self.keyset_path = self.root / "keyset.json"
        self._write(
            self.keyset_path,
            {
                "schemaVersion": KEYSET_SCHEMA,
                "organizationId": organization_id,
                "keys": [
                    {
                        "keyId": "key.guardrail.test",
                        "algorithm": "ED25519",
                        "state": "ACTIVE",
                        "purposes": [SIGNATURE_PURPOSE],
                        "publicKey": b64url_encode(public),
                        "notBefore": "2026-09-01T14:00:00Z",
                        "notAfter": "2026-09-01T18:00:00Z",
                    }
                ],
            },
        )
        self._counter = 0

    def artifact(
        self,
        *,
        profile_id: str,
        stage: str,
        fail_mode: str = "FAIL_CLOSED",
        maximum_content_bytes: int = 2048,
        detectors: Iterable[dict[str, str]] | None = None,
        version: str = "1.0.0",
        supersedes: str | None = None,
        organization_id: str | None = None,
        purpose: str = SIGNATURE_PURPOSE,
        effective_at: str = "2026-09-01T15:00:00Z",
        expires_at: str = "2026-09-01T17:00:00Z",
    ) -> tuple[Path, str]:
        detector_list = list(detectors or [{"detectorId": "detector.allow", "implementation": "ALLOW_ALL_V1"}])
        profile = {
            "apiVersion": "harness.planeon.ai/v1alpha1",
            "kind": "GuardrailProfile",
            "profileId": profile_id,
            "version": version,
            "stage": stage,
            "failMode": fail_mode,
            "maximumContentBytes": maximum_content_bytes,
            "detectorIds": [item["detectorId"] for item in detector_list],
        }
        profile_digest = digest_json({"profile": profile, "detectors": detector_list})
        payload = {
            "organizationId": organization_id or self.organization_id,
            "profile": profile,
            "detectors": detector_list,
            "profileDigest": profile_digest,
            "effectiveAt": effective_at,
            "expiresAt": expires_at,
            "supersedesProfileDigest": supersedes,
        }
        message = canonical_json(payload)
        document = {
            "schemaVersion": ARTIFACT_SCHEMA,
            "payload": payload,
            "signature": {
                "algorithm": "ED25519",
                "keyId": "key.guardrail.test",
                "purpose": purpose,
                "signedMessageDigest": digest_bytes(message),
                "value": b64url_encode(self.private.sign(message)),
            },
        }
        self._counter += 1
        path = self.root / f"profile-{self._counter}.json"
        self._write(path, document)
        return path, profile_digest

    @staticmethod
    def _write(path: Path, value: object) -> None:
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    def mutate(self, source: Path, callback) -> Path:
        document = json.loads(source.read_text(encoding="utf-8"))
        callback(document)
        self._counter += 1
        path = self.root / f"mutated-{self._counter}.json"
        self._write(path, document)
        return path

    def close(self) -> None:
        self.temporary.cleanup()


@dataclass(slots=True)
class ServiceBundle:
    authority: ProfileAuthority
    profiles: GuardrailProfileManager
    streams: GuardrailStreamRegistry
    store: GuardrailMemoryStore
    service: GuardrailService
    profile_digest: str

    def close(self) -> None:
        self.authority.close()


def service_bundle(
    *,
    profile_id: str = "profile.output",
    stage: str = "OUTPUT",
    fail_mode: str = "FAIL_CLOSED",
    maximum_content_bytes: int = 2048,
    detectors: Iterable[dict[str, str]] | None = None,
) -> ServiceBundle:
    authority = ProfileAuthority()
    artifact, digest = authority.artifact(
        profile_id=profile_id,
        stage=stage,
        fail_mode=fail_mode,
        maximum_content_bytes=maximum_content_bytes,
        detectors=detectors,
    )
    streams = GuardrailStreamRegistry()
    profiles = GuardrailProfileManager(streams.expire_profile)
    profiles.activate(artifact, authority.keyset_path, now=NOW)
    store = GuardrailMemoryStore()
    service = GuardrailService(identity=FakeIdentity(), profiles=profiles, streams=streams, store=store)
    return ServiceBundle(authority, profiles, streams, store, service, digest)
