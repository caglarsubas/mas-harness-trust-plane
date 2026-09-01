"""Closed local OIDC registry and asymmetric JWT tenant admission."""

from __future__ import annotations

import json
import threading
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .canonical import CanonicalError, b64url_decode, digest_bytes, opaque_digest
from .json_io import JsonContractError, load_json_bytes, load_regular_json, require_object
from .time import require_now


REGISTRY_SCHEMA = "harness.planeon.ai/oidc-tenant-registry/v1alpha1"
ALGORITHMS = frozenset({"RS256", "ES256", "EdDSA"})
TENANT_KEYS = frozenset({"organizationId", "tenantId", "orgId", "organization_id", "tenant_id"})


class IdentityDenied(PermissionError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(f"identity denied: {reason_code}")
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class TenantIdentity:
    organization_id: str
    subject_id: str
    issuer: str
    token_identity_digest: str


@dataclass(frozen=True, slots=True)
class IssuerConfig:
    issuer: str
    audiences: frozenset[str]
    organization_id: str
    allowed_algorithms: frozenset[str]
    tenant_claim: str
    tenant_value: str
    clock_skew_seconds: int
    maximum_token_lifetime_seconds: int
    keys: Mapping[str, Mapping[str, Any]]


def _stable_id(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 200:
        raise JsonContractError(f"{field} is invalid")
    if any(character.isspace() for character in value):
        raise JsonContractError(f"{field} is invalid")
    return value


def _string_set(value: object, field: str) -> frozenset[str]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        raise JsonContractError(f"{field} must be a non-empty string array")
    if len(value) != len(set(value)):
        raise JsonContractError(f"{field} contains duplicates")
    return frozenset(value)


def _validate_jwk(raw: object, allowed: frozenset[str]) -> Mapping[str, Any]:
    if not isinstance(raw, dict):
        raise JsonContractError("JWK must be an object")
    alg = raw.get("alg")
    if alg not in allowed or alg not in ALGORITHMS:
        raise JsonContractError("JWK algorithm is not allowed")
    if raw.get("use") != "sig" or not isinstance(raw.get("kid"), str) or not raw["kid"]:
        raise JsonContractError("JWK identity is invalid")
    if alg == "RS256":
        expected = {"kty", "kid", "use", "alg", "n", "e"}
        if set(raw) != expected or raw.get("kty") != "RSA":
            raise JsonContractError("RSA JWK is invalid")
        modulus = int.from_bytes(b64url_decode(raw["n"], field="jwk.n"), "big")
        exponent = int.from_bytes(b64url_decode(raw["e"], field="jwk.e"), "big")
        if modulus.bit_length() < 2048 or exponent < 3 or exponent % 2 == 0:
            raise JsonContractError("RSA JWK strength is invalid")
    elif alg == "ES256":
        expected = {"kty", "kid", "use", "alg", "crv", "x", "y"}
        if set(raw) != expected or raw.get("kty") != "EC" or raw.get("crv") != "P-256":
            raise JsonContractError("EC JWK is invalid")
        b64url_decode(raw["x"], field="jwk.x", size=32)
        b64url_decode(raw["y"], field="jwk.y", size=32)
    else:
        expected = {"kty", "kid", "use", "alg", "crv", "x"}
        if set(raw) != expected or raw.get("kty") != "OKP" or raw.get("crv") != "Ed25519":
            raise JsonContractError("Ed25519 JWK is invalid")
        b64url_decode(raw["x"], field="jwk.x", size=32)
    return MappingProxyType(dict(raw))


def load_registry(raw: object) -> Mapping[str, IssuerConfig]:
    document = require_object(raw, fields={"schemaVersion", "issuers"}, label="OIDC registry")
    if document["schemaVersion"] != REGISTRY_SCHEMA or not isinstance(document["issuers"], list) or not document["issuers"]:
        raise JsonContractError("OIDC registry identity is invalid")
    issuers: dict[str, IssuerConfig] = {}
    fields = {
        "issuer", "audiences", "organizationId", "allowedAlgorithms", "tenantClaim",
        "tenantValue", "clockSkewSeconds", "maximumTokenLifetimeSeconds", "jwks",
    }
    for raw_issuer in document["issuers"]:
        item = require_object(raw_issuer, fields=fields, label="issuer")
        issuer = _stable_id(item["issuer"], "issuer")
        if not issuer.startswith("https://") or "?" in issuer or "#" in issuer or issuer.endswith("/"):
            raise JsonContractError("issuer must be an exact HTTPS identifier")
        if issuer in issuers:
            raise JsonContractError("issuer is duplicated")
        algorithms = _string_set(item["allowedAlgorithms"], "allowedAlgorithms")
        if not algorithms <= ALGORITHMS:
            raise JsonContractError("issuer algorithm is unsupported")
        skew = item["clockSkewSeconds"]
        lifetime = item["maximumTokenLifetimeSeconds"]
        if not isinstance(skew, int) or isinstance(skew, bool) or not 0 <= skew <= 120:
            raise JsonContractError("clockSkewSeconds is invalid")
        if not isinstance(lifetime, int) or isinstance(lifetime, bool) or not 60 <= lifetime <= 3600:
            raise JsonContractError("maximumTokenLifetimeSeconds is invalid")
        jwks = require_object(item["jwks"], fields={"keys"}, label="jwks")
        if not isinstance(jwks["keys"], list) or not jwks["keys"]:
            raise JsonContractError("jwks.keys must be non-empty")
        keys: dict[str, Mapping[str, Any]] = {}
        for raw_key in jwks["keys"]:
            key = _validate_jwk(raw_key, algorithms)
            kid = str(key["kid"])
            if kid in keys:
                raise JsonContractError("JWK key id is duplicated")
            keys[kid] = key
        tenant_claim = _stable_id(item["tenantClaim"], "tenantClaim")
        if tenant_claim in {"iss", "aud", "sub", "iat", "nbf", "exp", "jti"}:
            raise JsonContractError("tenant claim collides with a standard claim")
        issuers[issuer] = IssuerConfig(
            issuer=issuer,
            audiences=_string_set(item["audiences"], "audiences"),
            organization_id=_stable_id(item["organizationId"], "organizationId"),
            allowed_algorithms=algorithms,
            tenant_claim=tenant_claim,
            tenant_value=_stable_id(item["tenantValue"], "tenantValue"),
            clock_skew_seconds=skew,
            maximum_token_lifetime_seconds=lifetime,
            keys=MappingProxyType(keys),
        )
    return MappingProxyType(issuers)


def load_registry_file(path: str) -> Mapping[str, IssuerConfig]:
    return load_registry(load_regular_json(Path(path)))


def _verify_signature(key: Mapping[str, Any], message: bytes, signature: bytes) -> None:
    try:
        if key["alg"] == "RS256":
            modulus = int.from_bytes(b64url_decode(key["n"], field="jwk.n"), "big")
            exponent = int.from_bytes(b64url_decode(key["e"], field="jwk.e"), "big")
            rsa.RSAPublicNumbers(exponent, modulus).public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        elif key["alg"] == "ES256":
            if len(signature) != 64:
                raise IdentityDenied("SIGNATURE_INVALID")
            x = int.from_bytes(b64url_decode(key["x"], field="jwk.x", size=32), "big")
            y = int.from_bytes(b64url_decode(key["y"], field="jwk.y", size=32), "big")
            public = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
            public.verify(encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")), message, ec.ECDSA(hashes.SHA256()))
        else:
            public = ed25519.Ed25519PublicKey.from_public_bytes(b64url_decode(key["x"], field="jwk.x", size=32))
            public.verify(signature, message)
    except IdentityDenied:
        raise
    except (CanonicalError, InvalidSignature, ValueError) as exc:
        raise IdentityDenied("SIGNATURE_INVALID") from exc


class TokenIdentityTracker:
    """Bounded jti-to-identity binding; exact token reuse remains valid."""

    def __init__(self, maximum_entries: int = 4096) -> None:
        if not 1 <= maximum_entries <= 65536:
            raise ValueError("identity tracker bound is invalid")
        self._maximum = maximum_entries
        self._items: OrderedDict[str, tuple[str, str]] = OrderedDict()
        self._lock = threading.Lock()

    def bind(self, token_identity_digest: str, organization_id: str, subject_id: str) -> None:
        with self._lock:
            existing = self._items.get(token_identity_digest)
            if existing is not None and existing != (organization_id, subject_id):
                raise IdentityDenied("TOKEN_IDENTITY_CONFLICT")
            self._items[token_identity_digest] = (organization_id, subject_id)
            self._items.move_to_end(token_identity_digest)
            while len(self._items) > self._maximum:
                self._items.popitem(last=False)


class IdentityVerifier:
    def __init__(self, registry: Mapping[str, IssuerConfig], tracker: TokenIdentityTracker | None = None) -> None:
        self._registry = registry
        self._tracker = tracker or TokenIdentityTracker()

    def verify(self, token: object, *, now: datetime) -> TenantIdentity:
        current = require_now(now)
        if not isinstance(token, str) or not 1 <= len(token) <= 16384 or token.count(".") != 2:
            raise IdentityDenied("TOKEN_MALFORMED")
        encoded_header, encoded_payload, encoded_signature = token.split(".")
        try:
            header = load_json_bytes(b64url_decode(encoded_header, field="jwt.header"), maximum=4096)
            payload = load_json_bytes(b64url_decode(encoded_payload, field="jwt.payload"), maximum=8192)
            signature = b64url_decode(encoded_signature, field="jwt.signature")
            if not isinstance(header, dict) or set(header) != {"alg", "kid", "typ"} or header.get("typ") != "JWT":
                raise IdentityDenied("TOKEN_MALFORMED")
            if not isinstance(payload, dict):
                raise IdentityDenied("TOKEN_MALFORMED")
            issuer = payload.get("iss")
            config = self._registry.get(issuer) if isinstance(issuer, str) else None
            if config is None:
                raise IdentityDenied("ISSUER_UNKNOWN")
            allowed_claims = {"iss", "aud", "sub", "iat", "nbf", "exp", "jti", config.tenant_claim}
            if set(payload) != allowed_claims:
                raise IdentityDenied("TOKEN_MALFORMED")
            alg, kid = header.get("alg"), header.get("kid")
            if alg not in config.allowed_algorithms:
                raise IdentityDenied("ALGORITHM_DENIED")
            key = config.keys.get(kid) if isinstance(kid, str) else None
            if key is None:
                raise IdentityDenied("SIGNER_UNKNOWN")
            if key["alg"] != alg:
                raise IdentityDenied("ALGORITHM_DENIED")
            _verify_signature(key, f"{encoded_header}.{encoded_payload}".encode("ascii"), signature)
            audience = payload["aud"]
            audience_values = {audience} if isinstance(audience, str) else set(audience) if isinstance(audience, list) and all(isinstance(item, str) for item in audience) else set()
            if not audience_values or not audience_values & config.audiences:
                raise IdentityDenied("AUDIENCE_MISMATCH")
            subject = _stable_id(payload["sub"], "sub")
            jti = _stable_id(payload["jti"], "jti")
            if payload[config.tenant_claim] != config.tenant_value:
                raise IdentityDenied("TENANT_MISMATCH")
            times = [payload[name] for name in ("iat", "nbf", "exp")]
            if not all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in times):
                raise IdentityDenied("TOKEN_MALFORMED")
            issued, not_before, expires = times
            now_epoch = int(current.replace(tzinfo=timezone.utc).timestamp())
            skew = config.clock_skew_seconds
            if issued > now_epoch + skew or not_before > now_epoch + skew:
                raise IdentityDenied("TOKEN_NOT_YET_VALID")
            if expires <= now_epoch - skew:
                raise IdentityDenied("TOKEN_EXPIRED")
            if expires <= issued or not_before < issued - skew or expires - issued > config.maximum_token_lifetime_seconds:
                raise IdentityDenied("TOKEN_LIFETIME_INVALID")
            token_identity_digest = digest_bytes(f"{issuer}\x00{jti}".encode("utf-8"))
            self._tracker.bind(token_identity_digest, config.organization_id, subject)
            return TenantIdentity(config.organization_id, subject, issuer, token_identity_digest)
        except IdentityDenied:
            raise
        except (CanonicalError, JsonContractError, UnicodeError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise IdentityDenied("TOKEN_MALFORMED") from exc


def contains_tenant_identity(value: object) -> bool:
    if isinstance(value, dict):
        return any(key in TENANT_KEYS or contains_tenant_identity(item) for key, item in value.items())
    if isinstance(value, list):
        return any(contains_tenant_identity(item) for item in value)
    return False
