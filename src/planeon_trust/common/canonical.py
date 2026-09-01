"""Canonical JSON and digest adapters pinned to the public SDK-003 release."""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from planeon_harness.runtime.canonical import canonical_json as _sdk_canonical_json
from planeon_harness.runtime.canonical import sha256_digest as _sdk_sha256_digest


class CanonicalError(ValueError):
    """A value cannot participate in a signed or digest-bound contract."""


def canonical_json(value: Any) -> bytes:
    try:
        return _sdk_canonical_json(value)
    except (TypeError, ValueError) as exc:
        raise CanonicalError("value is not canonical JSON") from exc


def digest_bytes(value: bytes) -> str:
    if not isinstance(value, bytes):
        raise CanonicalError("digest input must be bytes")
    return _sdk_sha256_digest(value)


def digest_json(value: Any) -> str:
    return digest_bytes(canonical_json(value))


def require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:"):
        raise CanonicalError(f"{field} must be a sha256 digest")
    try:
        bytes.fromhex(value[7:])
    except ValueError as exc:
        raise CanonicalError(f"{field} must be a sha256 digest") from exc
    return value


def b64url_decode(value: object, *, field: str, size: int | None = None) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise CanonicalError(f"{field} is not unpadded base64url")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise CanonicalError(f"{field} is not unpadded base64url") from exc
    if size is not None and len(raw) != size:
        raise CanonicalError(f"{field} has the wrong size")
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise CanonicalError(f"{field} is not canonical base64url")
    return raw


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def opaque_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
