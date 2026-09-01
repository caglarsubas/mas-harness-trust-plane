"""Strict bounded JSON loading without duplicate-member ambiguity."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any


class JsonContractError(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JsonContractError("duplicate JSON member")
        result[key] = value
    return result


def load_json_bytes(data: bytes, *, maximum: int = 65536) -> Any:
    if not isinstance(data, bytes) or not data or len(data) > maximum:
        raise JsonContractError("JSON input size is invalid")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise JsonContractError("JSON input is malformed") from exc
    return value


def load_regular_json(path: Path, *, maximum: int = 1_048_576) -> Any:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0 or metadata.st_size > maximum:
                raise JsonContractError("JSON authority must be a bounded regular file")
            chunks = bytearray()
            while True:
                chunk = os.read(descriptor, min(65536, maximum + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
                if len(chunks) > maximum:
                    raise JsonContractError("JSON authority is oversized")
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise JsonContractError("JSON authority cannot be opened safely") from exc
    return load_json_bytes(bytes(chunks), maximum=maximum)


def require_object(value: object, *, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise JsonContractError(f"{label} must be an object")
    if set(value) != fields:
        raise JsonContractError(f"{label} fields are closed")
    return value
