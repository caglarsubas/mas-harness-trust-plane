"""Closed resource dimensions and integer arithmetic."""

from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

from .errors import UsageDenied


DIMENSIONS = (
    "concurrentTasks",
    "taskSeconds",
    "retries",
    "toolCalls",
    "modelTokens",
    "modelCalls",
    "inputTokens",
    "outputTokens",
    "cpuSeconds",
    "gpuSeconds",
    "storageBytes",
)
DIMENSION_SET = frozenset(DIMENSIONS)
SAFE_INTEGER_MAX = 9_000_000_000_000_000
PUBLIC_MAXIMA = MappingProxyType(
    {
        "concurrentTasks": 1024,
        "taskSeconds": 86400,
        "retries": 100,
        "toolCalls": 10000,
        "modelTokens": 10000000,
    }
)


def zero_dimensions() -> dict[str, int]:
    return {name: 0 for name in DIMENSIONS}


def normalize_dimensions(
    value: object,
    *,
    label: str,
    require_nonzero: bool,
    enforce_public_maxima: bool,
) -> Mapping[str, int]:
    if not isinstance(value, dict) or not value or not all(isinstance(key, str) for key in value):
        raise UsageDenied(f"{label}_INVALID")
    if not set(value) <= DIMENSION_SET:
        raise UsageDenied(f"{label}_INVALID")
    normalized = zero_dimensions()
    for name, amount in value.items():
        if isinstance(amount, bool) or not isinstance(amount, int) or not 0 <= amount <= SAFE_INTEGER_MAX:
            raise UsageDenied(f"{label}_INVALID")
        if enforce_public_maxima and name in PUBLIC_MAXIMA and amount > PUBLIC_MAXIMA[name]:
            raise UsageDenied(f"{label}_INVALID")
        normalized[name] = amount
    if require_nonzero and not any(normalized.values()):
        raise UsageDenied(f"{label}_INVALID")
    return MappingProxyType(normalized)


def add_dimensions(*values: Mapping[str, int]) -> Mapping[str, int]:
    result = zero_dimensions()
    for value in values:
        for name in DIMENSIONS:
            result[name] += value[name]
            if result[name] > SAFE_INTEGER_MAX:
                raise UsageDenied("DIMENSION_OVERFLOW")
    return MappingProxyType(result)


def subtract_dimensions(left: Mapping[str, int], right: Mapping[str, int]) -> Mapping[str, int]:
    result = {name: left[name] - right[name] for name in DIMENSIONS}
    if any(amount < 0 for amount in result.values()):
        raise UsageDenied("COUNTER_UNDERFLOW")
    return MappingProxyType(result)


def exceeded_dimensions(value: Mapping[str, int], limits: Mapping[str, int]) -> tuple[str, ...]:
    return tuple(name for name in DIMENSIONS if value[name] > limits[name])


def reached_dimensions(value: Mapping[str, int], limits: Mapping[str, int]) -> tuple[str, ...]:
    return tuple(name for name in DIMENSIONS if limits[name] > 0 and value[name] >= limits[name])


def within_reservation(observed: Mapping[str, int], reserved: Mapping[str, int]) -> bool:
    return all(observed[name] <= reserved[name] for name in DIMENSIONS)
