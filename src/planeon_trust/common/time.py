"""Strict UTC time utilities."""

from __future__ import annotations

from datetime import datetime, timezone


def utc_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z") or "." in value:
        raise ValueError(f"{field} must be a whole-second UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError(f"{field} must be a whole-second UTC timestamp") from exc
    return parsed


def render_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamp must be timezone aware")
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def require_now(value: datetime) -> datetime:
    if value.tzinfo is None or value.microsecond:
        raise ValueError("now must be timezone aware with whole-second precision")
    return value.astimezone(timezone.utc)
