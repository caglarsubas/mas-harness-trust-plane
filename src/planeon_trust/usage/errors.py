"""Stable content-free denials for the usage ledger."""

from __future__ import annotations


class UsageDenied(PermissionError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(f"usage operation denied: {reason_code}")
        self.reason_code = reason_code


class TelemetrySaturated(RuntimeError):
    """The bounded buffer cannot preserve another audit-required record."""
