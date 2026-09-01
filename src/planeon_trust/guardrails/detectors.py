"""Closed deterministic detector registry for the guardrail service."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping, Sequence

from planeon_harness.guardrail import (
    DetectorAction,
    DetectorFinding,
    GuardrailDetector,
    GuardrailRequest,
    RedactionRange,
)


IMPLEMENTATIONS = frozenset(
    {
        "ALLOW_ALL_V1",
        "PROMPT_INJECTION_V1",
        "RUNTIME_QUARANTINE_V1",
        "SECRET_PATTERN_V1",
    }
)
_SECRET = re.compile(
    r"(?i)(?:api[_-]?key|password|token)\s*[:=]\s*[a-z0-9._~-]{4,128}"
)
_INJECTION_MARKERS = (
    "ignore previous instructions",
    "reveal system prompt",
    "override guardrails",
)
_RUNTIME_MARKERS = (
    "__unsafe_tool__",
    "file:///etc/passwd",
    "169.254.169.254",
)


class DetectorConfigurationError(ValueError):
    """A signed detector specification is not in the closed registry."""


@dataclass(frozen=True, slots=True)
class DetectorSpec:
    detector_id: str
    implementation: str

    @classmethod
    def from_dict(cls, raw: object) -> DetectorSpec:
        if not isinstance(raw, dict) or set(raw) != {"detectorId", "implementation"}:
            raise DetectorConfigurationError("detector specification fields are closed")
        detector_id, implementation = raw["detectorId"], raw["implementation"]
        if (
            not isinstance(detector_id, str)
            or not detector_id
            or len(detector_id) > 128
            or implementation not in IMPLEMENTATIONS
        ):
            raise DetectorConfigurationError("detector specification is invalid")
        return cls(detector_id, implementation)

    def to_dict(self) -> dict[str, str]:
        return {"detectorId": self.detector_id, "implementation": self.implementation}


@dataclass(frozen=True, slots=True)
class _ClosedDetector(GuardrailDetector):
    detector_id: str
    implementation: str

    def evaluate(self, request: GuardrailRequest) -> DetectorFinding:
        if self.implementation == "ALLOW_ALL_V1":
            return self._finding(DetectorAction.ALLOW, "NO_MATCH")
        if self.implementation == "PROMPT_INJECTION_V1":
            folded = request.content.casefold()
            if any(marker in folded for marker in _INJECTION_MARKERS):
                return self._finding(DetectorAction.DENY, "PROMPT_INJECTION")
            return self._finding(DetectorAction.ALLOW, "NO_MATCH")
        if self.implementation == "RUNTIME_QUARANTINE_V1":
            folded = request.content.casefold()
            if any(marker in folded for marker in _RUNTIME_MARKERS):
                return self._finding(DetectorAction.QUARANTINE, "RUNTIME_ISOLATE")
            return self._finding(DetectorAction.ALLOW, "NO_MATCH")
        if self.implementation == "SECRET_PATTERN_V1":
            ranges = tuple(RedactionRange(match.start(), match.end()) for match in _SECRET.finditer(request.content))
            if ranges:
                return DetectorFinding(self.detector_id, DetectorAction.REDACT, "SECRET_PATTERN", ranges)
            return self._finding(DetectorAction.ALLOW, "NO_MATCH")
        raise DetectorConfigurationError("detector implementation is unavailable")

    def _finding(self, action: DetectorAction, reason: str) -> DetectorFinding:
        return DetectorFinding(self.detector_id, action, reason)


def parse_specs(raw: object) -> tuple[DetectorSpec, ...]:
    if not isinstance(raw, list) or not 1 <= len(raw) <= 64:
        raise DetectorConfigurationError("detector specifications must be a bounded array")
    specs = tuple(DetectorSpec.from_dict(item) for item in raw)
    identifiers = tuple(spec.detector_id for spec in specs)
    if len(identifiers) != len(set(identifiers)):
        raise DetectorConfigurationError("detector identifiers are duplicated")
    return specs


def build_detectors(
    detector_ids: Sequence[str],
    specs: Sequence[DetectorSpec],
) -> tuple[GuardrailDetector, ...]:
    by_id: Mapping[str, DetectorSpec] = {spec.detector_id: spec for spec in specs}
    if len(by_id) != len(specs) or set(by_id) != set(detector_ids):
        raise DetectorConfigurationError("detector registration is incomplete")
    return tuple(_ClosedDetector(identifier, by_id[identifier].implementation) for identifier in detector_ids)
