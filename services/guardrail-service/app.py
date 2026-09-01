"""Composition root for the install-inert guardrail ASGI service."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from planeon_trust.common.identity import IdentityVerifier, load_registry_file
from planeon_trust.guardrails import (
    GuardrailAsgiApp,
    GuardrailMemoryStore,
    GuardrailProfileManager,
    GuardrailService,
    GuardrailStreamRegistry,
)


def create_app(
    *,
    oidc_registry_path: str,
    profile_keyset_path: str,
    profile_artifact_paths: tuple[str, ...],
    readiness_organization_id: str,
    now: datetime | None = None,
) -> GuardrailAsgiApp:
    if not profile_artifact_paths:
        raise ValueError("at least one signed guardrail profile is required")
    current = now or datetime.now(timezone.utc).replace(microsecond=0)
    streams = GuardrailStreamRegistry()
    profiles = GuardrailProfileManager(streams.expire_profile)
    keyset = Path(profile_keyset_path)
    for artifact in profile_artifact_paths:
        profiles.activate(Path(artifact), keyset, now=current)
    service = GuardrailService(
        identity=IdentityVerifier(load_registry_file(oidc_registry_path)),
        profiles=profiles,
        streams=streams,
        store=GuardrailMemoryStore(),
    )
    return GuardrailAsgiApp(service, readiness_organization_id=readiness_organization_id)


def create_app_from_environment() -> GuardrailAsgiApp:
    required = {
        "PLANEON_OIDC_REGISTRY_FILE",
        "PLANEON_GUARDRAIL_PROFILE_KEYSET_FILE",
        "PLANEON_GUARDRAIL_PROFILE_FILES",
        "PLANEON_READINESS_ORGANIZATION_ID",
    }
    missing = sorted(name for name in required if not os.environ.get(name))
    if missing:
        raise RuntimeError("guardrail service authority references are incomplete")
    profile_paths = tuple(item for item in os.environ["PLANEON_GUARDRAIL_PROFILE_FILES"].split(os.pathsep) if item)
    return create_app(
        oidc_registry_path=os.environ["PLANEON_OIDC_REGISTRY_FILE"],
        profile_keyset_path=os.environ["PLANEON_GUARDRAIL_PROFILE_KEYSET_FILE"],
        profile_artifact_paths=profile_paths,
        readiness_organization_id=os.environ["PLANEON_READINESS_ORGANIZATION_ID"],
    )
