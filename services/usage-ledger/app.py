"""Composition root for the install-inert usage-ledger ASGI service."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from planeon_trust.common.canonical import opaque_digest
from planeon_trust.common.identity import IdentityVerifier, TenantIdentity, load_registry_file
from planeon_trust.usage import BoundedTelemetryBuffer, DependencyHealth, UsageAsgiApp, UsageLedger, UsageService
from planeon_trust.usage.config import load_usage_config
from planeon_trust.usage.module_contracts import validate_collector_contract


def create_app(
    *,
    oidc_registry_path: str,
    usage_config_path: str,
    collector_contract_path: str,
    readiness_organization_id: str,
    dependency_health: DependencyHealth | None = None,
    now: datetime | None = None,
) -> UsageAsgiApp:
    current = now or datetime.now(timezone.utc).replace(microsecond=0)
    validate_collector_contract(Path(collector_contract_path))
    budgets, limits = load_usage_config(Path(usage_config_path))
    ledger = UsageLedger()
    for budget in budgets:
        ledger.add_budget(budget)
        ledger.reconcile(
            TenantIdentity(
                organization_id=budget.organization_id,
                subject_id="usage.startup",
                issuer="local-startup",
                token_identity_digest=opaque_digest("usage.startup:" + budget.organization_id),
            ),
            budget_id=budget.budget_id,
            now=current,
        )
    service = UsageService(
        identity=IdentityVerifier(load_registry_file(oidc_registry_path)),
        ledger=ledger,
        buffer=BoundedTelemetryBuffer(**{
            "maximum_records": limits["maximumRecords"],
            "maximum_bytes": limits["maximumBytes"],
            "maximum_age_seconds": limits["maximumAgeSeconds"],
        }),
        health=dependency_health,
    )
    return UsageAsgiApp(service, readiness_organization_id=readiness_organization_id)


def create_app_from_environment() -> UsageAsgiApp:
    required = {
        "PLANEON_OIDC_REGISTRY_FILE",
        "PLANEON_USAGE_CONFIG_FILE",
        "PLANEON_OTEL_COLLECTOR_CONTRACT_FILE",
        "PLANEON_READINESS_ORGANIZATION_ID",
    }
    missing = sorted(name for name in required if not os.environ.get(name))
    if missing:
        raise RuntimeError("usage-ledger authority references are incomplete")
    return create_app(
        oidc_registry_path=os.environ["PLANEON_OIDC_REGISTRY_FILE"],
        usage_config_path=os.environ["PLANEON_USAGE_CONFIG_FILE"],
        collector_contract_path=os.environ["PLANEON_OTEL_COLLECTOR_CONTRACT_FILE"],
        readiness_organization_id=os.environ["PLANEON_READINESS_ORGANIZATION_ID"],
    )
