"""Strict local usage configuration loading."""

from __future__ import annotations

from pathlib import Path

from planeon_trust.common.json_io import JsonContractError, load_regular_json, require_object
from planeon_trust.common.time import utc_timestamp

from .models import BudgetDefinition


CONFIG_SCHEMA = "harness.planeon.ai/usage-ledger-config/v1alpha1"


def load_usage_config(path: Path) -> tuple[tuple[BudgetDefinition, ...], dict[str, int]]:
    document = require_object(load_regular_json(path), fields={"schemaVersion", "budgets", "buffer"}, label="usage config")
    if document["schemaVersion"] != CONFIG_SCHEMA:
        raise JsonContractError("usage config schema is invalid")
    raw_budgets = document["budgets"]
    if not isinstance(raw_budgets, list) or not raw_budgets:
        raise JsonContractError("usage config budgets must be non-empty")
    fields = {
        "organizationId",
        "budgetId",
        "budgetDigest",
        "scopeType",
        "scopeId",
        "limits",
        "enforcement",
        "windowEpoch",
        "windowSeconds",
        "warningThresholdBasisPoints",
        "reservationTtlSeconds",
        "retentionWindows",
        "enabled",
    }
    budgets: list[BudgetDefinition] = []
    for raw in raw_budgets:
        item = require_object(raw, fields=fields, label="budget definition")
        budgets.append(
            BudgetDefinition(
                organization_id=item["organizationId"],
                budget_id=item["budgetId"],
                budget_digest=item["budgetDigest"],
                scope_type=item["scopeType"],
                scope_id=item["scopeId"],
                limits=item["limits"],
                enforcement=item["enforcement"],
                window_epoch=utc_timestamp(item["windowEpoch"], "windowEpoch"),
                window_seconds=item["windowSeconds"],
                warning_threshold_basis_points=item["warningThresholdBasisPoints"],
                reservation_ttl_seconds=item["reservationTtlSeconds"],
                retention_windows=item["retentionWindows"],
                enabled=item["enabled"],
            )
        )
    if len({(item.organization_id, item.budget_id) for item in budgets}) != len(budgets):
        raise JsonContractError("usage config budget ids are duplicated")
    buffer = require_object(document["buffer"], fields={"maximumRecords", "maximumBytes", "maximumAgeSeconds"}, label="usage buffer")
    if not all(isinstance(buffer[name], int) and not isinstance(buffer[name], bool) for name in buffer):
        raise JsonContractError("usage buffer limits are invalid")
    return tuple(budgets), dict(buffer)
