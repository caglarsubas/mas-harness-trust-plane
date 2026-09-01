"""Closed source validation for local observability module declarations."""

from __future__ import annotations

from pathlib import Path

from planeon_trust.common.json_io import JsonContractError, load_regular_json, require_object


COLLECTOR_SCHEMA = "harness.planeon.ai/otel-collector-module/v1alpha1"
BACKEND_SCHEMA = "harness.planeon.ai/external-otel-backend/v1alpha1"


def validate_collector_contract(path: Path) -> dict[str, object]:
    fields = {
        "schemaVersion",
        "moduleId",
        "artifactState",
        "enabled",
        "image",
        "receivers",
        "processors",
        "exporters",
        "buffer",
        "cardinality",
        "contentPolicy",
        "network",
    }
    document = require_object(load_regular_json(path), fields=fields, label="collector contract")
    if document["schemaVersion"] != COLLECTOR_SCHEMA or document["moduleId"] != "module.trust.observability.otel-collector":
        raise JsonContractError("collector identity is invalid")
    if document["artifactState"] != "SOURCE_CONTRACT_ONLY" or document["enabled"] is not False:
        raise JsonContractError("collector must remain install-inert")
    image = require_object(document["image"], fields={"repository", "digest", "immutableDigestRequired"}, label="collector image")
    if image != {"repository": "", "digest": "", "immutableDigestRequired": True}:
        raise JsonContractError("collector image must be operator-pinned")
    if document["receivers"] != ["OTLP_GRPC", "OTLP_HTTP"]:
        raise JsonContractError("collector receiver set is invalid")
    if document["processors"] != ["MEMORY_LIMIT", "CONTENT_REDACTION", "CARDINALITY_LIMIT", "BATCH"]:
        raise JsonContractError("collector processor order is invalid")
    if document["exporters"] != [
        {"backendRef": "external.otel-backend", "signal": "METRICS"},
        {"backendRef": "external.otel-backend", "signal": "TRACES"},
    ]:
        raise JsonContractError("collector exporters must resolve through the external catalog id")
    buffer = require_object(document["buffer"], fields={"maximumRecords", "maximumBytes", "maximumAgeSeconds", "storage"}, label="collector buffer")
    if not _integer(buffer["maximumRecords"], 1, 100_000) or not _integer(buffer["maximumBytes"], 1024, 1_073_741_824) or not _integer(buffer["maximumAgeSeconds"], 1, 86_400) or buffer["storage"] != "BOUNDED_LOCAL_WAL":
        raise JsonContractError("collector buffer is not bounded")
    cardinality = require_object(document["cardinality"], fields={"maximumValuesPerKey", "unknownAttributeDisposition"}, label="collector cardinality")
    if not _integer(cardinality["maximumValuesPerKey"], 1, 10_000) or cardinality["unknownAttributeDisposition"] != "DROP_WITH_COUNT":
        raise JsonContractError("collector cardinality is not bounded")
    if document["contentPolicy"] != {"payloadCapture": "DISABLED", "sensitiveAttributeDisposition": "DROP_WITHOUT_VALUE_ECHO"}:
        raise JsonContractError("collector content policy is invalid")
    if document["network"] != {"resolutionAuthority": "CATALOG_EXTERNAL_ID", "tenantPrivateOnly": True, "publicHostsAllowed": False, "urlLiteralsAllowed": False}:
        raise JsonContractError("collector network authority is invalid")
    return document


def validate_backend_contract(path: Path, *, signal: str) -> dict[str, object]:
    fields = {
        "schemaVersion",
        "providerId",
        "backendKind",
        "ownership",
        "artifactState",
        "builtByRepository",
        "imageDigestRequired",
        "tenantAttestationRequired",
        "tenantIsolationRequired",
        "retentionDays",
        "storageBytesLimit",
        "ingestSignal",
        "queryCatalog",
        "network",
    }
    document = require_object(load_regular_json(path), fields=fields, label="external backend contract")
    if document["schemaVersion"] != BACKEND_SCHEMA or document["providerId"] != "external.otel-backend":
        raise JsonContractError("external backend identity is invalid")
    if document["backendKind"] != signal or document["ingestSignal"] != signal:
        raise JsonContractError("external backend signal is invalid")
    expected = {
        "ownership": "TENANT_SUPPLIED_EXTERNAL",
        "artifactState": "MISSING_PLANNED",
        "builtByRepository": False,
        "imageDigestRequired": True,
        "tenantAttestationRequired": True,
        "tenantIsolationRequired": True,
    }
    if any(document[name] != value for name, value in expected.items()):
        raise JsonContractError("external backend custody is invalid")
    if not _integer(document["retentionDays"], 1, 366) or not _integer(document["storageBytesLimit"], 1_048_576, 9_000_000_000_000_000):
        raise JsonContractError("external backend storage is unbounded")
    network = document["network"]
    if network != {"resolutionAuthority": "CATALOG_EXTERNAL_ID", "tenantPrivateOnly": True, "publicHostsAllowed": False, "urlLiteralsAllowed": False, "remoteWriteAllowed": False}:
        raise JsonContractError("external backend network authority is invalid")
    catalog = document["queryCatalog"]
    if not isinstance(catalog, list) or not catalog or len(catalog) != len(set(catalog)) or not all(isinstance(item, str) and item.startswith("harness.") for item in catalog):
        raise JsonContractError("external backend query catalog is invalid")
    return document


def _integer(value: object, minimum: int, maximum: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and minimum <= value <= maximum
