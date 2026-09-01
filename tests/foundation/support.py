from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from planeon_trust.common.cache import DecisionCache
from planeon_trust.common.decision import DecisionService
from planeon_trust.common.identity import IdentityVerifier, load_registry
from planeon_trust.common.opa import OpaClient
from planeon_trust.common.policy import PolicyManager
from planeon_trust.common.storage import AtomicMemoryStore


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures" / "policy"
NOW = datetime(2026, 9, 1, 12, 5, 0, tzinfo=timezone.utc)
REQUEST = {"action": "source.read", "resource": {"kind": "dataset", "id": "dataset.orders"}, "attributes": {"purpose": "support"}, "mutation": False}


def document(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def registry():
    return load_registry(document(FIXTURES / "oidc-registry.json"))


def tokens():
    return document(FIXTURES / "tokens.json")


class FakeOpa:
    def __init__(self, body: dict | bytes | None = None, status: int = 200, failure: Exception | None = None):
        self.body = body if body is not None else document(FIXTURES / "opa-results.json")["allow"]
        self.status = status
        self.failure = failure
        self.calls = 0
        self.inputs: list[bytes] = []

    def __call__(self, body: bytes, timeout: float):
        self.calls += 1
        self.inputs.append(body)
        if self.failure:
            raise self.failure
        encoded = self.body if isinstance(self.body, bytes) else json.dumps(self.body, sort_keys=True, separators=(",", ":")).encode()
        return self.status, encoded


def service(fake: FakeOpa | None = None, *, ready: bool = True):
    cache = DecisionCache()
    policies = PolicyManager(cache.clear)
    policies.activate(FIXTURES / "v1" / "policy-artifact.json", FIXTURES / "policy-keyset.json", now=NOW)
    transport = fake or FakeOpa()
    store = AtomicMemoryStore()
    result = DecisionService(
        identity=IdentityVerifier(registry()),
        policies=policies,
        opa=OpaClient(transport=transport, readiness_probe=lambda _: ready),
        cache=cache,
        store=store,
    )
    return result, policies, cache, store, transport
