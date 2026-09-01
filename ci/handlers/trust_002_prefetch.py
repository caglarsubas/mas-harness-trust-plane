#!/usr/bin/env python3
"""Verify the exact local TRUST-002 SDK-006 toolchain without mutation."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import stat
import sys
import zipfile
from pathlib import Path

import planeon_harness.guardrail as guardrail


EXPECTED_UPSTREAM = {
    "schemaVersion": "harness.planeon.ai/trust-guardrail-upstream-lock/v1alpha1",
    "contracts": {
        "repository": "mas-harness-contracts",
        "commit": "2146278a95344cd2a8e22596b2f315b46edffc88",
        "releaseManifestSha256": "c5dd4c39d1c69d07f8d8de3d1a09584bb906172fee2d5ac20ad25ff344b0db79",
        "entries": {
            "EvidenceRecord": "sha256:05ea50ee0ad9fb74414871c8c3fa572e9f1a22bbc667194f911834f26b829674",
            "LifecycleCommonTypes": "sha256:08326b0089973097698776011a2d5c386cd6e0e6490642f1b9bfd942d6f7e409",
            "TrustApi": "sha256:b16d5bd0a16186c4a6c98c5fce938f1b9e2c8fda562586f1466715de0b531271",
        },
        "guardrailRoutePresent": False,
        "guardrailCloudEventPresent": False,
    },
    "sdk": {
        "repository": "mas-harness-sdks",
        "commit": "a181302f81bf6a83760cfae3890551ace89f51e4",
        "distribution": "planeon-harness-sdk",
        "version": "0.1.0",
        "wheelSha256": "9b85d01b7079fe27c189d70b7fba46614c3df647d6f44e9270fe4683d7337fa4",
    },
}
EXPECTED_SYMBOLS = {
    "API_VERSION",
    "DetectorAction",
    "DetectorFinding",
    "FailMode",
    "GuardrailClient",
    "GuardrailContractError",
    "GuardrailDetector",
    "GuardrailOutcome",
    "GuardrailProfile",
    "GuardrailRequest",
    "GuardrailResult",
    "GuardrailStage",
    "GuardrailStream",
    "MAXIMUM_CONTENT_BYTES",
    "PROFILE_KIND",
    "REDACTION_TOKEN",
    "RedactionRange",
}


def _digest(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or metadata.st_mode & 0o022:
            raise SystemExit("wheelhouse member custody is invalid")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 65536):
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def main() -> int:
    if sys.version_info[:3] != (3, 12, 14):
        raise SystemExit("Python 3.12.14 is required")
    lock_path = Path(__file__).resolve().parents[1] / "toolchains" / "trust-002.lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    upstream = json.loads(Path("services/guardrail-service/contracts/upstream.lock.json").read_text(encoding="utf-8"))
    if upstream != EXPECTED_UPSTREAM:
        raise SystemExit("TRUST-002 upstream contract lock changed")
    if set(lock) != {"schemaVersion", "packetId", "python", "wheelhouse", "packages", "sdkGuardrailMembers", "networkRequired"}:
        raise SystemExit("TRUST-002 toolchain lock fields changed")
    if lock["packetId"] != "TRUST-002" or lock["python"] != "3.12.14" or lock["networkRequired"] is not False:
        raise SystemExit("TRUST-002 toolchain identity changed")
    wheelhouse = Path(lock["wheelhouse"])
    if not wheelhouse.is_dir() or wheelhouse.is_symlink():
        raise SystemExit("TRUST-002 wheelhouse is unavailable")
    uv_lock = Path("uv.lock").read_text(encoding="utf-8")
    sdk_wheel: Path | None = None
    for record in lock["packages"]:
        if set(record) != {"distribution", "version", "wheel", "sha256"}:
            raise SystemExit("toolchain package record fields changed")
        if importlib.metadata.version(record["distribution"]) != record["version"]:
            raise SystemExit(f"installed distribution mismatch: {record['distribution']}")
        wheel = wheelhouse / record["wheel"]
        if _digest(wheel) != record["sha256"]:
            raise SystemExit(f"wheel digest mismatch: {record['wheel']}")
        if str(wheel) not in uv_lock or record["sha256"] not in uv_lock:
            raise SystemExit(f"uv.lock omits TRUST-002 binding: {record['distribution']}")
        if record["distribution"] == "planeon-harness-sdk":
            sdk_wheel = wheel
    if sdk_wheel is None or set(guardrail.__all__) != EXPECTED_SYMBOLS:
        raise SystemExit("SDK-006 guardrail surface is unavailable")
    members = lock["sdkGuardrailMembers"]
    if members != ["planeon_harness/guardrail/__init__.py", "planeon_harness/guardrail/_core.py"]:
        raise SystemExit("SDK-006 member inventory changed")
    installed_root = Path(guardrail.__file__).resolve().parent
    with zipfile.ZipFile(sdk_wheel) as archive:
        for member in members:
            installed = installed_root / Path(member).name
            if installed.is_symlink() or not installed.is_file() or installed.read_bytes() != archive.read(member):
                raise SystemExit(f"installed SDK-006 member mismatch: {member}")
    if "packet = \"TRUST-002\"" not in Path("pyproject.toml").read_text(encoding="utf-8"):
        raise SystemExit("pyproject packet identity is not TRUST-002")
    print("prefetch: exact local TRUST-002 Python, SDK-006, contracts, and wheel closure is present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
