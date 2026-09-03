#!/usr/bin/env python3
"""Verify the immutable preinstalled toolchain and wheelhouse without mutation."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import stat
import sys
from pathlib import Path


EXPECTED_UPSTREAM = {
    "schemaVersion": "harness.planeon.ai/trust-upstream-lock/v1alpha1",
    "contracts": {
        "repository": "mas-harness-contracts",
        "commit": "2146278a95344cd2a8e22596b2f315b46edffc88",
        "releaseManifestSha256": "c5dd4c39d1c69d07f8d8de3d1a09584bb906172fee2d5ac20ad25ff344b0db79",
        "entries": {
            "PolicyBundle": "sha256:c0444183121d156d001d0b004975b14dd25df3a6065bd4ecfecd4c965a0fd13d",
            "LifecycleCloudEvent": "sha256:f0be09712101b61980e7752ae4a394bd09fa21640df4cbeeec4764f1e6004d0f",
            "LifecycleCommonTypes": "sha256:08326b0089973097698776011a2d5c386cd6e0e6490642f1b9bfd942d6f7e409",
            "TrustApi": "sha256:b16d5bd0a16186c4a6c98c5fce938f1b9e2c8fda562586f1466715de0b531271",
        },
    },
    "compatibility": {
        "authority": "compatibility/data-harness-v1/mappings.json",
        "rawSha256": "81cc6d9ed39099534b61e45830f95af6bb215854f43dc21c37dd8080055445a3",
    },
    "sdk": {
        "repository": "mas-harness-sdks",
        "commit": "a083d0462012160a8ce5a4cc5b7b0fe077840200",
        "distribution": "planeon-harness-sdk",
        "version": "0.1.0",
        "wheelSha256": "5a4fa30c64432622083d8a0eeb32cf3ae67fa9975795eb2f0b5a209bd76d56a5",
    },
}


def main() -> int:
    if sys.version_info[:3] != (3, 12, 14):
        raise SystemExit("Python 3.12.14 is required")
    lock_path = Path(__file__).resolve().parents[1] / "toolchain.lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    upstream_path = Path("services/policy-decision/contracts/upstream.lock.json")
    upstream = json.loads(upstream_path.read_text(encoding="utf-8"))
    if upstream != EXPECTED_UPSTREAM:
        raise SystemExit("upstream contract lock changed")
    if set(lock) != {"schemaVersion", "packetId", "python", "wheelhouse", "packages", "networkRequired"}:
        raise SystemExit("toolchain lock fields changed")
    if lock["packetId"] != "TRUST-001" or lock["python"] != "3.12.14" or lock["networkRequired"] is not False:
        raise SystemExit("toolchain lock identity changed")
    wheelhouse = Path(lock["wheelhouse"])
    if not wheelhouse.is_dir() or wheelhouse.is_symlink():
        raise SystemExit("preprovisioned wheelhouse is unavailable")
    uv_lock = Path("uv.lock").read_text(encoding="utf-8")
    for record in lock["packages"]:
        if set(record) != {"distribution", "version", "wheel", "sha256"}:
            raise SystemExit("toolchain package record fields changed")
        if importlib.metadata.version(record["distribution"]) != record["version"]:
            raise SystemExit(f"installed distribution mismatch: {record['distribution']}")
        wheel = wheelhouse / record["wheel"]
        descriptor = os.open(wheel, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise SystemExit("wheelhouse member is not regular")
            digest = hashlib.sha256()
            while chunk := os.read(descriptor, 65536):
                digest.update(chunk)
        finally:
            os.close(descriptor)
        if digest.hexdigest() != record["sha256"]:
            raise SystemExit(f"wheel digest mismatch: {record['wheel']}")
        if record["version"] not in uv_lock or record["sha256"] not in uv_lock:
            raise SystemExit(f"uv.lock omits toolchain binding: {record['distribution']}")
    print("prefetch: exact local TRUST-001 Python and wheel closure is present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
