"""Dependency-free deterministic wheel backend for the trust-plane library."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import time
import zipfile
from pathlib import Path
from typing import Any


NAME = "planeon_harness_trust_plane"
VERSION = "0.1.0"
DIST_INFO = f"{NAME}-{VERSION}.dist-info"
ROOT = Path(__file__).resolve().parents[4]
PACKAGE_ROOT = ROOT / "src" / "planeon_trust"
FIXED_EPOCH = 946684800


def get_requires_for_build_wheel(config_settings: dict[str, Any] | None = None) -> list[str]:
    del config_settings
    return []


def _metadata() -> bytes:
    return (
        "Metadata-Version: 2.4\n"
        "Name: planeon-harness-trust-plane\n"
        f"Version: {VERSION}\n"
        "Summary: Offline-first Planeon trust-plane service foundation\n"
        "License-Expression: Apache-2.0\n"
        "Requires-Python: >=3.12\n"
        "Requires-Dist: planeon-harness-sdk==0.1.0\n"
        "Requires-Dist: cryptography==49.0.0\n"
        "Requires-Dist: cffi==2.1.0\n"
        "Requires-Dist: pycparser==3.0\n\n"
    ).encode("utf-8")


def _record_digest(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")


def build_wheel(wheel_directory: str, config_settings: dict[str, Any] | None = None, metadata_directory: str | None = None) -> str:
    del config_settings, metadata_directory
    destination = Path(wheel_directory)
    destination.mkdir(parents=True, exist_ok=True)
    filename = f"{NAME}-{VERSION}-py3-none-any.whl"
    files: list[tuple[str, bytes]] = []
    for path in sorted(PACKAGE_ROOT.rglob("*.py"), key=lambda item: item.relative_to(PACKAGE_ROOT).as_posix()):
        if path.is_symlink():
            raise ValueError("linked package source is forbidden")
        files.append((f"planeon_trust/{path.relative_to(PACKAGE_ROOT).as_posix()}", path.read_bytes()))
    files.extend(
        [
            (f"{DIST_INFO}/METADATA", _metadata()),
            (f"{DIST_INFO}/WHEEL", b"Wheel-Version: 1.0\nGenerator: planeon-trust-stdlib-backend-1\nRoot-Is-Purelib: true\nTag: py3-none-any\n"),
            (f"{DIST_INFO}/licenses/LICENSE", (ROOT / "LICENSE").read_bytes()),
        ]
    )
    files.sort(key=lambda item: item[0])
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    for name, data in files:
        writer.writerow((name, _record_digest(data), len(data)))
    writer.writerow((f"{DIST_INFO}/RECORD", "", ""))
    files.append((f"{DIST_INFO}/RECORD", stream.getvalue().encode("utf-8")))
    epoch = max(int(os.environ.get("SOURCE_DATE_EPOCH", FIXED_EPOCH)), 315532800)
    with zipfile.ZipFile(destination / filename, "w", strict_timestamps=True) as archive:
        for name, data in files:
            info = zipfile.ZipInfo(name, time.gmtime(epoch)[:6])
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return filename
