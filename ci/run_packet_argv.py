#!/usr/bin/env python3
"""Execute hash-pinned inline packet argv arrays without shell transport."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


PACKET_ENV = "HARNESS_TASK_PACKET"
OFFLINE_ENV = {"UV_OFFLINE": "1", "UV_FROZEN": "1", "UV_NO_SYNC": "1"}
EXPECTED_EXECUTION = {
    "wrapperArgv": ["./ci/verify-offline.sh"],
    "packetPathEnvironment": PACKET_ENV,
    "packetPathMode": "HASH_PINNED_READ_ONCE_NO_CHILD_PATH",
    "commandTransport": "ARGV_ARRAY_V1",
    "isolation": "OS_ENFORCED_DENY_ALL_OUTBOUND",
    "sessionScope": "SINGLE_PROCESS_TREE",
    "prefetchOutsideSession": False,
    "offlineEnvironment": OFFLINE_ENV,
}
FORBIDDEN_EXECUTABLES = {"bash", "dash", "env", "sh", "zsh"}
FORBIDDEN_OFFLINE_TOKENS = {"add", "curl", "download", "fetch", "install", "npx", "prefetch", "pull", "sync", "wget"}
CHILD_ENV_ALLOWLIST = {
    "CI", "GITHUB_ACTIONS", "GITHUB_WORKSPACE", "HOME", "LANG", "LC_ALL", "LOGNAME", "PATH",
    "PYTHONDONTWRITEBYTECODE", "PYTHONPATH", "SOURCE_DATE_EPOCH", "TMPDIR", "USER", "VIRTUAL_ENV",
    "UV_CACHE_DIR", "UV_FROZEN", "UV_NO_SYNC", "UV_OFFLINE", "UV_PROJECT_ENVIRONMENT",
    "UV_PYTHON_DOWNLOADS", "HARNESS_OFFLINE_BACKEND", "HARNESS_OFFLINE_ENFORCED", "HARNESS_OFFLINE_SESSION_ID",
}


class PacketTransportError(ValueError):
    pass


def read_packet(path: Path) -> tuple[str, str]:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise PacketTransportError("packet must be regular")
        data = bytearray()
        while chunk := os.read(descriptor, 65536):
            data.extend(chunk)
    finally:
        os.close(descriptor)
    return bytes(data).decode("utf-8"), hashlib.sha256(data).hexdigest()


def inline_json(text: str, field: str) -> Any:
    prefix = f"{field}:"
    values = [line[len(prefix):].strip() for line in text.splitlines() if line.startswith(prefix)]
    if len(values) != 1 or not values[0]:
        raise PacketTransportError(f"packet must contain one inline JSON {field}")
    try:
        return json.loads(values[0])
    except json.JSONDecodeError as exc:
        raise PacketTransportError(f"packet {field} is not inline JSON") from exc


def commands(text: str, field: str) -> list[list[str]]:
    value = inline_json(text, field)
    if not isinstance(value, list):
        raise PacketTransportError(f"packet {field} must be an array")
    for command in value:
        if not isinstance(command, list) or not command or not all(isinstance(item, str) and item and "\x00" not in item for item in command):
            raise PacketTransportError(f"packet {field} contains invalid argv")
        if Path(command[0]).name in FORBIDDEN_EXECUTABLES:
            raise PacketTransportError("shell transport is forbidden")
    return value


def verify_digest(path: Path, expected: str) -> None:
    if read_packet(path)[1] != expected:
        raise PacketTransportError("packet authority changed during execution")


def run(items: list[list[str]], environment: dict[str, str], packet: Path, digest: str, phase: str) -> int:
    for command in items:
        print(f"{phase} argv: {json.dumps(command, separators=(',', ':'))}", flush=True)
        result = subprocess.run(command, env=environment, shell=False, check=False)
        verify_digest(packet, digest)
        if result.returncode:
            return result.returncode
    return 0


def main() -> int:
    raw_path = os.environ.get(PACKET_ENV)
    if not raw_path:
        raise PacketTransportError(f"{PACKET_ENV} is required")
    packet = Path(raw_path)
    text, digest = read_packet(packet)
    if inline_json(text, "offlineExecution") != EXPECTED_EXECUTION:
        raise PacketTransportError("offlineExecution contract mismatch")
    prefetch = commands(text, "prefetchCommands")
    acceptance = commands(text, "offlineAcceptanceCommands")
    if prefetch != [["make", "prefetch"]]:
        raise PacketTransportError("prefetch must use its fixed local-cache-only target")
    for command in acceptance:
        overlap = sorted({argument.casefold() for argument in command} & FORBIDDEN_OFFLINE_TOKENS)
        if overlap:
            raise PacketTransportError(f"offline argv contains forbidden token {overlap[0]}")
    environment = {name: value for name, value in os.environ.items() if name in CHILD_ENV_ALLOWLIST}
    if environment.get("HARNESS_OFFLINE_ENFORCED") != "1":
        raise PacketTransportError("OS-enforced isolation is required")
    if any(environment.get(name) != value for name, value in OFFLINE_ENV.items()):
        raise PacketTransportError("offline environment contract mismatch")
    canary = Path(__file__).with_name("network_canary.py")
    if subprocess.run([sys.executable, str(canary)], env=environment, shell=False, check=False).returncode:
        return 2
    verify_digest(packet, digest)
    print(f"packet={digest} phases=prefetch,offline session={environment.get('HARNESS_OFFLINE_SESSION_ID')}", flush=True)
    result = run(prefetch, environment, packet, digest, "prefetch-local-cache-only")
    return result or run(acceptance, environment, packet, digest, "offline-acceptance")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, PacketTransportError) as exc:
        print(f"packet transport refused: {exc}", file=sys.stderr)
        raise SystemExit(2)
