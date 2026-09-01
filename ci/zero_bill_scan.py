#!/usr/bin/env python3
"""Fail closed on billable, hosted, mutable, or runtime-fetching configuration."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


EXCLUDED = {".git", ".venv", "__pycache__", "dist", "build"}
SCANNABLE = {".py", ".sh", ".json", ".yaml", ".yml", ".toml", ".tpl", ".sql"}
PROHIBITED_IMPLEMENTATION = {
    "actions/upload-artifact", "actions/cache", "ubuntu-latest", "macos-latest", "windows-latest",
    "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com", "bedrock-runtime",
    "terraform apply", "pulumi up", "helm install", "docker pull", "kubectl apply",
}
MUTABLE_IMAGE = re.compile(r"(?:image|repository):\s*[^\s\"']+:(?:latest|main|edge|nightly)\b", re.IGNORECASE)


def files(root: Path):
    for path in sorted(root.rglob("*")):
        if any(part in EXCLUDED for part in path.parts) or not path.is_file() or path.is_symlink():
            continue
        if path.suffix in SCANNABLE or path.name in {"Makefile"}:
            yield path


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) == 2 else ".").resolve()
    findings: list[str] = []
    scanned = 0
    for path in files(root):
        scanned += 1
        relative = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8")
        if relative not in {"ci/zero_bill_scan.py"}:
            for marker in PROHIBITED_IMPLEMENTATION:
                if marker.casefold() in text.casefold():
                    findings.append(f"{relative}: prohibited billing/runtime marker: {marker}")
            if MUTABLE_IMAGE.search(text):
                findings.append(f"{relative}: mutable image reference")
        if relative.startswith(".github/workflows/"):
            required = ["self-hosted", "harness-engineering", "ephemeral", "credential-free", "contents: read"]
            for marker in required:
                if marker not in text:
                    findings.append(f"{relative}: missing workflow boundary {marker}")
            if re.search(r"^\s*schedule\s*:", text, re.MULTILINE):
                findings.append(f"{relative}: scheduled workflow is forbidden")
        if relative.startswith("deploy/") and re.search(r"\bkind:\s*(?:Secret|Namespace|PersistentVolume|PersistentVolumeClaim)\b", text):
            findings.append(f"{relative}: chart provisions forbidden state or credentials")
    lock = json.loads((root / "ci/toolchain.lock.json").read_text(encoding="utf-8"))
    if lock.get("networkRequired") is not False or not str(lock.get("wheelhouse", "")).startswith("/opt/planeon/wheelhouse/"):
        findings.append("ci/toolchain.lock.json: toolchain is not local-only")
    values = (root / "deploy/helm/policy-decision/values.yaml").read_text(encoding="utf-8")
    if "repository: \"\"" not in values or "digest: \"\"" not in values or "enabled: false" not in values:
        findings.append("Helm defaults are not install-inert")
    if findings:
        print("\n".join(sorted(findings)), file=sys.stderr)
        return 1
    print(f"zero_bill_status=PASS scanned_files={scanned} hosted_runners=0 remote_caches=0 artifacts_uploaded=0 paid_providers=0 runtime_downloads=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
