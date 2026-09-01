#!/usr/bin/env python3
"""Validate the inert TRUST-001 destination porting ledger."""

from __future__ import annotations

import sys
from pathlib import Path


EXPECTED = """schemaVersion: harness.planeon.ai/porting-ledger/v1alpha1
repository: mas-harness-trust-plane
state: NO_AUTHORIZATION
authorizations: []
ports: []
"""


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) == 2 else None
    if path is None or path.is_symlink() or not path.is_file() or path.read_text(encoding="utf-8") != EXPECTED:
        print("PORTING ledger is not the exact NO_AUTHORIZATION sentinel", file=sys.stderr)
        return 2
    print("porting_status=NO_AUTHORIZATION authorized_mappings=0 applied_ports=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
