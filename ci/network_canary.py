#!/usr/bin/env python3
"""Prove that the outer host boundary denies outbound networking."""

from __future__ import annotations

import socket


def main() -> int:
    attempts = [(socket.AF_INET, ("198.51.100.1", 9)), (socket.AF_INET6, ("2001:db8::1", 9, 0, 0))]
    for family, address in attempts:
        candidate = socket.socket(family, socket.SOCK_STREAM)
        candidate.settimeout(0.1)
        try:
            candidate.connect(address)
        except OSError:
            pass
        else:
            raise SystemExit("outbound network canary unexpectedly connected")
        finally:
            candidate.close()
    print("network canary: outbound connection attempts denied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
