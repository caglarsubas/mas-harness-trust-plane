# Sol-High Execution Rules

1. Implement exactly one merged task packet per branch and pull request.
2. Touch only the packet's `allowedPaths` and read every predecessor binding.
3. Never mount, open, or receive a warm-start checkout. Implement clean-room.
4. Never add cloud provisioning, hosted runners, paid APIs, API keys, runtime
   downloads, mutable artifacts, remote telemetry, caches, or uploaded artifacts.
5. Run packet prefetch and acceptance only through the signed, hash-pinned,
   deny-all-outbound launcher. Never bypass unavailable isolation.
6. The TRUST-001 Makefile and dispatcher are bootstrap authorities. Later
   packets add only their exact descriptor and packet-owned handlers.
7. Keep source, contract/unit, PR check, merge, artifact/SBOM,
   signature/release, deployment, runtime, security, assurance, and tenant
   acceptance as independent evidence axes.
8. Open a `codex/*` PR, monitor the required self-hosted checks, apply bounded
   fixes, and merge only after every required check is green.
9. Stop on a missing public-contract, tenant-isolation, destructive-data,
   licensing, or billing decision.
