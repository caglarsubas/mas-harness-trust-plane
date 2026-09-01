# Planeon MAS Harness Trust Plane

Offline-first, modular trust and lifecycle services for the Planeon enterprise
multi-agent platform. This repository owns the security/safety,
governance/AgentOps, observability/FinOps, and evaluation/assurance harnesses as
independently selectable capabilities.

TRUST-001 provides the dependency-minimal foundation:

- locally configured OIDC verification with server-derived tenant identity;
- signed, tenant-bound policy activation and explicit last-known-good state;
- a loopback-only OPA decision adapter and fail-closed local client;
- metadata-only bounded caching and atomic decision/audit/outbox recording;
- PostgreSQL role, RLS, least-privilege, and append-only migration authority;
- an install-inert Helm chart requiring operator-supplied immutable images and
  existing Secret references; and
- signed, deny-all-outbound, credential-free self-hosted verification.

## Commands

```console
make prefetch
make policy-vectors
make security
make zero-bill
```

The prefetch target only verifies the preinstalled digest-locked toolchain. It
never downloads or installs a dependency. OPA, PostgreSQL, OIDC, Kubernetes,
OpenShift, and image execution are not claimed by offline unit evidence; their
deployment/runtime/security/assurance states remain `NOT_RUN_ENV_UNAVAILABLE`.
