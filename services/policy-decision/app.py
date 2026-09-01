"""Service entrypoint factory; deployment supplies all local trust dependencies."""

from planeon_trust.common.asgi import PolicyAsgiApp

__all__ = ["PolicyAsgiApp"]
