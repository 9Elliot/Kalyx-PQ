"""Transport contracts to keep crypto engine network-agnostic."""

from __future__ import annotations

from typing import Protocol

from .engine import HandshakeArtifacts, HandshakeResult


class HandshakeTransport(Protocol):
    """
    Network abstraction for moving handshake payloads.

    Implementations can target HTTP, WebSockets, gRPC, raw TCP, etc.
    """

    async def send_client_artifacts(self, artifacts: HandshakeArtifacts) -> HandshakeResult:
        """Send artifacts and return server response."""


class ServerHandshakeHandler(Protocol):
    """Optional server-side contract for transport adapters."""

    def handle_client_artifacts(self, artifacts: HandshakeArtifacts) -> HandshakeResult:
        """Process client artifacts and return server handshake response."""
