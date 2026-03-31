"""Async HTTP transport implementation using httpx."""

from __future__ import annotations

import base64

import httpx

from .engine import HandshakeArtifacts, HandshakeResult
from .transport import HandshakeTransport


def _b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))


class HTTPHandshakeTransport(HandshakeTransport):
    """HTTP transport that posts handshake artifacts and receives response JSON."""

    def __init__(
        self,
        endpoint: str,
        *,
        client: httpx.AsyncClient | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self._endpoint = endpoint
        self._external_client = client
        self._timeout_seconds = timeout_seconds

    async def send_client_artifacts(self, artifacts: HandshakeArtifacts) -> HandshakeResult:
        payload = {
            "client_classical_public_key": _b64e(artifacts.client_classical_public_key),
            "client_pq_public_key": _b64e(artifacts.client_pq_public_key),
        }
        if self._external_client is not None:
            response = await self._external_client.post(self._endpoint, json=payload)
        else:
            async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                response = await client.post(self._endpoint, json=payload)
        response.raise_for_status()
        body = response.json()
        return HandshakeResult(
            server_classical_public_key=_b64d(body["server_classical_public_key"]),
            classical_ciphertext=_b64d(body["classical_ciphertext"]),
            pq_ciphertext=_b64d(body["pq_ciphertext"]),
            server_context=_b64d(body["server_context"]),
            key_material=b"",
        )
