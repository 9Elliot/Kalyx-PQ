"""In-process async HTTP server mock for Kalyx-PQ demos."""

from __future__ import annotations

import base64
import json
import asyncio

import httpx

from kalyxpq import (
    HandshakeArtifacts,
    HandshakeResult,
    KalyxEngine,
    decrypt_result,
    kalyx_safe,
)
from kalyxpq.engine import MockKemAdapter

# In-process mock HTTP transport: both sides must use the same KEM (mock here, no liboqs).
_SERVER_ENGINE = KalyxEngine(kem_adapter=MockKemAdapter(), strict_pq=False)
_API_DECORATOR_KEY = b"\xA5" * 32


def _b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))


@kalyx_safe(key_provider=lambda: _API_DECORATOR_KEY)
def get_sensitive_profile(user_id: str) -> dict[str, str]:
    """Example sensitive API endpoint protected with @kalyx_safe."""
    return {"user_id": user_id, "classification": "research-sensitive"}


def build_mock_transport() -> httpx.MockTransport:
    """
    Build a local HTTP mock transport exposing:
    - POST /kalyx/handshake
    - POST /api/profile
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/kalyx/handshake":
            body = json.loads(request.read().decode("utf-8"))
            response = _SERVER_ENGINE.server_respond(
                HandshakeArtifacts(
                    client_classical_public_key=_b64d(body["client_classical_public_key"]),
                    client_pq_public_key=_b64d(body["client_pq_public_key"]),
                )
            )
            return httpx.Response(
                200,
                json={
                    "server_classical_public_key": _b64e(response.server_classical_public_key),
                    "classical_ciphertext": _b64e(response.classical_ciphertext),
                    "pq_ciphertext": _b64e(response.pq_ciphertext),
                    "server_context": _b64e(response.server_context),
                },
            )

        if request.method == "POST" and request.url.path == "/api/profile":
            body = json.loads(request.read().decode("utf-8"))
            user_id = body["user_id"]
            encrypted = get_sensitive_profile(user_id)
            decrypted_for_demo = decrypt_result(encrypted, _API_DECORATOR_KEY)
            return httpx.Response(200, json=decrypted_for_demo)

        return httpx.Response(404, json={"detail": "not found"})

    return httpx.MockTransport(handler)


if __name__ == "__main__":
    # Small manual smoke test that does not need a real network server.
    async def _demo() -> None:
        transport = build_mock_transport()
        client_engine = KalyxEngine(kem_adapter=MockKemAdapter(), strict_pq=False)
        artifacts, client_classical_private, client_pq_secret = client_engine.client_prepare()
        async with httpx.AsyncClient(transport=transport, base_url="https://mock.kalyx") as client:
            handshake = await client.post(
                "/kalyx/handshake",
                json={
                    "client_classical_public_key": _b64e(artifacts.client_classical_public_key),
                    "client_pq_public_key": _b64e(artifacts.client_pq_public_key),
                },
            )
            print("Handshake route status:", handshake.status_code)
            server_payload = handshake.json()
            server_result = HandshakeResult(
                server_classical_public_key=_b64d(server_payload["server_classical_public_key"]),
                classical_ciphertext=_b64d(server_payload["classical_ciphertext"]),
                pq_ciphertext=_b64d(server_payload["pq_ciphertext"]),
                server_context=_b64d(server_payload["server_context"]),
                key_material=b"",
            )
            session_key = client_engine.client_finalize(
                server_result,
                client_classical_private_key=client_classical_private,
                client_pq_secret_key=client_pq_secret,
            )
            print("Session key length:", len(session_key))
            profile = await client.post("/api/profile", json={"user_id": "u-123"})
            print("Profile route status:", profile.status_code)
            print("Profile JSON:", profile.json())

    asyncio.run(_demo())
