import base64

import httpx
import pytest

from kalyxpq.engine import HandshakeArtifacts, KalyxEngine, MockKemAdapter
from kalyxpq.http_transport import HTTPHandshakeTransport


def _b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


@pytest.mark.asyncio
async def test_http_handshake_transport_roundtrip():
    engine = KalyxEngine(kem_adapter=MockKemAdapter(), strict_pq=False)
    artifacts, client_classical_private, client_pq_secret = engine.client_prepare()

    def handler(request: httpx.Request) -> httpx.Response:
        body = request.read().decode("utf-8")
        req = __import__("json").loads(body)
        server_result = engine.server_respond(
            HandshakeArtifacts(
                client_classical_public_key=base64.b64decode(req["client_classical_public_key"]),
                client_pq_public_key=base64.b64decode(req["client_pq_public_key"]),
            )
        )
        payload = {
            "server_classical_public_key": _b64e(server_result.server_classical_public_key),
            "classical_ciphertext": _b64e(server_result.classical_ciphertext),
            "pq_ciphertext": _b64e(server_result.pq_ciphertext),
            "server_context": _b64e(server_result.server_context),
        }
        return httpx.Response(200, json=payload)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, base_url="https://example.test") as client:
        handshake_transport = HTTPHandshakeTransport(
            endpoint="/kalyx/handshake",
            client=client,
        )
        response = await handshake_transport.send_client_artifacts(artifacts)
        client_key = engine.client_finalize(
            response=response,
            client_classical_private_key=client_classical_private,
            client_pq_secret_key=client_pq_secret,
        )
        assert len(client_key) == 32
