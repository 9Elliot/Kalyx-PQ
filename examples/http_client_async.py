"""Async client demo for HTTPHandshakeTransport using mock server."""

from __future__ import annotations

import asyncio

import httpx

from kalyxpq import HTTPHandshakeTransport, KalyxEngine
from kalyxpq.engine import MockKemAdapter

from examples.http_server_mock import build_mock_transport


async def main() -> None:
    engine = KalyxEngine(kem_adapter=MockKemAdapter(), strict_pq=False)
    artifacts, client_classical_private, client_pq_secret = engine.client_prepare()

    transport = build_mock_transport()
    async with httpx.AsyncClient(
        transport=transport,
        base_url="https://mock.kalyx",
    ) as client:
        handshake_transport = HTTPHandshakeTransport(
            endpoint="/kalyx/handshake",
            client=client,
        )
        response = await handshake_transport.send_client_artifacts(artifacts)
        session_key = engine.client_finalize(
            response=response,
            client_classical_private_key=client_classical_private,
            client_pq_secret_key=client_pq_secret,
        )

        profile_resp = await client.post("/api/profile", json={"user_id": "u-999"})
        profile_resp.raise_for_status()
        print("Handshake complete. Session key bytes:", len(session_key))
        print("Profile API payload:", profile_resp.json())


if __name__ == "__main__":
    asyncio.run(main())
