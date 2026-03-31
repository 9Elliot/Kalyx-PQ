"""Local client/server simulation for a decoupled hybrid handshake."""

from __future__ import annotations

from kalyxpq.engine import KalyxEngine, MockKemAdapter


def main() -> None:
    engine = KalyxEngine(kem_adapter=MockKemAdapter(), strict_pq=False)

    # Client phase (could be sent over HTTP/WebSocket/TCP).
    artifacts, client_classical_private, client_pq_secret = engine.client_prepare()

    # Server phase.
    server_response = engine.server_respond(artifacts)

    # Client finalize phase.
    client_session_key = engine.client_finalize(
        response=server_response,
        client_classical_private_key=client_classical_private,
        client_pq_secret_key=client_pq_secret,
    )

    print("KEM algorithm:", engine.kem_algorithm)
    print("Client and Server keys match:", client_session_key == server_response.key_material)
    print("Session key length:", len(client_session_key))


if __name__ == "__main__":
    main()
