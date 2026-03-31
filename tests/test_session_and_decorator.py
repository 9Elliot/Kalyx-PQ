import pytest

from kalyxpq.decorators import decrypt_result, kalyx_safe
from kalyxpq.engine import KalyxEngine, MockKemAdapter
from kalyxpq.session import MAGIC_HEADER, KalyxSession


def test_session_encrypt_decrypt_roundtrip():
    engine = KalyxEngine(kem_adapter=MockKemAdapter(), strict_pq=False)
    client = KalyxSession(engine=engine)
    artifacts, cpriv, cpq = client.begin_client_handshake()
    response = engine.server_respond(artifacts)
    client.accept_server_handshake(response, cpriv, cpq)
    msg = client.encrypt_json({"msg": "hello", "n": 1})
    assert msg.ciphertext.startswith(MAGIC_HEADER)
    dec = client.decrypt_json(msg)
    assert dec == {"msg": "hello", "n": 1}


def test_kalyx_safe_encrypts_return_value():
    key = b"\x01" * 32

    @kalyx_safe(key_provider=lambda: key)
    def sensitive() -> dict[str, str]:
        return {"token": "secret"}

    encrypted = sensitive()
    recovered = decrypt_result(encrypted, key)
    assert recovered == {"token": "secret"}


def test_session_supports_msgpack_serializer():
    pytest.importorskip("msgpack")

    engine = KalyxEngine(kem_adapter=MockKemAdapter(), strict_pq=False)
    session = KalyxSession(engine=engine)
    artifacts, cpriv, cpq = session.begin_client_handshake()
    response = engine.server_respond(artifacts)
    session.accept_server_handshake(response, cpriv, cpq)

    payload = {"msg": "hello", "nums": [1, 2, 3]}
    sealed = session.encrypt_payload(payload, serializer="msgpack")
    assert sealed.ciphertext.startswith(MAGIC_HEADER)
    recovered = session.decrypt_payload(sealed)
    assert recovered == payload
