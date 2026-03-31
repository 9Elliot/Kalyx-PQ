"""Session wrapper inspired by requests.Session semantics."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Literal

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .engine import HandshakeArtifacts, HandshakeResult, KalyxEngine

MAGIC_HEADER = b"\x4B\x41\x4C\x58"  # 0x4B414C58 ("KALX")


@dataclass(slots=True)
class SealedMessage:
    """Transport-neutral encrypted payload."""

    nonce: bytes
    ciphertext: bytes
    aad: bytes = b""
    serializer: Literal["json", "msgpack"] = "json"


class KalyxSession:
    """Developer-facing session abstraction for transparent protection."""

    def __init__(self, engine: KalyxEngine | None = None):
        self.engine = engine or KalyxEngine()
        self._session_key: bytes | None = None

    def begin_client_handshake(self) -> tuple[HandshakeArtifacts, bytes, bytes]:
        return self.engine.client_prepare()

    def accept_server_handshake(
        self,
        response: HandshakeResult,
        client_classical_private_key: bytes,
        client_pq_secret_key: bytes,
    ) -> bytes:
        self._session_key = self.engine.client_finalize(
            response=response,
            client_classical_private_key=client_classical_private_key,
            client_pq_secret_key=client_pq_secret_key,
        )
        return self._session_key

    def encrypt_json(self, payload: dict[str, Any]) -> SealedMessage:
        return self.encrypt_payload(payload, serializer="json")

    def decrypt_json(self, message: SealedMessage) -> dict[str, Any]:
        decrypted = self.decrypt_payload(message)
        if not isinstance(decrypted, dict):
            raise TypeError("Expected dict payload for decrypt_json.")
        return decrypted

    def encrypt_payload(
        self, payload: Any, *, serializer: Literal["json", "msgpack"] = "json"
    ) -> SealedMessage:
        key = self._require_key()
        nonce = os.urandom(12)
        plaintext = self._serialize(payload, serializer)
        aad = serializer.encode("ascii")
        ciphertext = MAGIC_HEADER + AESGCM(key).encrypt(nonce, plaintext, aad)
        return SealedMessage(
            nonce=nonce,
            ciphertext=ciphertext,
            aad=aad,
            serializer=serializer,
        )

    def decrypt_payload(self, message: SealedMessage) -> Any:
        key = self._require_key()
        aad = message.aad or message.serializer.encode("ascii")
        if not message.ciphertext.startswith(MAGIC_HEADER):
            raise RuntimeError("Invalid message header: expected KALX protocol magic.")
        payload = memoryview(message.ciphertext)[len(MAGIC_HEADER) :].tobytes()
        plaintext = AESGCM(key).decrypt(message.nonce, payload, aad)
        return self._deserialize(plaintext, message.serializer)

    def _require_key(self) -> bytes:
        if self._session_key is None:
            raise RuntimeError("Session key not established. Run handshake first.")
        return self._session_key

    @staticmethod
    def _serialize(payload: Any, serializer: Literal["json", "msgpack"]) -> bytes:
        if serializer == "json":
            return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if serializer == "msgpack":
            try:
                import msgpack  # type: ignore # pylint: disable=import-error
            except Exception as exc:
                raise RuntimeError(
                    "MessagePack serializer requested but dependency is missing. "
                    "Install with: pip install kalyxpq[msgpack]"
                ) from exc
            return msgpack.packb(payload, use_bin_type=True)
        raise ValueError(f"Unsupported serializer: {serializer}")

    @staticmethod
    def _deserialize(raw: bytes, serializer: Literal["json", "msgpack"]) -> Any:
        if serializer == "json":
            return json.loads(raw.decode("utf-8"))
        if serializer == "msgpack":
            try:
                import msgpack  # type: ignore # pylint: disable=import-error
            except Exception as exc:
                raise RuntimeError(
                    "Cannot decode MessagePack payload because msgpack is not installed."
                ) from exc
            return msgpack.unpackb(raw, raw=False)
        raise ValueError(f"Unsupported serializer: {serializer}")
