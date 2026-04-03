"""Decoupled cryptographic engine for hybrid classical+PQC exchange."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_256
from secrets import token_bytes
from time import perf_counter
from typing import Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .exceptions import DependencyUnavailableError, InvalidHandshakeError, KalyxSecurityError
from .telemetry import HandshakeTelemetry, TelemetryCollector, utc_now_iso


class KEMAdapter(Protocol):
    """Adapter contract to decouple ML-KEM implementation details."""

    algorithm: str

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Return (public_key, secret_key)."""

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Return (ciphertext, shared_secret)."""

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """Return shared_secret."""


class OqsKemAdapter:
    """ML-KEM adapter powered by liboqs-python."""

    def __init__(self, algorithm: str = "ML-KEM-768") -> None:
        self.algorithm = algorithm
        try:
            import oqs  # type: ignore # pylint: disable=import-error
        except Exception as exc:  # pragma: no cover - runtime dependency
            raise DependencyUnavailableError(
                "liboqs-python is required for ML-KEM operations."
            ) from exc
        if not hasattr(oqs, "KeyEncapsulation"):
            raise DependencyUnavailableError(
                "liboqs-python is installed but the native liboqs library did not load "
                "(missing .so/.dll, or failed build). Install liboqs, set OQS_INSTALL_PATH if needed, "
                "or run in the official Docker image for this project."
            )
        self._oqs = oqs

    def generate_keypair(self) -> tuple[bytes, bytes]:
        with self._oqs.KeyEncapsulation(self.algorithm) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            return bytes(public_key), bytes(secret_key)

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        with self._oqs.KeyEncapsulation(self.algorithm) as kem:
            ciphertext, shared_secret = kem.encap_secret(bytes(public_key))
            return bytes(ciphertext), bytes(shared_secret)

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        with self._oqs.KeyEncapsulation(self.algorithm, bytes(secret_key)) as kem:
            return bytes(kem.decap_secret(bytes(ciphertext)))


class MockKemAdapter:
    """Deterministic in-process KEM fallback for local development/testing."""

    algorithm = "MOCK-ML-KEM-768"
    _seed_size = 32

    def generate_keypair(self) -> tuple[bytes, bytes]:
        seed = token_bytes(self._seed_size)
        public_key = b"MKP0" + seed
        secret_key = b"MKS0" + seed
        return public_key, secret_key

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        if not public_key.startswith(b"MKP0"):
            raise InvalidHandshakeError("Invalid mock KEM public key prefix.")
        seed = memoryview(public_key)[4:].tobytes()
        nonce = token_bytes(self._seed_size)
        shared_secret = sha3_256(seed + nonce).digest()
        ciphertext = b"MKC0" + nonce
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        if not ciphertext.startswith(b"MKC0"):
            raise InvalidHandshakeError("Invalid mock KEM ciphertext prefix.")
        if not secret_key.startswith(b"MKS0"):
            raise InvalidHandshakeError("Invalid mock KEM secret key prefix.")
        nonce = memoryview(ciphertext)[4:].tobytes()
        seed = memoryview(secret_key)[4:].tobytes()
        return sha3_256(seed + nonce).digest()


@dataclass(slots=True)
class HandshakeArtifacts:
    """Client handshake artifacts transferable over any transport."""

    client_classical_public_key: bytes
    client_pq_public_key: bytes


@dataclass(slots=True)
class HandshakeResult:
    """Server response and handshake metadata for decoupled transport."""

    server_classical_public_key: bytes
    classical_ciphertext: bytes
    pq_ciphertext: bytes
    server_context: bytes
    key_material: bytes


class KalyxEngine:
    """
    Decoupled cryptographic engine for hybrid key establishment.

    The hybrid handshake combines:
    - Classical X25519 ECDH (for broad interoperability)
    - ML-KEM (Kyber family, NIST FIPS 203 standard track)

    A session key is derived from both secrets so that confidentiality remains
    if either layer withstands future cryptanalysis.

    By default the engine uses **liboqs** (``pip install 'kalyxpq[oqs]'``) and does **not**
    fall back to a placeholder KEM. For unit tests only, pass ``allow_mock_kem=True`` or
    ``kem_adapter=MockKemAdapter()``.
    """

    def __init__(
        self,
        kem_adapter: KEMAdapter | None = None,
        *,
        key_length: int = 32,
        strict_pq: bool = True,
        allow_mock_kem: bool = False,
        telemetry: TelemetryCollector | None = None,
    ):
        if kem_adapter is not None:
            self._kem = kem_adapter
        else:
            try:
                self._kem = OqsKemAdapter(algorithm="ML-KEM-768")
            except DependencyUnavailableError:
                if not allow_mock_kem:
                    raise
                self._kem = MockKemAdapter()
        self._key_length = key_length
        self._strict_pq = strict_pq
        self._telemetry = telemetry or TelemetryCollector()

    @property
    def kem_algorithm(self) -> str:
        return self._kem.algorithm

    @property
    def telemetry(self) -> TelemetryCollector:
        return self._telemetry

    @property
    def strict_pq(self) -> bool:
        return self._strict_pq

    def client_prepare(self) -> tuple[HandshakeArtifacts, bytes, bytes]:
        """
        Create client public artifacts plus private state.

        Returns (artifacts, classical_private_key_bytes, pq_secret_key).
        """
        client_private = x25519.X25519PrivateKey.generate()
        client_public = client_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        pq_public, pq_secret = self._kem.generate_keypair()
        self._ensure_pq_component("client_prepare", pq_public, pq_secret)
        private_bytes = client_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return (
            HandshakeArtifacts(
                client_classical_public_key=bytes(client_public),
                client_pq_public_key=bytes(pq_public),
            ),
            bytes(private_bytes),
            bytes(pq_secret),
        )

    def server_respond(self, artifacts: HandshakeArtifacts) -> HandshakeResult:
        """Produce server response and server-side derived session key."""
        started = perf_counter()
        self._ensure_pq_component(
            "server_respond",
            artifacts.client_pq_public_key,
        )
        client_pub = x25519.X25519PublicKey.from_public_bytes(
            bytes(artifacts.client_classical_public_key)
        )
        server_private = x25519.X25519PrivateKey.generate()
        server_public = server_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        classical_secret = server_private.exchange(client_pub)
        pq_ciphertext, pq_secret = self._kem.encapsulate(
            bytes(artifacts.client_pq_public_key)
        )
        self._ensure_pq_component("server_respond", pq_ciphertext, pq_secret)

        # Preserve compact, copy-efficient handling of input bytes.
        classical_mv = memoryview(classical_secret)
        pq_mv = memoryview(pq_secret)
        session_key = self._derive_hybrid_key(classical_mv, pq_mv)
        context = sha3_256(server_public + pq_ciphertext).digest()
        result = HandshakeResult(
            server_classical_public_key=bytes(server_public),
            classical_ciphertext=bytes(server_public),
            pq_ciphertext=bytes(pq_ciphertext),
            server_context=bytes(context),
            key_material=session_key,
        )
        duration_ms = (perf_counter() - started) * 1000.0
        self._telemetry.record(
            HandshakeTelemetry(
                timestamp_utc=utc_now_iso(),
                kem_algorithm=self.kem_algorithm,
                duration_ms=duration_ms,
                client_artifact_bytes=self._artifact_size(artifacts),
                server_response_bytes=self._response_size(result),
                classical_component_bytes=len(result.server_classical_public_key),
                pq_component_bytes=len(result.pq_ciphertext),
            )
        )
        return result

    def client_finalize(
        self,
        response: HandshakeResult,
        client_classical_private_key: bytes,
        client_pq_secret_key: bytes,
    ) -> bytes:
        """Derive the same hybrid session key on the client."""
        client_private = x25519.X25519PrivateKey.from_private_bytes(
            bytes(client_classical_private_key)
        )
        server_pub = x25519.X25519PublicKey.from_public_bytes(
            bytes(response.server_classical_public_key)
        )
        classical_secret = client_private.exchange(server_pub)
        pq_secret = self._kem.decapsulate(
            bytes(response.pq_ciphertext),
            bytes(client_pq_secret_key),
        )
        self._ensure_pq_component(
            "client_finalize",
            response.pq_ciphertext,
            client_pq_secret_key,
            pq_secret,
        )
        return self._derive_hybrid_key(memoryview(classical_secret), memoryview(pq_secret))

    def _derive_hybrid_key(
        self, classical_secret: memoryview, pq_secret: memoryview
    ) -> bytes:
        if not classical_secret or not pq_secret:
            raise InvalidHandshakeError("Hybrid key derivation requires both secrets.")
        ikm = classical_secret.tobytes() + pq_secret.tobytes()
        hkdf = HKDF(
            algorithm=hashes.SHA3_256(),
            length=self._key_length,
            salt=None,
            info=b"KALYX-PQ-HYBRID-HANDSHAKE-v1",
        )
        return bytes(hkdf.derive(ikm))

    @staticmethod
    def _artifact_size(artifacts: HandshakeArtifacts) -> int:
        return len(artifacts.client_classical_public_key) + len(artifacts.client_pq_public_key)

    @staticmethod
    def _response_size(response: HandshakeResult) -> int:
        return (
            len(response.server_classical_public_key)
            + len(response.classical_ciphertext)
            + len(response.pq_ciphertext)
            + len(response.server_context)
        )

    def _ensure_pq_component(self, stage: str, *components: bytes) -> None:
        if not self._strict_pq:
            return
        if self.kem_algorithm.startswith("MOCK-"):
            raise KalyxSecurityError(
                "strict_pq is enabled but a mock KEM adapter is active; "
                "configure liboqs-backed ML-KEM for strict mode."
            )
        if not components or any(len(c) == 0 for c in components):
            raise KalyxSecurityError(
                f"strict_pq is enabled and the {stage} step is missing a valid PQC component."
            )
