import pytest

from kalyxpq.engine import KalyxEngine, MockKemAdapter
from kalyxpq.exceptions import DependencyUnavailableError, KalyxSecurityError


def test_hybrid_handshake_derives_same_key():
    engine = KalyxEngine(kem_adapter=MockKemAdapter(), strict_pq=False)
    artifacts, client_classical_private, client_pq_secret = engine.client_prepare()
    server_result = engine.server_respond(artifacts)
    client_key = engine.client_finalize(
        server_result,
        client_classical_private_key=client_classical_private,
        client_pq_secret_key=client_pq_secret,
    )
    assert client_key == server_result.key_material
    assert len(client_key) == 32


def test_engine_collects_handshake_telemetry():
    engine = KalyxEngine(kem_adapter=MockKemAdapter(), strict_pq=False)
    artifacts, _, _ = engine.client_prepare()
    engine.server_respond(artifacts)
    sample = engine.telemetry.latest()
    assert sample is not None
    assert sample.duration_ms >= 0.0
    assert sample.client_artifact_bytes > 0
    assert sample.server_response_bytes > 0
    assert sample.total_overhead_bytes == (
        sample.client_artifact_bytes + sample.server_response_bytes
    )


def test_strict_pq_rejects_mock_kem_usage():
    engine = KalyxEngine(kem_adapter=MockKemAdapter(), strict_pq=True)
    with pytest.raises(KalyxSecurityError):
        engine.client_prepare()


def test_default_engine_propagates_when_oqs_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(*_a: object, **_kw: object) -> None:
        raise DependencyUnavailableError("no liboqs in test")

    monkeypatch.setattr("kalyxpq.engine.OqsKemAdapter", _raise)
    with pytest.raises(DependencyUnavailableError):
        KalyxEngine(allow_mock_kem=False)


def test_allow_mock_kem_true_falls_back_when_oqs_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(*_a: object, **_kw: object) -> None:
        raise DependencyUnavailableError("no liboqs in test")

    monkeypatch.setattr("kalyxpq.engine.OqsKemAdapter", _raise)
    engine = KalyxEngine(allow_mock_kem=True, strict_pq=False)
    assert engine.kem_algorithm.startswith("MOCK")
