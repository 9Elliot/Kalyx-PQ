from pathlib import Path

from kalyxpq.engine import KalyxEngine, MockKemAdapter


def test_telemetry_can_save_to_csv(tmp_path: Path):
    engine = KalyxEngine(kem_adapter=MockKemAdapter(), strict_pq=False)
    artifacts, _, _ = engine.client_prepare()
    engine.server_respond(artifacts)

    out_file = tmp_path / "telemetry" / "samples.csv"
    engine.telemetry.save_to_csv(str(out_file))

    assert out_file.exists()
    text = out_file.read_text(encoding="utf-8")
    assert "timestamp_utc,kem_algorithm,duration_ms" in text
