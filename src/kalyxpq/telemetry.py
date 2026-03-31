"""Telemetry primitives for handshake performance and overhead tracking."""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass(slots=True)
class HandshakeTelemetry:
    """Single hybrid handshake measurement sample."""

    timestamp_utc: str
    kem_algorithm: str
    duration_ms: float
    client_artifact_bytes: int
    server_response_bytes: int
    classical_component_bytes: int
    pq_component_bytes: int

    @property
    def total_overhead_bytes(self) -> int:
        return self.client_artifact_bytes + self.server_response_bytes


@dataclass(slots=True)
class TelemetryCollector:
    """In-memory collector that can feed research docs and benchmarks."""

    samples: list[HandshakeTelemetry] = field(default_factory=list)

    def record(self, sample: HandshakeTelemetry) -> None:
        self.samples.append(sample)

    def latest(self) -> HandshakeTelemetry | None:
        if not self.samples:
            return None
        return self.samples[-1]

    def to_markdown_rows(self) -> str:
        """Render samples as markdown table rows for README_RESEARCH.md."""
        rows: list[str] = []
        for sample in self.samples:
            rows.append(
                "| {ts} | {alg} | {lat:.3f} | {co} | {so} | {tot} |".format(
                    ts=sample.timestamp_utc,
                    alg=sample.kem_algorithm,
                    lat=sample.duration_ms,
                    co=sample.client_artifact_bytes,
                    so=sample.server_response_bytes,
                    tot=sample.total_overhead_bytes,
                )
            )
        return "\n".join(rows)

    def save_to_csv(self, path: str) -> None:
        """Persist collected telemetry samples to a CSV file."""
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", newline="", encoding="utf-8") as file_obj:
            writer = csv.writer(file_obj)
            writer.writerow(
                [
                    "timestamp_utc",
                    "kem_algorithm",
                    "duration_ms",
                    "client_artifact_bytes",
                    "server_response_bytes",
                    "classical_component_bytes",
                    "pq_component_bytes",
                    "total_overhead_bytes",
                ]
            )
            for sample in self.samples:
                writer.writerow(
                    [
                        sample.timestamp_utc,
                        sample.kem_algorithm,
                        f"{sample.duration_ms:.6f}",
                        sample.client_artifact_bytes,
                        sample.server_response_bytes,
                        sample.classical_component_bytes,
                        sample.pq_component_bytes,
                        sample.total_overhead_bytes,
                    ]
                )


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
