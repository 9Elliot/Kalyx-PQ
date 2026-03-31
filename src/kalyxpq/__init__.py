"""Kalyx-PQ public package API."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from .decorators import EncryptedResult, decrypt_result, kalyx_safe
from .engine import HandshakeArtifacts, HandshakeResult, KalyxEngine
from .exceptions import KalyxSecurityError
from .http_transport import HTTPHandshakeTransport
from .session import KalyxSession, MAGIC_HEADER
from .telemetry import HandshakeTelemetry, TelemetryCollector
from .transport import HandshakeTransport

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _resolve_version() -> str:
    """Version from installed package metadata (matches Git tag at build time)."""
    try:
        return version("kalyxpq")
    except PackageNotFoundError:
        pass
    # Editable / source checkout without metadata: derive from Git via setuptools-scm (dev extra).
    try:
        from setuptools_scm import get_version  # type: ignore # pylint: disable=import-error

        return get_version(root=str(_REPO_ROOT))
    except Exception:
        return "0.0.0.dev0+unknown"


__version__ = _resolve_version()

__all__ = [
    "__version__",
    "HandshakeArtifacts",
    "HandshakeTransport",
    "HandshakeResult",
    "HandshakeTelemetry",
    "TelemetryCollector",
    "HTTPHandshakeTransport",
    "KalyxSecurityError",
    "MAGIC_HEADER",
    "KalyxEngine",
    "KalyxSession",
    "EncryptedResult",
    "decrypt_result",
    "kalyx_safe",
]
