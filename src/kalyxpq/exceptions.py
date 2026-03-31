"""Domain-specific exceptions for Kalyx-PQ."""


class KalyxError(Exception):
    """Base error raised by the Kalyx-PQ library."""


class DependencyUnavailableError(KalyxError):
    """Raised when an optional crypto dependency is not available."""


class InvalidHandshakeError(KalyxError):
    """Raised when handshake artifacts are malformed or invalid."""


class KalyxSecurityError(KalyxError):
    """Raised when strict security policy requirements are not met."""
