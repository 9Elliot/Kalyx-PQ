"""Decorator helpers for sensitive function outputs."""

from __future__ import annotations

import functools
import json
import os
from dataclasses import dataclass
from typing import Any, Callable, ParamSpec, TypeVar

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

P = ParamSpec("P")
T = TypeVar("T")


@dataclass(slots=True)
class EncryptedResult:
    """Structured encrypted output payload."""

    nonce: bytes
    ciphertext: bytes


def kalyx_safe(key_provider: Callable[[], bytes]) -> Callable[[Callable[P, T]], Callable[P, EncryptedResult]]:
    """
    Encrypt a function's return value with an app-managed symmetric key.

    The wrapped function may return any JSON-serializable object.
    """

    def decorator(func: Callable[P, T]) -> Callable[P, EncryptedResult]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> EncryptedResult:
            result = func(*args, **kwargs)
            key = key_provider()
            nonce = os.urandom(12)
            plaintext = json.dumps(result).encode("utf-8")
            ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
            return EncryptedResult(nonce=nonce, ciphertext=ciphertext)

        return wrapper

    return decorator


def decrypt_result(encrypted: EncryptedResult, key: bytes) -> Any:
    """Decrypt the output produced by @kalyx_safe."""
    plaintext = AESGCM(key).decrypt(encrypted.nonce, encrypted.ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))
