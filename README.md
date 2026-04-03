# Kalyx-PQ

Kalyx-PQ is a developer-friendly Python library that wraps hybrid post-quantum cryptography into a simple Session + Decorator model.

It is designed for the **Harvest Now, Decrypt Later (HNDL)** threat model: an attacker can steal encrypted traffic today and wait for future cryptanalytic or quantum advances to decrypt it later.  
Kalyx-PQ mitigates this by combining **classical X25519** and **ML-KEM (Kyber family)** in every handshake.

## Quick Start

`KalyxEngine()` uses **real ML-KEM** via [liboqs](https://github.com/open-quantum-safe/liboqs) (install the optional `oqs` extra and ensure native `liboqs` is on the loader path, e.g. set `OQS_INSTALL_PATH`).

```python
from kalyxpq import KalyxEngine
e = KalyxEngine()  # strict_pq=True by default; requires liboqs + liboqs-python
artifacts, classical_priv, pq_secret = e.client_prepare()
```

For **unit tests** without liboqs, use `KalyxEngine(kem_adapter=MockKemAdapter(), strict_pq=False)` or `KalyxEngine(allow_mock_kem=True, strict_pq=False)` (never rely on silent mock in production).

## Installation

```bash
pip install kalyxpq
```

For MessagePack payload serialization:

```bash
pip install "kalyxpq[msgpack]"
```

For **production** hybrid PQ (recommended):

```bash
pip install "kalyxpq[oqs]"
```

On **Windows**, building or loading liboqs locally is often painful; use **WSL2**, a **Linux CI image**, or **Docker** for development and integration tests so `liboqs` is available in a predictable path.

For development:

```bash
pip install -e ".[dev,oqs]"
pytest
```

## Why Hybrid?

- `X25519` gives immediate interoperability and mature deployment confidence.
- `ML-KEM` (NIST FIPS 203 track) adds post-quantum resistance.
- The derived session key combines both secrets, so confidentiality holds if either component remains secure.

## Core Concepts

- `KalyxEngine`: transport-agnostic hybrid handshake primitives.
- `KalyxSession`: simple encrypted payload flow similar to `requests.Session`.
- `@kalyx_safe`: function-level return-value encryption for sensitive outputs.
- `HTTPHandshakeTransport`: async `httpx` transport adapter for remote handshake exchange.

## Async HTTP Handshake Transport

```python
from kalyxpq import HTTPHandshakeTransport, KalyxEngine

engine = KalyxEngine()
transport = HTTPHandshakeTransport(endpoint="https://api.example.com/kalyx/handshake")
artifacts, cpriv, cpq = engine.client_prepare()
response = await transport.send_client_artifacts(artifacts)
session_key = engine.client_finalize(response, cpriv, cpq)
```

## AES-GCM with Optional MessagePack

`KalyxSession.encrypt_payload(..., serializer="msgpack")` allows compact binary encoding before encryption.

```python
sealed = session.encrypt_payload({"token": "abc", "roles": ["admin"]}, serializer="msgpack")
plain = session.decrypt_payload(sealed)
```

## Local Example

Run:

```bash
python examples/local_hybrid_simulation.py
```

This simulates a full client/server hybrid handshake without coupling to HTTP or any specific transport.

For async transport mock examples:

```bash
python examples/http_client_async.py
```