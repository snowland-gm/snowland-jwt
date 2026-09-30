# snowland-jwt

#### Introduction
A Chinese national cryptography (Guomi) flavored JWT implementation.

#### Software Architecture
Built on the `jwt.algorithms.Algorithm` extension point of
[PyJWT](https://pypi.org/project/PyJWT/), it implements asymmetric signing with
SM2 (GB/T 0003, full `ZA||M` pre-hashing, interoperable with standard Guomi
toolchains) and symmetric signing with HMAC-SM3, thereby replacing the
RSA/ECDSA/HMAC-SHA families to satisfy token issuance and verification needs in
Guomi scenarios.

**The underlying cryptography uses pluggable, optional backends** (the library
does not hard-depend on any single one):
- `pysmx` (distribution name `snowland-smx`): a class-based SM2 API whose
  signatures use the raw `r || s` encoding;
- `gmssl-pyx`: a GmSSL binding whose signatures use ASN.1 DER `rs` encoding.

Both implement the same GB/T 0003 `ZA||M` pre-hash (default signer ID
`1234567812345678`), so with the same `IDA` and the same backend they are
interoperable. Note that the two backends produce **different signature byte
encodings** (raw vs DER), so a token can only be verified by the same backend
that produced it; HMAC-SM3, however, is computed from the standard SM3 digest
and is backend-independent and interoperable across backends.

The output is still a standard JWT (`header.payload.signature`) — only the
`alg` value is a Guomi algorithm name, so it remains compatible with existing
JWT toolchains.

Supported algorithms:

| alg name | Type | Replaces |
|----------|------|----------|
| `SM2` | Asymmetric (SM2 + SM3 signature, full `ZA||M` pre-hash) | ES256 / RS256 |
| `HS256-SM3` | Symmetric (HMAC + SM3) | HS256 |

#### Installation

The base dependencies are only `pyjwt` and `cryptography`; the Guomi backend is
optional — install whichever one you need:

```bash
# Use the snowland-smx (pysmx) backend
pip install "snowland-jwt[smx]"      # snowland-smx>=1.1.0

# Or use the gmssl-pyx backend
pip install "snowland-jwt[gmssl]"    # gmssl-pyx>=2.1.0
```

Without any backend installed, the library imports fine, but the first
sign/verify call raises `BackendNotAvailable`, prompting you to install one of
the backends above. When no backend is specified, one is auto-selected in the
order `gmssl-pyx` → `pysmx`.

#### Usage

```python
import snowland_jwt as jwt

# Generate an SM2 key pair (private key 32 bytes / 64 hex chars,
# public key 64 bytes / 128 hex chars)
private_key, public_key = jwt.generate_key()

# Sign (default algorithm is SM2)
token = jwt.encode({"sub": "user-001"}, private_key, algorithm=jwt.SM2)

# Verify
payload = jwt.decode(token, public_key, algorithms=[jwt.SM2])
```

Symmetric algorithm example:

```python
secret = "guomi-shared-secret-key-0123456789abcdef"
token = jwt.encode({"iss": "snowland"}, secret, algorithm=jwt.HS256_SM3)
payload = jwt.decode(token, secret, algorithms=[jwt.HS256_SM3])
```

Selecting a backend (when both parties agree on a backend, or on a non-default
`IDA`):

```python
# Explicitly bind the gmssl-pyx backend with the default IDA
jwt.register_sm2(jwt.DEFAULT_SM2_UID, backend="gmssl_pyx")

# Agree on a custom IDA (both parties must match; the IDA itself is not stored
# in the token)
jwt.register_sm2(b"custom-ida-2026", alg_name="SM2-MY", backend="gmssl_pyx")
```

Key format notes (`SM2`):
- Raw `bytes`: a 32-byte private key (the public point `d·G` is derived
  automatically on the SM2 curve), or a 64-byte (`x||y`) / 65-byte
  (`0x04||x||y`) public key;
- Hex string: hexadecimal of the same lengths as above;
- PEM (`-----BEGIN ...`): parsed via `cryptography`;
- JWK (`dict` / JSON, `kty=EC`, `crv=SM2`).

After importing this library, the standard `import jwt; jwt.encode(...,
algorithm="SM2")` also works (it is registered into the global algorithm table).

#### API Documentation

##### v0.1
See [API.md](docs/api/v0_1_0/API.en.md) for the full function-level reference (parameters, return
values, exceptions).
