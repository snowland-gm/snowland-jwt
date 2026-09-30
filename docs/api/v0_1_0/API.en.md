# snowland-jwt API Reference

> 中文版：[API.md](API.md)

This document describes every public function of `snowland_jwt` with its
**parameters, return values, behavior, and exceptions**.

Conventions:
- The `key` argument accepts several forms: raw `bytes`, hex `str`, PEM text
  (`-----BEGIN ...`), JWK (`dict` or JSON `str` with `kty=EC`, `crv=SM2`), or a
  backend-native key object.
- All cryptography is delegated to a **pluggable backend** (`pysmx` /
  `gmssl_pyx`). Backends are optional dependencies; the first crypto call raises
  `BackendNotAvailable` if none is installed.
- Algorithm name constants: `SM2` (`"SM2"`), `HS256_SM3` (`"HS256-SM3"`).

---

## 1. Package-level functions (`snowland_jwt`)

### 1.1 `encode(payload, key, algorithm=SM2, headers=None, json_encoder=None, sort_headers=True)`

Create a JWT string.

| Param | Type | Description |
|---|---|---|
| `payload` | `dict` | Claims, serialized to JSON. |
| `key` | `bytes` / `str` / key object | Signing key. Private key for SM2; shared secret for `HS256-SM3`. |
| `algorithm` | `str` | Algorithm name, default `SM2`. Also `HS256_SM3` or any `register_sm2` variant. |
| `headers` | `dict` / `None` | Extra JWT header fields (e.g. `kid`). |
| `json_encoder` | `json.JSONEncoder` / `None` | Custom JSON encoder. |
| `sort_headers` | `bool` | Sort header fields, default `True`. |

- **Returns**: `str` -- the JWT `header.payload.signature`.
- **Raises**: `BackendNotAvailable` (no backend), `InvalidKeyError` (bad key),
  `InvalidAlgorithmError` (algorithm not registered).

---

### 1.2 `decode(token, key, algorithms=None, options=None, **kwargs)`

Verify and decode a JWT, returning the payload.

| Param | Type | Description |
|---|---|---|
| `token` | `str` / `bytes` | JWT string. |
| `key` | varies | Verification key. Public key for SM2; shared secret for `HS256-SM3`. |
| `algorithms` | `list` / `None` | Allowed algorithm names. **Defaults to `[SM2, HS256_SM3]`** when `None`. |
| `options` | `dict` / `None` | Verification options (same as PyJWT: `verify_signature`, `verify_exp`, ...). |
| `**kwargs` | — | Forwarded to PyJWT, e.g. `audience`, `issuer`, `leeway`. |

- **Returns**: `dict` -- the decoded payload.
- **Raises**: `InvalidSignatureError` (bad signature), `ExpiredSignatureError`
  (expired), `InvalidTokenError` (format/validation failure), etc.; also
  `BackendNotAvailable`, `InvalidKeyError`.

---

### 1.3 `decode_complete(token, key, algorithms=None, options=None, **kwargs)`

Same as `decode` but returns the full structure.

- **Params**: same as `decode`.
- **Returns**: `dict` -- `{"header": ..., "payload": ..., "signature": ...}`.
- **Raises**: same as `decode`.

---

### 1.4 `generate_key()`

Generate an SM2 key pair using the default backend.

- **Params**: none.
- **Returns**: `tuple[str, str]` -- `(private_key_hex, public_key_hex)`.
  - Private key: 32 bytes / 64 hex chars.
  - Public key: 64 bytes / 128 hex chars, `x || y`.
- **Raises**: `BackendNotAvailable` (no backend).

---

### 1.5 `register_sm2(uid=DEFAULT_SM2_UID, alg_name=None, backend=None)`

Register an SM2 algorithm variant bound to a specific `IDA` (user identifier)
 and/or backend.

Both parties must agree on the same `IDA`; they interoperate only when `IDA`
and backend match. Different `IDA` values are not mutually verifiable.

| Param | Type | Description |
|---|---|---|
| `uid` | `str` / `bytes` | User identifier `IDA` for the GB/T 0003 `ZA || M` pre-hash. |
| `alg_name` | `str` / `None` | Registered algorithm name. If omitted, auto-derived as `"SM2-" + first 8 hex bytes of uid`, e.g. `"SM2-31323334"`. |
| `backend` | `str` / `None` | Backend name `"pysmx"` / `"gmssl_pyx"`; `None` auto-selects. |

- **Returns**: `str` -- the actual registered algorithm name (for `algorithm=`).
- **Raises**: `BackendNotAvailable` (requested backend not installed).
- **Note**: if `alg_name` is already registered, it is returned without
  re-registering.

---

### 1.6 `register_hmac_sm3(alg_name=HS256_SM3, backend=None)`

Register an HMAC-SM3 variant bound to a specific backend.

| Param | Type | Description |
|---|---|---|
| `alg_name` | `str` | Registered algorithm name, default `"HS256-SM3"`. |
| `backend` | `str` / `None` | Backend name; the SM3 digest comes from the backend `sm3_hash` and is backend-independent, so this is for interface symmetry only. |

- **Returns**: `str` -- the registered algorithm name.
- **Raises**: `BackendNotAvailable` (backend not installed).

---

### 1.7 `get_crypto_backend(name=None)`

Return an initialized crypto backend instance. Provided by
`snowland_jwt.backends`.

| Param | Type | Description |
|---|---|---|
| `name` | `str` / `None` | Backend name. If omitted, the first available backend in `_DEFAULT_PROBE_ORDER` (`("gmssl_pyx", "pysmx")`) is used. |

- **Returns**: a `CryptoBackend` instance (`PysmxBackend` or `GmsslPyxBackend`).
- **Raises**: `BackendNotAvailable` (none available, or `name` unknown/not installed).

---

## 2. Algorithm classes (`snowland_jwt.algorithms`)

### 2.1 `SM2Algorithm(backend=None, uid=DEFAULT_SM2_UID)`

SM2 signature algorithm (GM/T 0003, full `ZA || M` pre-hash).

| Param | Type | Description |
|---|---|---|
| `backend` | `str` / `None` | Backend name or auto-select. |
| `uid` | `str` / `bytes` | User identifier `IDA`, default `b"1234567812345678"`. |

**Methods**

| Method | Params | Returns | Behavior / Raises |
|---|---|---|---|
| `prepare_key(key)` | any key form | `SM2Key` | Normalize to a backend-neutral `SM2Key`. `InvalidKeyError` on unsupported format. |
| `sign(msg, key)` | `msg: bytes`, `key: SM2Key` (with private) | `bytes` | SM2 sign `msg` via backend (with `ZA || M` pre-hash). `InvalidKeyError` if no private key. |
| `verify(msg, key, sig)` | `msg: bytes`, `key: SM2Key` (with public), `sig: bytes` | `bool` | Verify. `InvalidKeyError` if no public key. |
| `to_jwk(key_obj, as_dict=False)` | `SM2Key`, `bool` | `dict` or JSON `str` | Export as `kty=EC, crv=SM2` JWK. `InvalidKeyError` if not `SM2Key`. |
| `from_jwk(jwk)` | `dict`/JSON `str` | `SM2Key` | Import from JWK. `InvalidKeyError` if not `EC/SM2`. |
| `_prepare_raw(key_bytes)` | `bytes` | `SM2Key` | Parse raw bytes: 32-byte private auto-derives public `d·G`; 64-byte or `0x04`+64-byte public. `InvalidKeyError` on bad length. |
| `_prepare_pem(key_bytes)` | `bytes` | `SM2Key` | Parse PEM private/public key. `InvalidKeyError` if unsupported. |
| `_derive_public_point(d)` | `int` (private scalar) | `(x, y)` | Compute `d·G` on the SM2 curve (standard point multiplication, backend-agnostic). |
| `_crypto()` | none | `CryptoBackend` | Lazily obtain the backend instance. |

### 2.2 `HMACSM3Algorithm(backend=None)`

HMAC-SM3 symmetric algorithm (RFC 2104, hash = standard SM3).

| Param | Type | Description |
|---|---|---|
| `backend` | `str` / `None` | Backend name; SM3 comes from the backend `sm3_hash` and is backend-independent. |

**Methods**

| Method | Params | Returns | Behavior / Raises |
|---|---|---|---|
| `prepare_key(key)` | any | `bytes` | Normalize to byte key; `dict` routed through `from_jwk`. |
| `sign(msg, key)` | `msg: bytes`, `key: bytes` | `bytes` | Compute HMAC-SM3 signature. |
| `verify(msg, key, sig)` | same as `sign` + `sig` | `bool` | Constant-time verify. |
| `to_jwk(key_obj, as_dict=False)` | `bytes`/`str`, `bool` | `dict`/JSON `str` | Export as `kty=oct` JWK. |
| `from_jwk(jwk)` | `dict`/JSON `str` | `bytes` | Import shared secret from JWK. `InvalidKeyError` if not `oct`. |
| `_hmac_sm3(key, data, hash_func)` | `key: bytes`, `data: bytes`, `hash_func` | `bytes` | Standard RFC 2104 HMAC (block size 64). |
| `_crypto()` | none | `CryptoBackend` | Lazily obtain the backend instance. |

### 2.3 `SM2Key` (`dataclass`)

Backend-neutral SM2 key container.

| Field | Type | Description |
|---|---|---|
| `public_key` | `bytes` | 64-byte public point `x || y` (required). |
| `private_key` | `Optional[bytes]` | 32-byte private scalar `d` (present only for private keys). |

---

## 3. Backend classes (`snowland_jwt.backends`)

### 3.1 `CryptoBackend` (abstract base)

Common interface implemented by all backends; keys are always raw bytes
(private 32 bytes, public 64 bytes).

| Method | Params | Returns | Behavior |
|---|---|---|---|
| `sm3_hash(data)` | `bytes` | `bytes` | Standard SM3 digest (32 bytes). |
| `sm2_generate_keypair()` | none | `(priv: bytes, pub: bytes)` | Generate an SM2 key pair. |
| `sm2_sign(msg, private_key, public_key, uid)` | `bytes` ×3 + `uid` | `bytes` | SM2 sign (with `ZA || M`). |
| `sm2_verify(msg, signature, public_key, uid)` | `bytes` ×3 + `uid` | `bool` | SM2 verify. |

### 3.2 `PysmxBackend` / `GmsslPyxBackend`

The two concrete `CryptoBackend` implementations.

- `PysmxBackend` (`name="pysmx"`): built on `snowland-smx` (pysmx). Class-based
  SM2 API, raw `r || s` signature encoding; SM3 from `pysmx.crypto.hashlib`.
- `GmsslPyxBackend` (`name="gmssl_pyx"`): built on `gmssl-pyx`. ASN.1 DER `rs`
  signature encoding; SM3 from `gmssl_pyx.sm3_hash`.
- The two SM2 backends emit **different signature encodings**, so a token is
  verifiable only by the backend that produced it; HMAC-SM3 is backend-independent
  because SM3 is a fixed standard digest.

### 3.3 `BackendNotAvailable` (exception)

Subclass of `jwt.exceptions.InvalidKeyError`, raised by `get_crypto_backend`
when no backend is available (or the requested one is not installed).

---

## 4. Constants

| Name | Value | Description |
|---|---|---|
| `SM2` | `"SM2"` | SM2 algorithm name. |
| `HS256_SM3` | `"HS256-SM3"` | HMAC-SM3 algorithm name. |
| `DEFAULT_SM2_UID` | `b"1234567812345678"` | GB/T 0003 example `IDA`, the default user identifier for SM2 pre-hashing. |
| `__version__` | `"0.1.0"` | Package version. |

---

## 5. Exceptions

All exceptions are re-exported from `jwt.exceptions` and can be imported
directly, e.g. `from snowland_jwt import InvalidSignatureError`:
`DecodeError`, `ExpiredSignatureError`, `ImmatureSignatureError`,
`InvalidAudienceError`, `InvalidIssuedAtError`, `InvalidIssuerError`,
`InvalidKeyError`, `InvalidSignatureError`, `InvalidTokenError`,
`InvalidAlgorithmError`, `MissingRequiredClaimError`, `PyJWKError`,
`PyJWKSetError`, `InvalidSubjectError`, `InvalidJTIError`, plus the library-specific
`BackendNotAvailable`.
