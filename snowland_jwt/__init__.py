# -*- coding: utf-8 -*-
"""snowland-jwt: a national-cryptography (guomi) JWT implementation.

It is built on top of PyJWT and a pluggable national-cryptography backend
(``snowland-smx`` / ``pysmx`` or ``gmssl-pyx``), replacing the usual
RSA/ECDSA/HMAC-SHA families with SM2 / SM3 so that JWT tokens can be issued and
verified in GM/T compliant scenarios.

Typical usage::

    import snowland_jwt as jwt

    private_key, public_key = jwt.generate_key()
    token = jwt.encode({"sub": "123"}, private_key, algorithm=jwt.SM2)
    payload = jwt.decode(token, public_key, algorithms=[jwt.SM2])

Backend selection (both backends are optional)::

    # Use the gmssl-pyx backend explicitly for SM2 and HMAC-SM3.
    jwt.register_sm2(jwt.DEFAULT_SM2_UID, backend="gmssl_pyx")
    jwt.register_hmac_sm3(backend="gmssl_pyx")
"""
import binascii

from jwt import PyJWT
from jwt.api_jws import _jws_global_obj
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidTokenError,
    InvalidAlgorithmError,
    MissingRequiredClaimError,
    PyJWKError,
    PyJWKSetError,
    InvalidSubjectError,
    InvalidJTIError,
)

from snowland_jwt.algorithms import (
    DEFAULT_SM2_UID,
    HMACSM3Algorithm,
    SM2Algorithm,
    generate_key,
)
from snowland_jwt.backends import (
    BackendNotAvailable,
    get_crypto_backend,
)

__version__ = "0.1.0"

# Algorithm identifiers exposed as constants.
SM2 = "SM2"                         # GB/T 0003 pre-hash: e = SM3(ZA || M)
HS256_SM3 = "HS256-SM3"

_ALGORITHM_INSTANCES = {
    SM2: SM2Algorithm(uid=DEFAULT_SM2_UID),
    HS256_SM3: HMACSM3Algorithm(),
}


def _register_algorithms(jws):
    for name, algorithm in _ALGORITHM_INSTANCES.items():
        try:
            jws.register_algorithm(name, algorithm)
        except ValueError:
            # Already registered (e.g. the shared global object).
            pass


def register_sm2(uid=DEFAULT_SM2_UID, alg_name=None, backend=None):
    """Register an SM2 variant with a specific user identifier ``IDA`` and/or
    crypto backend.

    Useful when the two parties agreed on a non-default ``IDA`` for the GB/T
    0003 ``ZA || M`` pre-hash, or when a specific backend must be pinned.

    :param uid: user identifier IDA (``str`` / ``bytes``). Both parties must
                agree on the same ``IDA``.
    :param alg_name: algorithm name to register (auto-derived from ``uid`` when
                     omitted, e.g. ``"SM2-<hex8>"``).
    :param backend: backend name (``"pysmx"`` / ``"gmssl_pyx"``) or ``None`` to
                    auto-select.
    :returns: the algorithm name to use in ``encode``/``decode``.
    """
    if alg_name is None:
        alg_name = "SM2-" + binascii.hexlify(
            uid.encode() if isinstance(uid, str) else uid
        ).hex()[:8]
    if alg_name in _ALGORITHM_INSTANCES:
        return alg_name
    instance = SM2Algorithm(uid=uid, backend=backend)
    _ALGORITHM_INSTANCES[alg_name] = instance
    _register_algorithms(_jws_global_obj)
    return alg_name


def register_hmac_sm3(alg_name=HS256_SM3, backend=None):
    """Register an HMAC-SM3 variant bound to a specific crypto backend.

    :param alg_name: algorithm name to register.
    :param backend: backend name (``"pysmx"`` / ``"gmssl_pyx"``) or ``None`` to
                    auto-select.
    :returns: the algorithm name to use in ``encode``/``decode``.
    """
    if alg_name in _ALGORITHM_INSTANCES:
        return alg_name
    instance = HMACSM3Algorithm(backend=backend)
    _ALGORITHM_INSTANCES[alg_name] = instance
    _register_algorithms(_jws_global_obj)
    return alg_name


# Register onto PyJWT's shared global object so that the plain
# ``import jwt; jwt.encode(..., algorithm="SM2")`` path also works.
_register_algorithms(_jws_global_obj)

# A single shared PyJWT instance. ``PyJWT.__init__`` builds a fresh ``_jws``
# algorithm table, so we point it at the shared global one (already populated by
# ``_register_algorithms``) instead. This way newly registered algorithms (via
# ``register_sm2`` / ``register_hmac_sm3``) stay visible, and we avoid rebuilding
# a PyJWT() and re-registering algorithms on every call.
_JWT_INSTANCE = PyJWT()
_JWT_INSTANCE._jws = _jws_global_obj


def encode(payload, key, algorithm=SM2, headers=None, json_encoder=None,
           sort_headers=True):
    """Encode a JWT with a national-cryptography algorithm.

    Mirrors ``jwt.encode`` but defaults ``algorithm`` to ``SM2`` and ensures
    the GM/T algorithms are registered.
    """
    return _JWT_INSTANCE.encode(
        payload,
        key,
        algorithm=algorithm,
        headers=headers,
        json_encoder=json_encoder,
        sort_headers=sort_headers,
    )


def decode(token, key, algorithms=None, options=None, **kwargs):
    """Decode / verify a JWT. See ``jwt.decode`` for parameters."""
    if algorithms is None:
        algorithms = [SM2, HS256_SM3]
    return _JWT_INSTANCE.decode(
        token, key, algorithms=algorithms, options=options, **kwargs
    )


def decode_complete(token, key, algorithms=None, options=None, **kwargs):
    """Decode a JWT and return the full result. See ``jwt.decode_complete``."""
    if algorithms is None:
        algorithms = [SM2, HS256_SM3]
    return _JWT_INSTANCE.decode_complete(
        token, key, algorithms=algorithms, options=options, **kwargs
    )


__all__ = [
    "encode",
    "decode",
    "decode_complete",
    "generate_key",
    "SM2Algorithm",
    "HMACSM3Algorithm",
    "SM2",
    "HS256_SM3",
    "DEFAULT_SM2_UID",
    "register_sm2",
    "register_hmac_sm3",
    "get_crypto_backend",
    "BackendNotAvailable",
    "DecodeError",
    "ExpiredSignatureError",
    "ImmatureSignatureError",
    "InvalidAudienceError",
    "InvalidIssuedAtError",
    "InvalidIssuerError",
    "InvalidKeyError",
    "InvalidSignatureError",
    "InvalidTokenError",
    "InvalidAlgorithmError",
    "MissingRequiredClaimError",
    "PyJWKError",
    "PyJWKSetError",
    "InvalidSubjectError",
    "InvalidJTIError",
]
