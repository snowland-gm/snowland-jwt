# -*- coding: utf-8 -*-
"""GM/T algorithm adapters for PyJWT.

This module provides SM2 (asymmetric, SM3-hashed signature) and HMAC-SM3
(symmetric) algorithm implementations that plug into PyJWT's
``jwt.algorithms.Algorithm`` extension point, so that standard JWT tokens can
be issued / verified under Chinese national cryptography (guomi) scenarios.

The actual cryptography is delegated to a pluggable backend (see
``snowland_jwt.backends``); ``snowland-smx`` (``pysmx``) and ``gmssl-pyx`` are
both supported and optional.

SM2 implementation note (important)
-----------------------------------
The SM2 algorithm uses the full GB/T 0003 pre-hash ``e = SM3(ZA || M)`` with

    ZA = SM3(ENTL_A || ID_A || a || b || xG || yG || xA || yA)

which is inter-operable with standard SM2 (GMSSL / national-cryptography)
tooling. The user identifier ``IDA`` is selected via the ``uid`` argument of
:class:`SM2Algorithm`; both parties MUST agree on the same ``IDA`` (the default
is the GB/T example ``b"1234567812345678"``). ``IDA`` itself is NOT carried in
the JWT.

Key material is handled in a backend-neutral way as raw ``bytes``: a 32-byte
SM2 private scalar ``d`` and a 64-byte public point ``x || y``. Accepted input
forms for ``encode``/``decode`` keys are: raw ``bytes``, hex ``str``, PEM
(``-----BEGIN ...``), JWK (``kty=EC``, ``crv=SM2``), or a backend-native key
object.
"""
import binascii
import json
import hmac as _hmac

from dataclasses import dataclass
from typing import Optional

from jwt.algorithms import Algorithm
from jwt.exceptions import InvalidKeyError
from jwt.utils import base64url_decode, base64url_encode, force_bytes

from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

from snowland_jwt.backends import get_crypto_backend


# Default user identifier IDA for the GB/T 0003 ZA||M pre-hash (the GB/T example).
DEFAULT_SM2_UID = b"1234567812345678"

# SM2 domain parameters (GB/T 0003), used to derive the public point from a
# private scalar so that a 32-byte private key input is backend-agnostic.
# Only the field prime and the standard base point are needed; the curve
# coefficient ``a`` is the fixed identity ``a = p - 3`` (Weierstrass form).
_SM2_P = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
_SM2_GX = int("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
_SM2_GY = int("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)


@dataclass
class SM2Key:
    """Backend-neutral holder for an SM2 key.

    ``public_key`` is the 64-byte uncompressed point ``x || y``; ``private_key``
    is the 32-byte secret scalar ``d`` (``None`` for a public-only key).
    """

    public_key: bytes
    private_key: Optional[bytes] = None


class SM2Algorithm(Algorithm):
    """SM2 signature algorithm (GM/T 0003) with the full ``ZA || M`` pre-hash.

    Registered alg name: ``SM2`` (GB/T 0003 ``e = SM3(ZA || M)``, inter-operable
    with standard SM2 tooling).

    :param backend: backend name (``"pysmx"`` / ``"gmssl_pyx"``) or ``None`` to
                    auto-select the first available backend.
    :param uid: user distinguishable identifier IDA (``str`` / ``bytes``). Both
                parties must agree on the same ``IDA``. Defaults to the GB/T
                example ``b"1234567812345678"``.
    """

    def __init__(self, backend=None, uid=DEFAULT_SM2_UID):
        self._backend_name = backend
        self._backend = None
        self.uid = uid

    def _crypto(self):
        if self._backend is None:
            self._backend = get_crypto_backend(self._backend_name)
        return self._backend

    def prepare_key(self, key):
        if isinstance(key, SM2Key):
            return key
        # pysmx key objects (only if the package is installed).
        try:
            from pysmx.SM2 import (
                SM2EllipticCurvePrivateKey,
                SM2EllipticCurvePublicKey,
            )
        except ImportError:
            SM2EllipticCurvePrivateKey = SM2EllipticCurvePublicKey = None
        if SM2EllipticCurvePrivateKey is not None:
            if isinstance(key, SM2EllipticCurvePrivateKey):
                return SM2Key(
                    public_key=key.public_key()._public_key,
                    private_key=key._private_key,
                )
            if isinstance(key, SM2EllipticCurvePublicKey):
                return SM2Key(public_key=key._public_key)
        # cryptography EC keys.
        if isinstance(key, EllipticCurvePrivateKey):
            nums = key.private_numbers()
            return SM2Key(
                public_key=nums.public_numbers.x.to_bytes(32, "big")
                + nums.public_numbers.y.to_bytes(32, "big"),
                private_key=nums.private_value.to_bytes(32, "big"),
            )
        if isinstance(key, EllipticCurvePublicKey):
            nums = key.public_numbers()
            return SM2Key(
                public_key=nums.x.to_bytes(32, "big")
                + nums.y.to_bytes(32, "big")
            )
        if isinstance(key, dict):
            return self.from_jwk(key)
        if isinstance(key, str):
            text = key.strip()
            if text.startswith("{"):
                return self.from_jwk(json.loads(text))
            if text.startswith("-----BEGIN"):
                return self._prepare_pem(force_bytes(text))
            try:
                raw = binascii.unhexlify(text)
            except (binascii.Error, ValueError):
                raise InvalidKeyError("Unsupported SM2 key format")
            return self._prepare_raw(raw)
        return self._prepare_raw(force_bytes(key))

    def _prepare_pem(self, key_bytes):
        try:
            private = load_pem_private_key(key_bytes, password=None)
        except Exception:
            private = None
        if isinstance(private, EllipticCurvePrivateKey):
            return self.prepare_key(private)
        public = load_pem_public_key(key_bytes)
        if isinstance(public, EllipticCurvePublicKey):
            return self.prepare_key(public)
        raise InvalidKeyError("Unsupported SM2 PEM key")

    @staticmethod
    def _derive_public_point(d: int):
        """Derive the SM2 public point ``(x, y)`` for private scalar ``d``."""
        p, a = _SM2_P, _SM2_P - 3

        def inv(x):
            return pow(x % p, -1, p)

        def ec_add(p1, p2):
            if p1 is None:
                return p2
            if p2 is None:
                return p1
            x1, y1 = p1
            x2, y2 = p2
            if x1 == x2 and (y1 + y2) % p == 0:
                return None
            if p1 == p2:
                lam = (3 * x1 * x1 + a) * inv(2 * y1) % p
            else:
                lam = (y2 - y1) * inv((x2 - x1) % p) % p
            x3 = (lam * lam - x1 - x2) % p
            y3 = (lam * (x1 - x3) - y1) % p
            return (x3, y3)

        def ec_mul(k, point):
            result = None
            addend = point
            while k:
                if k & 1:
                    result = ec_add(result, addend)
                addend = ec_add(addend, addend)
                k >>= 1
            return result

        return ec_mul(d, (_SM2_GX, _SM2_GY))

    @staticmethod
    def _prepare_raw(key_bytes):
        if len(key_bytes) == 32:
            x, y = SM2Algorithm._derive_public_point(
                int.from_bytes(key_bytes, "big")
            )
            pub = x.to_bytes(32, "big") + y.to_bytes(32, "big")
            return SM2Key(public_key=pub, private_key=key_bytes)
        if len(key_bytes) == 65 and key_bytes[0] == 0x04:
            key_bytes = key_bytes[1:]
        if len(key_bytes) == 64:
            return SM2Key(public_key=key_bytes)
        raise InvalidKeyError("Unsupported SM2 key length")

    def sign(self, msg, key):
        if key.private_key is None:
            raise InvalidKeyError("SM2 signing requires a private key")
        return self._crypto().sm2_sign(
            msg, key.private_key, key.public_key, self.uid
        )

    def verify(self, msg, key, sig):
        if key.public_key is None:
            raise InvalidKeyError("SM2 verification requires a public key")
        return self._crypto().sm2_verify(msg, sig, key.public_key, self.uid)

    @staticmethod
    def to_jwk(key_obj, as_dict=False):
        if not isinstance(key_obj, SM2Key):
            raise InvalidKeyError("Expected an SM2Key instance")
        jwk = {
            "kty": "EC",
            "crv": "SM2",
            "x": base64url_encode(key_obj.public_key[:32]).decode("ascii"),
            "y": base64url_encode(key_obj.public_key[32:]).decode("ascii"),
        }
        if key_obj.private_key is not None:
            jwk["d"] = base64url_encode(key_obj.private_key).decode("ascii")
        if as_dict:
            return jwk
        return json.dumps(jwk)

    @staticmethod
    def from_jwk(jwk):
        if isinstance(jwk, str):
            jwk = json.loads(jwk)
        if jwk.get("kty") != "EC" or jwk.get("crv") != "SM2":
            raise InvalidKeyError("Not an SM2 (EC/SM2) JWK")
        x = base64url_decode(jwk["x"])
        y = base64url_decode(jwk["y"])
        public_key = x + y
        private_key = base64url_decode(jwk["d"]) if "d" in jwk else None
        return SM2Key(public_key=public_key, private_key=private_key)


class HMACSM3Algorithm(Algorithm):
    """HMAC using SM3 as the hash (alg name ``HS256-SM3``).

    The SM3 digest is taken from the active crypto backend's ``sm3_hash`` (e.g.
    ``pysmx.crypto.hashlib`` for the pysmx backend, ``gmssl_pyx.sm3_hash`` for
    the gmssl backend). ``sm3_hash`` is a fixed standard digest across backends,
    so the resulting HMAC token is byte-identical regardless of the backend.
    """

    def __init__(self, backend=None):
        self._backend_name = backend
        self._backend = None

    def _crypto(self):
        if self._backend is None:
            self._backend = get_crypto_backend(self._backend_name)
        return self._backend

    @staticmethod
    def _hmac_sm3(key, data, hash_func):
        """RFC 2104 HMAC over a backend-provided SM3 digest function."""
        key = force_bytes(key)
        block_size = 64
        if len(key) > block_size:
            key = hash_func(key)
        key = key.ljust(block_size, b"\x00")
        o_key = bytes(c ^ 0x5C for c in key)
        i_key = bytes(c ^ 0x36 for c in key)
        inner = hash_func(i_key + data)
        return hash_func(o_key + inner)

    def prepare_key(self, key):
        if isinstance(key, dict):
            return self.from_jwk(key)
        return force_bytes(key)

    def sign(self, msg, key):
        return self._hmac_sm3(key, msg, self._crypto().sm3_hash)

    def verify(self, msg, key, sig):
        expected = self._hmac_sm3(key, msg, self._crypto().sm3_hash)
        return _hmac.compare_digest(sig, expected)

    @staticmethod
    def to_jwk(key_obj, as_dict=False):
        jwk = {"kty": "oct", "k": base64url_encode(force_bytes(key_obj)).decode("ascii")}
        if as_dict:
            return jwk
        return json.dumps(jwk)

    @staticmethod
    def from_jwk(jwk):
        if isinstance(jwk, str):
            jwk = json.loads(jwk)
        if jwk.get("kty") != "oct":
            raise InvalidKeyError("Not an HMAC (oct) JWK")
        return base64url_decode(jwk["k"])


def generate_key():
    """Generate an SM2 key pair using the default backend.

    Returns a ``(private_key_hex, public_key_hex)`` tuple. The private key is
    32 bytes (64 hex chars) and the public key is 64 bytes (128 hex chars,
    ``x || y``).
    """
    private_key, public_key = get_crypto_backend().sm2_generate_keypair()
    return private_key.hex(), public_key.hex()
