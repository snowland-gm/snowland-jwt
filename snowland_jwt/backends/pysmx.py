# -*- coding: utf-8 -*-
"""Backend built on ``snowland-smx`` (``pysmx``).

The whole module is imported eagerly by ``snowland_jwt.backends`` only when the
optional ``pysmx`` package is installed, so the heavy import happens once at
package load rather than on every signing/verification call.
"""
from cryptography.exceptions import InvalidSignature
from pysmx.SM2 import (
    SM2EllipticCurve,
    SM2EllipticCurvePrivateKey,
    SM2EllipticCurvePublicKey,
    SM2SM3SignatureAlgorithm,
)
from pysmx.crypto import hashlib as _sm3_hashlib

from snowland_jwt.backends.base import CryptoBackend


class PysmxBackend(CryptoBackend):
    """Backend built on ``snowland-smx`` (``pysmx``).

    SM2 uses the class API with the raw ``r || s`` signature encoding; SM3 is
    taken from ``pysmx.crypto.hashlib`` (the national-cryptography SM3, not the
    stdlib ``hashlib`` which does not ship SM3).
    """

    name = "pysmx"

    def sm3_hash(self, data: bytes) -> bytes:
        return _sm3_hashlib.new("sm3", data).digest()

    def sm2_generate_keypair(self):
        private = SM2EllipticCurvePrivateKey.generate(SM2EllipticCurve())
        return private._private_key, private.public_key()._public_key

    def sm2_sign(self, msg: bytes, private_key: bytes, public_key: bytes,
                 uid: bytes) -> bytes:
        key = SM2EllipticCurvePrivateKey(SM2EllipticCurve(), private_key, public_key)
        return key.sign(msg, SM2SM3SignatureAlgorithm(), uid=uid)

    def sm2_verify(self, msg: bytes, signature: bytes, public_key: bytes,
                   uid: bytes) -> bool:
        key = SM2EllipticCurvePublicKey(SM2EllipticCurve(), public_key)
        try:
            key.verify(signature, msg, SM2SM3SignatureAlgorithm(), uid=uid)
        except InvalidSignature:
            return False
        return True
