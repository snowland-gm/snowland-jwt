# -*- coding: utf-8 -*-
"""Backend built on ``gmssl-pyx`` (GmSSL bindings).

The whole module is imported eagerly by ``snowland_jwt.backends`` only when the
optional ``gmssl-pyx`` package is installed, so the native library is loaded a
single time at package import -- this is what keeps the ``gmssl_pyx`` path fast
(no repeated ``import gmssl_pyx`` on every signing/verification call).
"""
from gmssl_pyx import (
    sm2_key_generate,
    sm2_sign,
    sm2_verify,
    sm3_hash,
)

from snowland_jwt.backends.base import CryptoBackend


class GmsslPyxBackend(CryptoBackend):
    """Backend built on ``gmssl-pyx`` (libgmssl bindings, ASN.1 DER ``rs``)."""

    name = "gmssl_pyx"

    def sm3_hash(self, data: bytes) -> bytes:
        return sm3_hash(data)

    def sm2_generate_keypair(self):
        public_key, private_key = sm2_key_generate()
        return private_key, public_key

    def sm2_sign(self, msg: bytes, private_key: bytes, public_key: bytes,
                 uid: bytes) -> bytes:
        return sm2_sign(private_key, public_key, msg, uid)

    def sm2_verify(self, msg: bytes, signature: bytes, public_key: bytes,
                   uid: bytes) -> bool:
        return sm2_verify(public_key, msg, signature, uid)
