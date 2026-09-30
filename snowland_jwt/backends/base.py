# -*- coding: utf-8 -*-
"""Abstract base classes shared by all national-cryptography backends."""
from jwt.exceptions import InvalidKeyError


class BackendNotAvailable(InvalidKeyError):
    """Raised when no (or the requested) crypto backend is importable."""


class CryptoBackend:
    """Interface a national-cryptography backend must implement.

    Key material is always exchanged as raw ``bytes``: a 32-byte SM2 private
    scalar ``d`` and a 64-byte public point ``x || y``.
    """

    name = "abstract"

    def sm3_hash(self, data: bytes) -> bytes:
        raise NotImplementedError

    def sm2_generate_keypair(self):
        """Return ``(private_key: bytes, public_key: bytes)``."""
        raise NotImplementedError

    def sm2_sign(self, msg: bytes, private_key: bytes, public_key: bytes,
                 uid: bytes) -> bytes:
        raise NotImplementedError

    def sm2_verify(self, msg: bytes, signature: bytes, public_key: bytes,
                   uid: bytes) -> bool:
        raise NotImplementedError
