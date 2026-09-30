# -*- coding: utf-8 -*-
"""Pluggable national-cryptography backends.

Two backends are provided, both **optional**:

* ``pysmx``    -- the ``snowland-smx`` package (SM2 class API, raw ``r || s``
  signature encoding);
* ``gmssl_pyx`` -- the ``gmssl-pyx`` package (libgmssl bindings, ASN.1 DER
  ``rs`` signature encoding).

Both implement the same GB/T 0003 SM2 pre-hash ``e = SM3(ZA || M)`` with the
default signer id ``b"1234567812345678"``, so a signer and a verifier that use
the *same* backend and the same ``IDA`` interoperate. Note that the two backends
emit different signature byte encodings (raw vs DER), therefore a token is only
verifiable by the same backend that produced it.

Concrete backend modules are imported eagerly below (once) so that the optional
native libraries are loaded a single time at package import, rather than on
every ``get_crypto_backend`` call -- this is what keeps the ``gmssl_pyx`` path
fast.
"""
from snowland_jwt.backends.base import BackendNotAvailable, CryptoBackend

# Backend registry. The default probe order prefers gmssl_pyx (standard,
# DER-encoded signatures) and falls back to pysmx.
_BACKEND_REGISTRY = {}
_DEFAULT_PROBE_ORDER = ("gmssl_pyx", "pysmx")


def _load_backends():
    for name in _DEFAULT_PROBE_ORDER:
        try:
            if name == "pysmx":
                from snowland_jwt.backends.pysmx import PysmxBackend as _cls
            else:
                from snowland_jwt.backends.gmssl_pyx import GmsslPyxBackend as _cls
        except ImportError:
            # Optional backend not installed; skip silently.
            continue
        _BACKEND_REGISTRY[name] = _cls


_load_backends()


def get_crypto_backend(name=None):
    """Return an initialized crypto backend.

    If ``name`` is omitted, probe the available backends in
    ``_DEFAULT_PROBE_ORDER`` and return the first usable one. If no backend can
    be imported, raise ``BackendNotAvailable``.
    """
    if name is None:
        for candidate in _DEFAULT_PROBE_ORDER:
            # Skip backends that were never registered (i.e. their optional
            # package failed to import at load time) instead of raising KeyError.
            if candidate not in _BACKEND_REGISTRY:
                continue
            try:
                return _BACKEND_REGISTRY[candidate]()
            except ImportError:
                continue
        raise BackendNotAvailable(
            "No national-cryptography backend available. Install one of: "
            "snowland-smx (pysmx) or gmssl-pyx."
        )
    if name not in _BACKEND_REGISTRY:
        raise BackendNotAvailable("Unknown crypto backend: %r" % (name,))
    try:
        return _BACKEND_REGISTRY[name]()
    except ImportError as exc:
        raise BackendNotAvailable(
            "Crypto backend %r is not installed." % (name,)
        ) from exc


__all__ = ["BackendNotAvailable", "CryptoBackend", "get_crypto_backend"]
