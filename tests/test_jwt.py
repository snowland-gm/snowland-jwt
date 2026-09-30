# -*- coding: utf-8 -*-
"""Unit tests for the snowland-jwt national-cryptography JWT implementation."""
import unittest

import snowland_jwt as jwt
from snowland_jwt import DEFAULT_SM2_UID, HS256_SM3, SM2, SM2Algorithm
from snowland_jwt.algorithms import SM2Key


def _backend_installed(name):
    try:
        jwt.get_crypto_backend(name)
        return True
    except Exception:
        return False


_HAS_PYSMS = _backend_installed("pysmx")
_HAS_GMSSL = _backend_installed("gmssl_pyx")


class TestSM2JWT(unittest.TestCase):
    def setUp(self):
        self.private_key, self.public_key = jwt.generate_key()
        self.payload = {"sub": "user-001", "role": "admin"}

    def test_generate_key_lengths(self):
        self.assertEqual(len(self.private_key), 64)
        self.assertEqual(len(self.public_key), 128)

    def test_encode_decode_sm2(self):
        token = jwt.encode(self.payload, self.private_key, algorithm=SM2)
        self.assertTrue(token.startswith("eyJ") or isinstance(token, str))
        decoded = jwt.decode(token, self.public_key, algorithms=[SM2])
        self.assertEqual(decoded["sub"], "user-001")
        self.assertEqual(decoded["role"], "admin")

    def test_sm2_rejects_wrong_public_key(self):
        # Verifying with an unrelated public key must fail.
        _, other_pub = jwt.generate_key()
        token = jwt.encode(self.payload, self.private_key, algorithm=SM2)
        with self.assertRaises(jwt.InvalidTokenError):
            jwt.decode(token, other_pub, algorithms=[SM2])

    def test_sm2_invalid_key_format(self):
        alg = SM2Algorithm()
        with self.assertRaises(jwt.InvalidKeyError):
            alg.prepare_key("not-a-valid-key!!")

    def test_sm2_detects_tampered_token(self):
        token = jwt.encode(self.payload, self.private_key, algorithm=SM2)
        tampered = token[:-3] + ("aaa" if not token.endswith("aaa") else "bbb")
        with self.assertRaises(jwt.InvalidTokenError):
            jwt.decode(tampered, self.public_key, algorithms=[SM2])

    def test_sm2_za_m_roundtrip(self):
        # Default SM2 alg uses the full GB/T 0003 ZA||M pre-hash.
        token = jwt.encode(self.payload, self.private_key, algorithm=SM2)
        decoded = jwt.decode(token, self.public_key, algorithms=[SM2])
        self.assertEqual(decoded["sub"], "user-001")

    def test_sm2_default_uid_constant(self):
        # The default IDA used by SM2 must be the GB/T example identifier.
        self.assertEqual(DEFAULT_SM2_UID, b"1234567812345678")

    def test_sm2_custom_uid_roundtrip(self):
        # A custom-IDA variant (ZA||M) signs/verifies independently, and must
        # NOT be inter-operable with a different-IDA variant.
        alg_a = jwt.register_sm2(b"custom-ida-aaa", alg_name="SM2-A")
        alg_b = jwt.register_sm2(b"custom-ida-bbb", alg_name="SM2-B")
        token = jwt.encode(self.payload, self.private_key, algorithm=alg_a)
        decoded = jwt.decode(token, self.public_key, algorithms=[alg_a])
        self.assertEqual(decoded["sub"], "user-001")
        with self.assertRaises(jwt.InvalidTokenError):
            jwt.decode(token, self.public_key, algorithms=[alg_b])

    def test_sm2_jwk_roundtrip(self):
        key = SM2Key(
            public_key=bytes.fromhex(self.public_key),
            private_key=bytes.fromhex(self.private_key),
        )
        jwk = SM2Algorithm.to_jwk(key)
        restored = SM2Algorithm.from_jwk(jwk)
        self.assertEqual(restored.private_key, key.private_key)
        self.assertEqual(restored.public_key, key.public_key)

    def test_sm2_raw_private_key_derives_public(self):
        # A bare 32-byte (hex) private key must derive its public point and sign.
        token = jwt.encode(self.payload, self.private_key, algorithm=SM2)
        decoded = jwt.decode(token, self.public_key, algorithms=[SM2])
        self.assertEqual(decoded["sub"], "user-001")


class TestBackends(unittest.TestCase):
    def setUp(self):
        self.private_key, self.public_key = jwt.generate_key()
        self.payload = {"sub": "x"}

    @unittest.skipUnless(_HAS_PYSMS, "pysmx backend not installed")
    def test_pysmx_backend_roundtrip(self):
        alg = jwt.register_sm2(DEFAULT_SM2_UID, alg_name="SM2-PYSMS", backend="pysmx")
        token = jwt.encode(self.payload, self.private_key, algorithm=alg)
        decoded = jwt.decode(token, self.public_key, algorithms=[alg])
        self.assertEqual(decoded["sub"], "x")

    @unittest.skipUnless(_HAS_GMSSL, "gmssl-pyx backend not installed")
    def test_gmssl_backend_roundtrip(self):
        alg = jwt.register_sm2(
            DEFAULT_SM2_UID, alg_name="SM2-GMSSL", backend="gmssl_pyx"
        )
        token = jwt.encode(self.payload, self.private_key, algorithm=alg)
        decoded = jwt.decode(token, self.public_key, algorithms=[alg])
        self.assertEqual(decoded["sub"], "x")

    @unittest.skipUnless(_HAS_PYSMS and _HAS_GMSSL, "both backends required")
    def test_backends_different_signature_encoding(self):
        a_p = jwt.register_sm2(DEFAULT_SM2_UID, alg_name="SM2-P", backend="pysmx")
        a_g = jwt.register_sm2(
            DEFAULT_SM2_UID, alg_name="SM2-G", backend="gmssl_pyx"
        )
        t_p = jwt.encode(self.payload, self.private_key, algorithm=a_p)
        t_g = jwt.encode(self.payload, self.private_key, algorithm=a_g)
        # The two backends emit different signature encodings (raw r||s vs DER).
        self.assertNotEqual(t_p.split(".")[2], t_g.split(".")[2])
        # Each token verifies only with its own backend.
        self.assertEqual(jwt.decode(t_p, self.public_key, algorithms=[a_p])["sub"], "x")
        self.assertEqual(jwt.decode(t_g, self.public_key, algorithms=[a_g])["sub"], "x")
        with self.assertRaises(jwt.InvalidTokenError):
            jwt.decode(t_p, self.public_key, algorithms=[a_g])


class TestHMACSM3JWT(unittest.TestCase):
    def setUp(self):
        self.secret = "guomi-shared-secret-key-0123456789abcdef"
        self.payload = {"iss": "snowland", "scope": "read"}

    def test_encode_decode_hmac_sm3(self):
        token = jwt.encode(self.payload, self.secret, algorithm=HS256_SM3)
        decoded = jwt.decode(token, self.secret, algorithms=[HS256_SM3])
        self.assertEqual(decoded["iss"], "snowland")

    def test_hmac_sm3_rejects_wrong_secret(self):
        token = jwt.encode(self.payload, self.secret, algorithm=HS256_SM3)
        with self.assertRaises(jwt.InvalidTokenError):
            jwt.decode(token, "wrong-secret", algorithms=[HS256_SM3])

    @unittest.skipUnless(_HAS_PYSMS and _HAS_GMSSL, "both backends required")
    def test_hmac_sm3_backend_independent(self):
        # HMAC-SM3 is computed from a standard SM3 digest, so it is byte-identical
        # regardless of which SM2 backend is installed (unlike SM2 signatures,
        # whose encoding differs between backends).
        from snowland_jwt.algorithms import HMACSM3Algorithm

        msg = b"signing-input-bytes"
        s_p = HMACSM3Algorithm(backend="pysmx").sign(msg, self.secret)
        s_g = HMACSM3Algorithm(backend="gmssl_pyx").sign(msg, self.secret)
        self.assertEqual(s_p, s_g)


if __name__ == "__main__":
    unittest.main()
