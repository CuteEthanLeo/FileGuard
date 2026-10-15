"""FileGuard 加解密测试: python -m unittest discover tests"""

import os
import sys
import hashlib
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "FileGuard"))

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import core
from legacy import CFB
import crypto_v2
from crypto_v2 import FileGuardError, HEADER_SIZE

PASSWORD = "correct horse battery 电池"


def legacy_cfb_encrypt(data: bytes, password: str) -> bytes:
    """复刻 V1.x lock1.py 的加密格式"""
    salt, iv = os.urandom(16), os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000, dklen=32)
    enc = Cipher(algorithms.AES(key), CFB(iv)).encryptor()
    return salt + iv + enc.update(data) + enc.finalize() + hashlib.sha256(data).digest()


def legacy_gcm_encrypt(data: bytes, password: str) -> bytes:
    """复刻 V1.x lock2.py 的加密格式 (verifier 与密钥相同)"""
    salt, nonce = os.urandom(16), os.urandom(12)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000, dklen=32)
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    ct = enc.update(data) + enc.finalize()
    return salt + nonce + ct + enc.tag + key


class CryptoTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def path(self, name):
        return os.path.join(self.dir, name)

    def write(self, name, data):
        with open(self.path(name), "wb") as f:
            f.write(data)
        return self.path(name)

    def read(self, name):
        with open(self.path(name), "rb") as f:
            return f.read()

    def roundtrip(self, data, chunk_size=crypto_v2.DEFAULT_CHUNK_SIZE):
        src = self.write("plain.bin", data)
        crypto_v2.encrypt_file(src, self.path("plain.bin.enc"), PASSWORD, chunk_size=chunk_size)
        fmt, is_legacy = core.decrypt(self.path("plain.bin.enc"), self.path("out.bin"), PASSWORD)
        self.assertFalse(is_legacy)
        self.assertEqual(fmt, core.FORMAT_V2)
        self.assertEqual(self.read("out.bin"), data)

    def test_roundtrip_empty(self):
        self.roundtrip(b"")

    def test_roundtrip_small(self):
        self.roundtrip("你好 FileGuard".encode())

    def test_roundtrip_multi_chunk(self):
        self.roundtrip(os.urandom(3 * 1024 * 1024 + 123))

    def test_roundtrip_exact_chunk_boundary(self):
        self.roundtrip(os.urandom(4096 * 3), chunk_size=4096)

    def test_progress_reaches_total(self):
        src = self.write("p.bin", os.urandom(10000))
        seen = []
        crypto_v2.encrypt_file(src, self.path("p.enc"), PASSWORD,
                               progress=lambda d, t: seen.append((d, t)), chunk_size=4096)
        self.assertEqual(seen[-1], (10000, 10000))

    def test_wrong_password(self):
        src = self.write("a.txt", b"secret")
        core.encrypt(src, self.path("a.enc"), PASSWORD)
        with self.assertRaises(FileGuardError):
            core.decrypt(self.path("a.enc"), self.path("a.out"), "wrong")
        self.assertFalse(os.path.exists(self.path("a.out")))
        self.assertEqual([n for n in os.listdir(self.dir) if n.endswith(".tmp")], [])

    def test_tampered_byte(self):
        src = self.write("a.bin", os.urandom(20000))
        crypto_v2.encrypt_file(src, self.path("a.enc"), PASSWORD, chunk_size=4096)
        data = bytearray(self.read("a.enc"))
        data[HEADER_SIZE + 5000] ^= 1
        self.write("a.enc", bytes(data))
        with self.assertRaises(FileGuardError):
            core.decrypt(self.path("a.enc"), self.path("a.out"), PASSWORD)
        self.assertFalse(os.path.exists(self.path("a.out")))

    def test_truncated_at_chunk_boundary(self):
        src = self.write("a.bin", os.urandom(4096 * 3))
        crypto_v2.encrypt_file(src, self.path("a.enc"), PASSWORD, chunk_size=4096)
        data = self.read("a.enc")
        self.write("a.enc", data[:HEADER_SIZE + 2 * (4096 + 16)])
        with self.assertRaises(FileGuardError):
            core.decrypt(self.path("a.enc"), self.path("a.out"), PASSWORD)

    def test_header_tamper_detected(self):
        src = self.write("a.bin", b"data")
        core.encrypt(src, self.path("a.enc"), PASSWORD)
        data = bytearray(self.read("a.enc"))
        data[HEADER_SIZE - 1] ^= 1  # 保留字节: 头部进入 AAD, 任何改动都应被发现
        self.write("a.enc", bytes(data))
        with self.assertRaises(FileGuardError):
            core.decrypt(self.path("a.enc"), self.path("a.out"), PASSWORD)

    def test_key_not_stored_in_file(self):
        src = self.write("a.bin", b"x" * 100)
        core.encrypt(src, self.path("a.enc"), PASSWORD)
        info = crypto_v2.read_header(self.path("a.enc"))
        key = crypto_v2._derive_key(PASSWORD, info["kdf_id"], info["p1"], info["p2"], info["p3"],
                                    info["salt"])
        self.assertNotIn(key, self.read("a.enc"))

    def test_same_input_output_rejected(self):
        src = self.write("a.bin", b"data")
        with self.assertRaises(FileGuardError):
            core.encrypt(src, src, PASSWORD)
        self.assertEqual(self.read("a.bin"), b"data")

    def test_legacy_cfb(self):
        data = os.urandom(50000)
        self.write("old.enc", legacy_cfb_encrypt(data, PASSWORD))
        fmt, is_legacy = core.decrypt(self.path("old.enc"), self.path("old.out"), PASSWORD)
        self.assertTrue(is_legacy)
        self.assertIn("CFB", fmt)
        self.assertEqual(self.read("old.out"), data)

    def test_legacy_gcm(self):
        data = os.urandom(50000)
        self.write("old.enc", legacy_gcm_encrypt(data, PASSWORD))
        fmt, is_legacy = core.decrypt(self.path("old.enc"), self.path("old.out"), PASSWORD)
        self.assertTrue(is_legacy)
        self.assertIn("GCM", fmt)
        self.assertEqual(self.read("old.out"), data)

    def test_legacy_wrong_password(self):
        self.write("old.enc", legacy_cfb_encrypt(b"hello world", PASSWORD))
        with self.assertRaises(FileGuardError):
            core.decrypt(self.path("old.enc"), self.path("old.out"), "nope")
        self.assertFalse(os.path.exists(self.path("old.out")))


if __name__ == "__main__":
    unittest.main()
