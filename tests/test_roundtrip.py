import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config  # noqa: E402
config.LOG_PATH = os.path.join(tempfile.mkdtemp(), "test.log")   # тести не засмічують робочий журнал
config.PBKDF2_ITERATIONS = 200_000                                # швидше для тестів (≥ MIN_ITERATIONS)

import crypto_aes  # noqa: E402
from crypto_aes import EncryptionParams, decrypt_file, encrypt_file, read_header  # noqa: E402
from errors import *  # noqa: E402,F403
from key_manager import KeyStore  # noqa: E402

PW = "TestPass2025x"


def rd(p):
    with open(p, "rb") as f:
        return f.read()


def wr(p, data):
    with open(p, "wb") as f:
        f.write(data)



class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        cls.ks = KeyStore(os.path.join(cls.dir, "ks.json"))
        cls.kid = cls.ks.create(PW, 256, max_uses=1000)
        cls.mat = cls.ks.unlock(cls.kid, PW)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def path(self, name):
        return os.path.join(self.dir, name)

    def make(self, name, data):
        p = self.path(name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def lookup(self, kid):
        return self.mat if kid == self.kid else self.ks.unlock(kid, PW)

    def enc(self, src, mode="gcm", **kw):
        out = src + "." + mode + ".enc"
        encrypt_file(src, out, self.mat, EncryptionParams(mode=mode, **kw), self.ks)
        return out

    def flip(self, path, pos):
        data = bytearray(rd(path))
        data[pos] ^= 0x01
        bad = path + ".bad"
        wr(bad, bytes(data))
        return bad


class RoundTrip(Base):
    def test_all_modes_and_sizes(self):
        for mode in ("gcm", "cbc", "ctr"):
            for n in (0, 1, 15, 16, 17, 1000, 3 * 1024 * 1024 + 5):   # включно з багатошматковим файлом
                src = self.make(f"r_{mode}_{n}", os.urandom(n))
                enc = self.enc(src, mode, chunk_size=64 * 1024)
                out = src + ".dec"
                decrypt_file(enc, out, self.lookup, 64 * 1024)
                self.assertEqual(rd(src), rd(out), (mode, n))

    def test_paddings_and_gcm_nonce16(self):
        src = self.make("pad", b"hello world 12345")
        for kw in ({"mode": "cbc", "padding": "ansix923"}, {"mode": "gcm", "iv_len": 16}):
            enc = self.enc(src, **kw)
            out = src + ".dec"
            decrypt_file(enc, out, self.lookup)
            self.assertEqual(rd(out), b"hello world 12345")

    def test_unique_iv(self):
        src = self.make("iv", b"same data")
        a = rd(self.enc(src))
        b = rd(self.enc(src))
        self.assertNotEqual(a, b)

    def test_bad_params(self):
        src = self.make("bp", b"x")
        for p in (EncryptionParams(mode="xts"), EncryptionParams(padding="zero"),
                  EncryptionParams(mode="gcm", iv_len=7), EncryptionParams(chunk_size=100)):
            with self.assertRaises(ParamError):
                encrypt_file(src, src + ".x", self.mat, p)


class Tamper(Base):
    def test_tamper_detected(self):
        src = self.make("t", os.urandom(5000))
        for mode in ("gcm", "cbc", "ctr"):
            enc = self.enc(src, mode)
            with open(enc, "rb") as fh:
                hdr_len = len(read_header(fh)[1])
            size = os.path.getsize(enc)
            for pos in (hdr_len + 10, size - 1, hdr_len - 5):    # шифртекст, тег/HMAC, заголовок (created)
                bad = self.flip(enc, pos)
                with self.assertRaises(AesLabError):
                    decrypt_file(bad, bad + ".out", self.lookup)
                self.assertFalse(os.path.exists(bad + ".out"))   # файл-результат не створюється

    def test_header_tamper_is_integrity_error(self):
        src = self.make("th", os.urandom(100))
        enc = self.enc(src, "gcm")
        raw = bytearray(rd(enc))
        i = raw.index(b'"created":"') + 20
        raw[i] = ord("0") if raw[i] != ord("0") else ord("1")
        bad = enc + ".bad"
        wr(bad, bytes(raw))
        with self.assertRaises(IntegrityError):
            decrypt_file(bad, bad + ".out", self.lookup)

    def test_truncated_and_garbage(self):
        src = self.make("tr", os.urandom(2000))
        enc = self.enc(src, "cbc")
        data = rd(enc)
        cut = enc + ".cut"
        wr(cut, data[:-40])
        with self.assertRaises(AesLabError):
            decrypt_file(cut, cut + ".out", self.lookup)
        junk = self.make("junk", b"not a container at all")
        with self.assertRaises(FormatError):
            decrypt_file(junk, junk + ".out", self.lookup)


class Keys(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.ks = KeyStore(os.path.join(self.dir, "ks.json"))

    def test_password_rules(self):
        for bad in ("short1", "onlyletterslong", "12345678901"):
            with self.assertRaises(ParamError):
                self.ks.create(bad)

    def test_wrong_password(self):
        kid = self.ks.create(PW)
        with self.assertRaises(BadPasswordError):
            self.ks.unlock(kid, "WrongPass2025")

    def test_no_secrets_in_keystore(self):
        kid = self.ks.create(PW)
        mat = self.ks.unlock(kid, PW)
        with open(self.ks.path, encoding="utf-8") as fh:
            text = fh.read()
        import base64
        self.assertNotIn(base64.b64encode(mat.enc_key).decode(), text)
        self.assertNotIn(mat.enc_key.hex(), text)

    def test_limit_revoke_rotate(self):
        kid = self.ks.create(PW, 128, max_uses=2)
        mat = self.ks.unlock(kid, PW)
        src = os.path.join(self.dir, "f")
        wr(src, b"data")
        for _ in range(2):
            encrypt_file(src, src + ".enc", mat, EncryptionParams(), self.ks)
        with self.assertRaises(KeyPolicyError):
            encrypt_file(src, src + ".enc", mat, EncryptionParams(), self.ks)
        new = self.ks.rotate(kid, PW)
        self.assertEqual(self.ks.unlock(new, PW).key_bits, 128)
        statuses = {k["key_id"]: k["status"] for k in self.ks.list()}
        self.assertEqual(statuses[kid], "revoked")
        out = src + ".dec"                                       # старий ключ усе ще розшифровує
        decrypt_file(src + ".enc", out, lambda k: self.ks.unlock(k, PW))
        self.assertEqual(rd(out), b"data")
        self.ks.revoke(new)
        with self.assertRaises(KeyPolicyError):
            encrypt_file(src, src + ".e2", self.ks.unlock(new, PW), EncryptionParams(), self.ks)


if __name__ == "__main__":
    unittest.main(verbosity=2)
