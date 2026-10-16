"""Керування ключами: PBKDF2-HMAC-SHA256 + випадковий salt, контроль довжини,
життєвий цикл (active -> revoked), ліміт використань, перевірка пароля.
У keystore.json зберігаються ЛИШЕ метадані; ключі на диск не пишуться."""
import base64
import json
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import config
from errors import BadPasswordError, KeyPolicyError, ParamError
from logger_setup import log_event

b64e = lambda b: base64.b64encode(b).decode()
b64d = lambda s: base64.b64decode(s.encode())


@dataclass
class KeyMaterial:
    """Ключі, що живуть лише в пам'яті. enc_key - шифрування, mac_key - автентифікація."""
    key_id: str
    key_bits: int
    enc_key: bytes
    mac_key: bytes

    def close(self):
        self.enc_key = self.mac_key = b""


def check_password(password: str) -> None:
    if len(password) < config.MIN_PASSWORD_LEN:
        raise ParamError(f"Пароль занадто короткий (мінімум {config.MIN_PASSWORD_LEN} символів)")
    if not (re.search(r"[A-Za-zА-Яа-яІіЇїЄєҐґ]", password) and re.search(r"\d", password)):
        raise ParamError("Пароль має містити і літери, і цифри")


def derive(password: str, salt: bytes, iterations: int, key_bits: int):
    """Повертає (enc_key, mac_key, kcv). Довжини ключів перевіряються."""
    if key_bits not in config.KEY_SIZES_BITS:
        raise ParamError(f"Довжина ключа має бути {config.KEY_SIZES_BITS} біт")
    if iterations < config.MIN_ITERATIONS:
        raise ParamError(f"Забагато слабких ітерацій: {iterations} < {config.MIN_ITERATIONS}")
    master = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                        iterations=iterations).derive(password.encode("utf-8"))

    def sub(info, n):
        return HKDF(algorithm=hashes.SHA256(), length=n, salt=None, info=info).derive(master)

    enc_key, mac_key = sub(b"aes-lab enc", key_bits // 8), sub(b"aes-lab mac", 32)
    assert len(enc_key) * 8 == key_bits and len(mac_key) == 32
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(b"aes-lab key-check")
    return enc_key, mac_key, h.finalize()[:16]          # kcv - контрольне значення пароля


class KeyStore:
    def __init__(self, path=None):
        self.path = path or config.KEYSTORE_PATH

    # --- файл
    def _load(self):
        if not os.path.exists(self.path):
            return {"format": 1, "keys": {}}
        with open(self.path, encoding="utf-8") as f:
            return json.load(f)

    def _save(self, data):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _meta(self, data, key_id):
        if key_id not in data["keys"]:
            raise ParamError(f"Ключ '{key_id}' не знайдено у keystore")
        return data["keys"][key_id]

    # --- життєвий цикл
    def create(self, password, key_bits=None, max_uses=None, label="") -> str:
        key_bits = key_bits or config.DEFAULT_KEY_BITS
        check_password(password)
        salt = os.urandom(config.SALT_LEN)
        _, _, kcv = derive(password, salt, config.PBKDF2_ITERATIONS, key_bits)
        key_id = uuid.uuid4().hex[:10]
        now = datetime.now(timezone.utc)
        data = self._load()
        data["keys"][key_id] = {
            "key_id": key_id, "label": label, "kdf": config.KDF_NAME,
            "iterations": config.PBKDF2_ITERATIONS, "salt": b64e(salt), "kcv": b64e(kcv),
            "key_bits": key_bits, "created_at": now.isoformat(timespec="seconds"),
            "expires_at": (now + timedelta(days=config.MAX_AGE_DAYS)).isoformat(timespec="seconds"),
            "uses": 0, "max_uses": max_uses or config.MAX_USES, "status": "active",
            "format_version": config.FORMAT_VERSION,
        }
        self._save(data)
        log_event("key_new", "finish", key_id=key_id, key_bits=key_bits)
        return key_id

    def list(self):
        hide = {"salt", "kcv"}
        return [{k: v for k, v in m.items() if k not in hide} for m in self._load()["keys"].values()]

    def unlock(self, key_id, password) -> KeyMaterial:
        """Виводить ключі з пароля й перевіряє пароль за kcv. Працює і для відкликаних (для дешифрування)."""
        meta = self._meta(self._load(), key_id)
        enc, mac, kcv = derive(password, b64d(meta["salt"]), meta["iterations"], meta["key_bits"])
        if kcv != b64d(meta["kcv"]):
            log_event("unlock", "error", "WARNING", key_id=key_id, error="BadPasswordError")
            raise BadPasswordError("Неправильний пароль до ключа")
        return KeyMaterial(key_id, meta["key_bits"], enc, mac)

    def register_use(self, key_id) -> None:
        """Викликається ПЕРЕД кожним шифруванням: забороняє використання непридатного ключа."""
        data = self._load()
        m = self._meta(data, key_id)
        reason = None
        if m["status"] != "active":
            reason = f"ключ має статус '{m['status']}'"
        elif m["uses"] >= m["max_uses"]:
            reason = f"вичерпано ліміт використань ({m['max_uses']})"
        elif datetime.now(timezone.utc) > datetime.fromisoformat(m["expires_at"]):
            reason = "строк дії ключа минув"
        if reason:
            log_event("encrypt", "error", "WARNING", key_id=key_id, error="KeyPolicyError", reason=reason)
            raise KeyPolicyError(f"Шифрування заборонено: {reason}. Створіть/ротуйте ключ.")
        m["uses"] += 1
        self._save(data)

    def revoke(self, key_id) -> None:
        data = self._load()
        self._meta(data, key_id)["status"] = "revoked"
        self._save(data)
        log_event("key_revoke", "finish", key_id=key_id)

    def rotate(self, key_id, password) -> str:
        """Ротація: перевіряє пароль, створює новий ключ, старий відкликає (лишається для дешифрування)."""
        old = self.unlock(key_id, password)
        new_id = self.create(password, old.key_bits, label="rotated from " + key_id)
        self.revoke(key_id)
        old.close()
        return new_id
