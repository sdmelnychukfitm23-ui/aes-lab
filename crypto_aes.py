"""Шифрування файлів AES: GCM (AEAD), CBC+HMAC-SHA256 та CTR+HMAC-SHA256 (освітній, для розширюваності).
Файли обробляються потоково (шматками), тому пам'ять не залежить від розміру файлу.

Формат контейнера:
  MAGIC "AESL" (4 Б) | HDRLEN (2 Б, big-endian) | JSON-заголовок | ШИФРТЕКСТ | ТЕГ GCM (16 Б) / HMAC-SHA256 (32 Б)
Заголовок (MAGIC+HDRLEN+JSON) автентифікується: у GCM - як AAD, у CBC/CTR - входить до HMAC."""
import base64
import json
import os
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import config
from errors import FormatError, IntegrityError, KeyPolicyError, ParamError
from logger_setup import log_event

MAGIC = b"AESL"
BLOCK_BITS = 128                                  # AES завжди має блок 128 біт
TAG_LEN = {"gcm": 16, "cbc": 32, "ctr": 32}       # довжина тегу/HMAC наприкінці файлу
DEFAULT_IV = {"gcm": 12, "cbc": 16, "ctr": 16}
GCM_IV_ALLOWED = (12, 16)
PADDINGS = ("pkcs7", "ansix923")


@dataclass
class EncryptionParams:
    """Окремий інтерфейс налаштування параметрів шифрування."""
    mode: str = config.DEFAULT_MODE         # gcm | cbc | ctr
    padding: str = config.DEFAULT_PADDING   # pkcs7 | ansix923 (лише для CBC)
    iv_len: int = 0                         # 0 = за замовчуванням для режиму; IV завжди випадковий
    chunk_size: int = config.CHUNK_SIZE     # розмір шматка при потоковій обробці
    block_bits: int = BLOCK_BITS            # довжина блоку AES (фіксована = 128)

    def validate(self):
        if self.mode not in TAG_LEN:
            raise ParamError(f"Невідомий режим '{self.mode}'. Доступні: {', '.join(TAG_LEN)}")
        if self.block_bits != BLOCK_BITS:
            raise ParamError("AES має фіксований блок 128 біт")
        if self.padding not in PADDINGS:
            raise ParamError(f"Невідомий паддинг '{self.padding}'. Доступні: {', '.join(PADDINGS)}")
        iv = self.iv_len or DEFAULT_IV[self.mode]
        if self.mode == "gcm" and iv not in GCM_IV_ALLOWED:
            raise ParamError(f"Довжина nonce для GCM: {GCM_IV_ALLOWED} байт (рекомендовано 12)")
        if self.mode != "gcm" and iv != 16:
            raise ParamError("IV для CBC/CTR має бути 16 байт")
        if self.chunk_size < 4096 or self.chunk_size % 16:
            raise ParamError("chunk_size має бути ≥ 4096 і кратним 16")
        return iv


def _b64(b): return base64.b64encode(b).decode()


def _make_padder(name):
    return (padding.PKCS7(BLOCK_BITS) if name == "pkcs7" else padding.ANSIX923(BLOCK_BITS))


# ------------------------------------------------------------------ заголовок
def build_header(params, material, iv, orig_size) -> bytes:
    hdr = {"v": config.FORMAT_VERSION, "mode": params.mode, "key_bits": material.key_bits,
           "key_id": material.key_id, "iv": _b64(iv), "padding": params.padding if params.mode == "cbc" else "none",
           "orig_size": orig_size, "created": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    js = json.dumps(hdr, sort_keys=True, separators=(",", ":")).encode()
    return MAGIC + struct.pack(">H", len(js)) + js


def read_header(f):
    """Повертає (header_dict, raw_header_bytes). Кидає FormatError при будь-якій аномалії."""
    f.seek(0)
    start = f.read(6)
    if len(start) < 6 or start[:4] != MAGIC:
        raise FormatError("Це не контейнер AES-Lab (немає сигнатури AESL)")
    (hlen,) = struct.unpack(">H", start[4:6])
    js = f.read(hlen)
    if len(js) != hlen:
        raise FormatError("Файл обірваний у заголовку")
    try:
        h = json.loads(js)
        for k in ("v", "mode", "key_bits", "key_id", "iv", "orig_size"):
            h[k]
        iv = base64.b64decode(h["iv"])
    except (ValueError, KeyError, TypeError):
        raise FormatError("Заголовок контейнера пошкоджений")
    if h["v"] != config.FORMAT_VERSION or h["mode"] not in TAG_LEN:
        raise FormatError("Непідтримувана версія формату або режим")
    if len(iv) not in (12, 16):
        raise FormatError("Некоректна довжина IV у заголовку")
    return h, start + js


def _read_in_chunks(f, total, size):
    left = total
    while left > 0:
        chunk = f.read(min(size, left))
        if not chunk:
            raise FormatError("Файл обірваний (недостатньо даних)")
        left -= len(chunk)
        yield chunk


# ------------------------------------------------------------------ шифрування
def _encrypt_stream(fin, fout, aad, material, iv, params, size):
    if params.mode == "gcm":
        enc = Cipher(algorithms.AES(material.enc_key), modes.GCM(iv)).encryptor()
        enc.authenticate_additional_data(aad)
        for ch in _read_in_chunks(fin, size, params.chunk_size):
            fout.write(enc.update(ch))
        fout.write(enc.finalize())
        fout.write(enc.tag)
        return
    mode_obj = modes.CBC(iv) if params.mode == "cbc" else modes.CTR(iv)
    enc = Cipher(algorithms.AES(material.enc_key), mode_obj).encryptor()
    padder = _make_padder(params.padding).padder() if params.mode == "cbc" else None
    mac = hmac.HMAC(material.mac_key, hashes.SHA256())
    mac.update(aad)                                   # encrypt-then-MAC: заголовок+IV+шифртекст
    for ch in _read_in_chunks(fin, size, params.chunk_size):
        ct = enc.update(padder.update(ch) if padder else ch)
        mac.update(ct)
        fout.write(ct)
    tail = enc.update(padder.finalize()) if padder else b""
    tail += enc.finalize()
    mac.update(tail)
    fout.write(tail)
    fout.write(mac.finalize())


def encrypt_file(src, dst, material, params=None, keystore=None):
    """Шифрує src -> dst. Якщо передано keystore, спершу перевіряється політика ключа (ліміт/відкликання)."""
    params = params or EncryptionParams()
    iv_len = params.validate()
    t0 = time.perf_counter()
    if not os.path.isfile(src):
        raise ParamError(f"Файл не знайдено: {src}")
    if os.path.abspath(src) == os.path.abspath(dst):
        raise ParamError("Вихідний файл не може збігатися з вхідним")
    size = os.path.getsize(src)
    base = {"file": os.path.basename(src), "mode": params.mode, "size": size, "key_id": material.key_id}
    log_event("encrypt", "start", **base)
    tmp = dst + ".tmp"
    try:
        if keystore is not None:
            keystore.register_use(material.key_id)   # заборона повторного використання вичерпаного ключа
        iv = os.urandom(iv_len)                       # IV/nonce - завжди випадковий
        aad = build_header(params, material, iv, size)
        os.makedirs(os.path.dirname(os.path.abspath(dst)), exist_ok=True)
        with open(src, "rb") as fin, open(tmp, "wb") as fout:
            fout.write(aad)
            _encrypt_stream(fin, fout, aad, material, iv, params, size)
        os.replace(tmp, dst)
    except Exception as e:
        if os.path.exists(tmp):
            os.remove(tmp)
        if not isinstance(e, KeyPolicyError):      # KeyPolicyError уже записано в key_manager
            log_event("encrypt", "error", "ERROR", error=type(e).__name__, message=str(e), **base)
        raise
    secs = time.perf_counter() - t0
    out = os.path.getsize(dst)
    log_event("encrypt", "finish", ms=round(secs * 1000, 2), out_size=out, **base)
    return {"mode": params.mode, "key_bits": material.key_bits, "in_bytes": size, "out_bytes": out,
            "seconds": secs, "mb_s": (size / 1048576) / secs if secs else 0.0}


# ------------------------------------------------------------------ дешифрування
def _decrypt_stream(fin, fout, aad, material, header, params, ct_len, data_start):
    iv = base64.b64decode(header["iv"])
    cs = params.chunk_size
    mode = header["mode"]
    if mode == "gcm":
        fin.seek(data_start + ct_len)
        tag = fin.read(16)
        fin.seek(data_start)
        dec = Cipher(algorithms.AES(material.enc_key), modes.GCM(iv, tag)).decryptor()
        dec.authenticate_additional_data(aad)
        for ch in _read_in_chunks(fin, ct_len, cs):
            fout.write(dec.update(ch))
        try:
            fout.write(dec.finalize())               # тут перевіряється тег
        except InvalidTag:
            raise IntegrityError("Тег автентичності GCM не збігається: файл або заголовок змінено")
        return
    # CBC / CTR: СПОЧАТКУ перевіряємо HMAC (перший прохід), потім розшифровуємо
    fin.seek(data_start + ct_len)
    tag = fin.read(32)
    fin.seek(data_start)
    mac = hmac.HMAC(material.mac_key, hashes.SHA256())
    mac.update(aad)
    for ch in _read_in_chunks(fin, ct_len, cs):
        mac.update(ch)
    try:
        mac.verify(tag)
    except InvalidSignature:
        raise IntegrityError("HMAC не збігається: файл або заголовок змінено")
    fin.seek(data_start)
    mode_obj = modes.CBC(iv) if mode == "cbc" else modes.CTR(iv)
    dec = Cipher(algorithms.AES(material.enc_key), mode_obj).decryptor()
    unp = _make_padder(header.get("padding", "pkcs7")).unpadder() if mode == "cbc" else None
    for ch in _read_in_chunks(fin, ct_len, cs):
        pt = dec.update(ch)
        fout.write(unp.update(pt) if unp else pt)
    last = dec.finalize()
    try:
        fout.write((unp.update(last) + unp.finalize()) if unp else last)
    except ValueError:
        raise FormatError("Некоректний паддинг після розшифрування")


def decrypt_file(src, dst, key_lookup, chunk_size=config.CHUNK_SIZE):
    """Розшифровує src -> dst. key_lookup(key_id) -> KeyMaterial (бере ключ, вказаний у заголовку).
    Результат пишеться у тимчасовий файл і з'являється під справжнім ім'ям лише після успішної перевірки."""
    t0 = time.perf_counter()
    if not os.path.isfile(src):
        raise ParamError(f"Файл не знайдено: {src}")
    base = {"file": os.path.basename(src)}
    log_event("decrypt", "start", **base)
    tmp = dst + ".tmp"
    try:
        total = os.path.getsize(src)
        with open(src, "rb") as fin:
            header, aad = read_header(fin)
            base.update(mode=header["mode"], key_id=header["key_id"], size=total)
            material = key_lookup(header["key_id"])
            if material.key_bits != header["key_bits"]:
                raise FormatError("Довжина ключа не відповідає заголовку")
            ct_len = total - len(aad) - TAG_LEN[header["mode"]]
            if ct_len < 0 or (header["mode"] == "cbc" and (ct_len % 16 or ct_len == 0)):
                raise FormatError("Некоректна довжина шифртексту (файл обрізано?)")
            os.makedirs(os.path.dirname(os.path.abspath(dst)), exist_ok=True)
            params = EncryptionParams(mode=header["mode"], chunk_size=chunk_size,
                                      padding=header.get("padding", "pkcs7") if header["mode"] == "cbc" else "pkcs7")
            with open(tmp, "wb") as fout:
                _decrypt_stream(fin, fout, aad, material, header, params, ct_len, len(aad))
        if os.path.getsize(tmp) != header["orig_size"]:
            raise FormatError("Розмір розшифрованих даних не збігається із заголовком")
        os.replace(tmp, dst)
    except Exception as e:
        if os.path.exists(tmp):
            os.remove(tmp)
        extra = {"tag_valid": False} if isinstance(e, IntegrityError) else {}
        log_event("decrypt", "error", "WARNING" if extra else "ERROR",
                  error=type(e).__name__, message=str(e), **extra, **base)
        raise
    secs = time.perf_counter() - t0
    log_event("decrypt", "finish", ms=round(secs * 1000, 2), tag_valid=True, out_size=os.path.getsize(dst), **base)
    return {"mode": header["mode"], "key_bits": header["key_bits"], "key_id": header["key_id"],
            "in_bytes": total, "out_bytes": header["orig_size"], "seconds": secs,
            "mb_s": (header["orig_size"] / 1048576) / secs if secs else 0.0}
