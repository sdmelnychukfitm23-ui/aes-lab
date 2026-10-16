"""Імітація підміни зашифрованого файлу / тегу. Запуск: py tamper_demo.py
Кожен сценарій змінює ОДИН байт (або обрізає файл) і перевіряє, чи виявляє програма втручання."""
import os
import shutil

import config
from crypto_aes import EncryptionParams, decrypt_file, encrypt_file, read_header
from errors import AesLabError
from key_manager import KeyStore

PW = "DemoPassword2025"
WORK = os.path.join(config.OUTPUT_DIR, "tamper_demo")


def read(p):
    with open(p, "rb") as f:
        return f.read()


def write(p, data):
    with open(p, "wb") as f:
        f.write(data)


def mutate(data, pos):
    b = bytearray(data)
    b[pos] ^= 0x01
    return bytes(b)


def main():
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK)
    ks = KeyStore(os.path.join(WORK, "keystore_demo.json"))
    kid = ks.create(PW, 256, max_uses=100)
    mat = ks.unlock(kid, PW)
    lookup = lambda k: mat
    plain = os.path.join(WORK, "plain.bin")
    write(plain, os.urandom(4096))
    results = []

    def scenario(title, mode, make_bad, password_ok=True):
        enc = os.path.join(WORK, f"{mode}.enc")
        encrypt_file(plain, enc, mat, EncryptionParams(mode=mode), ks)
        data = read(enc)
        with open(enc, "rb") as f:
            hdr_len = len(read_header(f)[1])
        bad = os.path.join(WORK, "tampered.enc")
        write(bad, make_bad(data, hdr_len))
        try:
            decrypt_file(bad, os.path.join(WORK, "out.bin"), lookup)
            res, detail = "НЕ ВИЯВЛЕНО", "розшифровано без помилок!"
        except AesLabError as e:
            res, detail = "ВИЯВЛЕНО", f"{type(e).__name__}: {e}"
        exists = os.path.exists(os.path.join(WORK, "out.bin"))
        results.append((title, res))
        print(f"[{mode.upper():<3}] {title}\n      -> {res}. {detail}\n      вихідний файл створено: {'так' if exists else 'ні'}")

    print("=== Контроль: непошкоджений файл ===")
    for m in ("gcm", "cbc"):
        enc = os.path.join(WORK, f"{m}.enc")
        encrypt_file(plain, enc, mat, EncryptionParams(mode=m), ks)
        decrypt_file(enc, os.path.join(WORK, "ok.bin"), lookup)
        print(f"[{m.upper()}] розшифровано, збігається з оригіналом:", read(plain) == read(os.path.join(WORK, 'ok.bin')))

    print("\n=== Атаки ===")
    scenario("зміна 1 байта шифртексту", "gcm", lambda d, h: mutate(d, h + 100))
    scenario("зміна 1 байта тегу автентичності", "gcm", lambda d, h: mutate(d, len(d) - 1))
    scenario("зміна заголовка (поле created)", "gcm", lambda d, h: mutate(d, d.index(b'"created":"') + 20))
    scenario("обрізання файлу (відсікли 10 байт)", "gcm", lambda d, h: d[:-10])
    scenario("зміна 1 байта шифртексту", "cbc", lambda d, h: mutate(d, h + 100))
    scenario("зміна 1 байта HMAC", "cbc", lambda d, h: mutate(d, len(d) - 1))
    scenario("зміна IV у заголовку", "cbc", lambda d, h: mutate(d, d.index(b'"iv":"') + 8))
    scenario("обрізання файлу (відсікли 40 байт)", "cbc", lambda d, h: d[:-40])
    scenario("підміна вмісту іншим файлом", "gcm", lambda d, h: b"AESL" + os.urandom(len(d) - 4))

    ok = sum(1 for _, r in results if r == "ВИЯВЛЕНО")
    print(f"\nПідсумок: виявлено {ok} з {len(results)} спроб підміни. Деталі - у logs/aes_lab.log")
    shutil.rmtree(WORK, ignore_errors=True)


if __name__ == "__main__":
    main()
