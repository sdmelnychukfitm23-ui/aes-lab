"""Консольний застосунок AES-Lab (REPL). Запуск:  py aes_cli.py
Команди вводяться по черзі; режим шифрування можна змінювати «на льоту» без перезапуску (команда mode)."""
import cmd
import getpass
import os
import shlex
import time

import config
import logger_setup
from crypto_aes import EncryptionParams, decrypt_file, encrypt_file, read_header
from errors import AesLabError
from key_manager import KeyStore
from logger_setup import log_event


def ask_password(prompt="Пароль: "):
    return os.environ.get("AES_LAB_PASSWORD") or getpass.getpass(prompt)


class Shell(cmd.Cmd):
    intro = ("\n=== AES-Lab: шифрування файлів AES (GCM / CBC+HMAC / CTR+HMAC) ===\n"
             "Введіть help для списку команд, exit для виходу.\n")
    prompt = "aes-lab> "

    def __init__(self):
        super().__init__()
        self.ks = KeyStore()
        self.params = EncryptionParams()
        self.new_key_bits = config.DEFAULT_KEY_BITS
        self.unlocked = {}          # key_id -> KeyMaterial (лише в пам'яті)
        self.active = None          # key_id, яким шифруємо

    # ---------------------------------------------------------------- допоміжні
    def onecmd(self, line):
        try:
            return super().onecmd(line)
        except AesLabError as e:
            print(f"ПОМИЛКА [{type(e).__name__}]: {e}")
        except (OSError, ValueError) as e:
            print(f"ПОМИЛКА: {e}")

    def emptyline(self):
        pass

    def _lookup(self, key_id):
        if key_id not in self.unlocked:
            print(f"Для розшифрування потрібен ключ {key_id}.")
            t = time.perf_counter()
            self.unlocked[key_id] = self.ks.unlock(key_id, ask_password(f"Пароль до ключа {key_id}: "))
            print(f"Ключ розблоковано за {(time.perf_counter() - t) * 1000:.0f} мс (PBKDF2).")
        return self.unlocked[key_id]

    def _args(self, arg):
        return [x.strip('"') for x in shlex.split(arg, posix=(os.name != "nt"))]

    # ---------------------------------------------------------------- команди
    def do_status(self, arg):
        """status - поточні налаштування"""
        p = self.params
        print(f"  режим          : {p.mode.upper()}")
        print(f"  паддинг (CBC)  : {p.padding}")
        print(f"  довжина IV     : {p.iv_len or 'за замовчуванням'} (значення IV завжди випадкове)")
        print(f"  розмір блоку   : {p.block_bits} біт, шматок {p.chunk_size // 1024} KiB")
        print(f"  нові ключі     : AES-{self.new_key_bits}")
        print(f"  активний ключ  : {self.active or '— (виконайте key new або key use <id>)'}")

    def do_mode(self, arg):
        """mode <gcm|cbc|ctr> - змінити режим шифрування без перезапуску"""
        new = arg.strip().lower()
        old = self.params.mode
        p = EncryptionParams(mode=new, padding=self.params.padding, chunk_size=self.params.chunk_size)
        p.validate()
        self.params = p
        log_event("mode_change", "finish", old=old, new=new)
        print(f"Режим змінено: {old.upper()} -> {new.upper()}")

    def do_set(self, arg):
        """set padding <pkcs7|ansix923> | set iv <12|16> | set keybits <128|192|256> | set chunk <KiB>"""
        a = self._args(arg)
        if len(a) != 2:
            print(self.do_set.__doc__)
            return
        k, v = a[0].lower(), a[1].lower()
        p = self.params
        if k == "padding":
            new = EncryptionParams(mode=p.mode, padding=v, iv_len=p.iv_len, chunk_size=p.chunk_size)
        elif k == "iv":
            new = EncryptionParams(mode=p.mode, padding=p.padding, iv_len=int(v), chunk_size=p.chunk_size)
        elif k == "chunk":
            new = EncryptionParams(mode=p.mode, padding=p.padding, iv_len=p.iv_len, chunk_size=int(v) * 1024)
        elif k == "keybits":
            if int(v) not in config.KEY_SIZES_BITS:
                print(f"Допустимо: {config.KEY_SIZES_BITS}")
                return
            self.new_key_bits = int(v)
            print(f"Нові ключі будуть AES-{v}")
            return
        else:
            print(self.do_set.__doc__)
            return
        new.validate()
        self.params = new
        print("Параметри оновлено.")

    def do_key(self, arg):
        """key new [мітка] | key list | key use <id> | key lock | key revoke <id> | key rotate <id>"""
        a = self._args(arg)
        if not a:
            print(self.do_key.__doc__)
            return
        sub = a[0].lower()
        if sub == "new":
            pw = ask_password("Придумайте пароль (≥10 символів, літери+цифри): ")
            if "AES_LAB_PASSWORD" not in os.environ and getpass.getpass("Повторіть пароль: ") != pw:
                print("Паролі не збігаються.")
                return
            kid = self.ks.create(pw, self.new_key_bits, label=" ".join(a[1:]))
            self.unlocked[kid] = self.ks.unlock(kid, pw)
            self.active = kid
            print(f"Створено ключ AES-{self.new_key_bits}, key_id = {kid}. Він активний.")
        elif sub == "list":
            keys = self.ks.list()
            if not keys:
                print("Keystore порожній.")
            for k in keys:
                mark = "*" if k["key_id"] == self.active else " "
                print(f" {mark} {k['key_id']}  AES-{k['key_bits']}  {k['status']:<8} "
                      f"uses {k['uses']}/{k['max_uses']}  до {k['expires_at'][:10]}  {k['label']}")
        elif sub == "use" and len(a) == 2:
            self.unlocked[a[1]] = self.ks.unlock(a[1], ask_password(f"Пароль до ключа {a[1]}: "))
            self.active = a[1]
            print(f"Ключ {a[1]} розблоковано й обрано активним.")
        elif sub == "lock":
            for m in self.unlocked.values():
                m.close()
            self.unlocked.clear()
            self.active = None
            print("Усі ключі видалено з пам'яті.")
        elif sub == "revoke" and len(a) == 2:
            self.ks.revoke(a[1])
            print(f"Ключ {a[1]} відкликано: шифрувати ним більше не можна, розшифровувати - можна.")
        elif sub == "rotate" and len(a) == 2:
            pw = ask_password(f"Пароль до ключа {a[1]}: ")
            new = self.ks.rotate(a[1], pw)
            self.unlocked[new] = self.ks.unlock(new, pw)
            self.active = new
            print(f"Ротація виконана. Старий {a[1]} відкликано, новий активний ключ: {new}")
        else:
            print(self.do_key.__doc__)

    def do_encrypt(self, arg):
        """encrypt <файл> [вихід] - зашифрувати файл поточним режимом і активним ключем"""
        a = self._args(arg)
        if not a:
            print(self.do_encrypt.__doc__)
            return
        if not self.active:
            print("Немає активного ключа. Виконайте: key new   або   key use <id>")
            return
        dst = a[1] if len(a) > 1 else os.path.join(config.OUTPUT_DIR, os.path.basename(a[0]) + ".enc")
        r = encrypt_file(a[0], dst, self.unlocked[self.active], self.params, self.ks)
        print(f"Готово: {dst}")
        print(f"  режим {r['mode'].upper()}, AES-{r['key_bits']}, {r['in_bytes']} Б -> {r['out_bytes']} Б, "
              f"{r['seconds'] * 1000:.2f} мс ({r['mb_s']:.1f} MB/s)")

    def do_decrypt(self, arg):
        """decrypt <файл.enc> [вихід] - розшифрувати (режим і ключ беруться із заголовка файлу)"""
        a = self._args(arg)
        if not a:
            print(self.do_decrypt.__doc__)
            return
        base = os.path.basename(a[0])
        base = base[:-4] if base.endswith(".enc") else base
        dst = a[1] if len(a) > 1 else os.path.join(config.OUTPUT_DIR, base + ".dec")
        r = decrypt_file(a[0], dst, self._lookup, self.params.chunk_size)
        print(f"Готово: {dst}  (тег/HMAC перевірено: цілісність підтверджено)")
        print(f"  режим {r['mode'].upper()}, AES-{r['key_bits']}, ключ {r['key_id']}, {r['out_bytes']} Б, "
              f"{r['seconds'] * 1000:.2f} мс ({r['mb_s']:.1f} MB/s)")

    def do_info(self, arg):
        """info <файл.enc> - показати заголовок контейнера (без секретів)"""
        with open(arg.strip().strip('"'), "rb") as f:
            h, raw = read_header(f)
        print(f"  заголовок: {len(raw)} Б")
        for k in ("v", "mode", "key_bits", "key_id", "padding", "orig_size", "created"):
            print(f"  {k:<10}: {h.get(k)}")
        print(f"  iv/nonce  : {len(__import__('base64').b64decode(h['iv']))} байт")

    def do_tamper(self, arg):
        """tamper <файл.enc> [body|tag|header] - створити копію з 1 зміненим байтом (<файл>.tampered)"""
        a = self._args(arg)
        if not a:
            print(self.do_tamper.__doc__)
            return
        part = a[1].lower() if len(a) > 1 else "body"
        with open(a[0], "rb") as f:
            data = bytearray(f.read())
            f.seek(0)
            hlen = len(read_header(f)[1])
        pos = {"body": hlen + (len(data) - hlen) // 3, "tag": len(data) - 1,
               "header": data.index(b'"created":"') + 20}.get(part)
        if pos is None:
            print(self.do_tamper.__doc__)
            return
        data[pos] ^= 0x01
        out = a[0] + ".tampered"
        with open(out, "wb") as f:
            f.write(bytes(data))
        print(f"Змінено 1 байт ({part}, позиція {pos}). Створено {out}. Тепер спробуйте: decrypt {out}")
        log_event("tamper_sim", "finish", file=os.path.basename(a[0]), part=part)

    def do_bench(self, arg):
        """bench - швидкий бенчмарк (1MB, 10MB; повний - окремо: py benchmark.py)"""
        import benchmark
        benchmark.main(["--modes", "cbc", "gcm", "ctr", "--sizes", "1MB", "10MB", "--repeat", "2"])

    def do_logs(self, arg):
        """logs summary - аналіз журналу | logs tail [N] - останні N записів"""
        a = self._args(arg)
        if a and a[0] == "tail":
            n = int(a[1]) if len(a) > 1 else 10
            for r in logger_setup.read_log()[-n:]:
                print(" ", r)
        else:
            for ln in logger_setup.analyze():
                print(ln)

    def do_exit(self, arg):
        """exit - вийти (ключі з пам'яті видаляються)"""
        for m in self.unlocked.values():
            m.close()
        print("До побачення.")
        return True

    do_quit = do_exit
    do_EOF = do_exit


if __name__ == "__main__":
    Shell().cmdloop()
