"""Бенчмарк шифрування/дешифрування файлів різного розміру.
Запуск:  py benchmark.py --modes cbc gcm --sizes 1MB 10MB 100MB --repeat 3
Результат: outputs/bench.csv та outputs/bench.md  (1 MB = 1 048 576 байт)
Вимірюється: час (wall), процесорний час, пропускна здатність MB/s, пік пам'яті Python (tracemalloc),
накладні витрати контейнера. Ключі генеруються випадково (PBKDF2 міряється окремо)."""
import argparse
import csv
import os
import statistics
import sys
import time
import tracemalloc

import config
from crypto_aes import EncryptionParams, decrypt_file, encrypt_file
from key_manager import KeyMaterial, derive

MB = 1024 * 1024


def parse_size(s):
    s = s.upper().strip()
    if not s.endswith("MB"):
        raise SystemExit(f"Розмір задається у MB, напр. 10MB (отримано '{s}')")
    return int(s[:-2]) * MB


def make_file(path, size):
    if os.path.exists(path) and os.path.getsize(path) == size:
        return
    with open(path, "wb") as f:
        left = size
        while left:
            n = min(left, MB)
            f.write(os.urandom(n))
            left -= n


def timed(fn):
    w, c = time.perf_counter(), time.process_time()
    fn()
    return time.perf_counter() - w, time.process_time() - c


def peak_mem(fn):
    tracemalloc.start()
    fn()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak / MB


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--modes", nargs="+", default=["cbc", "gcm"], choices=["cbc", "gcm", "ctr"])
    ap.add_argument("--sizes", nargs="+", default=["1MB", "10MB", "100MB"])
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--keybits", type=int, default=256, choices=config.KEY_SIZES_BITS)
    a = ap.parse_args(argv)

    os.makedirs(config.DATA_DIR, exist_ok=True)
    os.makedirs(config.OUTPUT_DIR, exist_ok=True)
    # --- вартість KDF
    salt = os.urandom(16)
    kdf_t = []
    for _ in range(3):
        t = time.perf_counter()
        derive("BenchPassword123", salt, config.PBKDF2_ITERATIONS, a.keybits)
        kdf_t.append(time.perf_counter() - t)
    kdf_ms = statistics.mean(kdf_t) * 1000
    print(f"PBKDF2-HMAC-SHA256, {config.PBKDF2_ITERATIONS} ітерацій: {kdf_ms:.0f} мс (разова вартість при вводі пароля)")

    mat = KeyMaterial("bench", a.keybits, os.urandom(a.keybits // 8), os.urandom(32))
    rows = []
    for size_s in a.sizes:
        size = parse_size(size_s)
        src = os.path.join(config.DATA_DIR, f"bench_{size_s}.bin")
        print(f"Готуємо файл {src} ...")
        make_file(src, size)
        for mode in a.modes:
            enc_p, dec_p = os.path.join(config.OUTPUT_DIR, "bench.enc"), os.path.join(config.OUTPUT_DIR, "bench.dec")
            params = EncryptionParams(mode=mode)
            et, ec, dt, dc = [], [], [], []
            for _ in range(a.repeat):
                w, c = timed(lambda: encrypt_file(src, enc_p, mat, params))
                et.append(w); ec.append(c)
                w, c = timed(lambda: decrypt_file(enc_p, dec_p, lambda k: mat))
                dt.append(w); dc.append(c)
            overhead = os.path.getsize(enc_p) - size
            mem_e = peak_mem(lambda: encrypt_file(src, enc_p, mat, params))
            mem_d = peak_mem(lambda: decrypt_file(enc_p, dec_p, lambda k: mat))
            e, d = statistics.mean(et), statistics.mean(dt)
            rows.append({"mode": mode.upper(), "key_bits": a.keybits, "size_MB": size // MB,
                         "enc_s": round(e, 4), "dec_s": round(d, 4),
                         "enc_MBps": round(size / MB / e, 1), "dec_MBps": round(size / MB / d, 1),
                         "enc_cpu_s": round(statistics.mean(ec), 3), "dec_cpu_s": round(statistics.mean(dc), 3),
                         "peak_mem_MB": round(max(mem_e, mem_d), 2), "overhead_B": overhead})
            r = rows[-1]
            print(f"  {r['mode']:<4} {r['size_MB']:>4} MB: enc {r['enc_s']}s ({r['enc_MBps']} MB/s), "
                  f"dec {r['dec_s']}s ({r['dec_MBps']} MB/s), пам'ять {r['peak_mem_MB']} MB")
        for p in (enc_p, dec_p):
            if os.path.exists(p):
                os.remove(p)

    csv_path, md_path = os.path.join(config.OUTPUT_DIR, "bench.csv"), os.path.join(config.OUTPUT_DIR, "bench.md")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)
    keys = list(rows[0].keys())
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"PBKDF2-HMAC-SHA256, {config.PBKDF2_ITERATIONS} ітерацій: {kdf_ms:.0f} мс\n\n")
        f.write("| " + " | ".join(keys) + " |\n|" + "---|" * len(keys) + "\n")
        for r in rows:
            f.write("| " + " | ".join(str(r[k]) for k in keys) + " |\n")
    print(f"\nЗбережено: {csv_path}\n           {md_path}")


if __name__ == "__main__":
    main(sys.argv[1:])
