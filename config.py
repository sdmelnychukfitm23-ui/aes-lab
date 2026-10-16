"""Параметри за замовчуванням (змінюються в одному місці)."""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYSTORE_PATH = os.path.join(BASE_DIR, "keystore.json")
LOG_PATH = os.path.join(BASE_DIR, "logs", "aes_lab.log")
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")
DATA_DIR = os.path.join(BASE_DIR, "data")

# --- KDF (PBKDF2-HMAC-SHA256)
KDF_NAME = "PBKDF2-HMAC-SHA256"
PBKDF2_ITERATIONS = 310_000        # демо-значення з завдання
MIN_ITERATIONS = 200_000           # нижче - ключ вважається небезпечним
SALT_LEN = 16                      # байт, випадковий salt
MIN_PASSWORD_LEN = 10

# --- ключі
KEY_SIZES_BITS = (128, 192, 256)
DEFAULT_KEY_BITS = 256
MAX_USES = 10                      # ротація: після M шифрувань ключ блокується для шифрування
MAX_AGE_DAYS = 90                  # ротація: або через N днів

# --- шифрування
DEFAULT_MODE = "gcm"
DEFAULT_PADDING = "pkcs7"
CHUNK_SIZE = 1024 * 1024           # 1 MiB: файл обробляється шматками (потоково)
FORMAT_VERSION = 1
