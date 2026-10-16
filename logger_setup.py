"""JSON-журнал подій (один рядок = один JSON-запис) та аналіз журналу.
Секрети (пароль, ключі, IV/nonce, salt, tag, mac) у журнал не потрапляють."""
import json
import logging
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone

import config

SENSITIVE = {"password", "key", "enc_key", "mac_key", "master", "iv", "nonce", "salt", "tag", "mac"}
_logger = None


class _JsonFormatter(logging.Formatter):
    def format(self, record):
        data = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "level": record.levelname}
        data.update(record.msg)
        return json.dumps(data, ensure_ascii=False)


def _get_logger():
    global _logger
    if _logger is None:
        os.makedirs(os.path.dirname(config.LOG_PATH), exist_ok=True)
        _logger = logging.getLogger("aes_lab")
        _logger.setLevel(logging.INFO)
        _logger.propagate = False
        h = logging.FileHandler(config.LOG_PATH, encoding="utf-8")
        h.setFormatter(_JsonFormatter())
        _logger.addHandler(h)
    return _logger


def log_event(op: str, event: str, level: str = "INFO", **fields):
    """op: encrypt/decrypt/key_new/...; event: start/finish/error."""
    safe = {k: ("***MASKED***" if k.lower() in SENSITIVE else v) for k, v in fields.items()}
    record = {"op": op, "event": event, **safe}
    getattr(_get_logger(), level.lower())(record)


def read_log(path=None):
    path = path or config.LOG_PATH
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


def analyze(path=None):
    """Повертає список рядків-звітів: підсумок і виявлені ознаки інцидентів."""
    rows = read_log(path)
    if not rows:
        return ["Журнал порожній."]
    lines = [f"Записів у журналі: {len(rows)}"]
    cnt = Counter((r.get("op"), r.get("event")) for r in rows)
    for (op, ev), n in sorted(cnt.items(), key=lambda x: str(x)):
        lines.append(f"  {op:<14} {ev:<8} {n}")
    errs = [r for r in rows if r.get("event") == "error"]
    lines.append(f"Помилок: {len(errs)}")
    kinds = Counter(r.get("error") for r in errs)
    for k, n in kinds.items():
        lines.append(f"  {k}: {n}")
    lines.append("--- Ознаки інцидентів ---")
    alerts = 0
    integ = [r for r in errs if r.get("error") == "IntegrityError"]
    if integ:
        alerts += 1
        files = Counter(r.get("file") for r in integ)
        lines.append(f"[ВИСОКИЙ] {len(integ)} випадків tag_valid=false (можлива підміна/пошкодження). Файли: "
                     + ", ".join(f"{f} x{n}" for f, n in files.items()))
    bad_pw = defaultdict(int)
    for r in errs:
        if r.get("error") == "BadPasswordError":
            bad_pw[r.get("key_id", "?")] += 1
    for kid, n in bad_pw.items():
        if n >= 3:
            alerts += 1
            lines.append(f"[СЕРЕДНІЙ] {n} невдалих вводів пароля для ключа {kid}: можливий підбір пароля")
    pol = [r for r in errs if r.get("error") == "KeyPolicyError"]
    if pol:
        alerts += 1
        lines.append(f"[НИЗЬКИЙ] {len(pol)} спроб використати відкликаний/вичерпаний ключ")
    if not alerts:
        lines.append("Ознак інцидентів не виявлено.")
    return lines
