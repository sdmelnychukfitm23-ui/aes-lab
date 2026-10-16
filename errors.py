"""Власні винятки: програма показує зрозумілу помилку, а не 'падає'."""


class AesLabError(Exception):
    """Базовий виняток."""


class ParamError(AesLabError):
    """Некоректні параметри (режим, довжина ключа, паддинг, слабкий пароль)."""


class FormatError(AesLabError):
    """Файл не є контейнером AES-Lab або заголовок пошкоджений."""


class IntegrityError(AesLabError):
    """Тег GCM / HMAC не збігається: дані або заголовок змінено."""


class BadPasswordError(AesLabError):
    """Неправильний пароль до ключа."""


class KeyPolicyError(AesLabError):
    """Ключ відкликано, прострочено або вичерпано ліміт використань."""
