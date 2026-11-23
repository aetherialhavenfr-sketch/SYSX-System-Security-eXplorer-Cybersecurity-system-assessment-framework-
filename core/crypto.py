"""Encryption for stored test credentials (Fernet: AES-128-CBC + HMAC-SHA256)."""
from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken


class VaultError(Exception):
    pass


class Vault:
    def __init__(self, key: str | bytes):
        try:
            self._fernet = Fernet(key)
        except (ValueError, TypeError) as exc:
            raise VaultError("SYSX_ENCRYPTION_KEY is not a valid Fernet key.") from exc

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise VaultError("Stored secret cannot be decrypted with the current key.") from exc
