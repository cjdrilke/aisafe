"""
AES-GCM encryption for credential files.

Uses PBKDF2 for key derivation and AES-256-GCM for authenticated encryption.
All operations use the `cryptography` library.

File format (.enc):
    [16 bytes salt][12 bytes nonce][16 bytes tag][N bytes ciphertext]
"""

from __future__ import annotations

import os
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# PBKDF2 参数
PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16
KEY_SIZE = 32  # AES-256
NONCE_SIZE = 12  # GCM standard


def derive_key(password: str, salt: bytes) -> bytes:
    """从密码派生 AES-256 密钥 (PBKDF2-HMAC-SHA256)"""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=KEY_SIZE,
    )


def encrypt(plaintext: bytes, password: str) -> bytes:
    """加密数据，返回 salt + nonce + tag + ciphertext

    Args:
        plaintext: 待加密的明文字节
        password: master password

    Returns:
        加密后的字节: salt(16) + nonce(12) + ciphertext_with_tag
    """
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    # GCM 模式的 encrypt 返回 ciphertext + tag(16 bytes)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    return salt + nonce + ciphertext_with_tag


def decrypt(data: bytes, password: str) -> bytes:
    """解密数据

    Args:
        data: encrypt() 返回的完整字节
        password: master password

    Returns:
        解密后的明文字节

    Raises:
        ValueError: 密码错误或数据被篡改
    """
    if len(data) < SALT_SIZE + NONCE_SIZE + 16:
        raise ValueError("Invalid encrypted data: too short")

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    ciphertext_with_tag = data[SALT_SIZE + NONCE_SIZE :]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        return aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    except Exception:
        raise ValueError("解密失败：密码错误或数据已损坏")
