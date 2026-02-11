"""
Core credential store — read and write TOML-based credentials.

Supports both plaintext (.toml) and encrypted (.toml.enc) storage.
Encrypted mode uses AES-256-GCM with PBKDF2 key derivation.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

from .paths import get_credentials_path, ensure_config_dir


_cache: dict[str, Any] | None = None
_custom_path: Path | None = None
_master_password: str | None = None


def init(path: str | Path) -> None:
    """Set a custom credentials file path (overrides default and env var)."""
    global _custom_path, _cache
    _custom_path = Path(path).expanduser()
    _cache = None


def unlock(password: str) -> None:
    """Set the master password for encrypted credentials.

    Call this before any get/set operations when using encrypted mode.
    Alternatively, set the AISAFE_KEY environment variable.

    Args:
        password: The master password to decrypt credentials.
    """
    global _master_password, _cache
    _master_password = password
    _cache = None  # force reload with new password


def _get_password() -> str | None:
    """Get master password from unlock() or AISAFE_KEY env var."""
    if _master_password is not None:
        return _master_password
    return os.environ.get("AISAFE_KEY")


def _get_path() -> Path:
    """Return the active credentials file path."""
    if _custom_path is not None:
        return _custom_path
    return get_credentials_path()


def _get_enc_path() -> Path:
    """Return the encrypted credentials file path."""
    return _get_path().with_suffix(".toml.enc")


def is_encrypted() -> bool:
    """Check if the credential store is in encrypted mode."""
    return _get_enc_path().exists()


def _load() -> dict[str, Any]:
    """Load and cache the credentials file (plaintext or encrypted)."""
    global _cache
    if _cache is not None:
        return _cache

    enc_path = _get_enc_path()
    plain_path = _get_path()

    if enc_path.exists():
        # Encrypted mode
        password = _get_password()
        if password is None:
            raise RuntimeError(
                "凭证已加密，请先调用 aisafe.unlock('password') "
                "或设置环境变量 AISAFE_KEY"
            )
        from .crypto import decrypt

        raw = enc_path.read_bytes()
        plaintext = decrypt(raw, password)
        _cache = tomllib.loads(plaintext.decode("utf-8"))
    elif plain_path.exists():
        # Plaintext mode
        with open(plain_path, "rb") as f:
            _cache = tomllib.load(f)
    else:
        _cache = {}

    return _cache


def _save(data: dict[str, Any]) -> None:
    """Write the credential data back (plaintext or encrypted)."""
    ensure_config_dir()

    toml_bytes = _serialize_toml(data).encode("utf-8")
    enc_path = _get_enc_path()

    if enc_path.exists() or _get_password() is not None:
        # Encrypted mode
        password = _get_password()
        if password is None:
            raise RuntimeError(
                "凭证已加密，请先调用 aisafe.unlock('password') "
                "或设置环境变量 AISAFE_KEY"
            )
        from .crypto import encrypt

        enc_path.write_bytes(encrypt(toml_bytes, password))
        # Remove plaintext file if it exists
        plain_path = _get_path()
        if plain_path.exists():
            plain_path.unlink()
    else:
        # Plaintext mode
        _get_path().write_text(
            toml_bytes.decode("utf-8"), encoding="utf-8"
        )


def _serialize_toml(data: dict[str, Any]) -> str:
    """Serialize data to TOML format."""
    lines: list[str] = []
    for section, values in data.items():
        if isinstance(values, dict):
            lines.append(f"[{section}]")
            for key, val in values.items():
                lines.append(f"{key} = {_toml_value(val)}")
            lines.append("")
        else:
            lines.append(f"{section} = {_toml_value(values)}")
    return "\n".join(lines) + "\n"


def _toml_value(val: Any) -> str:
    """Serialize a Python value to TOML representation."""
    if isinstance(val, bool):
        return "true" if val else "false"
    elif isinstance(val, int):
        return str(val)
    elif isinstance(val, float):
        return str(val)
    elif isinstance(val, str):
        escaped = val.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    else:
        return f'"{val}"'


def reload() -> None:
    """Clear cache and force reload on next access."""
    global _cache
    _cache = None


def get(key: str, default: Any = None) -> Any:
    """Get a credential value.

    Args:
        key: Dot-separated key, e.g. 'database.password'.
        default: Value to return if key is not found.
    """
    data = _load()
    parts = key.split(".", 1)
    if len(parts) == 2:
        section, field = parts
        return data.get(section, {}).get(field, default)
    return data.get(parts[0], default)


def get_section(section: str) -> dict[str, Any]:
    """Get all key-value pairs in a section."""
    data = _load()
    result = data.get(section, {})
    return dict(result) if isinstance(result, dict) else {}


def set(key: str, value: Any) -> None:
    """Set a credential value."""
    data = _load().copy()
    parts = key.split(".", 1)

    if len(parts) == 2:
        section, field = parts
        if section not in data:
            data[section] = {}
        elif not isinstance(data[section], dict):
            data[section] = {}
        data[section] = dict(data[section])
        data[section][field] = value
    else:
        data[parts[0]] = value

    _save(data)
    reload()


def remove(key: str) -> bool:
    """Remove a credential value."""
    data = _load().copy()
    parts = key.split(".", 1)

    if len(parts) == 2:
        section, field = parts
        if section in data and isinstance(data[section], dict):
            data[section] = dict(data[section])
            if field in data[section]:
                del data[section][field]
                if not data[section]:
                    del data[section]
                _save(data)
                reload()
                return True
    else:
        if parts[0] in data:
            del data[parts[0]]
            _save(data)
            reload()
            return True

    return False


def list_sections() -> list[str]:
    """List all section names in the credentials file."""
    data = _load()
    return [k for k, v in data.items() if isinstance(v, dict)]


def list_keys(section: str | None = None) -> list[str]:
    """List all keys, optionally filtered by section."""
    data = _load()
    if section:
        sec_data = data.get(section, {})
        if isinstance(sec_data, dict):
            return list(sec_data.keys())
        return []

    keys: list[str] = []
    for sec_name, sec_data in data.items():
        if isinstance(sec_data, dict):
            for key in sec_data:
                keys.append(f"{sec_name}.{key}")
        else:
            keys.append(sec_name)
    return keys


def encrypt_store(password: str) -> None:
    """Encrypt an existing plaintext credential file.

    Reads the plaintext TOML, encrypts it, and removes the plaintext file.
    """
    global _master_password
    plain_path = _get_path()
    if not plain_path.exists():
        raise FileNotFoundError(f"明文凭证文件不存在: {plain_path}")

    with open(plain_path, "rb") as f:
        data = f.read()

    from .crypto import encrypt as crypto_encrypt

    enc_path = _get_enc_path()
    enc_path.write_bytes(crypto_encrypt(data, password))
    plain_path.unlink()
    _master_password = password
    reload()


def decrypt_store(password: str) -> None:
    """Decrypt the credential file back to plaintext.

    Reads the encrypted file, decrypts it, and writes plaintext TOML.
    """
    global _master_password
    enc_path = _get_enc_path()
    if not enc_path.exists():
        raise FileNotFoundError(f"加密凭证文件不存在: {enc_path}")

    from .crypto import decrypt as crypto_decrypt

    raw = enc_path.read_bytes()
    plaintext = crypto_decrypt(raw, password)

    plain_path = _get_path()
    plain_path.write_bytes(plaintext)
    enc_path.unlink()
    _master_password = None
    reload()
