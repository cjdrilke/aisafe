"""
Core credential store — read and write TOML-based credentials.

Provides get/set/remove/list operations on a TOML credentials file.
Write operations use manual TOML serialization to avoid external dependencies.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from .paths import get_credentials_path, ensure_config_dir


_cache: dict[str, Any] | None = None
_custom_path: Path | None = None


def init(path: str | Path) -> None:
    """Set a custom credentials file path (overrides default and env var)."""
    global _custom_path, _cache
    _custom_path = Path(path).expanduser()
    _cache = None


def _get_path() -> Path:
    """Return the active credentials file path."""
    if _custom_path is not None:
        return _custom_path
    return get_credentials_path()


def _load() -> dict[str, Any]:
    """Load and cache the credentials file."""
    global _cache
    if _cache is not None:
        return _cache

    path = _get_path()
    if not path.exists():
        _cache = {}
        return _cache

    with open(path, "rb") as f:
        _cache = tomllib.load(f)
    return _cache


def _save(data: dict[str, Any]) -> None:
    """Write the credential data back to TOML format."""
    path = _get_path()
    ensure_config_dir()
    path.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    for section, values in data.items():
        if isinstance(values, dict):
            lines.append(f"[{section}]")
            for key, val in values.items():
                lines.append(f"{key} = {_toml_value(val)}")
            lines.append("")
        else:
            # Top-level key (rare but supported)
            lines.append(f"{section} = {_toml_value(values)}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _toml_value(val: Any) -> str:
    """Serialize a Python value to TOML representation."""
    if isinstance(val, bool):
        return "true" if val else "false"
    elif isinstance(val, int):
        return str(val)
    elif isinstance(val, float):
        return str(val)
    elif isinstance(val, str):
        # Escape backslashes and quotes
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
        key: Dot-separated key, e.g. 'database.password' or 'api.key'.
        default: Value to return if key is not found.

    Returns:
        The credential value, or default if not found.
    """
    data = _load()
    parts = key.split(".", 1)
    if len(parts) == 2:
        section, field = parts
        return data.get(section, {}).get(field, default)
    return data.get(parts[0], default)


def get_section(section: str) -> dict[str, Any]:
    """Get all key-value pairs in a section.

    Args:
        section: Section name, e.g. 'database'.

    Returns:
        A dict of the section contents, or empty dict if not found.
    """
    data = _load()
    result = data.get(section, {})
    return dict(result) if isinstance(result, dict) else {}


def set(key: str, value: Any) -> None:
    """Set a credential value.

    Args:
        key: Dot-separated key, e.g. 'database.password'.
        value: The value to store.
    """
    data = _load().copy()
    parts = key.split(".", 1)

    if len(parts) == 2:
        section, field = parts
        if section not in data:
            data[section] = {}
        elif not isinstance(data[section], dict):
            data[section] = {}
        data[section] = dict(data[section])  # ensure mutable copy
        data[section][field] = value
    else:
        data[parts[0]] = value

    _save(data)
    reload()


def remove(key: str) -> bool:
    """Remove a credential value.

    Args:
        key: Dot-separated key, e.g. 'database.password'.
              If only section name given, removes entire section.

    Returns:
        True if the key was found and removed, False otherwise.
    """
    data = _load().copy()
    parts = key.split(".", 1)

    if len(parts) == 2:
        section, field = parts
        if section in data and isinstance(data[section], dict):
            data[section] = dict(data[section])
            if field in data[section]:
                del data[section][field]
                # Remove empty sections
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
    """List all keys, optionally filtered by section.

    Args:
        section: If given, list keys within that section.
                 If None, list all section.key combinations.
    """
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
