"""
Core credential store — read and write TOML-based credentials,
gated by the policy engine and audit log.

Supports both plaintext (.toml) and encrypted (.toml.enc) storage.
Encrypted mode uses AES-256-GCM with PBKDF2 key derivation.

Every read/write passes through:
  policy.evaluate(key)  →  allow / deny / stub / require-confirm
  audit.record(...)     →  append-only JSONL log

Reads that are denied return the `default` value rather than raising,
because raising an exception itself can leak (the AI sees the traceback
and learns that a sensitive key exists at that path).
"""

from __future__ import annotations

import os
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

from .paths import get_credentials_path, ensure_config_dir
from . import policy as _policy
from . import audit as _audit


# Credential keys are dotted identifiers. Each segment must start with a
# letter and contain only letters/digits/underscore/hyphen. This keeps the
# TOML serialization unambiguous and prevents an AI from picking a key name
# that injects TOML metadata.
_KEY_SEGMENT_RE = re.compile(r"[A-Za-z][A-Za-z0-9_\-]*")
# Credential keys are either a single identifier ("topkey") or a
# section.field pair ("database.password"). The store only supports two
# levels of nesting (one section + one field); deeper dotted keys would
# get truncated by split(".", 1) and create TOML serialization ambiguity.
_KEY_FULL_RE = re.compile(
    rf"^{_KEY_SEGMENT_RE.pattern}(\.{_KEY_SEGMENT_RE.pattern})?$"
)


def _validate_key(key: str) -> None:
    """Reject credential keys that aren't simple dotted identifiers."""
    if not isinstance(key, str):
        raise ValueError(f"key must be a string, got {type(key).__name__}")
    if not key:
        raise ValueError("key must not be empty")
    if len(key) > 256:
        raise ValueError(f"key too long ({len(key)} > 256)")
    if not _KEY_FULL_RE.fullmatch(key):
        raise ValueError(
            f"invalid key {key!r}: must be either 'identifier' or "
            "'section.field', where each segment matches "
            "<letter>[<letter|digit|_|->...]"
        )


_cache: dict[str, Any] | None = None
# Path the current `_cache` was loaded from. When `_get_path()` returns a
# different path (e.g. AI just appeared and we're now ignoring the prior
# `_custom_path`), the cache is stale and must be reloaded from the new
# canonical path.
_cache_path: Path | None = None
_custom_path: Path | None = None
_master_password: str | None = None


class AccessDenied(Exception):
    """Raised by explicit-fail APIs when a credential access is denied by policy."""


def init(path: str | Path) -> None:
    """Set a custom credentials file path (overrides default and env var).

    Refused when an AI agent is detected — otherwise the AI could redirect
    the store to an attacker-controlled file containing poisoned credentials
    that would then be injected into `aisafe exec` deploy scripts.
    """
    global _custom_path, _cache
    from . import detect as _detect
    ai = _detect.detect()
    if ai is not None:
        _audit.record(
            "init", "*",
            result="deny", ai=ai,
            reason="aisafe.init() refused under AI detection",
            extra={"requested_path": str(path)},
        )
        raise AccessDenied(
            f"refusing aisafe.init({str(path)!r}) under AI detection ({ai}). "
            f"The store path is enforced for AI callers."
        )
    _custom_path = Path(path).expanduser()
    _cache = None


def unlock(password: str) -> None:
    """Set the master password for encrypted credentials.

    Call this before any get/set operations when using encrypted mode.
    Alternatively, set the AISAFE_KEY environment variable.
    """
    global _master_password, _cache, _cache_path
    _master_password = password
    _cache = None  # force reload with new password
    _cache_path = None
    _audit.record("unlock", "*", result="allow", reason="master password set")


def _get_password() -> str | None:
    """Get master password from unlock() or AISAFE_KEY env var."""
    if _master_password is not None:
        return _master_password
    return os.environ.get("AISAFE_KEY")


def _get_path() -> Path:
    """Return the active credentials file path.

    A `_custom_path` set via `aisafe.init()` (by an earlier human caller)
    is IGNORED once an AI agent is detected — otherwise an attacker who
    can pivot from human to AI execution within the same Python process
    could keep the human-era custom path active and use it to feed
    poisoned credentials into `aisafe exec` deploy scripts.
    """
    if _custom_path is not None:
        from . import detect as _detect
        ai = _detect.detect()
        if ai is not None:
            print(
                f"aisafe: ignoring earlier aisafe.init() custom path under AI "
                f"detection ({ai}); using default credentials path",
                file=sys.stderr,
            )
            return get_credentials_path()
        return _custom_path
    return get_credentials_path()


def _get_enc_path() -> Path:
    """Return the encrypted credentials file path."""
    return _get_path().with_suffix(".toml.enc")


def is_encrypted() -> bool:
    """Check if the credential store is in encrypted mode."""
    return _get_enc_path().exists()


def _load() -> dict[str, Any]:
    """Load and cache the credentials file (plaintext or encrypted).

    The cache is keyed by the path that produced it. If `_get_path()` now
    returns a different path than the cached one — most importantly when
    AI detection has just become true and the prior `_custom_path` is
    being ignored — we invalidate and reload from the new canonical path.
    """
    global _cache, _cache_path

    enc_path = _get_enc_path()
    plain_path = _get_path()

    if _cache is not None and _cache_path == plain_path:
        return _cache

    # Path changed (e.g. AI just appeared, _custom_path ignored). Drop any
    # cleartext credential data that came from the old (possibly poisoned)
    # path before reloading.
    _cache = None
    _cache_path = None

    if enc_path.exists():
        password = _get_password()
        if password is None:
            raise RuntimeError(
                "credentials are encrypted; call aisafe.unlock('password') "
                "or set the AISAFE_KEY environment variable"
            )
        from .crypto import decrypt

        raw = enc_path.read_bytes()
        plaintext = decrypt(raw, password)
        _cache = tomllib.loads(plaintext.decode("utf-8"))
    elif plain_path.exists():
        with open(plain_path, "rb") as f:
            _cache = tomllib.load(f)
    else:
        _cache = {}

    _cache_path = plain_path
    return _cache


def _chmod_600(path: Path) -> None:
    """Restrict a credential file to owner read/write only.

    Best-effort: silently skipped on filesystems / platforms that don't
    support POSIX permissions (Windows FAT, some network shares).
    """
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _save(data: dict[str, Any]) -> None:
    """Write the credential data back (plaintext or encrypted)."""
    ensure_config_dir()

    toml_bytes = _serialize_toml(data).encode("utf-8")
    enc_path = _get_enc_path()

    if enc_path.exists() or _get_password() is not None:
        password = _get_password()
        if password is None:
            raise RuntimeError(
                "credentials are encrypted; call aisafe.unlock('password') "
                "or set the AISAFE_KEY environment variable"
            )
        from .crypto import encrypt

        enc_path.write_bytes(encrypt(toml_bytes, password))
        _chmod_600(enc_path)
        plain_path = _get_path()
        if plain_path.exists():
            plain_path.unlink()
    else:
        plain_path = _get_path()
        plain_path.write_text(toml_bytes.decode("utf-8"), encoding="utf-8")
        _chmod_600(plain_path)


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
    """Serialize a Python value to a TOML basic-string literal.

    TOML basic strings forbid raw control characters; escape them per
    the spec so that a credential containing \\n / \\r / \\x00 / etc.
    round-trips cleanly and cannot break out of the quoted literal.
    """
    if isinstance(val, bool):
        return "true" if val else "false"
    elif isinstance(val, int):
        return str(val)
    elif isinstance(val, float):
        return str(val)
    elif isinstance(val, str):
        out: list[str] = []
        for c in val:
            o = ord(c)
            if c == "\\":
                out.append("\\\\")
            elif c == '"':
                out.append('\\"')
            elif c == "\b":
                out.append("\\b")
            elif c == "\t":
                out.append("\\t")
            elif c == "\n":
                out.append("\\n")
            elif c == "\f":
                out.append("\\f")
            elif c == "\r":
                out.append("\\r")
            elif o < 0x20 or o == 0x7F:
                out.append(f"\\u{o:04X}")
            else:
                out.append(c)
        return '"' + "".join(out) + '"'
    else:
        return _toml_value(str(val))


def reload() -> None:
    """Clear cache and force reload on next access."""
    global _cache, _cache_path
    _cache = None
    _cache_path = None


def _raw_get(key: str, default: Any = None) -> Any:
    """Internal: fetch a value bypassing policy. Used by exec/MCP layers
    that have already enforced their own access checks."""
    data = _load()
    parts = key.split(".", 1)
    if len(parts) == 2:
        section, field = parts
        sec = data.get(section, {})
        if isinstance(sec, dict):
            return sec.get(field, default)
        return default
    return data.get(parts[0], default)


def _check_read(key: str) -> tuple[bool, _policy.Decision]:
    """Evaluate policy + audit for a read. Returns (allowed, decision)."""
    decision = _policy.evaluate(key, action="read")

    # `confirm` policy: upgrade to allow via TTY prompt.
    if not decision.allow and decision.policy == "confirm":
        if _policy.confirm_interactive(key, decision.ai):
            decision = _policy.Decision(
                allow=True, policy="confirm", ai=decision.ai, reason="user confirmed"
            )
            _audit.record(
                "read", key,
                result="allow", policy="confirm", ai=decision.ai,
                reason="user confirmed at TTY",
            )
            return True, decision
        else:
            _audit.record(
                "read", key,
                result="deny", policy="confirm", ai=decision.ai,
                reason="user declined or no TTY",
            )
            return False, decision

    result = "stub" if decision.redact else ("allow" if decision.allow else "deny")
    _audit.record(
        "read", key,
        result=result,
        policy=decision.policy,
        ai=decision.ai,
        reason=decision.reason or None,
    )
    return decision.allow, decision


def get(key: str, default: Any = None) -> Any:
    """Get a credential value, gated by the policy engine.

    Args:
        key: Dot-separated key, e.g. 'database.password'.
        default: Value to return when the key is missing OR access is denied.
                 The same return value is used for "key not found" and "access
                 denied" so the caller (which may be AI) cannot distinguish.
    """
    allowed, decision = _check_read(key)
    if not allowed:
        return default
    if decision.redact:
        return _policy.REDACTED_TEMPLATE.format(key=key)
    return _raw_get(key, default)


def get_section(section: str) -> dict[str, Any]:
    """Get all key-value pairs in a section, gated per-key by policy."""
    data = _load()
    raw = data.get(section, {})
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    for field, val in raw.items():
        full_key = f"{section}.{field}"
        allowed, decision = _check_read(full_key)
        if not allowed:
            continue
        if decision.redact:
            out[field] = _policy.REDACTED_TEMPLATE.format(key=full_key)
        else:
            out[field] = val
    return out


def set(key: str, value: Any) -> None:
    """Set a credential value, gated by the policy engine.

    Writes are denied if an AI agent is detected unless the policy is
    'open' or 'audit_only', because the user almost never wants an AI
    silently overwriting their secrets.
    """
    _validate_key(key)
    decision = _policy.evaluate(key, action="write")
    if not decision.allow:
        _audit.record(
            "write", key,
            result="deny", policy=decision.policy, ai=decision.ai,
            reason=decision.reason,
        )
        raise AccessDenied(
            f"write to '{key}' denied by policy={decision.policy}"
            + (f" (AI detected: {decision.ai})" if decision.ai else "")
        )

    data = _load().copy()
    parts = key.split(".", 1)

    if len(parts) == 2:
        section, field = parts
        if section not in data or not isinstance(data[section], dict):
            data[section] = {}
        data[section] = dict(data[section])
        data[section][field] = value
    else:
        data[parts[0]] = value

    _save(data)
    reload()
    _audit.record(
        "write", key,
        result="allow", policy=decision.policy, ai=decision.ai,
    )


def remove(key: str) -> bool:
    """Remove a credential value, gated by the policy engine."""
    _validate_key(key)
    decision = _policy.evaluate(key, action="write")
    if not decision.allow:
        _audit.record(
            "remove", key,
            result="deny", policy=decision.policy, ai=decision.ai,
            reason=decision.reason,
        )
        raise AccessDenied(
            f"remove '{key}' denied by policy={decision.policy}"
            + (f" (AI detected: {decision.ai})" if decision.ai else "")
        )

    data = _load().copy()
    parts = key.split(".", 1)
    removed = False

    if len(parts) == 2:
        section, field = parts
        if section in data and isinstance(data[section], dict):
            data[section] = dict(data[section])
            if field in data[section]:
                del data[section][field]
                if not data[section]:
                    del data[section]
                removed = True
    else:
        if parts[0] in data:
            del data[parts[0]]
            removed = True

    if removed:
        _save(data)
        reload()
        _audit.record(
            "remove", key,
            result="allow", policy=decision.policy, ai=decision.ai,
        )
    return removed


def list_sections() -> list[str]:
    """List all section names in the credentials file.

    Listing is not gated by per-key policy because section names are
    typically not sensitive (the secret is the value, not the schema).
    Access is still audited.
    """
    data = _load()
    sections = [k for k, v in data.items() if isinstance(v, dict)]
    _audit.record("list_sections", "*", result="allow",
                  extra={"count": len(sections)})
    return sections


def list_keys(section: str | None = None) -> list[str]:
    """List all keys, optionally filtered by section."""
    data = _load()
    if section:
        sec_data = data.get(section, {})
        if isinstance(sec_data, dict):
            keys = list(sec_data.keys())
        else:
            keys = []
        _audit.record("list_keys", section, result="allow",
                      extra={"count": len(keys)})
        return keys

    keys: list[str] = []
    for sec_name, sec_data in data.items():
        if isinstance(sec_data, dict):
            for key in sec_data:
                keys.append(f"{sec_name}.{key}")
        else:
            keys.append(sec_name)
    _audit.record("list_keys", "*", result="allow",
                  extra={"count": len(keys)})
    return keys


def encrypt_store(password: str) -> None:
    """Encrypt an existing plaintext credential file.

    Reads the plaintext TOML, encrypts it, and removes the plaintext file.
    """
    global _master_password
    plain_path = _get_path()
    if not plain_path.exists():
        raise FileNotFoundError(f"plaintext credentials file not found: {plain_path}")

    with open(plain_path, "rb") as f:
        data = f.read()

    from .crypto import encrypt as crypto_encrypt

    enc_path = _get_enc_path()
    enc_path.write_bytes(crypto_encrypt(data, password))
    _chmod_600(enc_path)
    plain_path.unlink()
    _master_password = password
    reload()
    _audit.record("encrypt_store", "*", result="allow")


def decrypt_store(password: str) -> None:
    """Decrypt the credential file back to plaintext."""
    global _master_password
    enc_path = _get_enc_path()
    if not enc_path.exists():
        raise FileNotFoundError(f"encrypted credentials file not found: {enc_path}")

    from .crypto import decrypt as crypto_decrypt

    raw = enc_path.read_bytes()
    plaintext = crypto_decrypt(raw, password)

    plain_path = _get_path()
    plain_path.write_bytes(plaintext)
    _chmod_600(plain_path)
    enc_path.unlink()
    _master_password = None
    reload()
    _audit.record("decrypt_store", "*", result="allow")
