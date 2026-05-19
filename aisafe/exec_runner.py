"""
`aisafe exec` — run a subprocess with credentials injected as env vars,
without the caller (or any AI watching it) ever holding the plaintext.

The flow:
  1. AI types `aisafe exec --env database -- ./deploy.sh`
  2. aisafe (running as a fresh process) loads creds from the store,
     translates each `section.field` into `SECTION_FIELD` env vars
  3. fork/exec the target command with that env
  4. the AI process tree only ever sees the env var *names* and the
     command's stdout/stderr — not the credential values

Three guards aisafe enforces on the exec path:

  - per-key policy is checked: `policy = "deny"` keys are NEVER exposed,
    even when their section is requested
  - the parent's AISAFE_* env vars (including AISAFE_KEY — the master
    password) are stripped from the child env. Otherwise unlocking the
    store once would hand the master password to every subprocess.
  - env-var name collisions are detected up front. Two keys mapping to
    the same env var name (e.g. `foo.bar-baz` and `foo.bar_baz`) cause
    a hard error instead of silent overwrite.

Each invocation is audit-logged with the section/keys exposed and the
command that was run; the values themselves are NEVER logged.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from typing import Iterable, Optional

from . import audit as _audit
from . import policy as _policy
from . import store as _store


class ExecPolicyError(Exception):
    """Raised when policy denies exposing a key via exec."""


# Env vars aisafe sets internally — never inherit these into a child.
# AISAFE_KEY is the master password; the rest carry state that could
# unintentionally widen the child's access to the store.
_SCRUB_ENV_NAMES = frozenset({
    "AISAFE_KEY",
    "AISAFE_FILE",
    "AISAFE_POLICY_FILE",
    "AISAFE_AUDIT_LOG",
    "AISAFE_STUB",
    "AISAFE_AI",
})


def _env_name(section: str, field: str, *, prefix: str = "") -> str:
    """Translate 'database.password' → 'DATABASE_PASSWORD' (with optional prefix)."""
    base = f"{section}_{field}".upper().replace("-", "_").replace(".", "_")
    return f"{prefix}{base}" if prefix else base


def _resolve_env(
    sections: Iterable[str] = (),
    keys: Iterable[str] = (),
    *,
    prefix: str = "",
) -> dict[str, str]:
    """Resolve sections + individual keys into a name→value env dict.

    Per-key policy is enforced: keys with policy `deny` are skipped (and
    audit-logged as denied). Env-name collisions are a hard error.
    """
    out: dict[str, str] = {}
    source: dict[str, str] = {}  # name → originating dotted key (for collision msg)
    data = _store._load()

    def _expose(section: str, field: str, val) -> None:
        full_key = f"{section}.{field}"
        if _policy.resolve(full_key) == "deny":
            _audit.record(
                "exec_expose", full_key,
                result="deny",
                policy="deny",
                reason="key has policy=deny; not exposed via exec",
            )
            return
        name = _env_name(section, field, prefix=prefix)
        if name in out and source.get(name) != full_key:
            raise ExecPolicyError(
                f"env var name collision: '{name}' would be set by both "
                f"'{source[name]}' and '{full_key}'; rename one of the keys "
                f"or use --prefix to disambiguate"
            )
        out[name] = str(val)
        source[name] = full_key

    for section in sections:
        sec = data.get(section, {})
        if not isinstance(sec, dict):
            continue
        for field, val in sec.items():
            _expose(section, field, val)

    for key in keys:
        if "." not in key:
            continue
        section, field = key.split(".", 1)
        val = _store._raw_get(key)
        if val is None:
            continue
        _expose(section, field, val)

    return out


def _scrubbed_env(*, inherit_env: bool) -> dict[str, str]:
    """Return a fresh env dict for the child process.

    If `inherit_env`, copy the parent's env but strip every AISAFE_* var
    so the master password and internal pointers don't leak through.
    """
    if not inherit_env:
        return {}
    return {k: v for k, v in os.environ.items() if not k.startswith("AISAFE_")}


def _filter_extra_env(extra_env: dict[str, str]) -> dict[str, str]:
    """Drop any AISAFE_* entries from caller-provided extra_env so that an
    AI cannot smuggle the master password back into the child via this
    parameter."""
    safe: dict[str, str] = {}
    for k, v in extra_env.items():
        if k.startswith("AISAFE_"):
            continue
        safe[k] = v
    return safe


def run(
    cmd: list[str],
    *,
    sections: Iterable[str] = (),
    keys: Iterable[str] = (),
    prefix: str = "",
    extra_env: Optional[dict[str, str]] = None,
    inherit_env: bool = True,
) -> int:
    """Execute `cmd` with credentials injected as env vars.

    Returns the subprocess exit code. The current process's environment
    is NOT modified, so credentials are scoped to the child only. The
    AISAFE_* internal env vars are stripped from the child's environment
    even when `inherit_env=True`.
    """
    if not cmd:
        raise ValueError("cmd must not be empty")

    # Compute the argv summary up front so EVERY audit branch (success,
    # collision, missing binary) records only `argv0`/`argc` and not the
    # full argv. AI/users may pass secrets as CLI args, and the audit log
    # must not preserve them verbatim.
    audit_cmd_summary = {"argv0": cmd[0], "argc": len(cmd)}

    try:
        creds = _resolve_env(sections, keys, prefix=prefix)
    except ExecPolicyError as e:
        print(f"aisafe: {e}", file=sys.stderr)
        _audit.record("exec", "*", result="error", reason=str(e),
                      extra={"cmd": audit_cmd_summary,
                             "sections": list(sections),
                             "keys": list(keys)})
        return 78  # EX_CONFIG

    env = _scrubbed_env(inherit_env=inherit_env)
    if extra_env:
        filtered = _filter_extra_env(extra_env)
        dropped = sorted(set(extra_env.keys()) - set(filtered.keys()))
        if dropped:
            print(
                f"aisafe: dropped {dropped} from extra_env "
                f"(AISAFE_* not allowed)",
                file=sys.stderr,
            )
        env.update(filtered)
    env.update(creds)
    # Always mark the child as running under aisafe-managed AI context, so
    # any in-child aisafe import re-applies the AI policy. This counters
    # the previous accidental scrub of AISAFE_AI.
    env["AISAFE_AI"] = "aisafe-exec-child"

    _audit.record(
        "exec", "*",
        result="allow",
        extra={
            "cmd": audit_cmd_summary,
            "sections": list(sections),
            "keys": list(keys),
            "exposed_env": sorted(creds.keys()),
            "inherit_env": inherit_env,
            "scrubbed_aisafe_names": sorted(
                k for k in os.environ if k.startswith("AISAFE_")
            ),
        },
    )

    try:
        result = subprocess.run(cmd, env=env, check=False)
        return result.returncode
    except FileNotFoundError:
        print(f"aisafe: command not found: {cmd[0]}", file=sys.stderr)
        _audit.record("exec", "*", result="error",
                      reason="command not found",
                      extra={"cmd": audit_cmd_summary})
        return 127
    except PermissionError:
        print(f"aisafe: permission denied: {cmd[0]}", file=sys.stderr)
        _audit.record("exec", "*", result="error",
                      reason="permission denied",
                      extra={"cmd": audit_cmd_summary})
        return 126


def env_export(
    sections: Iterable[str] = (),
    keys: Iterable[str] = (),
    *,
    prefix: str = "",
) -> str:
    """Generate a shell-eval'able export script.

    Usage:
        eval "$(aisafe env --section database)"

    Refused when an AI agent is detected: this function returns plaintext
    credentials as a string, which is the most direct possible exfiltration
    path. The CLI also gates this at the command layer, but the API gate
    here is the canonical one — any caller (including a malicious AI
    bypassing the CLI by doing `from aisafe import exec_runner;
    exec_runner.env_export(...)`) must go through it.
    """
    from . import detect as _detect
    ai = _detect.detect()
    if ai is not None:
        _audit.record(
            "env_export", "*",
            result="deny", ai=ai,
            reason="env_export refused under AI detection",
            extra={"sections": list(sections), "keys": list(keys)},
        )
        raise PermissionError(
            f"env_export refused under AI detection ({ai}); "
            f"the return value would expose plaintext credentials. "
            f"Use exec_runner.run() instead to scope credentials to a child process."
        )

    creds = _resolve_env(sections, keys, prefix=prefix)
    _audit.record(
        "env_export", "*",
        result="allow",
        extra={
            "sections": list(sections),
            "keys": list(keys),
            "exposed_env": sorted(creds.keys()),
        },
    )
    lines = []
    for name, value in creds.items():
        lines.append(f"export {name}={shlex.quote(value)}")
    return "\n".join(lines)
