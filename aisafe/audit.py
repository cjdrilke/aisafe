"""
Append-only audit log for credential access.

Every read, write, denial, and policy decision is recorded as a single
JSON line to `~/.config/aisafe/audit.log`. The log is the source of truth
for "who touched what, when" — useful both for forensic review and for
trusting the security guarantees of this tool.

The log is best-effort: failures to write the log do not block credential
operations (otherwise a corrupted log would lock the user out of their
own secrets). Log failures are surfaced via stderr.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Optional

from .paths import ensure_config_dir, get_config_dir
from .detect import AIDetection


AUDIT_FILENAME = "audit.log"


def _audit_path() -> Path:
    """Return the audit log path.

    `AISAFE_AUDIT_LOG` override is honored only when no AI is detected —
    otherwise the AI could redirect the audit log (e.g. to /dev/null) to
    suppress evidence of their access attempts.
    """
    override = os.environ.get("AISAFE_AUDIT_LOG")
    if override:
        from . import detect as _detect
        if _detect.detect() is not None:
            print(
                f"aisafe: refusing AISAFE_AUDIT_LOG override under AI detection; "
                f"using default audit path",
                file=sys.stderr,
            )
            return get_config_dir() / AUDIT_FILENAME
        return Path(override).expanduser()
    return get_config_dir() / AUDIT_FILENAME


def _caller_info() -> dict[str, Any]:
    """Capture the calling process identity (pid, exe, parent).

    Deliberately does NOT record `cmdline`/argv: CLI invocations like
    `aisafe set api.key SECRET` would otherwise put the secret value
    into argv, which would land in audit.log and become readable via
    the MCP `aisafe://audit` resource. Knowing the binary that called
    and the parent process is enough for forensic correlation; the
    `action`/`key` fields already record *what* was attempted.
    """
    info: dict[str, Any] = {"pid": os.getpid()}
    try:
        import psutil  # type: ignore

        p = psutil.Process(os.getpid())
        try:
            info["exe"] = p.exe()
        except (psutil.Error, OSError):
            pass
        try:
            parent = p.parent()
            if parent is not None:
                info["parent_pid"] = parent.pid
                info["parent_name"] = parent.name()
        except (psutil.Error, OSError):
            pass
    except ImportError:
        pass
    return info


def record(
    action: str,
    key: str,
    *,
    result: str,
    ai: Optional[AIDetection] = None,
    policy: Optional[str] = None,
    reason: Optional[str] = None,
    extra: Optional[dict[str, Any]] = None,
) -> None:
    """Record one audit event.

    Args:
        action: 'read' | 'write' | 'remove' | 'unlock' | 'exec' | 'mcp'
        key: dotted credential key (or '*' for whole-store ops)
        result: 'allow' | 'deny' | 'stub' | 'confirm' | 'error'
        ai: AIDetection record if AI was detected
        policy: name of policy that was applied
        reason: human-readable explanation
        extra: any additional structured fields
    """
    event: dict[str, Any] = {
        "ts": time.time(),
        "iso": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime()),
        "action": action,
        "key": key,
        "result": result,
        "caller": _caller_info(),
    }
    if ai is not None:
        event["ai"] = {"agent": ai.agent, "source": ai.source, "detail": ai.detail}
    if policy is not None:
        event["policy"] = policy
    if reason is not None:
        event["reason"] = reason
    if extra:
        event["extra"] = extra

    try:
        ensure_config_dir()
        path = _audit_path()
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        # Restrictive perms on the audit log — it can contain key names,
        # caller pids, and reason strings useful to an attacker.
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except Exception as e:
        print(f"aisafe: audit log write failed: {e}", file=sys.stderr)


def tail(n: int = 50) -> list[dict[str, Any]]:
    """Return the most recent `n` audit events (parsed)."""
    path = _audit_path()
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    out: list[dict[str, Any]] = []
    for line in lines[-n:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def path() -> Path:
    """Return the audit log path."""
    return _audit_path()
