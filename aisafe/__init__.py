"""
aisafe — Keep secrets out of AI agents' hands.

aisafe stores credentials outside the project workspace and enforces a
policy on every access. AI agents (Claude Code, Cursor, Copilot, etc.)
are detected by env-var markers and parent-process scan; sensitive keys
can be denied, redacted (stub), or proxied through capabilities (MCP).

Three patterns for letting an AI use credentials without seeing them:

  1. `aisafe exec --section database -- ./deploy.sh`
       child process gets the values in env; AI never holds plaintext.

  2. `aisafe mcp`
       run as an MCP server; AI calls `http_request` etc. via tools
       and gets responses, not values.

  3. policy = "stub_ai"
       AI's `aisafe.get(...)` returns "<REDACTED:section.key>" instead
       of the real value, so code can run without leaking.

Typical Python use:

    import aisafe
    aisafe.unlock("master")            # if store is encrypted
    aisafe.get("database.password")    # subject to policy + audit

For programmatic access from a human-driven script, set policy=open or
audit_only on the relevant keys, or run under `aisafe exec`.
"""

from . import audit, detect, exec_runner, policy
from .store import (
    AccessDenied,
    decrypt_store,
    encrypt_store,
    get,
    get_section,
    init,
    is_encrypted,
    list_keys,
    list_sections,
    reload,
    remove,
    set,
    unlock,
)

__version__ = "0.3.10"

__all__ = [
    "AccessDenied",
    "audit",
    "decrypt_store",
    "detect",
    "encrypt_store",
    "exec_runner",
    "get",
    "get_section",
    "init",
    "is_encrypted",
    "list_keys",
    "list_sections",
    "policy",
    "reload",
    "remove",
    "set",
    "unlock",
]
