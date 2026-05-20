"""
Per-key access policy engine.

Each credential key has a policy that governs how it can be read when an
AI agent is detected in the caller chain. The policy file lives at
`~/.config/aisafe/policies.toml`:

    default = "deny_ai"

    [keys]
    "api.public_key"      = "open"
    "database.password"   = "deny_ai"
    "github.token"        = "confirm"
    "stripe.secret"       = "stub_ai"

    # MCP http_request host allowlists (per credential)
    [hosts]
    "github.token"  = ["api.github.com", "*.github.com"]
    "stripe.secret" = ["api.stripe.com"]

Policy levels (strictest → most permissive):

  deny       — always deny reads from any caller; NEVER exposed via exec/env either
  deny_ai    — deny when AI agent detected; allow human callers (default)
  confirm    — prompt user via TTY for every read (skip prompt = deny)
  stub_ai    — return "<REDACTED:section.key>" when AI detected; real value otherwise
  audit_only — always allow, but log every access
  open       — allow without logging individual reads (still logs writes)

Note: `exec`/`env` paths only respect `deny`. `deny_ai`/`stub_ai`/`confirm` keys
WILL be injected into a subprocess env if the user requests the section/key.
This is intentional — `aisafe exec` is the sanctioned escape hatch for the
user to launch a process with credentials. `deny` is the way to say "never
expose, anywhere".

Resolution order:
  1. policy file is broken → fail-closed: every read denied
  2. AISAFE_STUB=1 env var → forces stub_ai for everything
  3. exact key match in [keys]
  4. section wildcard, e.g. "database.*"
  5. default

Two layers of protection against AI tampering with the policy itself:
  - Mutation APIs (set/remove/add_host/etc.) check `detect.detect()` and
    raise PolicyMutationDenied if an AI is in the caller chain.
  - `_policy_path()` ignores the `AISAFE_POLICY_FILE` env override when
    AI is detected, so an AI cannot launch aisafe pointing at an
    attacker-controlled permissive policy file.
"""

from __future__ import annotations

import os
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional
from urllib.parse import urlparse

from .paths import get_config_dir, ensure_config_dir
from .detect import AIDetection, detect


PolicyLevel = Literal["deny", "deny_ai", "confirm", "stub_ai", "audit_only", "open"]

VALID_POLICIES: tuple[PolicyLevel, ...] = (
    "deny",
    "deny_ai",
    "confirm",
    "stub_ai",
    "audit_only",
    "open",
)

DEFAULT_POLICY: PolicyLevel = "deny_ai"

POLICY_FILENAME = "policies.toml"

REDACTED_TEMPLATE = "<REDACTED:{key}>"

# HTTP methods always allowed via MCP http_request (no opt-in required).
_SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD"})

# HTTP methods that require explicit opt-in via the [unsafe_methods] table.
# OPTIONS is also safe in most cases but kept off the safe list for caution.
_UNSAFE_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})


# Policy keys can be 'key', 'section.field', 'section.*', or '*'.
_POLICY_KEY_RE = re.compile(
    r"^(?:"
    r"\*"                                       # global wildcard
    r"|[A-Za-z][A-Za-z0-9_\-]*"                 # single key
    r"|[A-Za-z][A-Za-z0-9_\-]*\.[A-Za-z][A-Za-z0-9_\-]*"  # section.field
    r"|[A-Za-z][A-Za-z0-9_\-]*\.\*"             # section.*
    r")$"
)


def _validate_policy_key(key: str) -> None:
    """Reject malformed policy keys at the mutation boundary."""
    if not isinstance(key, str):
        raise ValueError(f"policy key must be a string, got {type(key).__name__}")
    if not key:
        raise ValueError("policy key must not be empty")
    if len(key) > 256:
        raise ValueError(f"policy key too long ({len(key)} > 256)")
    if not _POLICY_KEY_RE.fullmatch(key):
        raise ValueError(
            f"invalid policy key {key!r}: must be '*', 'name', "
            f"'section.field', or 'section.*'"
        )


# Per-credential credential keys (no wildcards) — for hosts/unsafe_methods
# tables where wildcards don't make sense.
_CRED_KEY_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9_\-]*(\.[A-Za-z][A-Za-z0-9_\-]*)?$"
)


def _validate_cred_key(key: str) -> None:
    """Reject malformed credential keys (no wildcards allowed)."""
    if not isinstance(key, str):
        raise ValueError(f"credential key must be a string, got {type(key).__name__}")
    if not key:
        raise ValueError("credential key must not be empty")
    if len(key) > 256:
        raise ValueError(f"credential key too long ({len(key)} > 256)")
    if not _CRED_KEY_RE.fullmatch(key):
        raise ValueError(
            f"invalid credential key {key!r}: must be 'name' or 'section.field'"
        )


class PolicyMutationDenied(Exception):
    """Raised when a policy mutation is attempted while AI is detected."""


@dataclass(frozen=True)
class Decision:
    """Outcome of a policy evaluation for a single key access."""

    allow: bool
    policy: PolicyLevel
    ai: Optional[AIDetection]
    redact: bool = False
    reason: str = ""

    @property
    def stub_value(self) -> str:
        return REDACTED_TEMPLATE


@dataclass
class PolicyState:
    """Parsed contents of policies.toml.

    `broken` is the load-time failure flag. When set, every `resolve()` call
    returns "deny" — fail-closed.

    `unsafe_methods` maps `credential_key → list of HTTP methods` that are
    opt-in allowed for that credential via MCP http_request. By default only
    safe methods (GET/HEAD) are permitted; POST/PATCH/PUT/DELETE must be
    explicitly listed here. This defends against the confused-deputy attack
    where an AI calls a destructive endpoint on an allowlisted host.
    """
    default: PolicyLevel = DEFAULT_POLICY
    keys: dict[str, PolicyLevel] = field(default_factory=dict)
    hosts: dict[str, list[str]] = field(default_factory=dict)
    unsafe_methods: dict[str, list[str]] = field(default_factory=dict)
    broken: bool = False
    broken_reason: str = ""


def _policy_path() -> Path:
    """Resolve the policy file path. The `AISAFE_POLICY_FILE` env override
    is honored only when no AI is detected — otherwise an AI could launch
    aisafe pointing at an attacker-controlled permissive policy file."""
    override = os.environ.get("AISAFE_POLICY_FILE")
    if override:
        if detect() is not None:
            print(
                f"aisafe: refusing AISAFE_POLICY_FILE override under AI "
                f"detection; using default policy path",
                file=sys.stderr,
            )
            return get_config_dir() / POLICY_FILENAME
        return Path(override).expanduser()
    return get_config_dir() / POLICY_FILENAME


def _broken(reason: str) -> PolicyState:
    """Construct a fail-closed PolicyState."""
    print(f"aisafe: policy file broken: {reason}; fail-closed (all reads deny)",
          file=sys.stderr)
    return PolicyState(broken=True, broken_reason=reason)


def _load_state() -> PolicyState:
    """Load policies.toml. ANY parse / schema error → broken (fail-closed)."""
    path = _policy_path()
    if not path.exists():
        return PolicyState()

    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except Exception as e:
        return _broken(f"toml parse error: {e}")

    default_raw = data.get("default", DEFAULT_POLICY)
    if default_raw not in VALID_POLICIES:
        return _broken(f"invalid default policy '{default_raw}'")

    keys: dict[str, PolicyLevel] = {}
    if "keys" in data:
        if not isinstance(data["keys"], dict):
            return _broken(f"'keys' must be a table, got {type(data['keys']).__name__}")
        for k, v in data["keys"].items():
            if not isinstance(k, str):
                return _broken(f"non-string key in [keys]: {k!r}")
            try:
                _validate_policy_key(k)
            except ValueError as e:
                return _broken(f"invalid [keys] entry: {e}")
            if v not in VALID_POLICIES:
                return _broken(f"invalid policy '{v}' for key '{k}'")
            keys[k] = v  # type: ignore[assignment]

    hosts: dict[str, list[str]] = {}
    if "hosts" in data:
        if not isinstance(data["hosts"], dict):
            return _broken(f"'hosts' must be a table, got {type(data['hosts']).__name__}")
        for k, v in data["hosts"].items():
            if not isinstance(k, str):
                return _broken(f"non-string key in [hosts]: {k!r}")
            try:
                _validate_cred_key(k)
            except ValueError as e:
                return _broken(f"invalid [hosts] entry: {e}")
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                return _broken(f"hosts for '{k}' must be a list of strings")
            for pat in v:
                ok, reason = _validate_host_pattern(pat)
                if not ok:
                    return _broken(f"bad host pattern '{pat}' for '{k}': {reason}")
            hosts[k] = list(v)

    unsafe_methods: dict[str, list[str]] = {}
    if "unsafe_methods" in data:
        if not isinstance(data["unsafe_methods"], dict):
            return _broken(
                f"'unsafe_methods' must be a table, "
                f"got {type(data['unsafe_methods']).__name__}"
            )
        for k, v in data["unsafe_methods"].items():
            if not isinstance(k, str):
                return _broken(f"non-string key in [unsafe_methods]: {k!r}")
            try:
                _validate_cred_key(k)
            except ValueError as e:
                return _broken(f"invalid [unsafe_methods] entry: {e}")
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                return _broken(f"unsafe_methods for '{k}' must be a list of strings")
            normalized: list[str] = []
            for m in v:
                mu = m.upper()
                if mu not in _UNSAFE_METHODS:
                    return _broken(
                        f"method '{m}' is not an unsafe HTTP method for '{k}'; "
                        f"only {sorted(_UNSAFE_METHODS)} need opt-in"
                    )
                normalized.append(mu)
            unsafe_methods[k] = normalized

    return PolicyState(
        default=default_raw, keys=keys, hosts=hosts,
        unsafe_methods=unsafe_methods,
    )  # type: ignore[arg-type]


def _match(key: str, keys: dict[str, PolicyLevel]) -> Optional[PolicyLevel]:
    """Resolve a key against the policy map (exact > section wildcard)."""
    if key in keys:
        return keys[key]
    if "." in key:
        section = key.split(".", 1)[0]
        wildcard = f"{section}.*"
        if wildcard in keys:
            return keys[wildcard]
    if "*" in keys:
        return keys["*"]
    return None


def _resolve_with_state(key: str, state: PolicyState) -> PolicyLevel:
    """Stateless resolve used by both `resolve()` and `evaluate()`.

    Extracted so a single `evaluate()` call only reads `policies.toml` once —
    the previous code re-loaded the file via `resolve()`, opening a TOCTOU
    window between the two reads and doubling I/O.

    AISAFE_STUB=1 forces `stub_ai` for everything *except* keys that resolve
    to `deny`. `deny` means "never expose, anywhere" (see module docstring);
    a global stub override must not be able to downgrade that to `stub_ai`,
    or `aisafe exec` would happily inject a deny key into the child env when
    the AI sets AISAFE_STUB=1 in its own environment.
    """
    if state.broken:
        return "deny"
    underlying: PolicyLevel = _match(key, state.keys) or state.default
    if underlying == "deny":
        return "deny"
    if os.environ.get("AISAFE_STUB") == "1":
        return "stub_ai"
    return underlying


def resolve(key: str) -> PolicyLevel:
    """Return the effective policy for `key`. Fail-closed if policy file is broken."""
    return _resolve_with_state(key, _load_state())


def evaluate(key: str, *, action: str = "read") -> Decision:
    """Evaluate the policy for a single access and return a Decision."""
    state = _load_state()
    if state.broken:
        return Decision(
            allow=False, policy="deny", ai=detect(),
            reason=f"policy file broken: {state.broken_reason}",
        )

    policy = _resolve_with_state(key, state)
    ai = detect()

    if action != "read":
        if ai is None:
            return Decision(True, policy, None, reason="write by human caller")
        if policy in ("open", "audit_only"):
            return Decision(True, policy, ai, reason=f"write under {policy}")
        return Decision(
            False, policy, ai, reason=f"write blocked: AI detected ({ai}) and policy={policy}"
        )

    if policy == "deny":
        return Decision(False, policy, ai, reason="policy=deny")
    if policy == "open" or policy == "audit_only":
        return Decision(True, policy, ai)
    if policy == "deny_ai":
        if ai is None:
            return Decision(True, policy, None)
        return Decision(False, policy, ai, reason=f"deny_ai: AI detected ({ai})")
    if policy == "stub_ai":
        if ai is None:
            return Decision(True, policy, None)
        return Decision(True, policy, ai, redact=True, reason=f"stub_ai: AI detected ({ai})")
    if policy == "confirm":
        return Decision(False, policy, ai, reason="confirm required")

    return Decision(False, policy, ai, reason=f"unknown policy {policy}")


def confirm_interactive(key: str, ai: Optional[AIDetection]) -> bool:
    """TTY prompt for `confirm` policy. Returns True if user approved."""
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        return False
    suffix = f" (AI detected: {ai})" if ai else ""
    try:
        print(
            f"\naisafe: allow read of '{key}'?{suffix} [y/N] ",
            end="",
            file=sys.stderr,
            flush=True,
        )
        answer = sys.stdin.readline().strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("y", "yes")


# ────────────────────────────────────────────────────────────────────
# Host allowlist (used by MCP http_request)
# ────────────────────────────────────────────────────────────────────

_HOST_LABEL_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


def _validate_host_pattern(pattern: str) -> tuple[bool, str]:
    """Validate a host pattern. Accepts `host.tld` or `*.host.tld`.

    Rejects schemes/paths/ports/userinfo/wildcards-too-broad/control chars.
    """
    if not pattern:
        return False, "empty pattern"
    if len(pattern) > 253:
        return False, "pattern too long (>253 chars)"
    if any(c not in pattern_charset_print for c in pattern):
        return False, "non-printable / non-ascii character"
    # Reject any character that suggests scheme/path/port/userinfo.
    for bad in "/:@?#%&=\"'<>\\":
        if bad in pattern:
            return False, f"invalid character {bad!r} in pattern"

    work = pattern
    if work.startswith("*."):
        work = work[2:]
        if work.count(".") < 1:
            return False, (
                f"wildcard '{pattern}' is too broad; require at least 2 labels "
                "after '*.' (use 'foo.bar.com', not '*.com')"
            )
    elif "*" in work:
        return False, "wildcard '*' may only appear as the leftmost label"

    labels = work.split(".")
    for label in labels:
        if not label:
            return False, "empty label (consecutive or trailing dots)"
        if not _HOST_LABEL_RE.fullmatch(label):
            return False, f"invalid label {label!r}"

    return True, "ok"


# Printable ASCII (no control chars, no newlines).
pattern_charset_print = set(chr(c) for c in range(0x21, 0x7F))


def _host_matches(host: str, pattern: str) -> bool:
    """Match host against a pattern. '*.example.com' matches any subdomain."""
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix)
    return False


def method_allowed(credential_key: str, method: str) -> tuple[bool, str]:
    """Check whether `method` may be used with `credential_key`.

    GET/HEAD are always allowed; POST/PATCH/PUT/DELETE require an explicit
    opt-in entry in `[unsafe_methods]` for that credential. This blocks
    "confused deputy" abuse where an AI uses an allowlisted credential to
    perform a destructive operation on an allowlisted host.
    """
    method_u = method.upper()
    if method_u in _SAFE_METHODS:
        return True, "safe method"
    if method_u not in _UNSAFE_METHODS:
        return False, f"method '{method}' is not recognized"
    state = _load_state()
    if state.broken:
        return False, f"policy broken: {state.broken_reason}"
    allowed = state.unsafe_methods.get(credential_key, [])
    if method_u in allowed:
        return True, f"opted-in for '{credential_key}'"
    return False, (
        f"method '{method_u}' is unsafe; '{credential_key}' has not opted in. "
        f"Add via 'aisafe policy methods add {credential_key} {method_u}'."
    )


def host_allowed(credential_key: str, url: str) -> tuple[bool, str]:
    """Check whether `url` may be requested using `credential_key`.

    Default-deny: a credential with no `[hosts]` entry can NEVER be used by
    MCP http_request. Only https:// is permitted.
    """
    state = _load_state()
    if state.broken:
        return False, f"policy broken: {state.broken_reason}"

    allowlist = state.hosts.get(credential_key, [])
    if not allowlist:
        return False, (
            f"no host allowlist configured for '{credential_key}'. "
            f"Add hosts via 'aisafe policy hosts add {credential_key} <host>'."
        )

    try:
        parsed = urlparse(url)
    except ValueError as e:
        return False, f"invalid url: {e}"

    if parsed.scheme != "https":
        return False, f"scheme '{parsed.scheme}' not allowed; only https is permitted"

    host = (parsed.hostname or "").lower()
    if not host:
        return False, "url has no host"

    for pattern in allowlist:
        if _host_matches(host, pattern.lower()):
            return True, f"matched {pattern}"

    return False, f"host '{host}' not in allowlist for '{credential_key}': {allowlist}"


# ────────────────────────────────────────────────────────────────────
# Mutation APIs — all gated on AI detection
# ────────────────────────────────────────────────────────────────────

def _refuse_if_ai(operation: str) -> None:
    """Raise PolicyMutationDenied if an AI agent is in the caller chain."""
    ai = detect()
    if ai is not None:
        # audit the attempted mutation
        try:
            from . import audit as _audit
            _audit.record(
                "policy_mutation", "*",
                result="deny", ai=ai,
                reason=f"AI-detected caller cannot {operation}",
            )
        except Exception:
            pass
        raise PolicyMutationDenied(
            f"refusing to {operation}: AI agent detected ({ai}). "
            f"Policy changes must come from a human-driven shell."
        )


def set_key_policy(key: str, level: PolicyLevel) -> None:
    """Persist a per-key policy entry. Refused under AI."""
    _refuse_if_ai(f"set policy '{key}' = '{level}'")
    _validate_policy_key(key)
    if level not in VALID_POLICIES:
        raise ValueError(f"invalid policy '{level}'; must be one of {VALID_POLICIES}")
    state = _load_state()
    if state.broken:
        # Refuse to write on top of a broken file; force a manual fix first.
        raise PolicyMutationDenied(
            f"policy file is broken ({state.broken_reason}); fix it manually "
            f"before further mutations"
        )
    state.keys[key] = level
    _write_state(state)


def remove_key_policy(key: str) -> bool:
    """Delete a per-key policy entry. Refused under AI."""
    _refuse_if_ai(f"remove policy '{key}'")
    _validate_policy_key(key)
    state = _load_state()
    if state.broken:
        raise PolicyMutationDenied(
            f"policy file is broken ({state.broken_reason}); fix it manually first"
        )
    if key not in state.keys:
        return False
    del state.keys[key]
    _write_state(state)
    return True


def set_default_policy(level: PolicyLevel) -> None:
    """Persist the default policy. Refused under AI."""
    _refuse_if_ai(f"set default policy = '{level}'")
    if level not in VALID_POLICIES:
        raise ValueError(f"invalid policy '{level}'; must be one of {VALID_POLICIES}")
    state = _load_state()
    if state.broken:
        raise PolicyMutationDenied(
            f"policy file is broken ({state.broken_reason}); fix it manually first"
        )
    state.default = level
    _write_state(state)


def add_host(credential_key: str, host_pattern: str) -> None:
    """Add a host to the allowlist for `credential_key`. Refused under AI."""
    _refuse_if_ai(f"add host '{host_pattern}' to '{credential_key}'")
    _validate_cred_key(credential_key)
    ok, reason = _validate_host_pattern(host_pattern)
    if not ok:
        raise ValueError(f"invalid host pattern: {reason}")
    state = _load_state()
    if state.broken:
        raise PolicyMutationDenied(
            f"policy file is broken ({state.broken_reason}); fix it manually first"
        )
    existing = state.hosts.get(credential_key, [])
    if host_pattern not in existing:
        existing.append(host_pattern)
    state.hosts[credential_key] = existing
    _write_state(state)


def remove_host(credential_key: str, host_pattern: str) -> bool:
    """Remove a host from the allowlist. Refused under AI."""
    _refuse_if_ai(f"remove host '{host_pattern}' from '{credential_key}'")
    _validate_cred_key(credential_key)
    state = _load_state()
    if state.broken:
        raise PolicyMutationDenied(
            f"policy file is broken ({state.broken_reason}); fix it manually first"
        )
    existing = state.hosts.get(credential_key, [])
    if host_pattern not in existing:
        return False
    existing.remove(host_pattern)
    if existing:
        state.hosts[credential_key] = existing
    else:
        del state.hosts[credential_key]
    _write_state(state)
    return True


def list_policies() -> tuple[PolicyLevel, dict[str, PolicyLevel]]:
    """Return the current (default, per-key) policy map."""
    state = _load_state()
    return state.default, state.keys


def list_hosts() -> dict[str, list[str]]:
    """Return the host allowlist per credential key."""
    return _load_state().hosts


def list_unsafe_methods() -> dict[str, list[str]]:
    """Return the opt-in unsafe-method list per credential key."""
    return _load_state().unsafe_methods


def add_unsafe_method(credential_key: str, method: str) -> None:
    """Opt `credential_key` into using an unsafe HTTP method via MCP. Refused under AI."""
    _refuse_if_ai(f"add unsafe method '{method}' for '{credential_key}'")
    _validate_cred_key(credential_key)
    mu = method.upper()
    if mu in _SAFE_METHODS:
        raise ValueError(
            f"'{mu}' is always allowed; no opt-in needed"
        )
    if mu not in _UNSAFE_METHODS:
        raise ValueError(
            f"'{mu}' is not a recognized unsafe HTTP method "
            f"(must be one of {sorted(_UNSAFE_METHODS)})"
        )
    state = _load_state()
    if state.broken:
        raise PolicyMutationDenied(
            f"policy file is broken ({state.broken_reason}); fix it manually first"
        )
    existing = state.unsafe_methods.get(credential_key, [])
    if mu not in existing:
        existing.append(mu)
    state.unsafe_methods[credential_key] = existing
    _write_state(state)


def remove_unsafe_method(credential_key: str, method: str) -> bool:
    """Drop opt-in for an unsafe method on `credential_key`. Refused under AI."""
    _refuse_if_ai(f"remove unsafe method '{method}' for '{credential_key}'")
    _validate_cred_key(credential_key)
    mu = method.upper()
    state = _load_state()
    if state.broken:
        raise PolicyMutationDenied(
            f"policy file is broken ({state.broken_reason}); fix it manually first"
        )
    existing = state.unsafe_methods.get(credential_key, [])
    if mu not in existing:
        return False
    existing.remove(mu)
    if existing:
        state.unsafe_methods[credential_key] = existing
    else:
        del state.unsafe_methods[credential_key]
    _write_state(state)
    return True


def validate() -> tuple[bool, str]:
    """Validate the policy file. Returns (ok, message)."""
    state = _load_state()
    if state.broken:
        return False, state.broken_reason
    return True, "ok"


def reset_to_default() -> None:
    """OVERWRITE the policy file with a clean default state.

    This is the only mutation API that runs even when the existing file is
    broken — the user's escape hatch from a corrupted policies.toml.
    Refused under AI: only a human at a real terminal can clobber the
    existing policy.
    """
    _refuse_if_ai("reset policy to defaults")
    _write_state(PolicyState())


def _write_state(state: PolicyState) -> None:
    """Serialize the full policy state back to disk with restrictive perms."""
    ensure_config_dir()
    path = _policy_path()
    lines = [f'default = "{state.default}"', ""]

    if state.keys:
        lines.append("[keys]")
        for k, v in sorted(state.keys.items()):
            lines.append(f'"{_quote_toml_key(k)}" = "{v}"')
        lines.append("")

    if state.hosts:
        lines.append("[hosts]")
        for k, v in sorted(state.hosts.items()):
            hosts_str = ", ".join(f'"{_quote_toml_str(h)}"' for h in v)
            lines.append(f'"{_quote_toml_key(k)}" = [{hosts_str}]')
        lines.append("")

    if state.unsafe_methods:
        lines.append("[unsafe_methods]")
        for k, v in sorted(state.unsafe_methods.items()):
            methods_str = ", ".join(f'"{_quote_toml_str(m)}"' for m in v)
            lines.append(f'"{_quote_toml_key(k)}" = [{methods_str}]')
        lines.append("")

    content = "\n".join(lines)
    path.write_text(content, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _quote_toml_key(s: str) -> str:
    """Escape a string for safe inclusion as a TOML quoted key."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _quote_toml_str(s: str) -> str:
    """Escape a string for safe inclusion in a TOML basic-string literal."""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
