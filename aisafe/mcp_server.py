"""
MCP (Model Context Protocol) server for aisafe.

Exposes credentials to AI agents as *capabilities*, not raw values. The
AI can ask aisafe to *use* a credential (e.g. make an authenticated HTTP
request) but cannot ask for the value itself.

Transport: JSON-RPC 2.0 over stdio, following the MCP 2025-03-26 schema.

Exposed tools:

  list_keys             — return key names (NOT values), grouped by section
  http_request          — make an HTTPS request to a hostname that is
                          ALLOWLISTED for the named credential. The
                          credential is attached server-side (header or
                          query param) and the response is returned. Auto-
                          follow on redirects is disabled — a 3xx is
                          surfaced as-is so the credential cannot be
                          tricked into following an attacker's redirect.
  policy_show           — show the policy + host allowlist

Exposed resources:

  aisafe://policy       — policy configuration (JSON)

Note: `aisafe://audit` was REMOVED in 0.3.5. The audit log can contain
historical entries that predate later redaction passes, so exposing it
to the AI was deemed an unacceptable leak risk. Humans read the log
via `aisafe audit` from a non-AI shell, or directly from disk.

The `exec` tool was removed in 0.3.1 — it let the AI run arbitrary
commands with credentials in env, with stdout returned to the AI. That
trivially defeats "AI never sees the value" (e.g. `python -c 'import os;
print(os.environ["DB_PASS"])'`). Users who need AI-driven exec should
invoke `aisafe exec` from the AI's shell tool; that path is still gated
by per-key policy and the AISAFE_* env scrub, and the AI's shell at
least surfaces the command to the user for review.

Configure your AI client (Claude Desktop, Cursor, etc.) with:
    {
      "mcpServers": {
        "aisafe": { "command": "aisafe", "args": ["mcp"] }
      }
    }
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import traceback
import urllib.error
import urllib.request
from typing import Any, Callable

from . import audit as _audit
from . import policy as _policy
from . import store as _store


PROTOCOL_VERSION = "2025-03-26"
SERVER_NAME = "aisafe"
SERVER_VERSION = "0.3.10"

# Cap on response body bytes we return to the AI. Defends against an
# attacker-controlled endpoint streaming an oversized response to OOM
# the aisafe process.
RESPONSE_BYTE_LIMIT = 1_000_000  # 1 MB

# Allowed HTTP methods (whitelisted in tool schema; also enforced at runtime).
ALLOWED_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"})

# RFC 7230 token grammar for HTTP header names.
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

# Min/max for client-supplied timeouts (seconds).
TIMEOUT_MIN = 0.1
TIMEOUT_MAX = 600.0


# ────────────────────────────────────────────────────────────────────
# Policy-file integrity tracker
#
# The Python `policy.set_*` / `policy.add_*` APIs refuse to mutate the
# policy when an AI agent is detected. They do not, however, defend
# against an AI with shell access writing directly to
# `~/.config/aisafe/policies.toml`. To close that gap during an MCP
# session, the server SHA-256s the policy file at startup and refuses
# tool calls if the hash changes mid-session — the user must restart
# `aisafe mcp` to pick up legitimate policy updates.
# ────────────────────────────────────────────────────────────────────

_policy_hash_at_startup: bytes | None = None


def _compute_policy_hash() -> bytes:
    """SHA-256 of the policy file contents. Empty = file does not exist."""
    path = _policy._policy_path()
    try:
        return hashlib.sha256(path.read_bytes()).digest()
    except FileNotFoundError:
        return b""
    except OSError:
        # If we can't read the file, treat it as a change — fail-closed.
        return b"<unreadable>"


def _check_policy_integrity() -> None:
    """Raise `_ToolError` if the policy file changed since MCP startup.

    Called before every tool dispatch. The AI cannot get around this by
    flipping `_policy_hash_at_startup` — that would require Python access
    to the MCP server process, which is the same-process bypass that
    the README threat model already documents as out-of-scope.
    """
    if _policy_hash_at_startup is None:
        # Not in an MCP session (direct API call from a test or library
        # consumer) — the policy mutation APIs already enforce their own
        # gate, so we don't need a hash check here.
        return
    current = _compute_policy_hash()
    if current != _policy_hash_at_startup:
        raise _ToolError(
            "policy file has changed since aisafe mcp started; refusing "
            "tool calls until the server is restarted. (This guards "
            "against an attacker writing directly to policies.toml.)"
        )


def _check_header_name(name: Any) -> None:
    """Validate an HTTP header name against RFC 7230 token grammar."""
    if not isinstance(name, str):
        raise _ToolError(f"header name must be a string, got {type(name).__name__}")
    if not name:
        raise _ToolError("header name must not be empty")
    if not _HEADER_NAME_RE.fullmatch(name):
        raise _ToolError(f"invalid header name: {name!r}")


def _check_header_value(value: Any, name: str) -> None:
    """Validate an HTTP header value: no control chars (except HTAB)."""
    if not isinstance(value, str):
        raise _ToolError(f"header value for {name!r} must be a string")
    for c in value:
        o = ord(c)
        if o == 0x09:  # HTAB is allowed in field-value
            continue
        if o < 0x20 or o == 0x7F:
            raise _ToolError(
                f"control character (0x{o:02x}) in header value for {name!r}"
            )

_methods: dict[str, Callable[[dict[str, Any]], Any]] = {}


def _method(name: str):
    def deco(fn: Callable[[dict[str, Any]], Any]):
        _methods[name] = fn
        return fn
    return deco


# ────────────────────────────────────────────────────────────────────
# MCP lifecycle
# ────────────────────────────────────────────────────────────────────

@_method("initialize")
def _initialize(params: dict[str, Any]) -> dict[str, Any]:
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {"tools": {}, "resources": {}},
        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        "instructions": (
            "aisafe holds credentials the user marked as off-limits to direct "
            "value reads. Use http_request to make authenticated calls without "
            "seeing the token. NEVER expect to receive a raw credential."
        ),
    }


@_method("notifications/initialized")
def _initialized(params: dict[str, Any]) -> None:
    return None


@_method("ping")
def _ping(params: dict[str, Any]) -> dict[str, Any]:
    return {}


# ────────────────────────────────────────────────────────────────────
# Tools
# ────────────────────────────────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "name": "list_keys",
        "description": (
            "List credential keys available in aisafe. Returns key names "
            "(e.g. 'database.password') but NOT values. Key names are NOT "
            "considered secret; only the values are."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "section": {
                    "type": "string",
                    "description": "Optional section filter (e.g. 'database').",
                },
            },
        },
    },
    {
        "name": "http_request",
        "description": (
            "Make an authenticated HTTPS request. aisafe attaches the named "
            "credential as an Authorization header (or custom header / query "
            "param) and returns the response. aisafe makes a best-effort "
            "attempt to scrub the credential value out of the response body "
            "and headers before returning, but cannot defeat arbitrary "
            "transformations (hex/double-encoding/JSON-escape/etc) — the "
            "host allowlist configured by the user is the primary defense. "
            "Redirects are NOT followed automatically — a 3xx response is "
            "surfaced as-is. The URL host MUST be in the allowlist and the "
            "HTTP method must be GET/HEAD (default) or opted-in via "
            "[unsafe_methods]; otherwise the request is rejected. Only "
            "https:// is permitted."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["url", "credential_key"],
            "properties": {
                "url": {"type": "string", "description": "Full https:// URL."},
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"],
                    "default": "GET",
                },
                "credential_key": {
                    "type": "string",
                    "description": "Dotted credential key, e.g. 'github.token'.",
                },
                "auth_scheme": {
                    "type": "string",
                    "enum": ["bearer", "basic", "header", "query"],
                    "default": "bearer",
                    "description": (
                        "How to attach the credential. 'bearer' → "
                        "'Authorization: Bearer <value>'; 'basic' → "
                        "'Authorization: Basic <b64(user:value)>'; "
                        "'header' → set header named by `header_name`; "
                        "'query' → append as query param named by `query_param`."
                    ),
                },
                "header_name": {"type": "string"},
                "query_param": {"type": "string"},
                "basic_user": {"type": "string"},
                "headers": {
                    "type": "object",
                    "description": "Additional headers to send.",
                },
                "body": {
                    "type": "string",
                    "description": "Request body (string or JSON-stringified).",
                },
                "timeout": {"type": "number", "default": 30},
            },
        },
    },
    {
        "name": "policy_show",
        "description": "Show the policy levels and the per-credential host allowlists.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


@_method("tools/list")
def _tools_list(params: dict[str, Any]) -> dict[str, Any]:
    return {"tools": TOOLS}


@_method("tools/call")
def _tools_call(params: dict[str, Any]) -> dict[str, Any]:
    name = params.get("name")
    args = params.get("arguments") or {}

    handlers: dict[str, Callable[[dict[str, Any]], Any]] = {
        "list_keys": _tool_list_keys,
        "http_request": _tool_http_request,
        "policy_show": _tool_policy_show,
    }
    handler = handlers.get(name)  # type: ignore[arg-type]
    if handler is None:
        raise _RpcError(-32602, f"unknown tool: {name}")

    try:
        # Integrity check first — if the policy file was tampered with
        # mid-session, refuse the call before the handler runs.
        _check_policy_integrity()
        result = handler(args)
        text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False, indent=2)
        return {"content": [{"type": "text", "text": text}], "isError": False}
    except _ToolError as e:
        # _ToolError messages are deliberately scrubbed by tool authors;
        # safe to record and surface as-is.
        _audit.record(
            "mcp", str(name), result="deny", reason=str(e),
            extra={"args": _redact_args(args)},
        )
        return {"content": [{"type": "text", "text": str(e)}], "isError": True}
    except Exception:
        # Unexpected exceptions may carry the credential value in their
        # message (e.g. urllib.error.InvalidURL("...?api_key=SECRET...")).
        # Log a fixed string, return a generic message to the AI, and only
        # write the full traceback to stderr when AISAFE_DEBUG=1 AND no AI
        # agent is detected — otherwise an AI could itself flip the env
        # var, then read the traceback off the MCP server's stderr stream
        # (which many MCP clients tee or display).
        from . import detect as _detect
        debug = (
            os.environ.get("AISAFE_DEBUG") == "1"
            and _detect.detect() is None
        )
        if debug:
            traceback.print_exc(file=sys.stderr)
        else:
            print(
                "aisafe-mcp: internal error in tool call (details suppressed; "
                "set AISAFE_DEBUG=1 in a non-AI shell to enable traceback)",
                file=sys.stderr,
            )
        _audit.record(
            "mcp", str(name),
            result="error",
            reason="internal error (details redacted)",
            extra={"args": _redact_args(args)},
        )
        return {
            "content": [{
                "type": "text",
                "text": "internal error (details redacted; see server stderr)",
            }],
            "isError": True,
        }


class _ToolError(Exception):
    """Raised by a tool handler when the request is rejected by policy or
    input validation. The message is shown to the AI."""


_SENSITIVE_ARG_KEYS = frozenset({
    "body",
    "headers",
    "basic_user",  # may itself be sensitive (e.g. account id)
})


def _redact_args(args: dict[str, Any]) -> dict[str, Any]:
    """Strip likely-sensitive fields before logging tool args.

    - body/headers/basic_user → fully redacted
    - url → scheme://host/path only (query/fragment stripped, since the
            query can contain `?token=...` and the fragment can carry
            attacker-controlled data)
    - anything else is passed through as-is (must already be safe to log)
    """
    safe: dict[str, Any] = {}
    for k, v in args.items():
        if k in _SENSITIVE_ARG_KEYS:
            safe[k] = "<redacted>"
        elif k == "url" and isinstance(v, str):
            safe[k] = _strip_url_query_fragment(v)
        else:
            safe[k] = v
    return safe


def _strip_url_query_fragment(url: str) -> str:
    """Return scheme://host/path of `url`, dropping query, fragment, and
    userinfo (`https://user:pass@host` → `https://host`)."""
    try:
        from urllib.parse import urlsplit, urlunsplit
        parts = urlsplit(url)
        netloc = parts.hostname or ""
        if parts.port:
            netloc = f"{netloc}:{parts.port}"
        return urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    except Exception:
        return "<unparseable url>"


# ────────────────────────────────────────────────────────────────────
# Tool: list_keys
# ────────────────────────────────────────────────────────────────────

def _tool_list_keys(args: dict[str, Any]) -> dict[str, Any]:
    section = args.get("section")
    if section:
        return {"section": section, "keys": _store.list_keys(section)}
    return {"keys": _store.list_keys()}


# ────────────────────────────────────────────────────────────────────
# Tool: policy_show
# ────────────────────────────────────────────────────────────────────

def _tool_policy_show(args: dict[str, Any]) -> dict[str, Any]:
    default, keys = _policy.list_policies()
    return {
        "default": default,
        "keys": keys,
        "hosts": _policy.list_hosts(),
        "unsafe_methods": _policy.list_unsafe_methods(),
    }


# ────────────────────────────────────────────────────────────────────
# Tool: http_request
# ────────────────────────────────────────────────────────────────────

class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Surface 3xx responses instead of following them.

    A credential bound to (api.github.com) must never be auto-sent to
    whatever Location: header github.com decides to return — even
    benign-looking redirects can be a 302 to an attacker-controlled
    host. The AI can issue a new http_request to follow if it really
    needs to (and that request will pass through the allowlist check
    fresh, possibly with a different credential or none at all).
    """
    def http_error_301(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)
    http_error_302 = http_error_303 = http_error_307 = http_error_308 = http_error_301


_no_redirect_opener = urllib.request.build_opener(_NoRedirectHandler())


def _tool_http_request(args: dict[str, Any]) -> dict[str, Any]:
    url = args.get("url")
    if not isinstance(url, str) or not url:
        raise _ToolError("url is required")
    # Reject any URL containing control characters or raw whitespace. urllib
    # would later raise InvalidURL whose exception message embeds the FULL
    # final_url (including the appended secret in query mode); we must
    # refuse BEFORE the secret is pulled.
    for c in url:
        o = ord(c)
        if o < 0x21 or o == 0x7F:
            raise _ToolError(
                f"url contains a disallowed control/whitespace character "
                f"(0x{o:02x}); reject"
            )

    credential_key = args.get("credential_key")
    if not isinstance(credential_key, str) or not credential_key:
        raise _ToolError("credential_key is required")

    method = (args.get("method") or "GET")
    if not isinstance(method, str):
        raise _ToolError("method must be a string")
    method = method.upper()
    if method not in ALLOWED_HTTP_METHODS:
        raise _ToolError(
            f"method '{method}' is not allowed; "
            f"must be one of {sorted(ALLOWED_HTTP_METHODS)}"
        )

    auth_scheme = args.get("auth_scheme") or "bearer"
    headers_in = args.get("headers") or {}
    if not isinstance(headers_in, dict):
        raise _ToolError("headers must be an object (string→string)")
    headers: dict[str, str] = {}
    for k, v in headers_in.items():
        _check_header_name(k)
        _check_header_value(v, k)
        headers[k] = v

    body = args.get("body")
    if "timeout" not in args or args["timeout"] is None:
        timeout = 30.0
    else:
        try:
            timeout = float(args["timeout"])
        except (TypeError, ValueError):
            raise _ToolError("timeout must be a number")
        if not (TIMEOUT_MIN <= timeout <= TIMEOUT_MAX):
            raise _ToolError(
                f"timeout must be in [{TIMEOUT_MIN}, {TIMEOUT_MAX}] seconds"
            )

    # 1. Host allowlist check — the entire point of this tool's safety.
    allowed, reason = _policy.host_allowed(credential_key, url)
    if not allowed:
        raise _ToolError(f"request blocked: {reason}")

    # 1b. Method allowlist check — confused-deputy defense.
    method_ok, method_reason = _policy.method_allowed(credential_key, method)
    if not method_ok:
        raise _ToolError(f"request blocked: {method_reason}")

    # 1c. Re-verify the policy hash AFTER reading it but BEFORE pulling
    # the secret. This closes the TOCTOU window: an attacker who flips
    # the policy file between `host_allowed()` (which re-reads the file)
    # and `_raw_get()` (which doesn't) cannot ride a permissive policy
    # into a secret-bearing request. If anything moved, refuse.
    _check_policy_integrity()

    # 2. Pull the credential bypassing per-key policy (the user already
    # opted in by adding the host to this credential's allowlist).
    secret = _store._raw_get(credential_key)
    if secret is None:
        raise _ToolError(f"credential '{credential_key}' not found")
    secret = str(secret)

    # 3. Build the request. EVERY generated header value goes through
    # _check_header_value so a stored token containing \r/\n/NUL/etc.
    # cannot inject extra headers (CRLF injection via the secret itself).
    final_url = url
    if auth_scheme == "bearer":
        value = f"Bearer {secret}"
        _check_header_value(value, "Authorization")
        headers["Authorization"] = value
    elif auth_scheme == "basic":
        import base64
        user = args.get("basic_user", "")
        if not isinstance(user, str):
            raise _ToolError("basic_user must be a string")
        token = base64.b64encode(f"{user}:{secret}".encode("utf-8")).decode("ascii")
        value = f"Basic {token}"
        _check_header_value(value, "Authorization")
        headers["Authorization"] = value
    elif auth_scheme == "header":
        header_name = args.get("header_name")
        _check_header_name(header_name)
        _check_header_value(secret, header_name)
        headers[header_name] = secret
    elif auth_scheme == "query":
        param = args.get("query_param")
        if not isinstance(param, str) or not param:
            raise _ToolError("query_param is required for auth_scheme=query")
        from urllib.parse import urlsplit, urlunsplit, urlencode, parse_qsl, quote
        # Use urlsplit/urlunsplit so the secret is merged BEFORE any
        # `#fragment`, and url-encoded with `quote` (no '+' for spaces,
        # safe='' so every special character is %-encoded).
        parts = urlsplit(final_url)
        existing = parse_qsl(parts.query, keep_blank_values=True)
        existing.append((param, secret))
        new_query = urlencode(existing, quote_via=quote)
        final_url = urlunsplit(
            (parts.scheme, parts.netloc, parts.path, new_query, parts.fragment)
        )
    else:
        raise _ToolError(f"unsupported auth_scheme: {auth_scheme}")

    data: bytes | None = None
    if body is not None:
        data = body.encode("utf-8") if isinstance(body, str) else json.dumps(body).encode("utf-8")

    _audit.record(
        "mcp", credential_key,
        result="allow",
        reason=f"http_request {method}",
        extra={
            "method": method,
            "url": _strip_url_query_fragment(url),
            "auth_scheme": auth_scheme,
            "credential_key": credential_key,
            "allowlist_reason": reason,
        },
    )

    # Strings the response body / headers must NOT contain when we hand
    # the response back to the AI. This catches debug / echo endpoints
    # that reflect the auth token in their response, which would defeat
    # the "AI never sees the value" guarantee.
    redact_strings = _collect_redaction_strings(secret, auth_scheme, args)

    req = urllib.request.Request(final_url, data=data, method=method, headers=headers)
    try:
        with _no_redirect_opener.open(req, timeout=timeout) as resp:
            resp_body = _read_capped(resp)
            return {
                "status": resp.status,
                "headers": _scrub_headers(dict(resp.headers), redact_strings),
                "body": _scrub_text(resp_body, redact_strings),
                "truncated": len(resp_body) >= RESPONSE_BYTE_LIMIT,
            }
    except urllib.error.HTTPError as e:
        # Includes our intentional 3xx-as-error: surface the redirect target
        # to the AI WITHOUT auto-following it.
        body_text = ""
        if e.fp is not None:
            body_text = _read_capped(e.fp)
        return {
            "status": e.code,
            "headers": _scrub_headers(dict(e.headers) if e.headers else {}, redact_strings),
            "body": _scrub_text(body_text, redact_strings),
            "redirected": 300 <= e.code < 400,
        }
    except urllib.error.URLError as e:
        # `e.reason` can be a string that may include the full URL — which
        # already contains the secret in query mode. Only surface the
        # reason TYPE (a class name), never the message text.
        reason = e.reason
        if isinstance(reason, BaseException):
            reason_label = type(reason).__name__
        else:
            reason_label = "request error (details redacted; see server stderr)"
        raise _ToolError(f"request failed: {reason_label}")


def _collect_redaction_strings(
    secret: str, auth_scheme: str, args: dict[str, Any]
) -> list[str]:
    """Build the list of strings we must scrub from response data.

    Always includes the raw secret. For basic auth, also includes the
    base64-encoded `user:password` form. For query auth, also includes
    the URL-encoded secret and the `param=encoded` pair — since the
    response might echo back the request URL with the encoded form.

    Best-effort: cannot catch arbitrary transformations (hex, JSON-escape,
    multi-step encodings). See README for the response-redaction caveat.
    Strings <4 chars are skipped to avoid mangling unrelated text.
    """
    out: list[str] = []
    if secret and len(secret) >= 4:
        out.append(secret)
    if auth_scheme == "basic":
        import base64
        user = args.get("basic_user", "") or ""
        if isinstance(user, str):
            token = base64.b64encode(f"{user}:{secret}".encode("utf-8")).decode("ascii")
            if len(token) >= 4:
                out.append(token)
    elif auth_scheme == "query":
        from urllib.parse import quote
        if secret:
            encoded = quote(secret, safe="")
            if encoded != secret and len(encoded) >= 4:
                out.append(encoded)
            param = args.get("query_param") or ""
            if isinstance(param, str) and param:
                pair = f"{quote(param, safe='')}={encoded}"
                if len(pair) >= 4:
                    out.append(pair)
    # Deduplicate while preserving order so we always scrub the longest
    # forms first (small forms might be a prefix of larger encodings).
    seen: set[str] = set()
    dedup: list[str] = []
    for s in sorted(out, key=len, reverse=True):
        if s not in seen:
            seen.add(s)
            dedup.append(s)
    return dedup


def _scrub_text(text: str, redact_strings: list[str]) -> str:
    """Replace each sensitive string in `text` with `<REDACTED>`."""
    if not text or not redact_strings:
        return text
    for s in redact_strings:
        text = text.replace(s, "<REDACTED>")
    return text


def _scrub_headers(
    headers: dict[str, Any], redact_strings: list[str]
) -> dict[str, Any]:
    """Apply `_scrub_text` to every header name AND value.

    A server is free to put the secret in either position (e.g. an echo
    endpoint returning `X-<TOKEN>: 1`); both must be scrubbed.
    """
    if not redact_strings:
        return headers
    out: dict[str, Any] = {}
    for k, v in headers.items():
        scrubbed_k = _scrub_text(k, redact_strings) if isinstance(k, str) else k
        if isinstance(v, str):
            scrubbed_v = _scrub_text(v, redact_strings)
        else:
            scrubbed_v = v
        out[scrubbed_k] = scrubbed_v
    return out


def _read_capped(stream) -> str:
    """Read up to RESPONSE_BYTE_LIMIT bytes; decode as utf-8 with replacement."""
    raw = stream.read(RESPONSE_BYTE_LIMIT + 1)
    truncated_marker = b"\n[...truncated...]" if len(raw) > RESPONSE_BYTE_LIMIT else b""
    raw = raw[:RESPONSE_BYTE_LIMIT] + truncated_marker
    return raw.decode("utf-8", errors="replace")


# ────────────────────────────────────────────────────────────────────
# Resources
# ────────────────────────────────────────────────────────────────────

@_method("resources/list")
def _resources_list(params: dict[str, Any]) -> dict[str, Any]:
    # The audit log is INTENTIONALLY not exposed as an MCP resource:
    # historical audit events may contain reasons / extras / cmds that —
    # despite redaction in newer versions — predate the redaction and
    # could leak secrets to the AI. The human user can read it via
    # `aisafe audit` CLI.
    return {
        "resources": [
            {
                "uri": "aisafe://policy",
                "name": "Policy configuration",
                "mimeType": "application/json",
            },
        ]
    }


@_method("resources/read")
def _resources_read(params: dict[str, Any]) -> dict[str, Any]:
    uri = params.get("uri")
    if uri == "aisafe://policy":
        default, keys = _policy.list_policies()
        text = json.dumps(
            {
                "default": default,
                "keys": keys,
                "hosts": _policy.list_hosts(),
                "unsafe_methods": _policy.list_unsafe_methods(),
            },
            indent=2,
        )
        return {
            "contents": [{"uri": uri, "mimeType": "application/json", "text": text}]
        }
    raise _RpcError(-32602, f"unknown resource: {uri}")


# ────────────────────────────────────────────────────────────────────
# JSON-RPC plumbing
# ────────────────────────────────────────────────────────────────────

class _RpcError(Exception):
    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


def _read_message(stream) -> dict[str, Any] | None:
    line = stream.readline()
    if not line:
        return None
    line = line.strip()
    if not line:
        return _read_message(stream)
    try:
        return json.loads(line)
    except json.JSONDecodeError as e:
        raise _RpcError(-32700, f"parse error: {e}")


def _write_message(stream, obj: dict[str, Any]) -> None:
    stream.write(json.dumps(obj, ensure_ascii=False) + "\n")
    stream.flush()


def serve(stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr) -> None:
    """Run the MCP server over stdio until EOF."""
    global _policy_hash_at_startup
    _policy_hash_at_startup = _compute_policy_hash()
    _audit.record(
        "mcp", "*",
        result="allow",
        reason="server started",
        extra={"policy_hash": _policy_hash_at_startup.hex()
               if _policy_hash_at_startup else None},
    )
    try:
        _serve_loop(stdin, stdout, stderr)
    finally:
        # Always clear the hash, even if the loop blew up — otherwise a
        # later in-process consumer would see a stale "session is open"
        # state and refuse legitimate tool calls.
        _policy_hash_at_startup = None
        _audit.record("mcp", "*", result="allow", reason="server stopped")


def _serve_loop(stdin, stdout, stderr) -> None:
    while True:
        try:
            msg = _read_message(stdin)
        except _RpcError as e:
            _write_message(stdout, {
                "jsonrpc": "2.0", "id": None,
                "error": {"code": e.code, "message": e.message},
            })
            continue
        if msg is None:
            break

        method = msg.get("method")
        rpc_id = msg.get("id")
        params = msg.get("params") or {}
        handler = _methods.get(method)  # type: ignore[arg-type]

        if handler is None:
            if rpc_id is not None:
                _write_message(stdout, {
                    "jsonrpc": "2.0", "id": rpc_id,
                    "error": {"code": -32601, "message": f"method not found: {method}"},
                })
            continue

        try:
            result = handler(params)
        except _RpcError as e:
            _write_message(stdout, {
                "jsonrpc": "2.0", "id": rpc_id,
                "error": {"code": e.code, "message": e.message, "data": e.data},
            })
            continue
        except Exception:
            # The exception MESSAGE could include a final_url with a secret.
            # Never surface it; AISAFE_DEBUG=1 lets the operator opt in to
            # the traceback on stderr ONLY if no AI agent is detected.
            from . import detect as _detect
            debug = (
                os.environ.get("AISAFE_DEBUG") == "1"
                and _detect.detect() is None
            )
            if debug:
                print(f"aisafe-mcp: internal error in {method}", file=stderr)
                traceback.print_exc(file=stderr)
            else:
                print(
                    f"aisafe-mcp: internal error in {method} (details redacted)",
                    file=stderr,
                )
            if rpc_id is not None:
                _write_message(stdout, {
                    "jsonrpc": "2.0", "id": rpc_id,
                    "error": {"code": -32603, "message": "internal error (details redacted)"},
                })
            continue

        if rpc_id is None:
            continue
        _write_message(stdout, {"jsonrpc": "2.0", "id": rpc_id, "result": result})
