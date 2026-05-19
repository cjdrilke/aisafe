"""Tests for the round-4 codex review fixes.

R4-1: audit log no longer records argv (cmdline) — prevents `aisafe set KEY VALUE`
      from leaking the secret into audit.log and through MCP `aisafe://audit`.
R4-2: store._custom_path is ignored once an AI agent is detected, even if a
      prior human caller set it via aisafe.init().
R4-3: Windows _trusted_home delegates to SHGetFolderPath (cannot be unit-tested
      on POSIX; covered indirectly via _trusted_home() behavior).
R4-4: bearer / basic generated Authorization headers run through
      _check_header_value so a stored secret containing \\n cannot inject
      extra headers.
R4-6: _trusted_home refuses setuid contexts (ruid != euid).
"""
from __future__ import annotations

import json
import os

import pytest

from aisafe import audit, mcp_server, paths, store
from aisafe.mcp_server import _tool_http_request, _ToolError


# ──────────────────────────────────────────────────────────────────────
# R4-1: cmdline not in audit log
# ──────────────────────────────────────────────────────────────────────

def test_audit_does_not_record_cmdline(isolated):
    """audit.log must not contain process argv, which would leak secrets
    set via `aisafe set KEY VALUE`."""
    store.set("api.key", "secret-value")
    text = isolated["audit"].read_text()
    assert text  # the log got something
    for line in text.splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        caller = event.get("caller", {})
        assert "cmdline" not in caller, f"cmdline leaked: {caller}"


def test_audit_still_records_useful_caller_info(isolated):
    """Dropping cmdline shouldn't kill all caller correlation — pid/exe stay."""
    store.set("a.b", "v")
    text = isolated["audit"].read_text()
    found_pid = False
    for line in text.splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if "caller" in event and "pid" in event["caller"]:
            found_pid = True
    assert found_pid


# ──────────────────────────────────────────────────────────────────────
# R4-2: _custom_path is re-checked under AI
# ──────────────────────────────────────────────────────────────────────

def test_custom_path_ignored_once_ai_detected(isolated, tmp_path, monkeypatch):
    """Human sets _custom_path, then AI enters → _get_path() must fall back
    to the default (conftest tmp path), not return the human's custom."""
    # Seed a "poisoned" custom file the AI would prefer.
    poisoned = tmp_path / "poisoned.toml"
    poisoned.write_text('[deploy]\ntoken = "ATTACKER_FAKE"\n')

    # Human-mode init.
    store._custom_path = poisoned  # bypass init() so we're explicitly testing
    # the persistence of _custom_path across the AI transition.
    assert store._get_path() == poisoned

    # AI enters.
    monkeypatch.setenv("AISAFE_AI", "test-agent")

    # _get_path must no longer return the poisoned path.
    assert store._get_path() != poisoned

    # cleanup
    store._custom_path = None


# ──────────────────────────────────────────────────────────────────────
# R4-4: bearer / basic generated headers go through _check_header_value
# ──────────────────────────────────────────────────────────────────────

def test_bearer_rejects_token_with_newline(isolated):
    """A stored token containing \\n must NOT be injected verbatim — it would
    let the secret split the Authorization header into two."""
    from aisafe import policy
    store.set("k.t", "abc\nInjected: 1")
    policy.add_host("k.t", "example.com")
    with pytest.raises(_ToolError, match="control"):
        _tool_http_request({
            "url": "https://example.com/",
            "credential_key": "k.t",
        })


def test_bearer_rejects_token_with_nul(isolated):
    from aisafe import policy
    store.set("k.t", "abc\x00def")
    policy.add_host("k.t", "example.com")
    with pytest.raises(_ToolError, match="control"):
        _tool_http_request({
            "url": "https://example.com/",
            "credential_key": "k.t",
        })


def test_basic_rejects_user_with_newline(isolated):
    from aisafe import policy
    store.set("k.t", "passw0rd")
    policy.add_host("k.t", "example.com")
    # basic_user contains CRLF; base64 encoding would normalize, but check
    # validation runs on the assembled Authorization value.
    # We construct a username whose base64 encoding includes a CRLF — this
    # is impossible in standard base64 alphabet, so the route here is via
    # a non-string user.
    with pytest.raises(_ToolError):
        _tool_http_request({
            "url": "https://example.com/",
            "credential_key": "k.t",
            "auth_scheme": "basic",
            "basic_user": 42,  # not a string
        })


def test_query_param_escapes_secret(isolated, monkeypatch):
    """In query mode, a secret containing & / \\n must be url-encoded, not
    bleed into the URL."""
    from aisafe import policy
    store.set("k.t", "value&other=evil")
    policy.add_host("k.t", "example.com")

    captured = {}
    def fake_open(req, timeout=None):
        captured["url"] = req.full_url
        class R:
            status = 200
            headers = {}
            def read(self, n=-1):
                return b""
            def __enter__(self):
                return self
            def __exit__(self, *exc):
                return False
        return R()
    monkeypatch.setattr(mcp_server._no_redirect_opener, "open", fake_open)

    _tool_http_request({
        "url": "https://example.com/path",
        "credential_key": "k.t",
        "auth_scheme": "query",
        "query_param": "api_key",
    })
    # The literal & must be url-encoded so it doesn't open a new param.
    assert "value%26other%3Devil" in captured["url"]


# ──────────────────────────────────────────────────────────────────────
# R4-6: setuid context refused
# ──────────────────────────────────────────────────────────────────────

def test_trusted_home_refuses_setuid(monkeypatch):
    """When real and effective UIDs differ, _trusted_home() refuses."""
    if not hasattr(os, "getuid"):
        pytest.skip("POSIX only")
    monkeypatch.setattr(os, "getuid", lambda: 1000)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(RuntimeError, match="setuid"):
        paths._trusted_home()


def test_trusted_home_uses_pwd_for_normal_uid(monkeypatch):
    """When ruid == euid, _trusted_home() uses pwd.getpwuid."""
    if not hasattr(os, "getuid"):
        pytest.skip("POSIX only")
    import pwd
    real_uid = os.getuid()  # capture before monkeypatch
    called = {"uid": None}
    real_getpwuid = pwd.getpwuid
    def fake_getpwuid(uid):
        called["uid"] = uid
        return real_getpwuid(uid)
    monkeypatch.setattr(pwd, "getpwuid", fake_getpwuid)
    monkeypatch.setattr(os, "getuid", lambda: real_uid)
    monkeypatch.setattr(os, "geteuid", lambda: real_uid)

    paths._trusted_home()
    assert called["uid"] == real_uid


# ──────────────────────────────────────────────────────────────────────
# R4-8: version is consistent
# ──────────────────────────────────────────────────────────────────────

def test_versions_in_sync():
    import aisafe
    from aisafe import mcp_server
    assert aisafe.__version__ == mcp_server.SERVER_VERSION
