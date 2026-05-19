"""Tests for the round-5 codex review fixes.

R5-1: MCP http_request never returns/audits a string containing the secret
      even when urllib raises during URL construction. URLs with raw CTL
      characters are rejected before the secret is touched. The generic
      exception handler returns a redacted message and does NOT log
      traceback.
R5-2: store._cache is invalidated when _get_path() changes — preventing a
      poisoned credential cache from surviving the AI-detection boundary.
R5-3: audit log no longer records full exec argv (only argv0 + argc), no
      tracebacks, and MCP no longer exposes aisafe://audit to the AI.
R5-4: Windows get_config_dir uses SHGetFolderPathW result directly (does
      not double-append AppData/Roaming).
R5-5: query-mode auth uses urlsplit/urlunsplit so the secret is merged
      before any fragment.
R5-6: POSIX _posix_trusted_home(ai_detected=True) raises on pwd failure
      instead of falling back to HOME-derived Path.home().
R5-7: store.set() validates the credential key syntax.
"""
from __future__ import annotations

import io
import json
import os

import pytest

from aisafe import audit, exec_runner, mcp_server, paths, policy, store
from aisafe.mcp_server import _ToolError, _tool_http_request


# ──────────────────────────────────────────────────────────────────────
# R5-1: URL CTL rejection + scrubbed exception path
# ──────────────────────────────────────────────────────────────────────

def test_url_with_newline_rejected_before_secret_pulled(isolated):
    """A URL containing \\n must be refused before the credential is even
    touched — otherwise urllib's later InvalidURL exception would embed
    the secret."""
    store.set("k.t", "SUPER-SECRET-TOKEN-XYZ")
    policy.add_host("k.t", "example.com")
    with pytest.raises(_ToolError, match="control"):
        _tool_http_request({
            "url": "https://example.com/path\n",
            "credential_key": "k.t",
        })


def test_url_with_nul_rejected(isolated):
    store.set("k.t", "v")
    policy.add_host("k.t", "example.com")
    with pytest.raises(_ToolError, match="control"):
        _tool_http_request({
            "url": "https://example.com/\x00",
            "credential_key": "k.t",
        })


def test_url_with_space_rejected(isolated):
    """RFC 3986 disallows raw space; aisafe rejects to prevent ambiguous splits."""
    store.set("k.t", "v")
    policy.add_host("k.t", "example.com")
    with pytest.raises(_ToolError, match="control"):
        _tool_http_request({
            "url": "https://example.com/x y",
            "credential_key": "k.t",
        })


def test_internal_exception_does_not_leak_secret(isolated, monkeypatch):
    """Force a runtime exception AFTER the secret is in the URL. Ensure
    neither the MCP response NOR the audit log contains the secret."""
    SECRET = "FORENSIC-PROBE-SECRET-12345"
    store.set("k.t", SECRET)
    policy.add_host("k.t", "example.com")

    # Make the opener blow up with a message that includes the URL.
    def fake_open(req, timeout=None):
        # urllib.error.InvalidURL.__str__ includes the full URL — simulate.
        import urllib.error
        raise urllib.error.URLError(f"failed for {req.full_url}")

    monkeypatch.setattr(mcp_server._no_redirect_opener, "open", fake_open)

    # Route through the tools/call wrapper to hit the generic catch.
    result = mcp_server._tools_call({
        "name": "http_request",
        "arguments": {
            "url": "https://example.com/",
            "credential_key": "k.t",
            "auth_scheme": "query",
            "query_param": "api_key",
        },
    })
    # The text the AI sees must not contain the secret.
    surfaced = result["content"][0]["text"]
    assert SECRET not in surfaced

    # The audit log must not contain the secret either.
    audit_text = isolated["audit"].read_text() if isolated["audit"].exists() else ""
    assert SECRET not in audit_text


# ──────────────────────────────────────────────────────────────────────
# R5-2: cache invalidation across AI boundary
# ──────────────────────────────────────────────────────────────────────

def test_cache_invalidated_when_get_path_changes(isolated, tmp_path, monkeypatch):
    """Human-era _custom_path populates _cache; once AI appears and the
    custom path is ignored, the next _load() must re-read from the new
    canonical path rather than serving stale cache."""
    poisoned = tmp_path / "poisoned.toml"
    poisoned.write_text('[deploy]\ntoken = "ATTACKER_VALUE"\n')

    # Pretend a human had run aisafe.init() pointing at the poisoned file.
    store._custom_path = poisoned
    # Force load — cache now holds poisoned content.
    data = store._load()
    assert data.get("deploy", {}).get("token") == "ATTACKER_VALUE"

    # AI shows up.
    monkeypatch.setenv("AISAFE_AI", "test-agent")

    # _load() should re-read from the canonical (conftest-tmp) path,
    # which is empty — NOT serve poisoned cache.
    data2 = store._load()
    assert "deploy" not in data2 or data2.get("deploy", {}).get("token") != "ATTACKER_VALUE"

    # cleanup
    store._custom_path = None
    store._cache = None
    store._cache_path = None


# ──────────────────────────────────────────────────────────────────────
# R5-3: audit redaction (no full argv, no traceback, no MCP exposure)
# ──────────────────────────────────────────────────────────────────────

def test_exec_audit_records_only_argv0_and_argc(isolated, tmp_path):
    import sys
    store.set("api.token", "v")
    script = tmp_path / "child.py"
    script.write_text("import sys")
    exec_runner.run(
        [sys.executable, str(script), "POTENTIAL_SECRET_ARG"],
        sections=["api"],
    )
    text = isolated["audit"].read_text()
    assert "POTENTIAL_SECRET_ARG" not in text
    # But we should still see the binary name and arg count.
    found = False
    for line in text.splitlines():
        if not line.strip():
            continue
        ev = json.loads(line)
        cmd = ev.get("extra", {}).get("cmd")
        if isinstance(cmd, dict) and "argv0" in cmd and "argc" in cmd:
            found = True
            assert cmd["argc"] == 3
    assert found


def test_mcp_audit_resource_removed():
    """aisafe://audit was removed because the audit log can contain
    historical entries with old-format cmdlines that pre-date redaction."""
    result = mcp_server._resources_list({})
    uris = [r["uri"] for r in result["resources"]]
    assert "aisafe://audit" not in uris
    # policy resource still present.
    assert "aisafe://policy" in uris


def test_mcp_audit_resource_read_rejected():
    with pytest.raises(Exception):
        mcp_server._resources_read({"uri": "aisafe://audit"})


def test_internal_error_audit_has_no_traceback(isolated, monkeypatch):
    """When tools/call hits an unexpected exception, audit must not store
    a traceback (which could include the secret in a frame's locals/args)."""
    store.set("k.t", "v")
    policy.add_host("k.t", "example.com")

    def fake_open(req, timeout=None):
        raise RuntimeError("boom")
    monkeypatch.setattr(mcp_server._no_redirect_opener, "open", fake_open)

    mcp_server._tools_call({
        "name": "http_request",
        "arguments": {
            "url": "https://example.com/",
            "credential_key": "k.t",
        },
    })
    text = isolated["audit"].read_text()
    assert "traceback" not in text.lower()
    assert "Traceback" not in text


# ──────────────────────────────────────────────────────────────────────
# R5-5: query auth fragment handling
# ──────────────────────────────────────────────────────────────────────

def test_query_auth_with_fragment_in_url(isolated, monkeypatch):
    """A URL with a #fragment must have the secret param merged INTO the
    query, not appended after the fragment."""
    SECRET = "frag-test-secret"
    store.set("k.t", SECRET)
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
        "url": "https://example.com/path#anchor",
        "credential_key": "k.t",
        "auth_scheme": "query",
        "query_param": "api_key",
    })
    final = captured["url"]
    # The query must appear BEFORE the fragment.
    q_pos = final.find("?api_key=")
    f_pos = final.find("#anchor")
    assert q_pos > 0
    assert f_pos > q_pos


def test_query_auth_merges_with_existing_params(isolated, monkeypatch):
    """When the URL already has a query string, the secret param is appended
    via urlencode rather than naive concatenation."""
    store.set("k.t", "v")
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
        "url": "https://example.com/p?existing=1",
        "credential_key": "k.t",
        "auth_scheme": "query",
        "query_param": "api_key",
    })
    assert "existing=1" in captured["url"]
    assert "api_key=v" in captured["url"]


# ──────────────────────────────────────────────────────────────────────
# R5-6: POSIX trusted home fail-closed under AI
# ──────────────────────────────────────────────────────────────────────

def test_posix_trusted_home_fails_closed_under_ai_when_pwd_missing(monkeypatch):
    """When AI is detected and pwd lookup raises, do NOT fall back to
    Path.home() (which reads HOME)."""
    import pwd
    real_uid = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: real_uid)
    monkeypatch.setattr(os, "geteuid", lambda: real_uid)
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: (_ for _ in ()).throw(KeyError(uid)))

    with pytest.raises(RuntimeError, match="trusted home"):
        paths._posix_trusted_home(ai_detected=True)


def test_posix_trusted_home_falls_back_for_human_when_pwd_missing(monkeypatch):
    """Human caller can fall back to Path.home() (best-effort)."""
    import pwd
    real_uid = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: real_uid)
    monkeypatch.setattr(os, "geteuid", lambda: real_uid)
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: (_ for _ in ()).throw(KeyError(uid)))

    result = paths._posix_trusted_home(ai_detected=False)
    assert isinstance(result, type(paths.Path()))


# ──────────────────────────────────────────────────────────────────────
# R5-7: credential key syntax validation
# ──────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("good_key", [
    "api.key",
    "database.password",
    "section.field",
    "topkey",
    "x_y.z-w",
    "GitHub.Token",
])
def test_valid_keys_accepted(isolated, good_key):
    store.set(good_key, "value")
    assert store.get(good_key) == "value"


@pytest.mark.parametrize("bad_key", [
    "",
    ".leading.dot",
    "trailing.dot.",
    "double..dot",
    "a.b.c",                # 3 levels not supported
    "section.field.",
    "with space",
    "with\"quote",
    "with\nnewline",
    "with[bracket]",
    "with=equals",
    "0digit_first",
    "-hyphen_first",
    "section.0field",
    "a" * 300,
])
def test_invalid_keys_rejected(isolated, bad_key):
    with pytest.raises(ValueError):
        store.set(bad_key, "value")
