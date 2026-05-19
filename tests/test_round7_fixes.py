"""Tests for the round-7 codex review fixes.

R7-1: query auth scrubs URL-encoded forms of the secret from response.
R7-2: AISAFE_DEBUG is ignored when AI is detected.
R7-3: HTTP methods other than GET/HEAD require explicit policy opt-in.
R7-4: response header NAMES are scrubbed (not just values).
R7-5: audit URL strip also removes userinfo (user:pass@).
R7-9: policy mutation APIs validate credential keys.
"""
from __future__ import annotations

import io
import json
import os

import pytest

from aisafe import mcp_server, policy, store
from aisafe.mcp_server import (
    _ToolError,
    _tool_http_request,
    _redact_args,
    _strip_url_query_fragment,
    _collect_redaction_strings,
    _scrub_headers,
)
from aisafe.policy import PolicyMutationDenied


class _FakeResp:
    def __init__(self, status=200, headers=None, body=b""):
        self.status = status
        self.headers = headers or {}
        self._body = body
    def read(self, n=-1):
        if n is None or n < 0:
            data, self._body = self._body, b""
            return data
        data, self._body = self._body[:n], self._body[n:]
        return data
    def __enter__(self): return self
    def __exit__(self, *e): return False


# ──────────────────────────────────────────────────────────────────────
# R7-1: URL-encoded secret also redacted
# ──────────────────────────────────────────────────────────────────────

def test_query_auth_redacts_url_encoded_secret(isolated, monkeypatch):
    """Secret containing '+' / '/' gets URL-encoded by aisafe; if the
    endpoint echoes the URL, the encoded form must also be scrubbed."""
    SECRET = "tok+with/slash=="
    store.set("k.t", SECRET)
    policy.add_host("k.t", "example.com")

    from urllib.parse import quote
    encoded = quote(SECRET, safe="")  # 'tok%2Bwith%2Fslash%3D%3D'

    def fake_open(req, timeout=None):
        return _FakeResp(200, {}, f'{{"got": "?api_key={encoded}"}}'.encode())
    monkeypatch.setattr(mcp_server._no_redirect_opener, "open", fake_open)

    result = _tool_http_request({
        "url": "https://example.com/",
        "credential_key": "k.t",
        "auth_scheme": "query",
        "query_param": "api_key",
    })
    assert encoded not in result["body"]
    assert SECRET not in result["body"]


def test_collect_redaction_strings_includes_encoded_for_query():
    strings = _collect_redaction_strings(
        "tok+with/slash", "query", {"query_param": "api_key"}
    )
    from urllib.parse import quote
    encoded = quote("tok+with/slash", safe="")
    assert encoded in strings


def test_collect_redaction_strings_dedups_and_orders():
    """Longer strings come first so they get replaced before their prefixes."""
    strings = _collect_redaction_strings(
        "abcdef", "query", {"query_param": "k"}
    )
    # Should include raw, encoded (identical since no special chars), and pair.
    # The pair `k=abcdef` is longest, comes first.
    assert strings[0] == "k=abcdef"


# ──────────────────────────────────────────────────────────────────────
# R7-2: AISAFE_DEBUG ignored under AI
# ──────────────────────────────────────────────────────────────────────

def test_debug_env_ignored_under_ai(isolated, monkeypatch, capsys):
    """AI cannot enable traceback by setting AISAFE_DEBUG."""
    # Seed creds + host as human first.
    store.set("k.t", "v")
    policy.add_host("k.t", "example.com")
    monkeypatch.setenv("AISAFE_AI", "test-agent")

    def fake_open(req, timeout=None):
        raise RuntimeError("AI_SHOULD_NOT_SEE_THIS_MESSAGE")
    monkeypatch.setattr(mcp_server._no_redirect_opener, "open", fake_open)
    monkeypatch.setenv("AISAFE_DEBUG", "1")  # AI tries to enable

    mcp_server._tools_call({
        "name": "http_request",
        "arguments": {"url": "https://example.com/", "credential_key": "k.t"},
    })
    captured = capsys.readouterr()
    assert "AI_SHOULD_NOT_SEE_THIS_MESSAGE" not in captured.err
    assert "Traceback" not in captured.err


def test_debug_env_works_when_not_ai(isolated, monkeypatch, capsys):
    """Without AI, AISAFE_DEBUG=1 enables tracebacks normally."""
    store.set("k.t", "v")
    policy.add_host("k.t", "example.com")

    def fake_open(req, timeout=None):
        raise RuntimeError("HUMAN_DEBUG_OK")
    monkeypatch.setattr(mcp_server._no_redirect_opener, "open", fake_open)
    monkeypatch.setenv("AISAFE_DEBUG", "1")

    mcp_server._tools_call({
        "name": "http_request",
        "arguments": {"url": "https://example.com/", "credential_key": "k.t"},
    })
    captured = capsys.readouterr()
    assert "HUMAN_DEBUG_OK" in captured.err


# ──────────────────────────────────────────────────────────────────────
# R7-3: method allowlist
# ──────────────────────────────────────────────────────────────────────

def test_get_and_head_always_allowed(isolated):
    """GET/HEAD don't require any opt-in."""
    ok, _ = policy.method_allowed("any.key", "GET")
    assert ok
    ok, _ = policy.method_allowed("any.key", "HEAD")
    assert ok


@pytest.mark.parametrize("method", ["POST", "PATCH", "PUT", "DELETE"])
def test_unsafe_methods_denied_by_default(isolated, method):
    ok, reason = policy.method_allowed("k.t", method)
    assert ok is False
    assert "opt" in reason.lower() or "unsafe" in reason.lower()


def test_unsafe_method_after_opt_in(isolated):
    policy.add_unsafe_method("k.t", "POST")
    ok, _ = policy.method_allowed("k.t", "POST")
    assert ok
    ok, _ = policy.method_allowed("k.t", "DELETE")
    assert not ok  # only POST was opted in


def test_unsafe_method_opt_in_persisted(isolated):
    policy.add_unsafe_method("k.t", "POST")
    policy.add_unsafe_method("k.t", "PATCH")
    methods = policy.list_unsafe_methods()
    assert set(methods["k.t"]) == {"POST", "PATCH"}
    policy.remove_unsafe_method("k.t", "POST")
    assert policy.list_unsafe_methods()["k.t"] == ["PATCH"]


def test_add_unsafe_method_rejects_safe_method(isolated):
    with pytest.raises(ValueError, match="always allowed"):
        policy.add_unsafe_method("k.t", "GET")


def test_add_unsafe_method_rejects_unknown(isolated):
    with pytest.raises(ValueError, match="recognized"):
        policy.add_unsafe_method("k.t", "TRACE")


def test_add_unsafe_method_refused_under_ai(isolated, mark_as_ai):
    with pytest.raises(PolicyMutationDenied):
        policy.add_unsafe_method("k.t", "POST")


def test_http_request_post_denied_without_opt_in(isolated):
    store.set("k.t", "v")
    policy.add_host("k.t", "example.com")
    with pytest.raises(_ToolError, match="POST"):
        _tool_http_request({
            "url": "https://example.com/",
            "credential_key": "k.t",
            "method": "POST",
        })


def test_http_request_post_allowed_after_opt_in(isolated, monkeypatch):
    store.set("k.t", "v")
    policy.add_host("k.t", "example.com")
    policy.add_unsafe_method("k.t", "POST")

    captured = {}
    def fake_open(req, timeout=None):
        captured["method"] = req.get_method()
        return _FakeResp(200, {}, b"{}")
    monkeypatch.setattr(mcp_server._no_redirect_opener, "open", fake_open)

    _tool_http_request({
        "url": "https://example.com/",
        "credential_key": "k.t",
        "method": "POST",
    })
    assert captured["method"] == "POST"


# ──────────────────────────────────────────────────────────────────────
# R7-4: response header names also scrubbed
# ──────────────────────────────────────────────────────────────────────

def test_secret_in_response_header_name_scrubbed():
    """If the server returns `X-<TOKEN>: 1`, both the key and value are
    scrubbed for the secret."""
    SECRET = "leaked-via-header-name-XYZ"
    out = _scrub_headers(
        {f"X-{SECRET}": "1", "Content-Type": "text/plain"},
        [SECRET],
    )
    keys = list(out.keys())
    assert all(SECRET not in k for k in keys)
    assert "Content-Type" in keys


# ──────────────────────────────────────────────────────────────────────
# R7-5: _strip_url_query_fragment drops userinfo too
# ──────────────────────────────────────────────────────────────────────

def test_strip_url_removes_userinfo():
    stripped = _strip_url_query_fragment(
        "https://user:pass@api.example.com/path?x=1#frag"
    )
    assert "user" not in stripped
    assert "pass" not in stripped
    assert stripped == "https://api.example.com/path"


def test_strip_url_keeps_port():
    stripped = _strip_url_query_fragment("https://api.example.com:8443/v1?x=1")
    assert stripped == "https://api.example.com:8443/v1"


def test_strip_url_returns_unparseable_for_garbage():
    assert _strip_url_query_fragment("not a url at all") == "not a url at all" or \
        "<unparseable" in _strip_url_query_fragment("not a url at all")


def test_redact_args_url_drops_userinfo():
    out = _redact_args({"url": "https://u:p@x.example.com/path?q=1"})
    assert "u:p" not in out["url"]
    assert "u" not in out["url"].split("//")[1].split("/")[0]


# ──────────────────────────────────────────────────────────────────────
# R7-9: policy mutation APIs validate credential keys
# ──────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("bad_key", [
    "",
    "with space",
    "with\nnewline",
    "with\"quote",
    "a.b.c",          # 3 levels not in cred-key grammar
])
def test_policy_add_host_rejects_bad_cred_key(isolated, bad_key):
    with pytest.raises(ValueError):
        policy.add_host(bad_key, "example.com")


@pytest.mark.parametrize("bad_key", [
    "",
    "with space",
    "with\nnewline",
])
def test_policy_add_unsafe_method_rejects_bad_cred_key(isolated, bad_key):
    with pytest.raises(ValueError):
        policy.add_unsafe_method(bad_key, "POST")


@pytest.mark.parametrize("good_policy_key", [
    "key",
    "section.field",
    "section.*",
    "*",
])
def test_policy_set_key_policy_accepts_valid_forms(isolated, good_policy_key):
    policy.set_key_policy(good_policy_key, "deny_ai")


@pytest.mark.parametrize("bad_policy_key", [
    "",
    "*.foo",            # leading wildcard only allowed as the whole key
    "foo.*.bar",        # wildcard in middle
    "with space",
    "a.b.c",            # 3 levels
])
def test_policy_set_key_policy_rejects_bad_forms(isolated, bad_policy_key):
    with pytest.raises(ValueError):
        policy.set_key_policy(bad_policy_key, "deny_ai")


# ──────────────────────────────────────────────────────────────────────
# Version consistency
# ──────────────────────────────────────────────────────────────────────

def test_versions_in_sync_after_r7():
    import aisafe
    from aisafe import mcp_server
    assert aisafe.__version__ == mcp_server.SERVER_VERSION
