"""Tests for the MCP server's tools: JSON-RPC plumbing + http_request safety.

We don't run the full stdio loop; we call the in-process tool handlers
directly. Network calls in http_request are stubbed via monkeypatch of
the opener.
"""
from __future__ import annotations

import io
import json
import urllib.error
import urllib.request

import pytest

from aisafe import mcp_server, policy, store
from aisafe.mcp_server import _tool_http_request, _tool_list_keys, _tool_policy_show, _ToolError


# ──────────────────────────────────────────────────────────────────────
# http_request: allowlist gating
# ──────────────────────────────────────────────────────────────────────

def test_http_request_denied_without_allowlist(isolated):
    """No allowlist entry → tool rejects before any network call."""
    store.set("github.token", "ghp_xxx")
    with pytest.raises(_ToolError, match="no host allowlist"):
        _tool_http_request({
            "url": "https://api.github.com/user",
            "credential_key": "github.token",
        })


def test_http_request_denied_for_non_allowlisted_host(isolated):
    store.set("github.token", "ghp_xxx")
    policy.add_host("github.token", "api.github.com")
    with pytest.raises(_ToolError, match="not in allowlist"):
        _tool_http_request({
            "url": "https://evil.example.com/echo",
            "credential_key": "github.token",
        })


def test_http_request_denied_for_http_scheme(isolated):
    store.set("k.t", "v")
    policy.add_host("k.t", "example.com")
    with pytest.raises(_ToolError, match="scheme"):
        _tool_http_request({
            "url": "http://example.com/",
            "credential_key": "k.t",
        })


def test_http_request_credential_not_found(isolated):
    policy.add_host("missing.k", "example.com")
    with pytest.raises(_ToolError, match="not found"):
        _tool_http_request({
            "url": "https://example.com/",
            "credential_key": "missing.k",
        })


# ──────────────────────────────────────────────────────────────────────
# http_request: actual auth-header attachment (stubbed network)
# ──────────────────────────────────────────────────────────────────────

class _FakeResponse:
    """Minimal HTTPResponse stand-in."""
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
    def __exit__(self, *exc): return False


@pytest.fixture
def captured_request(monkeypatch):
    """Capture the Request object sent through the opener; return a 200 OK."""
    captured = {}

    def fake_open(req, timeout=None):
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["headers"] = dict(req.header_items())
        captured["data"] = req.data
        return _FakeResponse(200, {"Content-Type": "application/json"}, b'{"ok":true}')

    monkeypatch.setattr(mcp_server._no_redirect_opener, "open", fake_open)
    return captured


def test_http_request_attaches_bearer(isolated, captured_request):
    store.set("github.token", "ghp_xyz")
    policy.add_host("github.token", "api.github.com")
    result = _tool_http_request({
        "url": "https://api.github.com/user",
        "credential_key": "github.token",
    })
    assert result["status"] == 200
    # Header names in urllib.Request are title-cased for retrieval.
    assert captured_request["headers"].get("Authorization") == "Bearer ghp_xyz"


def test_http_request_attaches_basic(isolated, captured_request):
    import base64
    store.set("k.t", "passw0rd")
    policy.add_host("k.t", "example.com")
    _tool_http_request({
        "url": "https://example.com/",
        "credential_key": "k.t",
        "auth_scheme": "basic",
        "basic_user": "alice",
    })
    expected = "Basic " + base64.b64encode(b"alice:passw0rd").decode("ascii")
    assert captured_request["headers"].get("Authorization") == expected


def test_http_request_attaches_custom_header(isolated, captured_request):
    store.set("k.t", "key-abc")
    policy.add_host("k.t", "example.com")
    _tool_http_request({
        "url": "https://example.com/",
        "credential_key": "k.t",
        "auth_scheme": "header",
        "header_name": "X-Api-Key",
    })
    assert captured_request["headers"].get("X-api-key") == "key-abc"


def test_http_request_attaches_query_param(isolated, captured_request):
    store.set("k.t", "value with spaces")
    policy.add_host("k.t", "example.com")
    _tool_http_request({
        "url": "https://example.com/path?existing=1",
        "credential_key": "k.t",
        "auth_scheme": "query",
        "query_param": "api_key",
    })
    assert "api_key=value%20with%20spaces" in captured_request["url"]
    assert "existing=1" in captured_request["url"]


# ──────────────────────────────────────────────────────────────────────
# http_request: redirects are NOT followed
# ──────────────────────────────────────────────────────────────────────

def test_http_request_does_not_follow_redirect(isolated, monkeypatch):
    """A 302 surfaces as a normal 3xx response — credential is not auto-sent
    to the redirect target. The AI can decide what to do."""
    store.set("k.t", "secret")
    policy.add_host("k.t", "api.example.com")

    calls = []
    def fake_open(req, timeout=None):
        calls.append(req.full_url)
        # First (and only) call should be to api.example.com.
        # If urllib auto-followed, we'd see a second call to evil.example.com.
        raise urllib.error.HTTPError(
            req.full_url, 302, "Moved",
            __import__("http.client", fromlist=["HTTPMessage"]).HTTPMessage(),
            io.BytesIO(b"see other"),
        )

    monkeypatch.setattr(mcp_server._no_redirect_opener, "open", fake_open)
    result = _tool_http_request({
        "url": "https://api.example.com/",
        "credential_key": "k.t",
    })
    assert result["status"] == 302
    assert result.get("redirected") is True
    # Only one network call — no auto-follow.
    assert len(calls) == 1
    assert calls[0] == "https://api.example.com/"


# ──────────────────────────────────────────────────────────────────────
# http_request: response body is capped
# ──────────────────────────────────────────────────────────────────────

def test_http_request_caps_oversized_body(isolated, monkeypatch):
    store.set("k.t", "v")
    policy.add_host("k.t", "example.com")
    huge = b"A" * (mcp_server.RESPONSE_BYTE_LIMIT * 3)
    def fake_open(req, timeout=None):
        return _FakeResponse(200, {}, huge)
    monkeypatch.setattr(mcp_server._no_redirect_opener, "open", fake_open)
    result = _tool_http_request({
        "url": "https://example.com/",
        "credential_key": "k.t",
    })
    assert result["truncated"] is True
    assert len(result["body"]) <= mcp_server.RESPONSE_BYTE_LIMIT + 100


# ──────────────────────────────────────────────────────────────────────
# Other tools
# ──────────────────────────────────────────────────────────────────────

def test_list_keys_tool(isolated):
    store.set("a.b", "v")
    store.set("c.d", "w")
    result = _tool_list_keys({})
    assert set(result["keys"]) == {"a.b", "c.d"}


def test_policy_show_includes_hosts(isolated):
    policy.set_key_policy("a.b", "deny_ai")
    policy.add_host("a.b", "api.example.com")
    result = _tool_policy_show({})
    assert result["keys"]["a.b"] == "deny_ai"
    assert result["hosts"]["a.b"] == ["api.example.com"]


# ──────────────────────────────────────────────────────────────────────
# JSON-RPC loop sanity
# ──────────────────────────────────────────────────────────────────────

def _rpc_round_trip(*requests):
    """Drive mcp_server.serve() through an in-memory pipe of JSON-RPC requests."""
    stdin = io.StringIO("".join(json.dumps(r) + "\n" for r in requests))
    stdout = io.StringIO()
    stderr = io.StringIO()
    mcp_server.serve(stdin=stdin, stdout=stdout, stderr=stderr)
    responses = []
    for line in stdout.getvalue().splitlines():
        if line.strip():
            responses.append(json.loads(line))
    return responses


def test_rpc_initialize_and_list_tools(isolated):
    responses = _rpc_round_trip(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-03-26"}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )
    assert len(responses) == 2
    assert responses[0]["result"]["serverInfo"]["name"] == "aisafe"
    tools = [t["name"] for t in responses[1]["result"]["tools"]]
    assert "http_request" in tools
    assert "list_keys" in tools
    assert "exec" not in tools


def test_rpc_unknown_method_errors(isolated):
    responses = _rpc_round_trip(
        {"jsonrpc": "2.0", "id": 1, "method": "no_such_method", "params": {}},
    )
    assert responses[0]["error"]["code"] == -32601


def test_rpc_call_tool_via_loop(isolated):
    store.set("k.t", "v")
    responses = _rpc_round_trip(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "list_keys", "arguments": {}}},
    )
    assert responses[0]["result"]["isError"] is False
    payload = json.loads(responses[0]["result"]["content"][0]["text"])
    assert payload["keys"] == ["k.t"]
