"""Tests for the round-9 codex review fixes.

R9-1: MCP server seals the policy file's SHA-256 at startup. If the file
      changes mid-session (e.g. an AI shell `echo`s new entries directly
      into ~/.config/aisafe/policies.toml), subsequent tool calls fail
      until the user restarts `aisafe mcp`.
"""
from __future__ import annotations

import io
import json

import pytest

from aisafe import mcp_server, policy, store


def _drive_rpc(*requests):
    """Drive `mcp_server.serve()` through an in-memory stdin/stdout."""
    stdin = io.StringIO("".join(json.dumps(r) + "\n" for r in requests))
    stdout = io.StringIO()
    stderr = io.StringIO()
    mcp_server.serve(stdin=stdin, stdout=stdout, stderr=stderr)
    return [json.loads(l) for l in stdout.getvalue().splitlines() if l.strip()]


def test_policy_hash_recorded_on_serve(isolated):
    """Starting `serve()` seeds the policy hash; ending clears it."""
    # nothing in policy file yet
    assert mcp_server._policy_hash_at_startup is None

    # Run a no-op session to verify the seed/teardown cycle.
    _drive_rpc({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}})
    # After serve() returns, the hash is reset.
    assert mcp_server._policy_hash_at_startup is None


def test_tool_call_succeeds_when_policy_unchanged(isolated):
    """Baseline: with policy file static, list_keys succeeds."""
    store.set("a.b", "v")
    responses = _drive_rpc(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "list_keys", "arguments": {}}},
    )
    assert responses[0]["result"]["isError"] is False


def test_tool_call_refused_when_policy_changes_midsession(isolated):
    """Simulate `serve()` having started by manually setting the hash,
    then mutate the policy file and call a tool."""
    # Stage 1: seed a hash as if serve() just started.
    mcp_server._policy_hash_at_startup = mcp_server._compute_policy_hash()

    # Stage 2: an attacker modifies the policy file directly.
    isolated["policies"].write_text(
        'default = "open"\n[hosts]\n"github.token" = ["api.github.com"]\n'
    )

    # Stage 3: any tool call must now refuse.
    result = mcp_server._tools_call({
        "name": "list_keys",
        "arguments": {},
    })
    assert result["isError"] is True
    text = result["content"][0]["text"]
    assert "policy file" in text.lower()
    assert "changed" in text.lower() or "restart" in text.lower()

    # cleanup
    mcp_server._policy_hash_at_startup = None


def test_tool_call_refused_when_policy_deleted_midsession(isolated):
    """Deleting the policy file is also a change — refuse."""
    isolated["policies"].write_text('default = "deny_ai"\n')
    mcp_server._policy_hash_at_startup = mcp_server._compute_policy_hash()
    isolated["policies"].unlink()

    result = mcp_server._tools_call({
        "name": "list_keys", "arguments": {},
    })
    assert result["isError"] is True
    mcp_server._policy_hash_at_startup = None


def test_integrity_check_skipped_when_not_in_mcp_session(isolated):
    """`_check_policy_integrity()` is a no-op outside a `serve()` session,
    so direct API tests don't trip over it."""
    # _policy_hash_at_startup defaults to None, integrity check returns.
    assert mcp_server._policy_hash_at_startup is None
    mcp_server._check_policy_integrity()  # must not raise


def test_compute_policy_hash_no_file(isolated):
    """When no policies.toml exists yet, the hash is the empty bytes."""
    assert not isolated["policies"].exists()
    assert mcp_server._compute_policy_hash() == b""


def test_compute_policy_hash_stable(isolated):
    isolated["policies"].write_text('default = "deny_ai"\n')
    h1 = mcp_server._compute_policy_hash()
    h2 = mcp_server._compute_policy_hash()
    assert h1 == h2
    assert h1 != b""


def test_compute_policy_hash_changes_with_content(isolated):
    isolated["policies"].write_text('default = "deny_ai"\n')
    h1 = mcp_server._compute_policy_hash()
    isolated["policies"].write_text('default = "open"\n')
    h2 = mcp_server._compute_policy_hash()
    assert h1 != h2


def test_versions_in_sync_after_r9():
    import aisafe
    assert aisafe.__version__ == mcp_server.SERVER_VERSION


def test_toctou_race_closed_in_http_request(isolated, monkeypatch):
    """R10-1: an attacker that flips the policy file AFTER host_allowed
    re-reads it but BEFORE _raw_get pulls the secret must still be
    rejected by the post-check `_check_policy_integrity()`."""
    # Seed valid state under a sealed MCP session.
    store.set("k.t", "real-secret-do-not-leak")
    policy.add_host("k.t", "api.example.com")
    mcp_server._policy_hash_at_startup = mcp_server._compute_policy_hash()

    # Monkey-patch host_allowed so we can flip the file between it and
    # the post-check + _raw_get, simulating an attacker race.
    real_host_allowed = mcp_server._policy.host_allowed
    def racing_host_allowed(credential_key, url):
        result = real_host_allowed(credential_key, url)
        # Flip the policy file mid-request.
        isolated["policies"].write_text(
            'default = "open"\n[hosts]\n"k.t" = ["*.evil.com"]\n'
        )
        return result
    monkeypatch.setattr(mcp_server._policy, "host_allowed", racing_host_allowed)

    # Stub the opener so we'd see the request only if the race wins.
    sent = {"happened": False}
    def fake_open(req, timeout=None):
        sent["happened"] = True
        class R:
            status = 200
            headers = {}
            def read(self, n=-1):
                return b""
            def __enter__(self):
                return self
            def __exit__(self, *e):
                return False
        return R()
    monkeypatch.setattr(mcp_server._no_redirect_opener, "open", fake_open)

    with pytest.raises(mcp_server._ToolError, match="policy file"):
        mcp_server._tool_http_request({
            "url": "https://api.example.com/x",
            "credential_key": "k.t",
        })

    # Request must NOT have been sent — the post-check killed it.
    assert sent["happened"] is False
    mcp_server._policy_hash_at_startup = None
