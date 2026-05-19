"""Tests for the round-2 codex review fixes.

Covers:
  R2-1: policy mutations refused under AI detection
  R2-2: AISAFE_POLICY_FILE env override ignored under AI
  R2-3: aisafe env CLI refused under AI
  R2-4: malformed [keys] / [hosts] table → fail-closed
  R2-5: host pattern validation
  R2-6: _NoRedirectHandler.http_error_* raises HTTPError for each 3xx code
  R2-8: extra_env cannot smuggle AISAFE_*; child gets AISAFE_AI=aisafe-exec-child
  R2-9: http_request method/header/timeout runtime validation
"""
from __future__ import annotations

import io
import os
import subprocess
import sys

import pytest

from aisafe import exec_runner, mcp_server, policy, store
from aisafe.mcp_server import _ToolError, _tool_http_request
from aisafe.policy import PolicyMutationDenied


# ──────────────────────────────────────────────────────────────────────
# R2-1: policy mutations refused under AI detection
# ──────────────────────────────────────────────────────────────────────

def test_ai_cannot_set_key_policy(isolated, mark_as_ai):
    with pytest.raises(PolicyMutationDenied):
        policy.set_key_policy("github.token", "open")


def test_ai_cannot_set_default_policy(isolated, mark_as_ai):
    with pytest.raises(PolicyMutationDenied):
        policy.set_default_policy("open")


def test_ai_cannot_remove_key_policy(isolated, mark_as_ai):
    with pytest.raises(PolicyMutationDenied):
        policy.remove_key_policy("anything")


def test_ai_cannot_add_host(isolated, mark_as_ai):
    with pytest.raises(PolicyMutationDenied):
        policy.add_host("github.token", "attacker.example.com")


def test_ai_cannot_remove_host(isolated, mark_as_ai):
    with pytest.raises(PolicyMutationDenied):
        policy.remove_host("github.token", "x")


def test_policy_mutation_denial_is_audited(isolated, mark_as_ai):
    from aisafe import audit
    with pytest.raises(PolicyMutationDenied):
        policy.set_key_policy("a.b", "open")
    events = audit.tail()
    assert any(
        e.get("action") == "policy_mutation" and e.get("result") == "deny"
        for e in events
    )


def test_human_can_still_mutate_policy(isolated):
    """Human (no AI detected) can mutate normally."""
    policy.set_key_policy("a.b", "open")
    policy.add_host("a.b", "example.com")
    assert policy.resolve("a.b") == "open"
    assert "example.com" in policy.list_hosts()["a.b"]


# ──────────────────────────────────────────────────────────────────────
# R2-2: AISAFE_POLICY_FILE override is ignored under AI
# ──────────────────────────────────────────────────────────────────────

def test_policy_file_override_ignored_under_ai(tmp_path, monkeypatch):
    """The env override must NOT redirect _policy_path under AI detection.

    Doesn't use the `isolated` fixture (which monkeypatches the function),
    so the env-based override logic actually runs.
    """
    # Reload the env-based logic by removing the conftest monkeypatch.
    # `isolated` is not used; we test _policy_path directly.
    attacker = tmp_path / "attacker.toml"
    attacker.write_text('default = "open"\n')
    monkeypatch.setenv("AISAFE_POLICY_FILE", str(attacker))
    monkeypatch.setenv("AISAFE_AI", "test-agent")

    actual = policy._policy_path()
    assert actual != attacker, (
        f"AISAFE_POLICY_FILE override was honored under AI; "
        f"got {actual}, would have been attacker policy"
    )


def test_policy_file_override_honored_for_human(tmp_path, monkeypatch):
    """Without AI, the env override works (developer workflow)."""
    legit = tmp_path / "dev-policies.toml"
    legit.write_text('default = "deny_ai"\n')
    monkeypatch.setenv("AISAFE_POLICY_FILE", str(legit))
    # ensure no AI markers
    for v in ("AISAFE_AI", "CLAUDECODE", "CURSOR_AGENT"):
        monkeypatch.delenv(v, raising=False)

    actual = policy._policy_path()
    assert actual == legit


# ──────────────────────────────────────────────────────────────────────
# R2-3: aisafe env CLI refused under AI
# ──────────────────────────────────────────────────────────────────────

def test_cli_env_refused_under_ai(isolated, tmp_path, monkeypatch):
    """`aisafe env` must refuse to print export lines when AI is detected,
    because the values go to stdout where the AI can read them."""
    store.set("api.token", "secret-value")

    # Need to invoke the CLI in a fresh subprocess so it sees the AI env var.
    # But also need to thread the temp paths through.
    proc = subprocess.run(
        [sys.executable, "-m", "aisafe.cli", "env", "-s", "api"],
        env={
            **os.environ,
            "AISAFE_FILE": str(isolated["creds"]),
            "AISAFE_POLICY_FILE": str(isolated["policies"]),
            "AISAFE_AUDIT_LOG": str(isolated["audit"]),
            "AISAFE_AI": "test-agent",
        },
        capture_output=True, text=True,
    )
    assert proc.returncode == 2
    assert "secret-value" not in proc.stdout
    assert "secret-value" not in proc.stderr
    assert "refused" in proc.stderr.lower()


# ──────────────────────────────────────────────────────────────────────
# R2-4: malformed [keys] / [hosts] table → fail-closed
# ──────────────────────────────────────────────────────────────────────

def test_keys_not_a_table_is_fail_closed(isolated):
    """[keys] as a scalar / list / int → fail-closed, not silent ignore."""
    isolated["policies"].write_text('default = "deny_ai"\nkeys = "not a table"\n')
    ok, reason = policy.validate()
    assert ok is False
    assert "keys" in reason.lower() or "table" in reason.lower()
    # And reads must deny.
    isolated["creds"].write_text('[a]\nb = "v"\n')
    store.reload()
    sentinel = object()
    assert store.get("a.b", sentinel) is sentinel


def test_hosts_not_a_table_is_fail_closed(isolated):
    isolated["policies"].write_text('default = "deny_ai"\nhosts = [1,2,3]\n')
    ok, reason = policy.validate()
    assert ok is False


def test_hosts_value_not_a_list_is_fail_closed(isolated):
    isolated["policies"].write_text(
        'default = "deny_ai"\n[hosts]\n"k.t" = "not a list"\n'
    )
    ok, _ = policy.validate()
    assert ok is False


def test_bad_host_pattern_in_file_is_fail_closed(isolated):
    isolated["policies"].write_text(
        'default = "deny_ai"\n[hosts]\n"k.t" = ["*.com"]\n'  # too broad
    )
    ok, reason = policy.validate()
    assert ok is False
    assert "host pattern" in reason.lower() or "broad" in reason.lower()


# ──────────────────────────────────────────────────────────────────────
# R2-5: host pattern validation
# ──────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("pattern", [
    "api.github.com",
    "*.github.com",
    "github.com",
    "foo.bar.baz.example.com",
    "x.io",
    "localhost.localdomain",
])
def test_valid_host_patterns_accepted(isolated, pattern):
    policy.add_host("k.t", pattern)
    assert pattern in policy.list_hosts()["k.t"]


@pytest.mark.parametrize("pattern,reason_keyword", [
    ("",                              "empty"),
    ("*",                             "label"),
    ("*.com",                         "broad"),
    ("*.io",                          "broad"),
    ("https://api.github.com",        "character"),
    ("api.github.com/path",           "character"),
    ("api.github.com:443",            "character"),
    ("user@host.com",                 "character"),
    ("api.\nattacker.com",            "character"),
    ("api..github.com",               "label"),
    (".github.com",                   "label"),
    ("-bad.com",                      "label"),
    ("bad-.com",                      "label"),
    ("foo.*.com",                     "leftmost"),
    ("*foo.com",                      "leftmost"),
])
def test_invalid_host_patterns_rejected(isolated, pattern, reason_keyword):
    with pytest.raises(ValueError) as exc:
        policy.add_host("k.t", pattern)
    assert reason_keyword in str(exc.value).lower()


# ──────────────────────────────────────────────────────────────────────
# R2-6: _NoRedirectHandler raises on each 3xx
# ──────────────────────────────────────────────────────────────────────

class _FakeReq:
    full_url = "https://example.com/"
    def get_full_url(self):
        return self.full_url


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_no_redirect_handler_raises_for_each_3xx(code):
    """Each redirect code must surface as HTTPError, not be auto-followed."""
    import urllib.error
    handler = mcp_server._NoRedirectHandler()
    method = getattr(handler, f"http_error_{code}")
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        method(_FakeReq(), io.BytesIO(b""), code, "Moved", {})
    assert exc_info.value.code == code


def test_no_redirect_opener_uses_no_redirect_handler():
    """The opener really has the handler installed (not just defined)."""
    handlers = mcp_server._no_redirect_opener.handlers
    assert any(isinstance(h, mcp_server._NoRedirectHandler) for h in handlers)


# ──────────────────────────────────────────────────────────────────────
# R2-8: extra_env cannot smuggle AISAFE_*
# ──────────────────────────────────────────────────────────────────────

def test_extra_env_aisafe_keys_dropped(isolated, tmp_path):
    """AI trying to slip AISAFE_KEY back through extra_env must fail."""
    store.set("api.token", "v")

    out = tmp_path / "out.txt"
    script = tmp_path / "child.py"
    script.write_text(
        "import os, sys\n"
        "with open(sys.argv[1],'w') as f:\n"
        "  f.write(os.environ.get('AISAFE_KEY','MISS'))\n"
    )
    exec_runner.run(
        [sys.executable, str(script), str(out)],
        sections=["api"],
        extra_env={"AISAFE_KEY": "SMUGGLED", "SAFE_VAR": "ok"},
    )
    assert out.read_text() == "MISS"


def test_extra_env_non_aisafe_passes_through(isolated, tmp_path):
    store.set("api.token", "v")
    out = tmp_path / "out.txt"
    script = tmp_path / "child.py"
    script.write_text(
        "import os, sys\n"
        "with open(sys.argv[1],'w') as f:\n"
        "  f.write(os.environ.get('MY_CONFIG','MISS'))\n"
    )
    exec_runner.run(
        [sys.executable, str(script), str(out)],
        sections=["api"],
        extra_env={"MY_CONFIG": "passed"},
    )
    assert out.read_text() == "passed"


def test_child_sees_aisafe_ai_marker(isolated, tmp_path):
    """The child env should include AISAFE_AI=aisafe-exec-child so that any
    in-child aisafe import re-applies AI policy."""
    store.set("api.token", "v")
    out = tmp_path / "out.txt"
    script = tmp_path / "child.py"
    script.write_text(
        "import os, sys\n"
        "with open(sys.argv[1],'w') as f:\n"
        "  f.write(os.environ.get('AISAFE_AI','MISS'))\n"
    )
    exec_runner.run(
        [sys.executable, str(script), str(out)],
        sections=["api"],
    )
    assert out.read_text() == "aisafe-exec-child"


# ──────────────────────────────────────────────────────────────────────
# R2-9: http_request runtime validation
# ──────────────────────────────────────────────────────────────────────

def test_http_request_rejects_bad_method(isolated):
    store.set("k.t", "v")
    policy.add_host("k.t", "example.com")
    with pytest.raises(_ToolError, match="not allowed"):
        _tool_http_request({
            "url": "https://example.com/",
            "credential_key": "k.t",
            "method": "TRACE",
        })


def test_http_request_rejects_bad_header_name(isolated):
    store.set("k.t", "v")
    policy.add_host("k.t", "example.com")
    with pytest.raises(_ToolError, match="invalid header name"):
        _tool_http_request({
            "url": "https://example.com/",
            "credential_key": "k.t",
            "headers": {"Bad Name With Spaces": "v"},
        })


def test_http_request_rejects_header_value_with_crlf(isolated):
    store.set("k.t", "v")
    policy.add_host("k.t", "example.com")
    with pytest.raises(_ToolError, match="control character"):
        _tool_http_request({
            "url": "https://example.com/",
            "credential_key": "k.t",
            "headers": {"X-Custom": "ok\r\nInjected: 1"},
        })


@pytest.mark.parametrize("bad_timeout", [-1, 0, 0.01, 1000, 99999])
def test_http_request_rejects_bad_timeout(isolated, bad_timeout):
    store.set("k.t", "v")
    policy.add_host("k.t", "example.com")
    with pytest.raises(_ToolError, match="timeout"):
        _tool_http_request({
            "url": "https://example.com/",
            "credential_key": "k.t",
            "timeout": bad_timeout,
        })


def test_http_request_rejects_non_string_method(isolated):
    store.set("k.t", "v")
    policy.add_host("k.t", "example.com")
    with pytest.raises(_ToolError, match="method"):
        _tool_http_request({
            "url": "https://example.com/",
            "credential_key": "k.t",
            "method": 42,
        })
