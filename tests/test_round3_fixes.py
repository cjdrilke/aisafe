"""Tests for the round-3 codex review fixes.

Covers:
  R3-1: get_config_dir ignores XDG_CONFIG_HOME / APPDATA / HOME under AI
  R3-2: get_credentials_path ignores AISAFE_FILE; store.init() refused; AISAFE_AUDIT_LOG ignored
  R3-3: exec_runner.env_export refused under AI (gate at API level, not just CLI)
  R3-4: header_name validated with RFC 7230 token regex
  R3-5: header values reject all CTL chars (not just CR/LF)
  R3-8: aisafe policy reset works even on broken policy file (recovery path)
"""
from __future__ import annotations

import os
import subprocess
import sys

import pytest

from aisafe import audit, exec_runner, mcp_server, paths, policy, store
from aisafe.mcp_server import _ToolError, _tool_http_request, _check_header_name, _check_header_value
from aisafe.store import AccessDenied
from aisafe.policy import PolicyMutationDenied


# ──────────────────────────────────────────────────────────────────────
# R3-1: config root cannot be redirected via env when AI is detected
# ──────────────────────────────────────────────────────────────────────

def test_xdg_config_home_ignored_under_ai(tmp_path, monkeypatch):
    """XDG_CONFIG_HOME override is bypassed when AI is detected."""
    attacker = tmp_path / "evilcfg"
    attacker.mkdir()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(attacker))
    monkeypatch.setenv("AISAFE_AI", "test-agent")

    cfg = paths.get_config_dir()
    # Must NOT be inside the attacker directory.
    assert attacker not in cfg.parents, f"config dir under attacker root: {cfg}"


def test_xdg_config_home_honored_for_human(tmp_path, monkeypatch):
    """Without AI, XDG_CONFIG_HOME override works (normal user / dev workflow)."""
    custom = tmp_path / "mycfg"
    custom.mkdir()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(custom))
    for v in ("AISAFE_AI", "CLAUDECODE", "CURSOR_AGENT"):
        monkeypatch.delenv(v, raising=False)
    cfg = paths.get_config_dir()
    assert cfg == custom / "aisafe"


def test_home_env_bypassed_under_ai(tmp_path, monkeypatch):
    """Even HOME can't be redirected — pwd-derived home wins."""
    monkeypatch.setenv("HOME", str(tmp_path / "fake-home"))
    monkeypatch.setenv("AISAFE_AI", "test-agent")
    home = paths._trusted_home()
    assert home != tmp_path / "fake-home"


# ──────────────────────────────────────────────────────────────────────
# R3-2: AISAFE_FILE / store.init / AISAFE_AUDIT_LOG locked under AI
# ──────────────────────────────────────────────────────────────────────

def test_aisafe_file_env_ignored_under_ai(tmp_path, monkeypatch):
    """AISAFE_FILE override (supply-chain poisoning vector) refused under AI."""
    attacker = tmp_path / "poisoned-creds.toml"
    attacker.write_text('[deploy]\ntoken = "ATTACKER_FAKE"\n')
    monkeypatch.setenv("AISAFE_FILE", str(attacker))
    monkeypatch.setenv("AISAFE_AI", "test-agent")
    creds = paths.get_credentials_path()
    assert creds != attacker


def test_aisafe_file_env_honored_for_human(tmp_path, monkeypatch):
    custom = tmp_path / "my-creds.toml"
    monkeypatch.setenv("AISAFE_FILE", str(custom))
    for v in ("AISAFE_AI", "CLAUDECODE", "CURSOR_AGENT"):
        monkeypatch.delenv(v, raising=False)
    assert paths.get_credentials_path() == custom


def test_store_init_refused_under_ai(isolated, mark_as_ai):
    """aisafe.init(path) is the programmatic equivalent of the env override —
    same risk, so same refusal."""
    with pytest.raises(AccessDenied):
        store.init("/dev/shm/attacker.toml")


def test_aisafe_audit_log_env_ignored_under_ai(tmp_path, monkeypatch):
    """AI redirecting audit log = AI suppressing evidence."""
    attacker = tmp_path / "discard.log"
    monkeypatch.setenv("AISAFE_AUDIT_LOG", str(attacker))
    monkeypatch.setenv("AISAFE_AI", "test-agent")
    assert audit._audit_path() != attacker


# ──────────────────────────────────────────────────────────────────────
# R3-3: env_export refused under AI at the API level
# ──────────────────────────────────────────────────────────────────────

def test_env_export_refused_under_ai(isolated, mark_as_ai):
    """An AI bypassing the CLI by importing exec_runner.env_export must still
    be refused at the API boundary."""
    # Seed credentials as a human.
    import os as _os
    _os.environ.pop("AISAFE_AI")
    store.set("api.token", "secret-value")
    _os.environ["AISAFE_AI"] = "test-agent"

    with pytest.raises(PermissionError):
        exec_runner.env_export(sections=["api"])


def test_env_export_audits_the_refusal(isolated, mark_as_ai):
    import os as _os
    _os.environ.pop("AISAFE_AI")
    store.set("api.token", "v")
    _os.environ["AISAFE_AI"] = "test-agent"

    with pytest.raises(PermissionError):
        exec_runner.env_export(sections=["api"])

    events = audit.tail()
    assert any(
        e.get("action") == "env_export" and e.get("result") == "deny"
        for e in events
    )


def test_env_export_works_for_human(isolated):
    """Without AI, env_export still works (legitimate user workflow)."""
    store.set("api.token", "v")
    text = exec_runner.env_export(sections=["api"])
    assert "API_TOKEN" in text


# ──────────────────────────────────────────────────────────────────────
# R3-4: header_name (for auth_scheme=header) validated
# ──────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("bad_name", [
    "X-Bad Name",          # space
    "X\r\nInjected",       # CRLF
    "X:Bad",               # colon
    "",                    # empty
    None,                  # not a string
    42,                    # not a string
    "Bad Name With Spaces",
])
def test_http_request_rejects_bad_header_name_for_auth_scheme(isolated, bad_name):
    store.set("k.t", "v")
    policy.add_host("k.t", "example.com")
    with pytest.raises(_ToolError):
        _tool_http_request({
            "url": "https://example.com/",
            "credential_key": "k.t",
            "auth_scheme": "header",
            "header_name": bad_name,
        })


def test_check_header_name_accepts_rfc7230_tokens():
    """RFC 7230 tokens allow these characters: !#$%&'*+-.^_`|~ and alphanumeric."""
    for good in ("Authorization", "X-Api-Key", "Content-Type", "X_Custom",
                 "X.Dotted", "X-token-32"):
        _check_header_name(good)  # no raise


# ──────────────────────────────────────────────────────────────────────
# R3-5: header values reject all CTL chars (NUL, BEL, etc.)
# ──────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("bad_value", [
    "value\x00null",       # NUL
    "value\x07bell",       # BEL
    "value\x1bescape",     # ESC
    "value\x7fdel",        # DEL
])
def test_http_request_rejects_ctl_chars_in_header_value(isolated, bad_value):
    store.set("k.t", "v")
    policy.add_host("k.t", "example.com")
    with pytest.raises(_ToolError, match="control"):
        _tool_http_request({
            "url": "https://example.com/",
            "credential_key": "k.t",
            "headers": {"X-Custom": bad_value},
        })


def test_check_header_value_allows_tab():
    """HTAB (0x09) is allowed in field-value per RFC 7230."""
    _check_header_value("ok\tvalue", "X-Custom")  # no raise


def test_check_header_value_rejects_cr_lf():
    with pytest.raises(_ToolError):
        _check_header_value("ok\r\nInjected", "X-Custom")


# ──────────────────────────────────────────────────────────────────────
# R3-8: aisafe policy reset (recovery from broken file)
# ──────────────────────────────────────────────────────────────────────

def test_policy_reset_overwrites_broken_file(isolated):
    """reset_to_default works even when the existing file is broken."""
    isolated["policies"].write_text("garbage = not toml [\n")
    ok, _ = policy.validate()
    assert ok is False

    policy.reset_to_default()

    ok, _ = policy.validate()
    assert ok is True
    default, keys = policy.list_policies()
    assert default == "deny_ai"
    assert keys == {}


def test_policy_reset_refused_under_ai(isolated, mark_as_ai):
    with pytest.raises(PolicyMutationDenied):
        policy.reset_to_default()


def test_policy_reset_overwrites_existing_clean_file(isolated):
    """Even non-broken policy can be reset (intentional clobber)."""
    policy.set_key_policy("a.b", "open")
    policy.add_host("c.d", "example.com")
    policy.reset_to_default()
    assert policy.list_policies()[1] == {}
    assert policy.list_hosts() == {}


def test_policy_reset_cli_requires_yes_without_tty(isolated, tmp_path):
    """Without --yes on a non-TTY, reset must refuse (no silent destruction)."""
    proc = subprocess.run(
        [sys.executable, "-m", "aisafe.cli", "policy", "reset"],
        env={
            **os.environ,
            "AISAFE_FILE": str(isolated["creds"]),
            "AISAFE_POLICY_FILE": str(isolated["policies"]),
            "AISAFE_AUDIT_LOG": str(isolated["audit"]),
        },
        input="", capture_output=True, text=True,
    )
    assert proc.returncode != 0
    assert "--yes" in proc.stderr or "TTY" in proc.stderr
