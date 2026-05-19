"""Tests for the Critical/High fixes from the v0.3.1 codex review.

Covers:
  - exec scrubs AISAFE_* env vars from child
  - exec respects policy=deny per key
  - exec rejects env-name collisions instead of silent overwrite
  - policy file parse error → fail-closed (all reads deny)
  - host allowlist for MCP http_request
"""
from __future__ import annotations

import os
import sys

import pytest

from aisafe import exec_runner, policy, store
from aisafe.exec_runner import ExecPolicyError


# ──────────────────────────────────────────────────────────────────────
# Critical 3: scrub AISAFE_* from child env
# ──────────────────────────────────────────────────────────────────────

def test_exec_scrubs_aisafe_key_from_child(isolated, tmp_path, monkeypatch):
    """The master password (AISAFE_KEY) must not leak into the child env.

    The only AISAFE_* var the child should see is AISAFE_AI, which exec sets
    deliberately so any in-child aisafe import re-applies AI policy.
    """
    store.set("api.token", "secret-tok")
    monkeypatch.setenv("AISAFE_KEY", "MASTER-PASSWORD-DO-NOT-LEAK")

    out = tmp_path / "out.txt"
    script = tmp_path / "child.py"
    script.write_text(
        "import os, sys\n"
        "with open(sys.argv[1],'w') as f:\n"
        "  f.write(repr({k: os.environ.get(k) for k in os.environ if k.startswith('AISAFE_')}))\n"
    )

    rc = exec_runner.run([sys.executable, str(script), str(out)], sections=["api"])
    assert rc == 0
    contents = out.read_text()
    assert "AISAFE_KEY" not in contents, f"AISAFE_KEY leaked: {contents}"
    assert "MASTER-PASSWORD" not in contents
    # Child does see AISAFE_AI, but only the safe marker we injected.
    inherited = eval(contents)
    assert inherited == {"AISAFE_AI": "aisafe-exec-child"}


def test_exec_scrubs_all_aisafe_prefix(isolated, tmp_path, monkeypatch):
    """Anything starting with AISAFE_ is stripped, not only the known names."""
    store.set("api.token", "x")
    monkeypatch.setenv("AISAFE_NEW_INTERNAL_VAR", "value")

    out = tmp_path / "out.txt"
    script = tmp_path / "child.py"
    script.write_text(
        "import os, sys\n"
        "with open(sys.argv[1],'w') as f:\n"
        "  f.write(os.environ.get('AISAFE_NEW_INTERNAL_VAR','EMPTY'))\n"
    )
    exec_runner.run([sys.executable, str(script), str(out)], sections=["api"])
    assert out.read_text() == "EMPTY"


def test_exec_no_inherit_env_gives_clean_child(isolated, tmp_path, monkeypatch):
    """inherit_env=False starts the child with only the injected creds + extra_env."""
    monkeypatch.setenv("RANDOM_PARENT_VAR", "value")
    store.set("api.token", "x")

    out = tmp_path / "out.txt"
    script = tmp_path / "child.py"
    script.write_text(
        "import os, sys\n"
        "with open(sys.argv[1],'w') as f:\n"
        "  f.write(os.environ.get('RANDOM_PARENT_VAR','MISSING'))\n"
    )
    exec_runner.run([sys.executable, str(script), str(out)],
                    sections=["api"], inherit_env=False)
    assert out.read_text() == "MISSING"


# ──────────────────────────────────────────────────────────────────────
# High 5: exec respects per-key policy=deny
# ──────────────────────────────────────────────────────────────────────

def test_exec_skips_deny_policy_keys(isolated, tmp_path):
    store.set("db.host", "localhost")
    store.set("db.password", "SHOULD-NOT-LEAK")
    policy.set_key_policy("db.password", "deny")

    out = tmp_path / "out.txt"
    script = tmp_path / "child.py"
    script.write_text(
        "import os, sys\n"
        "with open(sys.argv[1],'w') as f:\n"
        "  f.write(f\"host={os.environ.get('DB_HOST','MISS')}|pw={os.environ.get('DB_PASSWORD','MISS')}\")\n"
    )
    rc = exec_runner.run(
        [sys.executable, str(script), str(out)],
        sections=["db"],
    )
    assert rc == 0
    contents = out.read_text()
    assert "host=localhost" in contents
    assert "pw=MISS" in contents
    assert "SHOULD-NOT-LEAK" not in contents


def test_exec_skips_deny_for_individual_key(isolated, tmp_path):
    """policy=deny on a key blocks even -k key explicit request."""
    store.set("a.b", "value")
    policy.set_key_policy("a.b", "deny")

    out = tmp_path / "out.txt"
    script = tmp_path / "child.py"
    script.write_text(
        "import os, sys\n"
        "with open(sys.argv[1],'w') as f:\n"
        "  f.write(os.environ.get('A_B','MISS'))\n"
    )
    exec_runner.run(
        [sys.executable, str(script), str(out)],
        keys=["a.b"],
    )
    assert out.read_text() == "MISS"


def test_exec_deny_is_audited(isolated):
    from aisafe import audit
    store.set("a.b", "value")
    policy.set_key_policy("a.b", "deny")
    exec_runner._resolve_env(keys=["a.b"])
    events = audit.tail()
    assert any(
        e.get("action") == "exec_expose" and e.get("result") == "deny"
        for e in events
    )


# ──────────────────────────────────────────────────────────────────────
# Medium 13: exec env-name collision detection
# ──────────────────────────────────────────────────────────────────────

def test_exec_collision_detection(isolated, tmp_path):
    """Two keys that map to the same env-var name must hard-fail, not silently overwrite."""
    store.set("a.b-c", "v1")
    store.set("a.b_c", "v2")  # both produce env name "A_B_C"

    with pytest.raises(ExecPolicyError, match="env var name collision"):
        exec_runner._resolve_env(sections=["a"])


# ──────────────────────────────────────────────────────────────────────
# High 7: policy parse error → fail-closed
# ──────────────────────────────────────────────────────────────────────

def test_broken_policy_denies_all_reads(isolated):
    """Malformed policies.toml must fail-closed, not fall back to deny_ai."""
    # Seed a credential first, while the policy file is still empty/clean.
    store.set("anything.here", "secret")
    assert store.get("anything.here") == "secret"

    # Now corrupt the policy file — reads must deny.
    isolated["policies"].write_text("this is = not [valid toml @#$\n")
    sentinel = object()
    assert store.get("anything.here", sentinel) is sentinel


def test_broken_policy_levels_deny_writes_too(isolated):
    """Broken policy file → writes are also blocked because evaluate() returns deny."""
    isolated["policies"].write_text('default = "made_up_level"\n')
    with pytest.raises(store.AccessDenied):
        store.set("api.key", "v")


def test_validate_reports_broken_file(isolated):
    isolated["policies"].write_text("garbage = not toml\n[")
    ok, msg = policy.validate()
    assert ok is False
    assert msg


def test_validate_reports_ok_when_clean(isolated):
    ok, msg = policy.validate()
    assert ok is True


def test_invalid_per_key_policy_is_fail_closed(isolated):
    isolated["policies"].write_text(
        'default = "deny_ai"\n[keys]\n"a.b" = "made_up_level"\n'
    )
    sentinel = object()
    # Pre-existing store value (written before policy was broken via raw file).
    isolated["creds"].write_text('[a]\nb = "v"\n')
    store.reload()
    assert store.get("a.b", sentinel) is sentinel


# ──────────────────────────────────────────────────────────────────────
# Critical 2: MCP http_request host allowlist
# ──────────────────────────────────────────────────────────────────────

def test_host_allowed_default_deny(isolated):
    """No allowlist entry → request denied."""
    ok, reason = policy.host_allowed("github.token", "https://api.github.com/user")
    assert ok is False
    assert "no host allowlist" in reason


def test_host_allowed_exact_match(isolated):
    policy.add_host("github.token", "api.github.com")
    ok, _ = policy.host_allowed("github.token", "https://api.github.com/user")
    assert ok is True
    ok, _ = policy.host_allowed("github.token", "https://gist.github.com/user")
    assert ok is False


def test_host_allowed_wildcard(isolated):
    policy.add_host("github.token", "*.github.com")
    for host in ("api.github.com", "gist.github.com", "raw.github.com"):
        ok, _ = policy.host_allowed("github.token", f"https://{host}/")
        assert ok is True, host
    # apex not matched by *.github.com
    ok, _ = policy.host_allowed("github.token", "https://github.com/")
    assert ok is False


def test_host_allowed_only_https(isolated):
    policy.add_host("github.token", "api.github.com")
    ok, reason = policy.host_allowed("github.token", "http://api.github.com/")
    assert ok is False
    assert "https" in reason.lower() or "scheme" in reason.lower()


def test_host_allowed_other_cred_does_not_grant(isolated):
    """Allowing api.github.com for github.token doesn't help stripe.secret."""
    policy.add_host("github.token", "api.github.com")
    ok, _ = policy.host_allowed("stripe.secret", "https://api.github.com/")
    assert ok is False


def test_add_remove_host_round_trip(isolated):
    policy.add_host("k.a", "host1.example.com")
    policy.add_host("k.a", "host2.example.com")
    hosts = policy.list_hosts()
    assert hosts["k.a"] == ["host1.example.com", "host2.example.com"]
    assert policy.remove_host("k.a", "host1.example.com") is True
    assert policy.list_hosts()["k.a"] == ["host2.example.com"]
    assert policy.remove_host("k.a", "host2.example.com") is True
    assert "k.a" not in policy.list_hosts()
    # Removing a host that's not there returns False.
    assert policy.remove_host("k.a", "anything") is False


# ──────────────────────────────────────────────────────────────────────
# Critical 1: MCP exec tool is removed
# ──────────────────────────────────────────────────────────────────────

def test_mcp_exec_tool_not_in_registry():
    """The dangerous `exec` MCP tool must not be exposed."""
    from aisafe import mcp_server
    tool_names = {t["name"] for t in mcp_server.TOOLS}
    assert "exec" not in tool_names
    # http_request, list_keys, policy_show still there
    assert "http_request" in tool_names
    assert "list_keys" in tool_names
