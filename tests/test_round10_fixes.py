"""
Round 10 — post-Linus review fixes.

Each test below documents a concrete defect that the Linus-style codex review
on 2026-05-19 found in v0.3.9, and pins down the fix:

  1. `store.py` wrote credential files without `chmod 0600`.
  2. `policy.evaluate()` loaded `policies.toml` twice per call (TOCTOU + waste).
  3. `AISAFE_STUB=1` could downgrade a `deny` policy to `stub_ai`, breaking the
     "deny means never expose, anywhere" invariant for `aisafe exec`.
  4. The autouse fixture stubbed out `_check_parent_chain` for the whole test
     suite, so the real parent-process scan was never exercised.

These tests are the regression net for those four fixes.
"""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest


# ────────────────────────────────────────────────────────────────────
# Fix 1 — store.py chmod 0600 on credential files
# ────────────────────────────────────────────────────────────────────

@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX perms only")
def test_plaintext_store_is_chmod_600(isolated, as_human):
    """Writing a plaintext credential creates a 0600 file.

    Before this fix, the file inherited the umask (typically 0644 or 0664),
    leaving credentials readable by other accounts on shared boxes."""
    from aisafe import store
    store.set("api.key", "secret-value")
    creds_path: Path = isolated["creds"]
    assert creds_path.exists()
    mode = stat.S_IMODE(creds_path.stat().st_mode)
    assert mode == 0o600, f"expected 0o600, got {oct(mode)}"


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX perms only")
def test_encrypted_store_is_chmod_600(isolated, as_human):
    """Encrypted writes get 0600 too — encryption is not an excuse to leave
    the file world-readable; an attacker with read access has the ciphertext
    and only needs to grind the master password."""
    from aisafe import store
    store.unlock("test-password-12345")
    store.set("api.key", "secret-value")
    enc_path: Path = isolated["creds"].with_suffix(".toml.enc")
    assert enc_path.exists()
    mode = stat.S_IMODE(enc_path.stat().st_mode)
    assert mode == 0o600, f"expected 0o600, got {oct(mode)}"


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX perms only")
def test_encrypt_store_resulting_file_is_chmod_600(isolated, as_human):
    """`aisafe.encrypt_store(...)` converting plaintext → encrypted must also
    chmod the encrypted output. Otherwise a user upgrading to encryption ends
    up with a world-readable .toml.enc."""
    from aisafe import store
    store.set("api.key", "secret-value")
    store.encrypt_store("password-9876")
    enc_path: Path = isolated["creds"].with_suffix(".toml.enc")
    assert enc_path.exists()
    mode = stat.S_IMODE(enc_path.stat().st_mode)
    assert mode == 0o600, f"expected 0o600, got {oct(mode)}"


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX perms only")
def test_decrypt_store_resulting_file_is_chmod_600(isolated, as_human):
    """Symmetric: downgrading encrypted → plaintext must chmod the plaintext."""
    from aisafe import store
    store.unlock("password-9876")
    store.set("api.key", "secret-value")
    store.decrypt_store("password-9876")
    plain_path: Path = isolated["creds"]
    assert plain_path.exists()
    mode = stat.S_IMODE(plain_path.stat().st_mode)
    assert mode == 0o600, f"expected 0o600, got {oct(mode)}"


# ────────────────────────────────────────────────────────────────────
# Fix 2 — policy.evaluate() must not re-load policies.toml twice
# ────────────────────────────────────────────────────────────────────

def test_evaluate_loads_policy_file_once_per_call(isolated, as_human):
    """`evaluate()` used to call `_load_state()` itself and then call
    `resolve()` which called `_load_state()` again — a TOCTOU window plus 2x
    file I/O for every credential access. After the fix it loads exactly once.
    """
    from aisafe import policy

    # Write a minimal policy so the file exists and is parsed.
    policy.set_default_policy("deny_ai")
    policy.set_key_policy("api.key", "open")

    calls = {"n": 0}
    original_load_state = policy._load_state

    def _counting_load_state():
        calls["n"] += 1
        return original_load_state()

    with patch.object(policy, "_load_state", side_effect=_counting_load_state):
        decision = policy.evaluate("api.key", action="read")

    assert decision.allow is True
    assert calls["n"] == 1, (
        f"evaluate() must read policies.toml exactly once, got {calls['n']} reads. "
        f"Two reads create a TOCTOU window where the file can be swapped between."
    )


# ────────────────────────────────────────────────────────────────────
# Fix 3 — AISAFE_STUB=1 cannot downgrade `deny` to `stub_ai`
# ────────────────────────────────────────────────────────────────────

def test_aisafe_stub_does_not_downgrade_deny(isolated, as_human, monkeypatch):
    """`AISAFE_STUB=1` forces stub_ai for everything *except* keys whose
    underlying policy is `deny`. Otherwise an AI that sets AISAFE_STUB=1 in
    its own env could trick `aisafe exec` (which only refuses keys whose
    `resolve()` returns "deny") into injecting deny-policy keys as
    environment variables on the child."""
    from aisafe import policy

    policy.set_key_policy("forbidden.key", "deny")
    policy.set_key_policy("other.key", "deny_ai")

    monkeypatch.setenv("AISAFE_STUB", "1")

    # AISAFE_STUB downgrades regular policies to stub_ai...
    assert policy.resolve("other.key") == "stub_ai"
    # ...but must NOT touch deny, because deny means "never expose, anywhere".
    assert policy.resolve("forbidden.key") == "deny"


def test_aisafe_stub_does_not_leak_deny_key_via_exec(
    isolated, as_human, monkeypatch
):
    """End-to-end version of the above: `aisafe exec` with `AISAFE_STUB=1` set
    must still skip deny-policy keys when building the child env."""
    from aisafe import policy, store, exec_runner

    policy.set_key_policy("vault.master", "deny")
    policy.set_key_policy("vault.other", "deny_ai")
    store.set("vault.master", "TOP-SECRET-VALUE")
    store.set("vault.other", "less-secret")

    monkeypatch.setenv("AISAFE_STUB", "1")

    env_dict = exec_runner._resolve_env(sections=["vault"])

    assert "VAULT_MASTER" not in env_dict, (
        "deny-policy key leaked into child env under AISAFE_STUB=1; this is "
        "the v0.3.9 bug Linus called out"
    )
    # The other key should still be present — it's deny_ai, not deny.
    assert "VAULT_OTHER" in env_dict
    assert env_dict["VAULT_OTHER"] == "less-secret"


# ────────────────────────────────────────────────────────────────────
# Fix 4 — real parent-chain scan is actually tested
# ────────────────────────────────────────────────────────────────────

def _fake_proc(name: str, pid: int = 999, parent=None, cmdline=None):
    """Build a stub object that quacks like psutil.Process for our needs."""
    return SimpleNamespace(
        name=lambda: name,
        pid=pid,
        parent=lambda: parent,
        cmdline=lambda: cmdline or [name],
    )


def test_parent_chain_detects_claude_binary(real_parent_chain, monkeypatch):
    """A parent process whose basename is exactly `claude` must trip the
    detector. This is the path Claude Code launches by — and the path the
    autouse fixture was hiding from every test in v0.3.9."""
    from aisafe import detect

    if not detect._HAS_PSUTIL:
        pytest.skip("psutil not installed")

    parent_claude = _fake_proc("claude", pid=4321)
    me = _fake_proc("python", pid=os.getpid(), parent=parent_claude)

    import psutil  # type: ignore

    monkeypatch.setattr(psutil, "Process", lambda pid=None: me)
    result = detect._check_parent_chain()

    assert result is not None
    assert result.agent == "claude-code"
    assert result.source == "parent-process"
    assert "claude" in result.detail


def test_parent_chain_detects_claude_via_node_cmdline(
    real_parent_chain, monkeypatch
):
    """Claude Code on macOS runs as `node /path/to/claude`. The detector
    peeks at cmdline when it sees a node parent — exercise that branch."""
    from aisafe import detect

    if not detect._HAS_PSUTIL:
        pytest.skip("psutil not installed")

    parent_node = _fake_proc(
        "node",
        pid=1234,
        cmdline=["node", "/usr/local/lib/node_modules/@anthropic/claude/cli.js"],
    )
    me = _fake_proc("python", pid=os.getpid(), parent=parent_node)

    import psutil  # type: ignore

    monkeypatch.setattr(psutil, "Process", lambda pid=None: me)
    result = detect._check_parent_chain()

    assert result is not None
    assert result.agent == "claude-code"
    assert result.source == "parent-process"


def test_parent_chain_detects_codex_binary(real_parent_chain, monkeypatch):
    """`codex` (OpenAI's CLI) — same shape as the claude case."""
    from aisafe import detect

    if not detect._HAS_PSUTIL:
        pytest.skip("psutil not installed")

    parent_codex = _fake_proc("codex", pid=5555)
    me = _fake_proc("python", pid=os.getpid(), parent=parent_codex)

    import psutil  # type: ignore

    monkeypatch.setattr(psutil, "Process", lambda pid=None: me)
    result = detect._check_parent_chain()

    assert result is not None
    assert result.agent == "codex"


def test_parent_chain_returns_none_for_innocent_parent(
    real_parent_chain, monkeypatch
):
    """A bash → python chain must NOT trip the detector."""
    from aisafe import detect

    if not detect._HAS_PSUTIL:
        pytest.skip("psutil not installed")

    grandparent = _fake_proc("init", pid=1)
    parent_bash = _fake_proc("bash", pid=42, parent=grandparent)
    me = _fake_proc("python", pid=os.getpid(), parent=parent_bash)

    import psutil  # type: ignore

    monkeypatch.setattr(psutil, "Process", lambda pid=None: me)
    result = detect._check_parent_chain()

    assert result is None


def test_parent_chain_respects_depth_limit(real_parent_chain, monkeypatch):
    """The detector walks at most 20 ancestors. Build a chain longer than
    that with the AI marker out past the limit — must return None."""
    from aisafe import detect

    if not detect._HAS_PSUTIL:
        pytest.skip("psutil not installed")

    # Chain shape: me → bash × 25 → claude.
    # The claude ancestor sits past depth=20, so it must be missed.
    claude_far_away = _fake_proc("claude", pid=9999)
    cursor = claude_far_away
    for i in range(25):
        cursor = _fake_proc(f"bash", pid=1000 + i, parent=cursor)
    me = _fake_proc("python", pid=os.getpid(), parent=cursor)

    import psutil  # type: ignore

    monkeypatch.setattr(psutil, "Process", lambda pid=None: me)
    result = detect._check_parent_chain()

    assert result is None, (
        "depth limit failed: claude found beyond 20 ancestors should not trip"
    )


def test_parent_chain_handles_psutil_error_gracefully(
    real_parent_chain, monkeypatch
):
    """If psutil raises (e.g. process vanished mid-walk), the detector must
    return None rather than propagate the exception — otherwise a flaky
    process tree would crash every `aisafe.get()` call."""
    from aisafe import detect

    if not detect._HAS_PSUTIL:
        pytest.skip("psutil not installed")

    import psutil  # type: ignore

    def _boom(pid=None):
        raise psutil.NoSuchProcess(pid or os.getpid())

    monkeypatch.setattr(psutil, "Process", _boom)
    # Must not raise.
    result = detect._check_parent_chain()
    assert result is None
