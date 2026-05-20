"""Shared fixtures: isolate every test in a temp config dir."""
from __future__ import annotations

import os
from pathlib import Path

import pytest


# Env vars set by the host shell that would leak AI-detection or unlock state
# into tests. Strip them at module import time.
for var in (
    "CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT",
    "CURSOR_AGENT", "CURSOR_TRACE_ID",
    "GITHUB_COPILOT_CLI", "AIDER_VERSION",
    "CODEX_SESSION_ID", "WINDSURF_AGENT", "AISAFE_AI",
    "AISAFE_KEY", "AISAFE_STUB",
    "AISAFE_FILE", "AISAFE_POLICY_FILE", "AISAFE_AUDIT_LOG",
):
    os.environ.pop(var, None)


@pytest.fixture(autouse=True)
def _suppress_parent_chain_detection(monkeypatch: pytest.MonkeyPatch):
    """Tests run inside CI / Claude Code / etc. — those parents would otherwise
    trip the AI detector. Force parent-chain scan to return None; tests that
    want to simulate AI use the AISAFE_AI env var via mark_as_ai.

    Tests that need to exercise the *real* parent-chain logic (e.g. against a
    mocked psutil) must depend on the `real_parent_chain` fixture, which
    overrides this suppression for their scope.
    """
    from aisafe import detect
    # Stash the real implementation once, so `real_parent_chain` can restore it
    # without the autouse fixture clobbering it again on the same test.
    if not hasattr(detect, "_real_check_parent_chain"):
        detect._real_check_parent_chain = detect._check_parent_chain  # type: ignore[attr-defined]
    monkeypatch.setattr(detect, "_check_parent_chain", lambda: None)
    yield


@pytest.fixture
def real_parent_chain(monkeypatch: pytest.MonkeyPatch):
    """Restore the real `detect._check_parent_chain` for one test.

    Without this opt-in, the autouse `_suppress_parent_chain_detection`
    fixture would have replaced the real implementation with a stub —
    masking the very logic these tests exist to exercise.
    """
    from aisafe import detect
    monkeypatch.setattr(
        detect,
        "_check_parent_chain",
        detect._real_check_parent_chain,  # type: ignore[attr-defined]
    )
    yield


@pytest.fixture(autouse=True)
def _reset_mcp_policy_hash():
    """Defensive reset of the MCP server's per-session policy hash. Tests
    that drive _tools_call directly may set this global; if they fail
    before cleanup, later tests would inherit the stale 'session open'
    state and refuse all tool calls."""
    from aisafe import mcp_server
    mcp_server._policy_hash_at_startup = None
    yield
    mcp_server._policy_hash_at_startup = None


@pytest.fixture
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Point aisafe at a private temp dir for credentials, policy, and audit.

    Uses monkeypatch.setattr on the path-resolving functions (not env vars)
    so that AI-detection gating doesn't break test isolation. With env
    vars, a test that calls `mark_as_ai` would trip the production
    safeguard that ignores AISAFE_POLICY_FILE under AI detection and
    reach for the user's real `~/.config/aisafe/policies.toml`.
    """
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    creds = cfg / "credentials.toml"
    policies = cfg / "policies.toml"
    audit_log = cfg / "audit.log"

    from aisafe import audit, policy, store
    monkeypatch.setattr(policy, "_policy_path", lambda: policies)
    monkeypatch.setattr(audit, "_audit_path", lambda: audit_log)
    # `store` imports get_credentials_path at module load → patch the bound
    # name inside the store namespace, not the one in `paths`.
    monkeypatch.setattr(store, "get_credentials_path", lambda: creds)

    # Force a clean module state — store has module-level caches.
    store._cache = None
    store._cache_path = None
    store._custom_path = None
    store._master_password = None

    yield {"cfg": cfg, "creds": creds, "policies": policies, "audit": audit_log}


@pytest.fixture
def mark_as_ai(monkeypatch: pytest.MonkeyPatch):
    """Make aisafe.detect.detect() return a fake AI detection."""
    monkeypatch.setenv("AISAFE_AI", "test-agent")
    yield


@pytest.fixture
def as_human(monkeypatch: pytest.MonkeyPatch):
    """Explicitly clear any AI markers — for tests that need to mutate policy.

    Tests using `isolated` plus mutation APIs need this fixture (or to be
    careful not to set AISAFE_AI), because the v0.3.2 policy mutation guard
    refuses mutations whenever detect() returns truthy.
    """
    for var in ("AISAFE_AI", "CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT",
                "CURSOR_AGENT", "CURSOR_TRACE_ID", "GITHUB_COPILOT_CLI",
                "AIDER_VERSION", "CODEX_SESSION_ID", "WINDSURF_AGENT"):
        monkeypatch.delenv(var, raising=False)
    yield
