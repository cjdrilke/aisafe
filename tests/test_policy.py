"""Tests for the policy engine."""
from __future__ import annotations

import pytest

from aisafe import policy


def test_default_policy_is_deny_ai(isolated):
    assert policy.resolve("anything.here") == "deny_ai"


def test_set_and_get_policy(isolated):
    policy.set_key_policy("database.password", "deny")
    assert policy.resolve("database.password") == "deny"


def test_section_wildcard(isolated):
    policy.set_key_policy("database.*", "stub_ai")
    assert policy.resolve("database.password") == "stub_ai"
    assert policy.resolve("database.user") == "stub_ai"
    # exact match wins over wildcard
    policy.set_key_policy("database.user", "open")
    assert policy.resolve("database.user") == "open"
    assert policy.resolve("database.password") == "stub_ai"


def test_default_override(isolated):
    policy.set_default_policy("open")
    assert policy.resolve("anything") == "open"


def test_stub_env_forces_stub_ai(isolated, monkeypatch):
    policy.set_key_policy("a.b", "open")
    monkeypatch.setenv("AISAFE_STUB", "1")
    # AISAFE_STUB overrides everything
    assert policy.resolve("a.b") == "stub_ai"


def test_evaluate_read_allows_human_for_deny_ai(isolated):
    decision = policy.evaluate("api.key", action="read")
    assert decision.allow is True
    assert decision.policy == "deny_ai"
    assert decision.redact is False


def test_evaluate_read_denies_ai_for_deny_ai(isolated, mark_as_ai):
    decision = policy.evaluate("api.key", action="read")
    assert decision.allow is False
    assert decision.policy == "deny_ai"
    assert decision.ai is not None


def test_evaluate_read_stubs_ai_for_stub_ai(isolated, monkeypatch):
    # Set the policy as a human first, then become AI to read.
    policy.set_key_policy("a.b", "stub_ai")
    monkeypatch.setenv("AISAFE_AI", "test-agent")
    decision = policy.evaluate("a.b", action="read")
    assert decision.allow is True
    assert decision.redact is True


def test_evaluate_open_allows_anyone(isolated, monkeypatch):
    policy.set_key_policy("a.b", "open")
    monkeypatch.setenv("AISAFE_AI", "test-agent")
    decision = policy.evaluate("a.b", action="read")
    assert decision.allow is True


def test_evaluate_deny_blocks_everyone(isolated):
    policy.set_key_policy("a.b", "deny")
    decision = policy.evaluate("a.b", action="read")
    assert decision.allow is False


def test_remove_key_policy(isolated):
    policy.set_key_policy("a.b", "open")
    assert policy.remove_key_policy("a.b") is True
    assert policy.resolve("a.b") == "deny_ai"  # back to default
    assert policy.remove_key_policy("a.b") is False  # already gone


def test_invalid_policy_rejected(isolated):
    with pytest.raises(ValueError):
        policy.set_key_policy("a.b", "nonsense")  # type: ignore[arg-type]
