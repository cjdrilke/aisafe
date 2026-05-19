"""Tests that the policy engine actually gates store.get/set."""
from __future__ import annotations

import pytest

from aisafe import policy, store
from aisafe.store import AccessDenied


def test_human_can_read_with_default_policy(isolated):
    store.set("api.key", "secret-123")
    assert store.get("api.key") == "secret-123"


def test_ai_cannot_read_with_default_policy(isolated, mark_as_ai):
    # Set the value as a "human" first.
    # Simulate the human write by temporarily lifting the AI marker.
    import os
    os.environ.pop("AISAFE_AI")
    store.set("api.key", "secret-123")
    os.environ["AISAFE_AI"] = "test-agent"
    store.reload()

    # AI tries to read — denied (returns default).
    sentinel = object()
    assert store.get("api.key", sentinel) is sentinel
    assert store.get("api.key") is None


def test_stub_ai_returns_redacted(isolated, mark_as_ai):
    import os
    os.environ.pop("AISAFE_AI")
    store.set("api.key", "secret-123")
    policy.set_key_policy("api.key", "stub_ai")
    os.environ["AISAFE_AI"] = "test-agent"
    store.reload()

    value = store.get("api.key")
    assert value == "<REDACTED:api.key>"
    assert "secret-123" not in str(value)


def test_open_policy_lets_ai_read(isolated, mark_as_ai):
    import os
    os.environ.pop("AISAFE_AI")
    store.set("api.public_key", "pub-abc")
    policy.set_key_policy("api.public_key", "open")
    os.environ["AISAFE_AI"] = "test-agent"
    store.reload()

    assert store.get("api.public_key") == "pub-abc"


def test_ai_cannot_overwrite(isolated, mark_as_ai):
    with pytest.raises(AccessDenied):
        store.set("api.key", "AI-injected-value")


def test_ai_cannot_remove(isolated, mark_as_ai):
    import os
    os.environ.pop("AISAFE_AI")
    store.set("api.key", "secret")
    os.environ["AISAFE_AI"] = "test-agent"
    store.reload()

    with pytest.raises(AccessDenied):
        store.remove("api.key")


def test_get_section_redacts_per_key(isolated, mark_as_ai):
    import os
    os.environ.pop("AISAFE_AI")
    store.set("db.host", "localhost")
    store.set("db.password", "s3cret")
    policy.set_key_policy("db.host", "open")        # AI can see
    policy.set_key_policy("db.password", "stub_ai")  # AI gets stub
    os.environ["AISAFE_AI"] = "test-agent"
    store.reload()

    section = store.get_section("db")
    assert section["host"] == "localhost"
    assert section["password"] == "<REDACTED:db.password>"
    assert "s3cret" not in str(section)


def test_audit_log_records_denial(isolated, mark_as_ai):
    import json
    sentinel = object()
    store.get("does_not_matter.key", sentinel)

    audit_path = isolated["audit"]
    assert audit_path.exists()
    lines = audit_path.read_text().splitlines()
    assert any(
        json.loads(line)["result"] == "deny" for line in lines if line
    )
