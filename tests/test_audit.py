"""Tests for the audit log."""
from __future__ import annotations

import json

from aisafe import audit, store


def test_audit_records_every_read(isolated):
    store.set("a.b", "v")
    store.get("a.b")
    events = audit.tail()
    actions = [e["action"] for e in events]
    assert "write" in actions
    assert "read" in actions


def test_audit_captures_caller_pid(isolated):
    store.set("a.b", "v")
    events = audit.tail()
    assert all("caller" in e for e in events)
    assert all("pid" in e["caller"] for e in events)


def test_audit_tail_limits(isolated):
    for i in range(20):
        store.set(f"a.k{i}", str(i))
    events = audit.tail(5)
    assert len(events) <= 5


def test_audit_records_deny(isolated, mark_as_ai):
    import os
    os.environ.pop("AISAFE_AI")
    store.set("a.b", "v")
    os.environ["AISAFE_AI"] = "test-agent"

    store.get("a.b")
    last = audit.tail(1)[0]
    assert last["result"] == "deny"
    assert last["ai"]["agent"] == "user-declared"


def test_audit_jsonl_is_parseable(isolated):
    store.set("a.b", "v")
    store.get("a.b")
    text = audit.path().read_text()
    for line in text.splitlines():
        if line.strip():
            json.loads(line)  # must parse
