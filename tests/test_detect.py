"""Tests for AI-agent detection."""
from __future__ import annotations

import os

from aisafe import detect


def test_detect_returns_none_when_clean(isolated, monkeypatch):
    # conftest already stripped AI env vars
    assert detect.detect() is None
    assert detect.is_ai() is False


def test_detect_via_env_claudecode(isolated, monkeypatch):
    monkeypatch.setenv("CLAUDECODE", "1")
    ai = detect.detect()
    assert ai is not None
    assert ai.agent == "claude-code"
    assert ai.source == "env"


def test_detect_via_env_cursor(isolated, monkeypatch):
    monkeypatch.setenv("CURSOR_AGENT", "1")
    ai = detect.detect()
    assert ai is not None
    assert ai.agent == "cursor-agent"


def test_detect_via_user_optin(isolated, monkeypatch):
    """Users can declare they're running under an AI we don't auto-detect."""
    monkeypatch.setenv("AISAFE_AI", "my-custom-agent")
    ai = detect.detect()
    assert ai is not None
    assert ai.source == "env"
