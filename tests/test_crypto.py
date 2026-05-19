"""Smoke tests for the crypto layer (unchanged from v0.2)."""
from __future__ import annotations

import pytest

from aisafe import crypto


def test_roundtrip():
    pt = b"hello world"
    blob = crypto.encrypt(pt, "password123")
    assert crypto.decrypt(blob, "password123") == pt


def test_wrong_password_fails():
    blob = crypto.encrypt(b"x", "right")
    with pytest.raises(ValueError):
        crypto.decrypt(blob, "wrong")


def test_tampering_detected():
    blob = bytearray(crypto.encrypt(b"x", "p"))
    blob[-1] ^= 0xFF
    with pytest.raises(ValueError):
        crypto.decrypt(bytes(blob), "p")
