"""
aisafe — Local credential manager.

Keep secrets invisible to AI coding assistants by storing them
outside of project workspaces, with optional AES-256-GCM encryption.

Usage:
    import aisafe

    # Plaintext mode
    password = aisafe.get("database.password")

    # Encrypted mode
    aisafe.unlock("master_password")  # or set AISAFE_KEY env var
    password = aisafe.get("database.password")
"""

from .store import (
    decrypt_store,
    encrypt_store,
    get,
    get_section,
    init,
    is_encrypted,
    list_keys,
    list_sections,
    reload,
    remove,
    set,
    unlock,
)

__version__ = "0.2.0"

__all__ = [
    "decrypt_store",
    "encrypt_store",
    "get",
    "get_section",
    "init",
    "is_encrypted",
    "list_keys",
    "list_sections",
    "reload",
    "remove",
    "set",
    "unlock",
]
