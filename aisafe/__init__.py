"""
aisafe — Local credential manager.

Keep secrets invisible to AI coding assistants by storing them
outside of project workspaces.

Usage:
    import aisafe

    password = aisafe.get("database.password")
    config = aisafe.get_section("database")
"""

from .store import (
    get,
    get_section,
    init,
    list_keys,
    list_sections,
    reload,
    remove,
    set,
)

__version__ = "0.1.0"

__all__ = [
    "get",
    "get_section",
    "init",
    "list_keys",
    "list_sections",
    "reload",
    "remove",
    "set",
]
