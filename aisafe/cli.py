"""
CLI interface for aisafe.

Usage:
    aisafe set <key> [value]       Set a credential (interactive if no value)
    aisafe get <key>               Get a credential value
    aisafe list [section]          List sections or keys within a section
    aisafe remove <key>            Remove a credential
    aisafe path                    Show credentials file path
"""

from __future__ import annotations

import argparse
import getpass
import sys

from . import store
from .paths import get_credentials_path


def cmd_set(args: argparse.Namespace) -> None:
    """Set a credential value."""
    key: str = args.key
    if args.value is not None:
        value = args.value
    else:
        value = getpass.getpass(f"Enter value for '{key}': ")

    store.set(key, value)
    print(f"✓ Set '{key}'")


def cmd_get(args: argparse.Namespace) -> None:
    """Get a credential value."""
    value = store.get(args.key)
    if value is None:
        print(f"✗ Key '{args.key}' not found", file=sys.stderr)
        sys.exit(1)
    print(value)


def cmd_list(args: argparse.Namespace) -> None:
    """List sections or keys."""
    if args.section:
        keys = store.list_keys(args.section)
        if not keys:
            print(f"✗ Section '{args.section}' not found or empty", file=sys.stderr)
            sys.exit(1)
        for key in keys:
            print(f"  {args.section}.{key}")
    else:
        sections = store.list_sections()
        if not sections:
            print("No credentials configured yet.")
            print(f"Run 'aisafe set <section>.<key>' to add one.")
            return
        for section in sections:
            keys = store.list_keys(section)
            print(f"[{section}]")
            for key in keys:
                print(f"  {key}")


def cmd_remove(args: argparse.Namespace) -> None:
    """Remove a credential."""
    if store.remove(args.key):
        print(f"✓ Removed '{args.key}'")
    else:
        print(f"✗ Key '{args.key}' not found", file=sys.stderr)
        sys.exit(1)


def cmd_path(args: argparse.Namespace) -> None:
    """Show credentials file path."""
    path = get_credentials_path()
    exists = path.exists()
    print(path)
    if not exists:
        print("(file does not exist yet)")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="aisafe",
        description="Local credential manager — keep secrets invisible to AI coding assistants",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # set
    p_set = subparsers.add_parser("set", help="Set a credential value")
    p_set.add_argument("key", help="Key in section.field format, e.g. database.password")
    p_set.add_argument("value", nargs="?", default=None, help="Value (omit for interactive input)")
    p_set.set_defaults(func=cmd_set)

    # get
    p_get = subparsers.add_parser("get", help="Get a credential value")
    p_get.add_argument("key", help="Key in section.field format")
    p_get.set_defaults(func=cmd_get)

    # list
    p_list = subparsers.add_parser("list", help="List sections or keys")
    p_list.add_argument("section", nargs="?", default=None, help="Section name (optional)")
    p_list.set_defaults(func=cmd_list)

    # remove
    p_remove = subparsers.add_parser("remove", help="Remove a credential")
    p_remove.add_argument("key", help="Key in section.field format")
    p_remove.set_defaults(func=cmd_remove)

    # path
    p_path = subparsers.add_parser("path", help="Show credentials file path")
    p_path.set_defaults(func=cmd_path)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
