"""
CLI interface for aisafe.

Usage:
    aisafe set <key> [value]       Set a credential (interactive if no value)
    aisafe get <key>               Get a credential value
    aisafe list [section]          List sections or keys within a section
    aisafe remove <key>            Remove a credential
    aisafe path                    Show credentials file path
    aisafe encrypt                 Encrypt the credential file
    aisafe decrypt                 Decrypt back to plaintext
    aisafe status                  Show encryption status
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from . import store
from .paths import get_credentials_path


def _ensure_unlocked() -> None:
    """Prompt for password if credentials are encrypted and not yet unlocked."""
    if store.is_encrypted() and store._get_password() is None:
        password = getpass.getpass("Master password: ")
        store.unlock(password)


def cmd_set(args: argparse.Namespace) -> None:
    """Set a credential value."""
    _ensure_unlocked()
    key: str = args.key
    if args.value is not None:
        value = args.value
    else:
        value = getpass.getpass(f"Enter value for '{key}': ")

    store.set(key, value)
    print(f"✓ Set '{key}'")


def cmd_get(args: argparse.Namespace) -> None:
    """Get a credential value."""
    _ensure_unlocked()
    value = store.get(args.key)
    if value is None:
        print(f"✗ Key '{args.key}' not found", file=sys.stderr)
        sys.exit(1)
    print(value)


def cmd_list(args: argparse.Namespace) -> None:
    """List sections or keys."""
    _ensure_unlocked()
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
    _ensure_unlocked()
    if store.remove(args.key):
        print(f"✓ Removed '{args.key}'")
    else:
        print(f"✗ Key '{args.key}' not found", file=sys.stderr)
        sys.exit(1)


def cmd_path(args: argparse.Namespace) -> None:
    """Show credentials file path."""
    plain_path = get_credentials_path()
    enc_path = plain_path.with_suffix(".toml.enc")

    if enc_path.exists():
        print(f"{enc_path} (encrypted 🔒)")
    elif plain_path.exists():
        print(f"{plain_path} (plaintext ⚠️)")
    else:
        print(f"{plain_path} (not created yet)")


def cmd_encrypt(args: argparse.Namespace) -> None:
    """Encrypt the credential file."""
    if store.is_encrypted():
        print("✗ Already encrypted", file=sys.stderr)
        sys.exit(1)

    plain_path = get_credentials_path()
    if not plain_path.exists():
        print("✗ No credentials file to encrypt", file=sys.stderr)
        sys.exit(1)

    password = getpass.getpass("Set master password: ")
    confirm = getpass.getpass("Confirm master password: ")
    if password != confirm:
        print("✗ Passwords do not match", file=sys.stderr)
        sys.exit(1)
    if len(password) < 4:
        print("✗ Password too short (min 4 characters)", file=sys.stderr)
        sys.exit(1)

    store.encrypt_store(password)
    print("✓ Credentials encrypted 🔒")
    print(f"  File: {plain_path.with_suffix('.toml.enc')}")
    print(f"  Plaintext file removed")


def cmd_decrypt(args: argparse.Namespace) -> None:
    """Decrypt the credential file back to plaintext."""
    if not store.is_encrypted():
        print("✗ Not encrypted", file=sys.stderr)
        sys.exit(1)

    password = getpass.getpass("Master password: ")

    try:
        store.decrypt_store(password)
    except ValueError as e:
        print(f"✗ {e}", file=sys.stderr)
        sys.exit(1)

    print("✓ Credentials decrypted to plaintext ⚠️")
    print(f"  File: {get_credentials_path()}")


def cmd_status(args: argparse.Namespace) -> None:
    """Show encryption status."""
    plain_path = get_credentials_path()
    enc_path = plain_path.with_suffix(".toml.enc")

    if enc_path.exists():
        size = enc_path.stat().st_size
        print(f"Status: Encrypted 🔒")
        print(f"File:   {enc_path}")
        print(f"Size:   {size} bytes")
    elif plain_path.exists():
        size = plain_path.stat().st_size
        print(f"Status: Plaintext ⚠️  (run 'aisafe encrypt' to protect)")
        print(f"File:   {plain_path}")
        print(f"Size:   {size} bytes")
    else:
        print(f"Status: No credentials file")
        print(f"Run 'aisafe set <section>.<key>' to create one.")


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

    # encrypt
    p_encrypt = subparsers.add_parser("encrypt", help="Encrypt the credential file")
    p_encrypt.set_defaults(func=cmd_encrypt)

    # decrypt
    p_decrypt = subparsers.add_parser("decrypt", help="Decrypt back to plaintext")
    p_decrypt.set_defaults(func=cmd_decrypt)

    # status
    p_status = subparsers.add_parser("status", help="Show encryption status")
    p_status.set_defaults(func=cmd_status)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
