"""
CLI interface for aisafe.

Commands:
  set / get / remove / list      manage credentials
  path / status                  inspect the store
  encrypt / decrypt              toggle on-disk encryption
  exec                           run a subprocess with creds injected
  env                            print export statements for shell eval
  policy                         show/set per-key access policies
  audit                          show recent audit log entries
  detect                         report whether AI is detected in the caller chain
  mcp                            run as an MCP server over stdio
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys

from . import audit as _audit
from . import detect as _detect
from . import exec_runner as _exec
from . import policy as _policy
from . import store
from .paths import get_credentials_path
from .store import AccessDenied


def _ensure_unlocked() -> None:
    """Prompt for password if credentials are encrypted and not yet unlocked."""
    if store.is_encrypted() and store._get_password() is None:
        password = getpass.getpass("Master password: ")
        store.unlock(password)


# ────────────────────────────────────────────────────────────────────
# Credential CRUD
# ────────────────────────────────────────────────────────────────────

def cmd_set(args: argparse.Namespace) -> None:
    _ensure_unlocked()
    key: str = args.key
    value = args.value if args.value is not None else getpass.getpass(
        f"Enter value for '{key}': "
    )
    try:
        store.set(key, value)
    except AccessDenied as e:
        print(f"✗ {e}", file=sys.stderr)
        sys.exit(2)
    print(f"✓ Set '{key}'")


def cmd_get(args: argparse.Namespace) -> None:
    _ensure_unlocked()
    sentinel = object()
    value = store.get(args.key, sentinel)
    if value is sentinel:
        print(f"✗ Key '{args.key}' not found or denied by policy", file=sys.stderr)
        sys.exit(1)
    print(value)


def cmd_list(args: argparse.Namespace) -> None:
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
            print("Run 'aisafe set <section>.<key>' to add one.")
            return
        for section in sections:
            keys = store.list_keys(section)
            print(f"[{section}]")
            for key in keys:
                print(f"  {key}")


def cmd_remove(args: argparse.Namespace) -> None:
    _ensure_unlocked()
    try:
        ok = store.remove(args.key)
    except AccessDenied as e:
        print(f"✗ {e}", file=sys.stderr)
        sys.exit(2)
    if ok:
        print(f"✓ Removed '{args.key}'")
    else:
        print(f"✗ Key '{args.key}' not found", file=sys.stderr)
        sys.exit(1)


# ────────────────────────────────────────────────────────────────────
# Store inspection
# ────────────────────────────────────────────────────────────────────

def cmd_path(args: argparse.Namespace) -> None:
    plain_path = get_credentials_path()
    enc_path = plain_path.with_suffix(".toml.enc")
    if enc_path.exists():
        print(f"{enc_path} (encrypted)")
    elif plain_path.exists():
        print(f"{plain_path} (plaintext)")
    else:
        print(f"{plain_path} (not created yet)")


def cmd_status(args: argparse.Namespace) -> None:
    plain_path = get_credentials_path()
    enc_path = plain_path.with_suffix(".toml.enc")

    if enc_path.exists():
        print(f"Store:     Encrypted (.toml.enc)")
        print(f"File:      {enc_path}")
        print(f"Size:      {enc_path.stat().st_size} bytes")
    elif plain_path.exists():
        print(f"Store:     Plaintext (.toml)")
        print(f"File:      {plain_path}")
        print(f"Size:      {plain_path.stat().st_size} bytes")
        print(f"           (run 'aisafe encrypt' to protect)")
    else:
        print("Store:     not initialized")

    default, _ = _policy.list_policies()
    print(f"Policy:    default={default}")

    ai = _detect.detect()
    if ai is None:
        print(f"AI:        not detected")
    else:
        print(f"AI:        DETECTED — {ai}")

    print(f"Audit log: {_audit.path()}")


# ────────────────────────────────────────────────────────────────────
# Encrypt / decrypt store
# ────────────────────────────────────────────────────────────────────

def cmd_encrypt(args: argparse.Namespace) -> None:
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
    if len(password) < 8:
        print("✗ Password too short (min 8 characters)", file=sys.stderr)
        sys.exit(1)

    store.encrypt_store(password)
    print(f"✓ Credentials encrypted → {plain_path.with_suffix('.toml.enc')}")
    print("  Plaintext file removed")


def cmd_decrypt(args: argparse.Namespace) -> None:
    if not store.is_encrypted():
        print("✗ Not encrypted", file=sys.stderr)
        sys.exit(1)
    password = getpass.getpass("Master password: ")
    try:
        store.decrypt_store(password)
    except ValueError as e:
        print(f"✗ {e}", file=sys.stderr)
        sys.exit(1)
    print(f"✓ Credentials decrypted → {get_credentials_path()}")


# ────────────────────────────────────────────────────────────────────
# exec / env  (subprocess injection)
# ────────────────────────────────────────────────────────────────────

def cmd_exec(args: argparse.Namespace) -> None:
    _ensure_unlocked()
    cmd = list(args.cmd)
    # argparse REMAINDER preserves a leading "--" — strip it.
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("✗ no command specified (use '--' to separate flags from command)",
              file=sys.stderr)
        sys.exit(2)
    code = _exec.run(
        cmd,
        sections=args.section or [],
        keys=args.key or [],
        prefix=args.prefix or "",
        inherit_env=not args.no_inherit_env,
    )
    sys.exit(code)


def cmd_env(args: argparse.Namespace) -> None:
    """Print 'export NAME=value' lines for shell eval.

    Refused when AI is detected: the values would print to stdout, which is
    the most direct possible exfiltration path. A human user can re-run this
    from a non-AI shell.
    """
    ai = _detect.detect()
    if ai is not None:
        _audit.record(
            "env_export", "*",
            result="deny", ai=ai,
            reason="aisafe env refused under AI detection",
        )
        print(
            f"✗ aisafe env is refused under AI detection ({ai}).\n"
            f"  Values would be printed to stdout where the AI can read them.\n"
            f"  Use 'aisafe exec' instead (values go only to a child process),\n"
            f"  or run 'aisafe env' from a non-AI shell.",
            file=sys.stderr,
        )
        sys.exit(2)
    _ensure_unlocked()
    print(_exec.env_export(
        sections=args.section or [],
        keys=args.key or [],
        prefix=args.prefix or "",
    ))


# ────────────────────────────────────────────────────────────────────
# policy
# ────────────────────────────────────────────────────────────────────

def cmd_policy(args: argparse.Namespace) -> None:
    sub = args.policy_cmd
    if sub == "show" or sub is None:
        default, keys = _policy.list_policies()
        print(f"default = {default}")
        if keys:
            print("\n[keys]")
            for k, v in sorted(keys.items()):
                print(f"  {k:32}  {v}")
        else:
            print("\n(no per-key policies set)")
        hosts = _policy.list_hosts()
        if hosts:
            print("\n[hosts]")
            for k, v in sorted(hosts.items()):
                print(f"  {k:32}  {', '.join(v)}")
        methods = _policy.list_unsafe_methods()
        if methods:
            print("\n[unsafe_methods]")
            for k, v in sorted(methods.items()):
                print(f"  {k:32}  {', '.join(v)}")
        return
    try:
        if sub == "set":
            _policy.set_key_policy(args.key, args.level)
            print(f"✓ Set policy {args.key} = {args.level}")
            return
        if sub == "remove":
            if _policy.remove_key_policy(args.key):
                print(f"✓ Removed policy for {args.key}")
            else:
                print(f"✗ No policy entry for {args.key}", file=sys.stderr)
                sys.exit(1)
            return
        if sub == "default":
            _policy.set_default_policy(args.level)
            print(f"✓ Default policy = {args.level}")
            return
        if sub == "hosts":
            action = args.hosts_action
            if action == "list" or action is None:
                hosts = _policy.list_hosts()
                if not hosts:
                    print("(no host allowlists configured)")
                    return
                for k, v in sorted(hosts.items()):
                    print(f"{k}")
                    for h in v:
                        print(f"  {h}")
                return
            if action == "add":
                _policy.add_host(args.key, args.host)
                print(f"✓ Added host '{args.host}' to allowlist for '{args.key}'")
                return
            if action == "remove":
                if _policy.remove_host(args.key, args.host):
                    print(f"✓ Removed host '{args.host}' from '{args.key}'")
                else:
                    print(f"✗ Host '{args.host}' not in allowlist for '{args.key}'",
                          file=sys.stderr)
                    sys.exit(1)
                return
        if sub == "methods":
            action = args.methods_action
            if action == "list" or action is None:
                methods = _policy.list_unsafe_methods()
                if not methods:
                    print("(no unsafe-method opt-ins configured; only GET/HEAD allowed)")
                    return
                for k, v in sorted(methods.items()):
                    print(f"{k}")
                    for m in v:
                        print(f"  {m}")
                return
            if action == "add":
                _policy.add_unsafe_method(args.key, args.method)
                print(f"✓ {args.key} opted into unsafe method {args.method.upper()}")
                return
            if action == "remove":
                if _policy.remove_unsafe_method(args.key, args.method):
                    print(f"✓ {args.key} no longer opted into {args.method.upper()}")
                else:
                    print(f"✗ {args.key} has no opt-in for {args.method.upper()}",
                          file=sys.stderr)
                    sys.exit(1)
                return
        if sub == "validate":
            ok, msg = _policy.validate()
            if ok:
                print("✓ policy file is valid")
                sys.exit(0)
            else:
                print(f"✗ policy file is broken: {msg}", file=sys.stderr)
                print("  → all reads will be denied until fixed (fail-closed).",
                      file=sys.stderr)
                print("  → 'aisafe policy reset' overwrites the file with a clean default.",
                      file=sys.stderr)
                sys.exit(2)
        if sub == "reset":
            if not getattr(args, "yes", False):
                if not (sys.stdin.isatty() and sys.stderr.isatty()):
                    print(
                        "✗ aisafe policy reset requires --yes when not on a TTY",
                        file=sys.stderr,
                    )
                    sys.exit(2)
                print(
                    "This will OVERWRITE policies.toml with a clean default "
                    "(default=deny_ai, no per-key entries, no host allowlists).\n"
                    "Existing per-key policies and host allowlists will be lost.\n"
                    "Type 'yes' to confirm: ",
                    end="", file=sys.stderr, flush=True,
                )
                answer = sys.stdin.readline().strip().lower()
                if answer != "yes":
                    print("✗ aborted", file=sys.stderr)
                    sys.exit(1)
            _policy.reset_to_default()
            print("✓ policy file reset to defaults")
            return
    except _policy.PolicyMutationDenied as e:
        print(f"✗ {e}", file=sys.stderr)
        sys.exit(2)
    except ValueError as e:
        print(f"✗ {e}", file=sys.stderr)
        sys.exit(2)


# ────────────────────────────────────────────────────────────────────
# audit
# ────────────────────────────────────────────────────────────────────

def cmd_audit(args: argparse.Namespace) -> None:
    ai = _detect.detect()
    if ai is not None:
        print(
            f"✗ aisafe audit is refused under AI detection ({ai}).\n"
            f"  The audit log can contain historical entries that predate "
            f"the redaction layer.\n"
            f"  Run from a non-AI shell, or read the file directly: {_audit.path()}",
            file=sys.stderr,
        )
        sys.exit(2)
    events = _audit.tail(args.n)
    if not events:
        print("(empty)")
        return
    if args.json:
        for e in events:
            print(json.dumps(e, ensure_ascii=False))
        return
    for e in events:
        ts = e.get("iso", "")
        action = e.get("action", "")
        key = e.get("key", "")
        result = e.get("result", "")
        ai = e.get("ai", {}).get("agent", "-") if e.get("ai") else "-"
        pol = e.get("policy", "-")
        reason = e.get("reason", "")
        line = f"{ts}  {action:8} {key:32} {result:6} ai={ai:14} policy={pol}"
        if reason:
            line += f"  ({reason})"
        print(line)


# ────────────────────────────────────────────────────────────────────
# detect (debug helper)
# ────────────────────────────────────────────────────────────────────

def cmd_detect(args: argparse.Namespace) -> None:
    ai = _detect.detect()
    if ai is None:
        print("no AI agent detected in caller chain")
        sys.exit(0)
    print(f"AI agent detected: {ai}")
    sys.exit(0)


# ────────────────────────────────────────────────────────────────────
# mcp (run MCP server)
# ────────────────────────────────────────────────────────────────────

def cmd_mcp(args: argparse.Namespace) -> None:
    from . import mcp_server
    _ensure_unlocked()
    mcp_server.serve()


# ────────────────────────────────────────────────────────────────────
# Argument parser
# ────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aisafe",
        description="Local credential manager that keeps secrets out of AI agents' hands.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("set", help="Set a credential value")
    p.add_argument("key")
    p.add_argument("value", nargs="?", default=None)
    p.set_defaults(func=cmd_set)

    p = sub.add_parser("get", help="Get a credential value")
    p.add_argument("key")
    p.set_defaults(func=cmd_get)

    p = sub.add_parser("list", help="List sections or keys")
    p.add_argument("section", nargs="?", default=None)
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("remove", help="Remove a credential")
    p.add_argument("key")
    p.set_defaults(func=cmd_remove)

    p = sub.add_parser("path", help="Show credentials file path")
    p.set_defaults(func=cmd_path)

    p = sub.add_parser("status", help="Show store, policy, and AI-detection status")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("encrypt", help="Encrypt the credentials file")
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("decrypt", help="Decrypt the credentials file back to plaintext")
    p.set_defaults(func=cmd_decrypt)

    p = sub.add_parser(
        "exec",
        help="Run a subprocess with credentials injected as env vars",
        description=(
            "Inject credentials into a child process's environment. "
            "The parent (and any AI watching it) never holds the values."
        ),
    )
    p.add_argument("-s", "--section", action="append",
                   help="Section to expose (repeatable), e.g. -s database")
    p.add_argument("-k", "--key", action="append",
                   help="Individual section.field key to expose (repeatable)")
    p.add_argument("--prefix", default="",
                   help="Optional env-var prefix, e.g. --prefix APP_")
    p.add_argument("--no-inherit-env", action="store_true",
                   help="Don't inherit parent environment (hermetic child env)")
    p.add_argument("cmd", nargs=argparse.REMAINDER,
                   help="Command to run (prefix with -- to be safe)")
    p.set_defaults(func=cmd_exec)

    p = sub.add_parser(
        "env",
        help="Print 'export NAME=value' lines for shell eval",
        description=(
            "Generate export statements. Type this YOURSELF — do not let an "
            "AI run it, because the values are printed to stdout."
        ),
    )
    p.add_argument("-s", "--section", action="append")
    p.add_argument("-k", "--key", action="append")
    p.add_argument("--prefix", default="")
    p.set_defaults(func=cmd_env)

    p = sub.add_parser("policy", help="Manage per-key access policies")
    psub = p.add_subparsers(dest="policy_cmd")
    psub.add_parser("show", help="Show all policies").set_defaults(func=cmd_policy)
    p_set = psub.add_parser("set", help="Set a per-key policy")
    p_set.add_argument("key", help="key, e.g. database.password (use '*' for default)")
    p_set.add_argument("level", choices=_policy.VALID_POLICIES)
    p_set.set_defaults(func=cmd_policy)
    p_rm = psub.add_parser("remove", help="Remove a per-key policy")
    p_rm.add_argument("key")
    p_rm.set_defaults(func=cmd_policy)
    p_def = psub.add_parser("default", help="Set the default policy")
    p_def.add_argument("level", choices=_policy.VALID_POLICIES)
    p_def.set_defaults(func=cmd_policy)
    p_hosts = psub.add_parser(
        "hosts",
        help="Manage per-credential host allowlists (for MCP http_request)",
    )
    p_hosts_sub = p_hosts.add_subparsers(dest="hosts_action")
    p_hosts_sub.add_parser("list", help="List host allowlists").set_defaults(
        func=cmd_policy, policy_cmd="hosts"
    )
    p_hosts_add = p_hosts_sub.add_parser(
        "add", help="Add a host pattern to a credential's allowlist"
    )
    p_hosts_add.add_argument("key", help="credential key, e.g. github.token")
    p_hosts_add.add_argument(
        "host", help="host pattern, e.g. api.github.com or *.github.com"
    )
    p_hosts_add.set_defaults(func=cmd_policy, policy_cmd="hosts")
    p_hosts_rm = p_hosts_sub.add_parser(
        "remove", help="Remove a host pattern from a credential's allowlist"
    )
    p_hosts_rm.add_argument("key")
    p_hosts_rm.add_argument("host")
    p_hosts_rm.set_defaults(func=cmd_policy, policy_cmd="hosts")
    p_hosts.set_defaults(func=cmd_policy, policy_cmd="hosts")

    p_methods = psub.add_parser(
        "methods",
        help=(
            "Opt a credential into unsafe HTTP methods (POST/PUT/PATCH/DELETE). "
            "Default: only GET/HEAD."
        ),
    )
    p_methods_sub = p_methods.add_subparsers(dest="methods_action")
    p_methods_sub.add_parser("list", help="Show per-credential unsafe-method opt-ins").set_defaults(
        func=cmd_policy, policy_cmd="methods"
    )
    p_m_add = p_methods_sub.add_parser("add", help="Allow an unsafe method for a credential")
    p_m_add.add_argument("key", help="credential key, e.g. github.token")
    p_m_add.add_argument("method", help="HTTP method: POST | PUT | PATCH | DELETE")
    p_m_add.set_defaults(func=cmd_policy, policy_cmd="methods")
    p_m_rm = p_methods_sub.add_parser("remove", help="Drop opt-in for an unsafe method")
    p_m_rm.add_argument("key")
    p_m_rm.add_argument("method")
    p_m_rm.set_defaults(func=cmd_policy, policy_cmd="methods")
    p_methods.set_defaults(func=cmd_policy, policy_cmd="methods")

    psub.add_parser(
        "validate",
        help="Validate the policy file; exits non-zero if it is broken",
    ).set_defaults(func=cmd_policy)
    p_reset = psub.add_parser(
        "reset",
        help="Overwrite the policy file with a clean default (recovery from broken)",
    )
    p_reset.add_argument(
        "--yes", action="store_true",
        help="skip the interactive confirmation (required on non-TTY)",
    )
    p_reset.set_defaults(func=cmd_policy)
    p.set_defaults(func=cmd_policy)

    p = sub.add_parser("audit", help="Show recent audit log entries")
    p.add_argument("-n", type=int, default=50, help="number of entries (default 50)")
    p.add_argument("--json", action="store_true", help="emit raw JSONL")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("detect", help="Report whether an AI agent is detected")
    p.set_defaults(func=cmd_detect)

    p = sub.add_parser("mcp", help="Run as an MCP server over stdio")
    p.set_defaults(func=cmd_mcp)

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except RuntimeError as e:
        # Fatal preconditions (e.g. setuid context, trusted-home lookup
        # failure under AI). Print a short message rather than the
        # whole traceback, then exit non-zero.
        print(f"aisafe: fatal: {e}", file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()
