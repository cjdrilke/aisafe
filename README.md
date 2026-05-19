# aisafe

**Make it harder for AI coding agents to leak your secrets.**

aisafe is a local credential broker designed for a world where AI assistants
(Claude Code, Cursor, Copilot, Aider, Codex, Windsurf, …) read your files,
run your commands, and can leak whatever they touch.

> aisafe is a **guardrail, not a sandbox.** It blocks the easy path —
> a tool calling `aisafe.get("github.token")` and pasting the value into
> a transcript — but it cannot stop arbitrary Python in your editor's
> Python interpreter from reading your secrets. The detection layer is
> evadable by definition. See [Threat model](#threat-model) below.

---

## Why this exists

Plain dotfiles, `.env`, `~/.netrc`, and most "vault" tools assume your code
is the only thing reading the secret. An AI assistant in your editor breaks
that assumption — it reads files, calls your Python functions, and pastes
results into transcripts.

aisafe's older "store outside the workspace" trick (v0.2) wasn't enough:
an AI with a shell can `cat ~/.config/aisafe/credentials.toml`. Encryption
alone wasn't enough either: once the master password is in memory, the AI
shares that memory.

aisafe v0.3 changes the model. The store is gated by a policy engine that
**detects AI agents in the caller chain** and routes them through one of
three safe paths: **deny**, **stub (`<REDACTED:key>`)**, or
**capability-mediated use** (exec injection, MCP tools).

---

## The three safe paths

### 1. `aisafe exec` — subprocess injection

The AI can run your deploy script with credentials, and the credentials
live **only inside the child process's environment** — the aisafe parent
and the AI's own process memory never hold the plaintext.

```bash
# AI types this; child sees DATABASE_PASSWORD; aisafe never returns it.
aisafe exec --section database -- ./deploy.sh
```

**Caveat:** the AI chooses the command. If the AI runs
`aisafe exec --section database -- python -c 'import os; print(os.environ)'`,
the child gleefully prints the credentials and the AI reads them back via
stdout. `aisafe exec` protects against *accidental* leaks from a well-
behaved deploy script; it does **not** stop a deliberately exfiltrating
child. For that, restrict which commands the AI is allowed to invoke,
prefer the MCP `http_request` path (no env at all), or only invoke
`aisafe exec` against trusted scripts you wrote.

### 2. `aisafe mcp` — capability-mediated access

Run aisafe as an MCP server. The AI gets *tools* like `http_request` that
attach the credential as an `Authorization: Bearer …` header server-side
and return only the HTTP response. The token never crosses the AI boundary.

```jsonc
// claude_desktop_config.json / .cursor/mcp.json / etc.
{
  "mcpServers": {
    "aisafe": { "command": "aisafe", "args": ["mcp"] }
  }
}
```

**Each credential must declare a host allowlist** before it can be used
via `http_request`. Without one, the request is rejected — otherwise an
AI could ask aisafe to send the token to a server it controls (SSRF /
exfiltration).

```bash
aisafe policy hosts add github.token api.github.com
aisafe policy hosts add github.token "*.github.com"
aisafe policy hosts add stripe.secret api.stripe.com
```

Only `https://` is permitted. Redirects (`3xx`) are surfaced as-is —
aisafe will **not** auto-follow a `Location:` header, because the target
might be off-allowlist.

**Methods.** Only `GET` and `HEAD` are allowed by default. Destructive
methods (`POST`, `PUT`, `PATCH`, `DELETE`) require explicit opt-in:

```bash
aisafe policy methods add github.token POST
```

This blocks the "confused deputy" attack where an AI uses a legitimately-
allowlisted credential to perform an unintended destructive operation on
the allowlisted host.

**Response redaction is best-effort.** aisafe scrubs the raw secret (and
the URL-encoded form for `query` auth, plus the base64-encoded form for
`basic` auth) out of response bodies and headers before handing them to
the AI. It does NOT catch arbitrary transformations — hex encoding,
double-encoding, JSON-escape, byte-splitting, etc. If an allowlisted
endpoint deliberately echoes the credential in a non-obvious form, an
attacking AI could still recover it. Treat the host allowlist as the
primary defense; response scrubbing is just defense-in-depth.

> **Wildcard caveat.** `*.example.com` is a suffix match: it accepts
> *any* subdomain of `example.com`, including ones the registrant doesn't
> own (subdomain-takeover scenarios). For credentials bound to a public
> suffix domain (e.g. you would *not* want `*.co.uk` to accept anything
> ending in `.co.uk`), prefer **exact** hostnames. aisafe does not
> consult the Public Suffix List; it requires at least two labels after
> `*.` to block obvious traps like `*.com`, but `*.co.uk` is allowed.

### 3. `stub_ai` policy — placeholder values

For code that imports `aisafe` and calls `aisafe.get("api.key")`: when an
AI is detected, return `<REDACTED:api.key>` instead of the real value.
The AI's code still type-checks and runs in dry-run; the real value only
appears under a human-driven execution.

```bash
aisafe policy set stripe.secret stub_ai
```

---

## Threat model

aisafe sits between the AI agent and your credentials. The protection
is *layered*; each layer raises the cost of a leak, but no single layer
is a hard sandbox.

**What aisafe protects against:**

- AI assistant calling `aisafe.get("github.token")` and printing the
  value to its transcript — the policy engine denies / redacts based
  on AI detection.
- AI assistant running `cat ~/.config/aisafe/credentials.toml.enc` —
  encrypted at rest (AES-256-GCM, PBKDF2-HMAC-SHA256, 600k iterations).
- AI assistant overwriting or removing credentials (`set`/`remove` is
  denied when AI is detected unless the key is `open`/`audit_only`).
- AI running `aisafe exec` and asking the *child* to dump aisafe's
  master password — `AISAFE_KEY` and all `AISAFE_*` env vars are
  scrubbed before the child is launched.
- AI asking aisafe to send a credential to an arbitrary URL — the MCP
  `http_request` tool refuses without a per-credential host allowlist
  and refuses to auto-follow redirects.
- A policy file typo silently widening access — a malformed
  `policies.toml` fails-closed (every read denied) until the user
  fixes it and re-runs `aisafe policy validate`.

**What aisafe does NOT protect against:**

- Same-process bypass. Any code in a Python interpreter where aisafe
  is importable can call `aisafe.store._raw_get(...)` or `aisafe.store._load()`
  and read the cleartext. The leading underscores are convention, not
  a sandbox. If the AI controls a Python REPL or your editor's runtime,
  it can bypass the policy engine.
- Same-user file tampering. The Python mutation APIs refuse to change
  policy under AI detection, but an AI with shell access (same uid) can
  `echo` directly into `~/.config/aisafe/policies.toml` or into the
  credentials file. Partial mitigations: (a) when `aisafe mcp` is
  running, the policy file is hashed at startup and tool calls are
  refused if it changes mid-session — the user must restart the server
  to apply policy edits; (b) on-disk encryption (`aisafe encrypt`) makes
  the credentials file useless without the master password. The
  long-term fix is moving policy/credentials out of the user's
  filesystem (broker daemon, OS keychain, MAC); planned for v0.4.
- Adversarial AI detection bypass. Detection uses environment variables
  (`CLAUDECODE`, `CURSOR_AGENT`, …) and parent process scanning. An AI
  that knows the rules can `os.environ.pop("CLAUDECODE")` before it
  imports aisafe. Treat detection as a tripwire for *naive* agents,
  not a barrier against motivated ones.
- Exfiltration through a legitimately-exposed child. If you `aisafe exec`
  a script that prints the env to stdout, aisafe can't help — that's
  a script-design problem.
- Confirmation prompts under an AI-controlled PTY. The `confirm` policy
  reads stdin; an AI with control of the PTY can write `y\n` itself.
  Pinentry / OS-level user-presence is the proper fix and is not yet
  implemented.
- Physical access to your unlocked machine.

The right mental model: **aisafe makes the unsafe path significantly
harder for a well-behaved AI to stumble into, and makes the safe path
the easy one.** It is one layer of defense in depth, not the only one.

---

## Install

```bash
pip install aisafe
```

Requires Python 3.11+. Installs `cryptography` and `psutil`.

---

## Quickstart

```bash
# 1. Store some secrets (do this from a regular shell, NOT inside an AI agent)
aisafe set database.password
aisafe set github.token

# 2. Pick policies for sensitive keys
aisafe policy set github.token deny_ai       # AI can never read
aisafe policy set stripe.secret stub_ai      # AI sees placeholder
aisafe policy set api.public_key open        # AI can read freely
aisafe policy default deny_ai                # for everything else

# 3. Allow specific hosts for credentials that AI will use via MCP
aisafe policy hosts add github.token api.github.com
aisafe policy hosts add stripe.secret api.stripe.com

# 4. Encrypt the store at rest
aisafe encrypt

# 5. Verify
aisafe status
aisafe policy validate
```

Now open your AI editor. Anything the AI does is gated by these rules.

---

## CLI reference

```text
aisafe set <key> [value]              set a credential (interactive if no value)
aisafe get <key>                      read (subject to policy)
aisafe list [section]                 list section/key names
aisafe remove <key>                   delete
aisafe path                           show where the file lives
aisafe status                         store + policy + AI-detection summary
aisafe encrypt | decrypt              toggle on-disk encryption (AES-256-GCM)

aisafe exec -s SECTION -- <cmd…>      run cmd with creds in env (parent never holds)
aisafe exec -k api.token -- <cmd…>    expose a single key
aisafe env  -s SECTION                print 'export X=…' lines (for shell eval)

aisafe policy show
aisafe policy set <key> <level>       level ∈ {deny, deny_ai, confirm, stub_ai, audit_only, open}
aisafe policy set "database.*" deny_ai
aisafe policy default <level>
aisafe policy remove <key>
aisafe policy validate                fail-closed check on policies.toml
aisafe policy reset [--yes]           overwrite policies.toml with a clean default

aisafe policy hosts list              show per-credential URL allowlists (MCP)
aisafe policy hosts add <key> <host>  e.g. add github.token api.github.com
aisafe policy hosts remove <key> <host>

aisafe policy methods list                    show unsafe-method opt-ins
aisafe policy methods add <key> <METHOD>      opt into POST/PUT/PATCH/DELETE
aisafe policy methods remove <key> <METHOD>   drop opt-in

aisafe audit [-n 50] [--json]         tail the audit log
aisafe detect                         is an AI agent in the caller chain?
aisafe mcp                            run as an MCP server over stdio
```

---

## Policy levels

| Level        | Human read | AI read              | Human write | AI write |
|--------------|-----------|----------------------|-------------|----------|
| `open`       | yes       | yes                  | yes         | yes      |
| `audit_only` | yes       | yes                  | yes         | yes      |
| `stub_ai`    | yes       | `<REDACTED:key>`     | yes         | no       |
| `deny_ai`    | yes       | no (returns default) | yes         | no       |
| `confirm`    | TTY prompt| no (no TTY)          | yes         | no       |
| `deny`       | no        | no                   | yes         | no       |

The default is `deny_ai`. Override with `aisafe policy default …`.

---

## Python API

```python
import aisafe

aisafe.unlock("master")   # if encrypted (or set AISAFE_KEY env var)

# Gated by policy + audit
password = aisafe.get("database.password")
if password == "<REDACTED:database.password>":
    print("running in AI context — using stub")

# Writes denied when AI is detected and policy != open/audit_only
try:
    aisafe.set("api.key", "sk-…")
except aisafe.AccessDenied as e:
    print("write blocked:", e)

# Inspection
aisafe.detect.is_ai()       # bool — am I in an AI agent's process tree?
aisafe.detect.detect()      # AIDetection record or None
aisafe.audit.tail(20)       # recent log entries
```

---

## AI agents currently auto-detected

By environment variable:

| Agent             | Marker                              |
|-------------------|-------------------------------------|
| Claude Code       | `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT` |
| Cursor            | `CURSOR_AGENT`, `CURSOR_TRACE_ID`   |
| GitHub Copilot    | `GITHUB_COPILOT_CLI`                |
| Aider             | `AIDER_VERSION`                     |
| Codex             | `CODEX_SESSION_ID`                  |
| Windsurf          | `WINDSURF_AGENT`                    |
| *Anything*        | `AISAFE_AI=1` (user opt-in)         |

By parent-process name: `claude`, `cursor-agent`, `gh-copilot`, `copilot`,
`aider`, `codex`, `windsurf`, `cody-agent`.

Pull requests welcome for additional markers.

---

## File locations

| OS      | Default                                              |
|---------|------------------------------------------------------|
| Linux   | `~/.config/aisafe/`                                  |
| macOS   | `~/Library/Application Support/aisafe/`              |
| Windows | `%APPDATA%\aisafe\`                                  |

Files:

- `credentials.toml` or `credentials.toml.enc` — the store
- `policies.toml` — per-key policy map
- `audit.log` — append-only JSONL

Overrides:

- `AISAFE_FILE` — credentials path
- `AISAFE_POLICY_FILE` — policy path
- `AISAFE_AUDIT_LOG` — audit log path
- `AISAFE_KEY` — master password (encrypted mode). **Caveat:** if your
  shell exports `AISAFE_KEY` and an AI later runs in that environment,
  the AI sees the master password in `os.environ`. Either unlock
  interactively (`aisafe` will prompt) or use a broker that scopes the
  password to a single subprocess. aisafe does NOT itself refuse the
  env-var unlock under AI detection — that would break legitimate
  workflows where the user exported the variable in a non-AI shell.
- `AISAFE_STUB=1` — force `stub_ai` for everything (good for AI dry-runs)

---

## License

MIT
