# aisafe

Local credential manager — keep secrets invisible to AI coding assistants.

## Why?

AI coding assistants (Copilot, Cursor, Claude, Gemini, etc.) index all files in your workspace. If credentials live in your project, the AI sees them.

**aisafe** stores credentials in your OS config directory — outside any project workspace — so AI tools never touch them.

| OS | Credential Location |
|---|---|
| Linux | `~/.config/aisafe/credentials.toml` |
| macOS | `~/Library/Application Support/aisafe/credentials.toml` |
| Windows | `%APPDATA%\aisafe\credentials.toml` |

## Install

```bash
pip install aisafe
```

Or for development:

```bash
git clone https://github.com/aisafe/aisafe.git
cd aisafe
pip install -e .
```

## CLI Usage

```bash
# Set credentials
aisafe set database.password              # Interactive (hidden input)
aisafe set database.user "admin"          # Direct

# Read credentials
aisafe get database.password

# List all
aisafe list

# List keys in a section
aisafe list database

# Remove
aisafe remove database.password

# Show config file path
aisafe path
```

## Python API

```python
import aisafe

# Get a single value
password = aisafe.get("database.password")

# Get with default
host = aisafe.get("database.host", "localhost")

# Get entire section
db = aisafe.get_section("database")
# {'host': 'localhost', 'port': 5432, 'user': 'admin', 'password': 'xxx'}

# Set programmatically
aisafe.set("api.key", "sk-xxx")

# Custom credentials file
aisafe.init("~/my-credentials.toml")
```

## Credentials File Format

Uses TOML with simple `[section]` grouping:

```toml
[database]
host = "localhost"
port = 5432
user = "admin"
password = "s3cret"

[api]
key = "sk-xxx"
secret = "xxx"
```

See [credentials.example.toml](credentials.example.toml) for a template.

## How It Works

1. Credentials live in your **OS config directory**, not in any project
2. AI tools only index the workspaces they're opened in
3. Your project code just calls `import aisafe; aisafe.get("key")`
4. The AI sees the `import` but never the actual credential values

No `.gitignore` tricks, no `.cursorignore`, no `.geminiignore` — just architectural separation.

## Environment Variable

Override the credentials file path:

```bash
export AISAFE_FILE=~/custom/path/credentials.toml
```

## License

MIT
