"""
Cross-platform credential file path resolution.

Default locations:
    Linux:   ~/.config/aisafe/credentials.toml
    macOS:   ~/Library/Application Support/aisafe/credentials.toml
    Windows: %APPDATA%\\aisafe\\credentials.toml

Override with AISAFE_FILE environment variable.
"""

import os
import sys
from pathlib import Path


APP_NAME = "aisafe"
CREDENTIALS_FILENAME = "credentials.toml"


def get_config_dir() -> Path:
    """Return the platform-specific configuration directory for aisafe."""
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home()))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / APP_NAME


def get_credentials_path() -> Path:
    """Return the path to the credentials file.

    Respects the AISAFE_FILE environment variable as an override.
    """
    override = os.environ.get("AISAFE_FILE")
    if override:
        return Path(override).expanduser()
    return get_config_dir() / CREDENTIALS_FILENAME


def ensure_config_dir() -> Path:
    """Ensure the configuration directory exists and return its path."""
    config_dir = get_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir
