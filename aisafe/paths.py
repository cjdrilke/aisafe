"""
Cross-platform credential file path resolution.

Default locations:
    Linux:   ~/.config/aisafe/credentials.toml
    macOS:   ~/Library/Application Support/aisafe/credentials.toml
    Windows: %APPDATA%\\aisafe\\credentials.toml

Override with the AISAFE_FILE environment variable — honored ONLY when no
AI agent is detected in the caller chain. Under AI detection, the override
is refused and the system default is used. Same for the config root
(XDG_CONFIG_HOME / APPDATA / HOME): when AI is detected, the location is
derived from the OS (pwd.getpwuid on POSIX, SHGetFolderPathW on Windows)
rather than env vars an attacker can override.
"""

import os
import sys
from pathlib import Path


APP_NAME = "aisafe"
CREDENTIALS_FILENAME = "credentials.toml"


def _posix_trusted_home(*, ai_detected: bool) -> Path:
    """Resolve POSIX home directory from /etc/passwd, bypassing HOME env.

    Setuid contexts (ruid != euid) always raise — there's no defensible
    aisafe use case as a setuid binary, and the mismatch usually means
    our path lookup would go to the wrong user's home.

    When pwd lookup fails (containers with no /etc/passwd entry, random
    UIDs), behaviour depends on AI detection:
      - AI detected → fail-closed (raise RuntimeError). Cannot trust HOME.
      - human caller → fall back to Path.home() (which reads HOME).
    """
    ruid = os.getuid()
    try:
        euid = os.geteuid()
    except AttributeError:
        euid = ruid
    if ruid != euid:
        raise RuntimeError(
            f"aisafe refuses to run setuid (ruid={ruid}, euid={euid})"
        )
    try:
        import pwd
        return Path(pwd.getpwuid(ruid).pw_dir)
    except (ImportError, KeyError, OSError) as e:
        if ai_detected:
            raise RuntimeError(
                f"trusted home lookup failed under AI detection ({e}); "
                f"refusing to fall back to HOME env which AI may control"
            )
        return Path.home()


def _win_trusted_appdata(*, ai_detected: bool) -> Path:
    """Resolve %APPDATA% via SHGetFolderPathW (not env-derived).

    The Win32 shell API returns the Roaming AppData folder directly, e.g.
    `C:\\Users\\Alice\\AppData\\Roaming`. This is the value `%APPDATA%`
    normally contains — but env vars can be redirected by an AI launching
    the process with `APPDATA=...`.

    Under AI detection, falling back to env-derived `Path.home()` defeats
    the lock; raise instead.
    """
    try:
        import ctypes
        from ctypes import wintypes  # type: ignore[import-not-found]

        CSIDL_APPDATA = 0x001A
        SHGFP_TYPE_CURRENT = 0
        shell32 = ctypes.windll.shell32  # type: ignore[attr-defined]
        shell32.SHGetFolderPathW.argtypes = [
            wintypes.HWND, ctypes.c_int, wintypes.HANDLE,
            wintypes.DWORD, wintypes.LPWSTR,
        ]
        shell32.SHGetFolderPathW.restype = wintypes.HRESULT
        buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
        result = shell32.SHGetFolderPathW(
            None, CSIDL_APPDATA, None, SHGFP_TYPE_CURRENT, buf
        )
        if result == 0 and buf.value:
            return Path(buf.value)
    except Exception as e:
        if ai_detected:
            raise RuntimeError(
                f"SHGetFolderPathW failed under AI detection ({e}); "
                f"refusing to fall back to env-derived Path.home() which "
                f"may be redirected via USERPROFILE"
            )
        print(
            f"aisafe: SHGetFolderPathW failed ({e}); using Path.home()",
            file=sys.stderr,
        )
    return Path.home() / "AppData" / "Roaming"


def get_config_dir() -> Path:
    """Return the platform-specific configuration directory for aisafe.

    Honors XDG_CONFIG_HOME (Linux) / APPDATA (Windows) ONLY when no AI
    agent is detected. Under AI detection, env vars are bypassed.
    """
    from . import detect as _detect
    ai = _detect.detect()

    if sys.platform == "win32":
        if ai is None:
            base = Path(os.environ.get("APPDATA") or _win_trusted_appdata(ai_detected=False))
        else:
            # Under AI, do not trust the APPDATA env; resolve via Win32 API.
            base = _win_trusted_appdata(ai_detected=True)
    elif sys.platform == "darwin":
        base = _posix_trusted_home(ai_detected=ai is not None) / "Library" / "Application Support"
    else:
        # Linux / *BSD
        if ai is None:
            base = Path(os.environ.get("XDG_CONFIG_HOME")
                        or _posix_trusted_home(ai_detected=False) / ".config")
        else:
            base = _posix_trusted_home(ai_detected=True) / ".config"
    return base / APP_NAME


def get_credentials_path() -> Path:
    """Return the path to the credentials file.

    Respects the AISAFE_FILE environment variable as an override — except
    when an AI agent is detected, in which case the override is refused.
    """
    override = os.environ.get("AISAFE_FILE")
    if override:
        from . import detect as _detect
        ai = _detect.detect()
        if ai is not None:
            print(
                f"aisafe: refusing AISAFE_FILE override under AI detection "
                f"({ai}); using default credentials path",
                file=sys.stderr,
            )
            return get_config_dir() / CREDENTIALS_FILENAME
        return Path(override).expanduser()
    return get_config_dir() / CREDENTIALS_FILENAME


def ensure_config_dir() -> Path:
    """Ensure the configuration directory exists and return its path."""
    config_dir = get_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(config_dir, 0o700)
    except OSError:
        pass
    return config_dir


# Backwards-compat alias. Some callers import the older internal helper name.
def _trusted_home() -> Path:
    if sys.platform == "win32":
        return _win_trusted_appdata(ai_detected=False)
    return _posix_trusted_home(ai_detected=False)
