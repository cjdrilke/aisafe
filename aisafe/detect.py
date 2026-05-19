"""
AI-agent detection.

Determines whether the current process is being driven by an AI coding agent
(Claude Code, Cursor, Copilot CLI, Aider, etc.) by examining environment
variables and walking the parent process tree.

Detection is best-effort, not adversarial — an AI agent that knows the rules
can bypass it. The goal is to prevent *accidental* leaks (an AI assistant
calling `aisafe.get()` and dumping the result into a transcript), not to
defend against a malicious agent that controls the Python interpreter.

For real "AI never sees the value" guarantees, use:
  - `aisafe exec` (subprocess injection)
  - `aisafe mcp` (capability-based access)
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

try:
    import psutil  # type: ignore
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False


# Environment variables set by known AI coding agents.
# When any of these is non-empty, we consider the process to be under AI control.
AI_ENV_MARKERS: dict[str, str] = {
    "CLAUDECODE": "claude-code",
    "CLAUDE_CODE_ENTRYPOINT": "claude-code",
    "CURSOR_AGENT": "cursor-agent",
    "CURSOR_TRACE_ID": "cursor",
    "GITHUB_COPILOT_CLI": "github-copilot",
    "AIDER_VERSION": "aider",
    "CODEX_SESSION_ID": "codex",
    "WINDSURF_AGENT": "windsurf",
    "AISAFE_AI": "user-declared",  # explicit user opt-in
}

# Process-name markers — matched against process basename in the parent chain.
AI_PROC_MARKERS: dict[str, str] = {
    "claude": "claude-code",
    "cursor-agent": "cursor-agent",
    "gh-copilot": "github-copilot",
    "copilot": "github-copilot",
    "aider": "aider",
    "codex": "codex",
    "windsurf": "windsurf",
    "cody-agent": "cody",
}


@dataclass(frozen=True)
class AIDetection:
    """Result of an AI-agent detection scan."""

    agent: str
    source: str  # 'env' | 'parent-process'
    detail: str  # env var name or process name + pid

    def __str__(self) -> str:
        return f"{self.agent} ({self.source}: {self.detail})"


def _check_env() -> Optional[AIDetection]:
    """Detect AI by environment variables."""
    for var, agent in AI_ENV_MARKERS.items():
        val = os.environ.get(var)
        if val:
            return AIDetection(agent=agent, source="env", detail=f"{var}={val}")
    return None


def _check_parent_chain() -> Optional[AIDetection]:
    """Walk parent processes looking for known AI binaries."""
    if not _HAS_PSUTIL:
        return None
    try:
        proc = psutil.Process(os.getpid()).parent()
    except (psutil.Error, OSError):
        return None

    depth = 0
    while proc is not None and depth < 20:
        try:
            name = proc.name().lower()
        except (psutil.Error, OSError):
            break

        # Direct binary name match
        for marker, agent in AI_PROC_MARKERS.items():
            if name == marker or name.startswith(marker + "-") or name.startswith(marker + "."):
                return AIDetection(
                    agent=agent, source="parent-process", detail=f"{name} pid={proc.pid}"
                )

        # If the process is `node`, peek at cmdline (Claude Code, Cursor are node apps)
        if name in ("node", "node.exe", "bun"):
            try:
                cmdline = " ".join(proc.cmdline()).lower()
            except (psutil.Error, OSError):
                cmdline = ""
            for marker, agent in AI_PROC_MARKERS.items():
                if f"/{marker}" in cmdline or f"\\{marker}" in cmdline or f" {marker} " in cmdline:
                    return AIDetection(
                        agent=agent, source="parent-process", detail=f"{name}->{marker} pid={proc.pid}"
                    )

        try:
            proc = proc.parent()
        except (psutil.Error, OSError):
            break
        depth += 1

    return None


def detect() -> Optional[AIDetection]:
    """Return AIDetection if the current process appears to be under AI control.

    Detection order: env vars (fast, reliable) → parent process scan (slower, optional).
    """
    return _check_env() or _check_parent_chain()


def is_ai() -> bool:
    """Convenience boolean wrapper around detect()."""
    return detect() is not None
