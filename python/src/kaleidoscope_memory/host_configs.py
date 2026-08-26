"""Pure renderers for profile-first host configuration.

These functions do not write host files or copy ambient environment variables.
"""

from __future__ import annotations

import json
from typing import Any

from .descriptor import LaunchDescriptor


def _json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _stdio_entry(descriptor: LaunchDescriptor, *, include_type: bool) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "command": descriptor.command,
        "args": list(descriptor.args),
        "env": {},
    }
    if include_type:
        entry = {"type": "stdio", **entry}
    return entry


def render_codex_config(descriptor: LaunchDescriptor) -> str:
    command = json.dumps(descriptor.command)
    args = ", ".join(json.dumps(item) for item in descriptor.args)
    tools = ", ".join(json.dumps(item) for item in descriptor.tools)
    return (
        "[mcp_servers.kaleidoscope]\n"
        f"command = {command}\n"
        f"args = [{args}]\n"
        "env = {}\n"
        "enabled = true\n"
        "required = false\n"
        "startup_timeout_sec = 10\n"
        "tool_timeout_sec = 30\n"
        f"enabled_tools = [{tools}]\n"
        'default_tools_approval_mode = "writes"\n\n'
        "# Ranked search appends an exposure row, so approve it deliberately.\n"
        "[mcp_servers.kaleidoscope.tools.search]\n"
        'approval_mode = "approve"\n'
    )


def render_claude_code_config(descriptor: LaunchDescriptor) -> str:
    return _json({"mcpServers": {"kaleidoscope": _stdio_entry(descriptor, include_type=True)}})


def render_cursor_config(descriptor: LaunchDescriptor) -> str:
    return _json({"mcpServers": {"kaleidoscope": _stdio_entry(descriptor, include_type=False)}})


def render_opencode_stable_v1_config(descriptor: LaunchDescriptor) -> str:
    """Render the released OpenCode shape; callers choose the version explicitly."""

    return _json(
        {
            "$schema": "https://opencode.ai/config.json",
            "mcp": {
                "kaleidoscope": {
                    "type": "local",
                    "command": [descriptor.command, *descriptor.args],
                    "environment": {},
                    "enabled": True,
                }
            },
        }
    )


def render_opencode_beta_v2_config(descriptor: LaunchDescriptor) -> str:
    """Render the opt-in v2 beta shape; never auto-detect or select it."""

    return _json(
        {
            "$schema": "https://opencode.ai/config.json",
            "mcp": {
                "servers": {
                    "kaleidoscope": {
                        "type": "local",
                        "command": [descriptor.command, *descriptor.args],
                        "environment": {},
                        "codemode": False,
                    }
                }
            },
        }
    )
