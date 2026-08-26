from __future__ import annotations

import json
from pathlib import Path

from kaleidoscope_memory.descriptor import LaunchDescriptor
from kaleidoscope_memory.host_configs import (
    render_claude_code_config,
    render_codex_config,
    render_cursor_config,
    render_opencode_beta_v2_config,
    render_opencode_stable_v1_config,
)


def descriptor(fake_binary: Path) -> LaunchDescriptor:
    return LaunchDescriptor.from_mapping(
        {
            "version": 1,
            "transport": "stdio",
            "command": str(fake_binary),
            "args": ["mcp", "--profile", "test"],
            "tools": ["search", "remember"],
            "environment": {},
        }
    )


def test_codex_config_pins_tool_allowlist_and_write_policy(fake_binary: Path) -> None:
    rendered = render_codex_config(descriptor(fake_binary))
    assert 'enabled_tools = ["search", "remember"]' in rendered
    assert 'default_tools_approval_mode = "writes"' in rendered
    assert "[mcp_servers.kaleidoscope.tools.search]" in rendered
    assert "workspace_id" not in rendered
    assert "API_TOKEN" not in rendered


def test_json_host_configs_are_profile_first_and_vault_coordinate_free(fake_binary: Path) -> None:
    launch = descriptor(fake_binary)
    claude = json.loads(render_claude_code_config(launch))
    cursor = json.loads(render_cursor_config(launch))
    opencode_stable = json.loads(render_opencode_stable_v1_config(launch))
    opencode_beta = json.loads(render_opencode_beta_v2_config(launch))

    assert claude["mcpServers"]["kaleidoscope"]["env"] == {}
    assert cursor["mcpServers"]["kaleidoscope"]["args"] == list(launch.args)
    assert opencode_stable["mcp"]["kaleidoscope"] == {
        "type": "local",
        "command": [launch.command, *launch.args],
        "environment": {},
        "enabled": True,
    }
    assert opencode_beta["mcp"]["servers"]["kaleidoscope"] == {
        "type": "local",
        "command": [launch.command, *launch.args],
        "environment": {},
        "codemode": False,
    }
    combined = json.dumps([claude, cursor, opencode_stable, opencode_beta])
    for forbidden in ("workspace_id", "principal_id", "journal", "root", "token"):
        assert forbidden not in combined.lower()
