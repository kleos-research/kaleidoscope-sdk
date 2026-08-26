import type { LaunchDescriptor } from "./descriptor.js";

function json(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

export function renderCodexConfig(descriptor: LaunchDescriptor): string {
  return `[mcp_servers.kaleidoscope]
command = ${JSON.stringify(descriptor.command)}
args = [${descriptor.args.map((item) => JSON.stringify(item)).join(", ")}]
env = {}
enabled = true
required = false
startup_timeout_sec = 10
tool_timeout_sec = 30
enabled_tools = [${descriptor.tools.map((item) => JSON.stringify(item)).join(", ")}]
default_tools_approval_mode = "writes"

# Ranked search appends an exposure row, so approve it deliberately.
[mcp_servers.kaleidoscope.tools.search]
approval_mode = "approve"
`;
}

export function renderClaudeCodeConfig(descriptor: LaunchDescriptor): string {
  return json({
    mcpServers: {
      kaleidoscope: {
        type: "stdio",
        command: descriptor.command,
        args: descriptor.args,
        env: {},
      },
    },
  });
}

export function renderCursorConfig(descriptor: LaunchDescriptor): string {
  return json({
    mcpServers: {
      kaleidoscope: {
        command: descriptor.command,
        args: descriptor.args,
        env: {},
      },
    },
  });
}

/** Released OpenCode configuration shape; callers must choose it explicitly. */
export function renderOpenCodeStableV1Config(descriptor: LaunchDescriptor): string {
  return json({
    $schema: "https://opencode.ai/config.json",
    mcp: {
      kaleidoscope: {
        type: "local",
        command: [descriptor.command, ...descriptor.args],
        environment: {},
        enabled: true,
      },
    },
  });
}

/** Opt-in OpenCode v2 beta shape; this is never selected automatically. */
export function renderOpenCodeBetaV2Config(descriptor: LaunchDescriptor): string {
  return json({
    $schema: "https://opencode.ai/config.json",
    mcp: {
      servers: {
        kaleidoscope: {
          type: "local",
          command: [descriptor.command, ...descriptor.args],
          environment: {},
          codemode: false,
        },
      },
    },
  });
}
