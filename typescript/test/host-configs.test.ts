import assert from "node:assert/strict";
import test from "node:test";

import {
  parseLaunchDescriptor,
  renderClaudeCodeConfig,
  renderCodexConfig,
  renderCursorConfig,
  renderOpenCodeBetaV2Config,
  renderOpenCodeStableV1Config,
} from "../src/index.js";
import { FAKE_BINARY } from "./helpers.js";

const descriptor = parseLaunchDescriptor({
  version: 1,
  transport: "stdio",
  command: FAKE_BINARY,
  args: ["mcp", "--profile", "test"],
  tools: ["search", "remember"],
  environment: {},
});
test("Codex config pins two tools and acknowledges search writes", () => {
  const rendered = renderCodexConfig(descriptor);
  assert.match(rendered, /enabled_tools = \["search", "remember"\]/u);
  assert.match(rendered, /default_tools_approval_mode = "writes"/u);
  assert.doesNotMatch(rendered, /workspace_id|principal_id|journal|token/iu);
});

test("JSON host configs remain profile-first and coordinate-free", () => {
  const claude = JSON.parse(renderClaudeCodeConfig(descriptor));
  const cursor = JSON.parse(renderCursorConfig(descriptor));
  const stable = JSON.parse(renderOpenCodeStableV1Config(descriptor));
  const beta = JSON.parse(renderOpenCodeBetaV2Config(descriptor));
  assert.deepEqual(claude.mcpServers.kaleidoscope.env, {});
  assert.deepEqual(cursor.mcpServers.kaleidoscope.args, descriptor.args);
  assert.equal(stable.mcp.kaleidoscope.enabled, true);
  assert.equal(beta.mcp.servers.kaleidoscope.codemode, false);
  assert.doesNotMatch(
    JSON.stringify([claude, cursor, stable, beta]),
    /workspace_id|principal_id|journal|root|token/iu,
  );
});

test("OpenCode stable v1 and beta v2 require an explicit renderer choice", () => {
  const stable = JSON.parse(renderOpenCodeStableV1Config(descriptor));
  const beta = JSON.parse(renderOpenCodeBetaV2Config(descriptor));
  assert.ok(stable.mcp.kaleidoscope);
  assert.equal(stable.mcp.servers, undefined);
  assert.ok(beta.mcp.servers.kaleidoscope);
  assert.equal(beta.mcp.kaleidoscope, undefined);
});
