import assert from "node:assert/strict";
import test from "node:test";

import {
  loadLaunchDescriptor,
  PersistentKaleidoscopeSession,
  ProtocolContractError,
  ToolRefusalError,
} from "../src/index.js";
import { FAKE_BINARY } from "./helpers.js";

class FakeProvider {
  async run(memory: PersistentKaleidoscopeSession): Promise<Record<string, unknown>[]> {
    const remembered = JSON.parse(await memory.rememberRaw({
        mode: "create",
        content_md: "# Fixture fact\n\nThe persistent process retained this fixture record.",
        semantic_delta: {
          memory_type: "architecture",
          title: "Fixture fact",
          facts: [
            {
              subject: "DX-07 fixture",
              predicate: "uses",
              object: "one persistent MCP process",
              basis: "stated",
              mode: "fact",
            },
          ],
        },
      })) as Record<string, unknown>;
    const first = JSON.parse(await memory.searchRaw({ query: "fixture" })) as Record<string, unknown>;
    const second = JSON.parse(await memory.searchRaw({ query: "fixture again" })) as Record<string, unknown>;
    return [remembered, first, second];
  }
}

test("fake provider reuses one TypeScript MCP process and session", async () => {
  const descriptor = loadLaunchDescriptor(FAKE_BINARY, "test");
  await using memory = await new PersistentKaleidoscopeSession(descriptor).connect();
  const [remembered, first, second] = await new FakeProvider().run(memory);
  assert.equal(remembered?.pid, first?.pid);
  assert.equal(first?.pid, second?.pid);
  assert.deepEqual(first?.records, second?.records);
});

test("TypeScript stdio child does not receive ambient provider secret", async () => {
  process.env.KALEIDOSCOPE_TEST_SECRET = "must-not-reach-child";
  try {
    const descriptor = loadLaunchDescriptor(FAKE_BINARY, "test");
    await using memory = await new PersistentKaleidoscopeSession(descriptor).connect();
    const result = JSON.parse(
      await memory.searchRaw({ query: "__environment__" }),
    ) as Record<string, unknown>;
    assert.equal(result.secret, "absent");
  } finally {
    delete process.env.KALEIDOSCOPE_TEST_SECRET;
  }
});

test("controller refuses operator-only tool before the wire", async () => {
  const descriptor = loadLaunchDescriptor(FAKE_BINARY, "test");
  await using memory = await new PersistentKaleidoscopeSession(descriptor).connect();
  await assert.rejects(() => memory.callText("feedback", {}), ProtocolContractError);
});

test("discovery, structured output, and tool refusal fail closed", async (context) => {
  await context.test("extra tool", async () => {
    const descriptor = loadLaunchDescriptor(FAKE_BINARY, "extra");
    await assert.rejects(
      () => new PersistentKaleidoscopeSession(descriptor).connect(),
      ProtocolContractError,
    );
  });
  await context.test("structuredContent", async () => {
    const descriptor = loadLaunchDescriptor(FAKE_BINARY, "structured");
    await using memory = await new PersistentKaleidoscopeSession(descriptor).connect();
    await assert.rejects(
      () => memory.rememberRaw({ mode: "create", content_md: "# test" }),
      ProtocolContractError,
    );
  });
  await context.test("tool refusal", async () => {
    const descriptor = loadLaunchDescriptor(FAKE_BINARY, "refuse");
    await using memory = await new PersistentKaleidoscopeSession(descriptor).connect();
    await assert.rejects(
      () => memory.rememberRaw({ mode: "create", content_md: "# test" }),
      ToolRefusalError,
    );
  });
});
