import assert from "node:assert/strict";
import test from "node:test";

import {
  loadLaunchDescriptor,
  partialBatch,
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

test("a partly written remember batch is reported, not thrown", async () => {
  // The engine answers isError=true when a remember batch wrote some items
  // and not others (its DATA-3 step 3). callText returns that receipt, which
  // names the items not written and says the others are stored; a batch that
  // wrote nothing is still a ToolRefusalError.
  const partly = loadLaunchDescriptor(FAKE_BINARY, "partial");
  {
    await using memory = await new PersistentKaleidoscopeSession(partly).connect();
    const text = await memory.rememberRaw({ mode: "create", content_md: "# test" });
    assert.ok(text.startsWith("Not written | 1 of 2 items: item 2 (items[1])."), text);
    assert.ok(text.includes("Item 1 | Created"), text);
    assert.deepEqual(partialBatch(text), { notWritten: [1], total: 2, stored: 1 });
  }
  const nothing = loadLaunchDescriptor(FAKE_BINARY, "unwritten");
  {
    await using memory = await new PersistentKaleidoscopeSession(nothing).connect();
    await assert.rejects(
      () => memory.rememberRaw({ mode: "create", content_md: "# test" }),
      ToolRefusalError,
    );
  }
  assert.equal(partialBatch("Item 1 | Created"), undefined);
});
