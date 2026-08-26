import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { assistantMessage, functionCall, ScriptedModel } from "@openai/agents/testing";
import { setTracingDisabled } from "@openai/agents";

import { runAgentTurns } from "../examples/openaiAgents.js";
import { loadLaunchDescriptor } from "../src/index.js";
import { FAKE_BINARY } from "./helpers.js";

test("OpenAI Agents SDK owns one persistent server lifecycle with a fake model", async () => {
  setTracingDisabled(true);
  const model = new ScriptedModel([
    [
      functionCall(
        "remember",
        {
          mode: "create",
          content_md: "# Agents SDK fixture\n\nStored by the scripted model.",
          semantic_delta: {
            memory_type: "architecture",
            title: "Agents SDK fixture",
            facts: [
              {
                subject: "OpenAI Agents SDK fixture",
                predicate: "uses",
                object: "Kaleidoscope MCP",
              },
            ],
          },
        },
        { callId: "remember-1" },
      ),
    ],
    [functionCall("search", { query: "Agents SDK fixture" }, { callId: "search-1" })],
    [assistantMessage("done")],
  ]);
  const profile = `spawn-count-${randomUUID()}`;
  const marker = join(tmpdir(), `${profile}.starts`);
  try {
    const descriptor = loadLaunchDescriptor(FAKE_BINARY, profile);
    const outputs = await runAgentTurns(descriptor, model, ["exercise memory"]);
    model.assertComplete();
    assert.equal(model.calls.length, 3);
    assert.match(JSON.stringify(model.calls.at(-1)?.request.input), /Agents SDK fixture/u);
    assert.equal(outputs.length, 1);
    assert.equal(readFileSync(marker, "utf8").trim().split("\n").length, 1);
  } finally {
    rmSync(marker, { force: true });
  }
});
