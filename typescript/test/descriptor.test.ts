import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";

import {
  DescriptorError,
  executableSha256,
  loadLaunchDescriptor,
  mcpStdioConfig,
  MissingBinaryError,
  parseLaunchDescriptor,
  resolveBinary,
} from "../src/index.js";
import { FAKE_BINARY } from "./helpers.js";

function validDescriptor(): Record<string, unknown> {
  return {
    version: 1,
    transport: "stdio",
    command: FAKE_BINARY,
    args: ["mcp", "--profile", "test"],
    tools: ["search", "remember"],
    environment: {},
  };
}

test("TypeScript accepts the same closed launch descriptor", () => {
  const descriptor = parseLaunchDescriptor(validDescriptor());
  assert.equal(descriptor.args[2], "test");
  assert.deepEqual(mcpStdioConfig(descriptor), {
    command: FAKE_BINARY,
    args: ["mcp", "--profile", "test"],
  });
});

for (const [field, value] of [
  ["version", 2],
  ["transport", "http"],
  ["args", ["mcp", "ROOT", "WORKSPACE", "PRINCIPAL", "JOURNAL"]],
  ["tools", ["search", "remember", "feedback"]],
  ["environment", { API_TOKEN: "must-not-pass" }],
] as const) {
  test(`TypeScript rejects descriptor drift in ${field}`, () => {
    assert.throws(
      () => parseLaunchDescriptor({ ...validDescriptor(), [field]: value }),
      DescriptorError,
    );
  });
}

test("profile launch uses a binary digest pin and does not inherit secrets", () => {
  process.env.KALEIDOSCOPE_TEST_SECRET = "must-not-reach-child";
  try {
    const descriptor = loadLaunchDescriptor(FAKE_BINARY, "test", {
      expectedSha256: executableSha256(FAKE_BINARY),
    });
    assert.equal(descriptor.command, FAKE_BINARY);
    assert.deepEqual(descriptor.environment, {});
  } finally {
    delete process.env.KALEIDOSCOPE_TEST_SECRET;
  }
});

test("missing binary has a stable error category", () => {
  assert.throws(
    () => resolveBinary(resolve("absent-kscope")),
    (error: unknown) => error instanceof MissingBinaryError && error.code === "missing_binary",
  );
});
