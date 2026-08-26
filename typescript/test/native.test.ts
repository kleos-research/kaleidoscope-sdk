import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

import {
  Controller,
  ControllerTurn,
  DuplicateSearchError,
  loadLaunchDescriptor,
  loadProfile,
  NativeRefusalError,
  Operator,
  OutputLimitError,
  ProcessCancelledError,
  ProtocolContractError,
  schema,
} from "../src/index.js";
import { FAKE_BINARY } from "./helpers.js";

const NATIVE_GOLDEN = JSON.parse(
  readFileSync(new URL("../../reference/native-controller-golden.json", import.meta.url), "utf8"),
) as {
  request: Record<string, unknown>;
  success: Record<string, unknown>;
  retry: { maximum_attempts: number };
};

test("TypeScript controller returns parsed native JSON", async () => {
  const descriptor = loadLaunchDescriptor(FAKE_BINARY, "native");
  const result = await new Controller(descriptor).searchRaw(NATIVE_GOLDEN.request);
  assert.deepEqual(result, NATIVE_GOLDEN.success);
});

test("pre-response crash retries once with identical payload bytes", async () => {
  const descriptor = loadLaunchDescriptor(FAKE_BINARY, "native");
  const { mkdtempSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const directory = mkdtempSync(join(tmpdir(), "kscope-ts-retry-"));
  const count = join(directory, "count");
  try {
    const arguments_ = { _fixture_mode: "crash_once", marker: count, query: "same bytes" };
    const result = (await new Controller(descriptor, { timeoutMs: 2_000 }).searchRaw(
      arguments_,
    )) as Record<string, unknown>;
    const encoded = JSON.stringify({
      _fixture_mode: "crash_once",
      marker: count,
      query: "same bytes",
    });
    assert.equal(result.invocation, NATIVE_GOLDEN.retry.maximum_attempts);
    assert.equal(result.payload_sha256, createHash("sha256").update(encoded).digest("hex"));
    assert.equal(readFileSync(count, "utf8"), "2");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("uncertain timeout retries once inside the original deadline", async () => {
  const { mkdtempSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const directory = mkdtempSync(join(tmpdir(), "kscope-ts-timeout-"));
  const marker = join(directory, "count");
  try {
    const descriptor = loadLaunchDescriptor(FAKE_BINARY, "native");
    const result = (await new Controller(descriptor, { timeoutMs: 1_000 }).searchRaw({
      _fixture_mode: "timeout_once",
      marker,
    })) as Record<string, unknown>;
    assert.equal(result.invocation, 2);
    assert.equal(readFileSync(marker, "utf8"), "2");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("native refusal, invalid JSON, and stderr flood are not retried", async () => {
  const { mkdtempSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const directory = mkdtempSync(join(tmpdir(), "kscope-ts-fail-"));
  const descriptor = loadLaunchDescriptor(FAKE_BINARY, "native");
  try {
    const refusal = join(directory, "refusal");
    await assert.rejects(
      () =>
        new Controller(descriptor).rememberRaw({
          _fixture_mode: "refuse",
          marker: refusal,
        }),
      (error: unknown) => {
        assert.ok(error instanceof NativeRefusalError);
        assert.deepEqual(error.response, { status: "refused", code: "invalid_schema" });
        return true;
      },
    );
    assert.equal(readFileSync(refusal, "utf8"), "1");

    const invalid = join(directory, "invalid");
    await assert.rejects(
      () =>
        new Controller(descriptor).searchRaw({
          _fixture_mode: "invalid_json",
          marker: invalid,
        }),
      ProtocolContractError,
    );
    assert.equal(readFileSync(invalid, "utf8"), "1");

    const flood = join(directory, "flood");
    await assert.rejects(
      () =>
        new Controller(descriptor, { stderrLimit: 1024 }).searchRaw({
          _fixture_mode: "stderr_flood",
          marker: flood,
        }),
      OutputLimitError,
    );
    assert.equal(readFileSync(flood, "utf8"), "1");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("non-JSON arguments fail before process launch", async () => {
  const descriptor = loadLaunchDescriptor(FAKE_BINARY, "native");
  await assert.rejects(
    () => new Controller(descriptor).searchRaw({ query: Number.NaN }),
    ProtocolContractError,
  );
  await assert.rejects(
    () => new Controller(descriptor).searchRaw({ query: new Date(0) }),
    ProtocolContractError,
  );
});

test("AbortSignal terminates the native child", async () => {
  const { existsSync, mkdtempSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const directory = mkdtempSync(join(tmpdir(), "kscope-ts-cancel-"));
  const marker = join(directory, "count");
  try {
    const descriptor = loadLaunchDescriptor(FAKE_BINARY, "native");
    const abort = new AbortController();
    const pending = new Controller(descriptor, { timeoutMs: 10_000 }).searchRaw(
      { _fixture_mode: "sleep", marker },
      { signal: abort.signal },
    );
    for (let attempt = 0; attempt < 50; attempt += 1) {
      if (existsSync(marker) && readFileSync(marker, "utf8") === "1") break;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    abort.abort();
    await assert.rejects(() => pending, ProcessCancelledError);
    assert.equal(readFileSync(marker, "utf8"), "1");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("profile/controller/operator surface stays explicitly separated", async () => {
  const descriptor = loadLaunchDescriptor(FAKE_BINARY, "native");
  assert.equal(loadProfile(FAKE_BINARY, "native").name, "native");
  const result = (await new Operator(descriptor).call("doctor", {})) as Record<string, unknown>;
  assert.equal(result.operation, "doctor");
  assert.throws(() => new Operator(descriptor).call("search", {}), RangeError);
  assert.equal(schema(FAKE_BINARY, "search"), "fixture schema search\n");
  assert.throws(() => schema(FAKE_BINARY, "not-public"), RangeError);
});

test("controller turn performs exactly one search and withholds MCP search", async () => {
  let calls = 0;
  const turn = new ControllerTurn({
    async searchRaw(arguments_) {
      calls += 1;
      return { selected_hits: [], query: arguments_.query };
    },
  });
  assert.deepEqual(await turn.searchRawOnce({ query: "one" }), {
    selected_hits: [],
    query: "one",
  });
  assert.deepEqual(turn.modelMcpTools, ["remember"]);
  await assert.rejects(() => turn.searchRawOnce({ query: "two" }), DuplicateSearchError);
  assert.equal(calls, 1);
});
