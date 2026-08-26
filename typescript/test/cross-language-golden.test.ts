import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  ChildProcessError,
  DeadlineExceededError,
  DescriptorError,
  DuplicateSearchError,
  EntitlementError,
  MissingBinaryError,
  ManagerCommandError,
  NativeRefusalError,
  OutputLimitError,
  parseLaunchDescriptor,
  ProcessCancelledError,
  ProtocolContractError,
  renderClaudeCodeConfig,
  renderCodexConfig,
  renderCursorConfig,
  renderOpenCodeBetaV2Config,
  renderOpenCodeStableV1Config,
  refusedBatchItems,
  ToolRefusalError,
} from "../src/index.js";
import { FAKE_BINARY } from "./helpers.js";

const reference = resolve(dirname(fileURLToPath(import.meta.url)), "../../reference");

function fixture<T>(name: string): T {
  return JSON.parse(readFileSync(resolve(reference, name), "utf8")) as T;
}

function descriptorFixture(): {
  descriptor: ReturnType<typeof parseLaunchDescriptor>;
  template: Record<string, unknown>;
} {
  const template = fixture<Record<string, unknown>>("dx03-launch-descriptor.template.json");
  return {
    descriptor: parseLaunchDescriptor({ ...template, command: FAKE_BINARY }),
    template,
  };
}

function normalize(value: unknown): unknown {
  if (value === FAKE_BINARY) return "__KSCOPE_BINARY__";
  if (Array.isArray(value)) return value.map(normalize);
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, normalize(item)]));
  }
  return value;
}

test("TypeScript consumes the shared descriptor template and binary pin", () => {
  const { descriptor, template } = descriptorFixture();
  const pin = fixture<{
    source_commit: string;
    sha256: string;
    shared_vault_runtime_sha256: string;
    isolated_distribution_candidate_sha256: string;
    public_contract_sha256: string;
  }>("binary-pin.json");
  const contract = fixture<{ executable: { sha256: string } }>(
    "kaleidoscope-public-contract.json",
  );
  assert.deepEqual(normalize(descriptor), template);
  assert.match(pin.source_commit, /^[0-9a-f]{40}$/u);
  assert.match(pin.sha256, /^[0-9a-f]{64}$/u);
  assert.match(pin.shared_vault_runtime_sha256, /^[0-9a-f]{64}$/u);
  assert.equal(pin.isolated_distribution_candidate_sha256, pin.sha256);
  assert.match(pin.isolated_distribution_candidate_sha256, /^[0-9a-f]{64}$/u);
  assert.equal(contract.executable.sha256, pin.sha256);
  const contractBytes = readFileSync(resolve(reference, "kaleidoscope-public-contract.json"));
  assert.equal(
    createHash("sha256").update(contractBytes).digest("hex"),
    pin.public_contract_sha256,
  );
});

test("TypeScript host renderers match the shared golden", () => {
  const { descriptor } = descriptorFixture();
  const golden = fixture<Record<string, Record<string, unknown>>>("host-config-golden.json");
  assert.deepEqual(normalize(JSON.parse(renderClaudeCodeConfig(descriptor))), golden.claude_code);
  assert.deepEqual(normalize(JSON.parse(renderCursorConfig(descriptor))), golden.cursor);
  assert.deepEqual(
    normalize(JSON.parse(renderOpenCodeStableV1Config(descriptor))),
    golden.opencode_stable_v1,
  );
  assert.deepEqual(
    normalize(JSON.parse(renderOpenCodeBetaV2Config(descriptor))),
    golden.opencode_beta_v2,
  );

  const codex = golden.codex as Record<string, unknown>;
  const rendered = renderCodexConfig(descriptor);
  assert.match(rendered, new RegExp(`enabled = ${String(codex.enabled)}`, "u"));
  assert.match(rendered, new RegExp(`required = ${String(codex.required)}`, "u"));
  assert.match(rendered, new RegExp(`startup_timeout_sec = ${String(codex.startup_timeout_sec)}`, "u"));
  assert.match(rendered, new RegExp(`tool_timeout_sec = ${String(codex.tool_timeout_sec)}`, "u"));
  assert.match(rendered, /enabled_tools = \["search", "remember"\]/u);
  assert.match(rendered, /default_tools_approval_mode = "writes"/u);
  assert.match(rendered, /approval_mode = "approve"/u);
});

test("TypeScript error classes match the shared category golden", () => {
  const categories = fixture<{
    categories: Record<string, { typescript: string }>;
  }>("error-categories-v1.json").categories;
  const errors: Record<string, Error & { code: string }> = {
    invalid_descriptor: new DescriptorError("fixture"),
    missing_binary: new MissingBinaryError("fixture"),
    child_crash: new ChildProcessError("fixture"),
    manager_command: new ManagerCommandError(["status", "--json"], 2, "fixture"),
    deadline_exceeded: new DeadlineExceededError("fixture"),
    cancelled: new ProcessCancelledError("fixture"),
    output_limit: new OutputLimitError("fixture"),
    protocol_contract: new ProtocolContractError("fixture"),
    native_refusal: new NativeRefusalError("search", {}),
    duplicate_search: new DuplicateSearchError("fixture"),
    tool_refusal: new ToolRefusalError("search", "fixture"),
    entitlement: new EntitlementError("E_NO_KEY"),
  };
  for (const [code, error] of Object.entries(errors)) {
    assert.equal(error.constructor.name, categories[code]?.typescript);
    assert.equal(error.code, code);
  }
  // Until this assertion existed, adding a category to the shared golden and
  // implementing it in only one language failed no test in either language:
  // each iterated its own local map and never asked whether the map was
  // complete.
  assert.deepEqual(Object.keys(errors).sort(), Object.keys(categories).sort());
});

test("TypeScript selects only index-aligned refused batch items", () => {
  const golden = fixture<{
    request: { items: Readonly<Record<string, unknown>>[] };
    response: { results: Readonly<Record<string, unknown>>[] };
    refused_indexes: number[];
  }>("partial-batch-golden.json");
  const selected = refusedBatchItems(golden.request, golden.response);
  assert.deepEqual(
    selected,
    golden.refused_indexes.map((index) => golden.request.items[index]),
  );
});

test("TypeScript refuses misaligned batch results", () => {
  assert.throws(
    () => refusedBatchItems({ items: [{}, {}] }, { results: [{ status: "created" }] }),
    ProtocolContractError,
  );
});
