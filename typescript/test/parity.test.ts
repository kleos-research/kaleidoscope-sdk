import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  Controller,
  EntitlementError,
  gateStatus,
  loadLaunchDescriptor,
  PersistentKaleidoscopeSession,
} from "../src/index.js";
import { withEnvironment } from "./entitlementHelpers.js";
import { FAKE_BINARY } from "./helpers.js";

const here = dirname(fileURLToPath(import.meta.url));
const reference = resolve(here, "../../reference");

/**
 * Behaviour parity, against the SHARED fake engine both SDKs drive.
 *
 * The declared-constant goldens keep the two SDKs' *tables* in step and cannot
 * see a divergence in what a caller actually receives. This file closes that:
 * the same eight refusals, the same fixture process, and an assertion against
 * `reference/entitlement-behaviour-golden.json`, which the Python side
 * regenerates. A TypeScript change that alters the observed error, code,
 * message or diagnostic fails here rather than reaching a user.
 */
interface Scenario {
  readonly reason: string;
  readonly code: string;
  readonly error_class: string;
  readonly message: string;
  readonly key_file: string;
  readonly diagnostic_present: boolean;
  readonly diagnostic_bounded: boolean;
}

const GOLDEN = JSON.parse(
  readFileSync(resolve(reference, "entitlement-behaviour-golden.json"), "utf8"),
) as {
  contract_version: number;
  key_file_placeholder: string;
  scenarios: Record<string, Scenario>;
};

const TEST_KEY = `ksk_alpha.${"A".repeat(43)}`;
const PLACEHOLDER = GOLDEN.key_file_placeholder;

interface Home {
  readonly entitlementHome: string;
  readonly keyFile: string;
}

/**
 * The shared fixture reads its build status from a control file inside the
 * entitlement directory, which is how a test selects the *enforcing* build. An
 * absent control file means the default, ungated build -- faithfully, because
 * the engine's cargo feature defaults off.
 */
function enforcingHome(): Home {
  const entitlementHome = realpathSync(mkdtempSync(join(realpathSync(tmpdir()), "kscope-parity-")));
  mkdirSync(entitlementHome, { recursive: true });
  writeFileSync(
    join(entitlementHome, "fixture-gate.json"),
    JSON.stringify({ entitlement_build: true }),
    "utf8",
  );
  return { entitlementHome, keyFile: join(entitlementHome, "api-key") };
}

function observe(error: unknown, home: Home): Scenario {
  assert.ok(error instanceof EntitlementError, `expected EntitlementError, got ${String(error)}`);
  return {
    reason: error.reason,
    code: error.code,
    error_class: error.constructor.name,
    // Normalised exactly as the descriptor golden normalises __KSCOPE_BINARY__.
    message: error.message.split(home.keyFile).join(PLACEHOLDER),
    key_file: (error.keyFile ?? "").split(home.keyFile).join(PLACEHOLDER),
    diagnostic_present: error.diagnostic.length > 0,
    diagnostic_bounded: Buffer.byteLength(error.diagnostic, "utf8") <= 4096 + 64,
  };
}

test("B13 the shared fixture refuses identically to both SDKs, on the native path", async (context) => {
  for (const identifier of Object.keys(GOLDEN.scenarios)) {
    await context.test(identifier, async () => {
      const home = enforcingHome();
      const observed = await withEnvironment(
        {
          KALEIDOSCOPE_API_KEY: TEST_KEY,
          KSCOPE_ENTITLEMENT_HOME: home.entitlementHome,
        },
        async () => {
          const descriptor = loadLaunchDescriptor(FAKE_BINARY, "test");
          const controller = new Controller(descriptor, { timeoutMs: 15_000 });
          try {
            await controller.searchRaw({
              _fixture_mode: "entitlement_refusal",
              _entitlement_code: identifier,
            });
          } catch (error) {
            return observe(error, home);
          }
          return undefined;
        },
      );
      assert.deepEqual(observed, GOLDEN.scenarios[identifier]);
    });
  }
});

test("B13 the shared fixture refuses identically on the MCP path too", async () => {
  const home = enforcingHome();
  const observed = await withEnvironment(
    { KALEIDOSCOPE_API_KEY: TEST_KEY, KSCOPE_ENTITLEMENT_HOME: home.entitlementHome },
    async () => {
      const descriptor = loadLaunchDescriptor(FAKE_BINARY, "refusal.E_REVOKED.1");
      try {
        await new PersistentKaleidoscopeSession(descriptor, { timeoutMs: 10_000 }).connect();
      } catch (error) {
        return observe(error, home);
      }
      return undefined;
    },
  );
  // The MCP path has no observable exit code at all -- the stdio client awaits
  // the process in its own finally and discards it -- so this is the marker
  // line doing the whole job, and it lands on the same golden row.
  assert.deepEqual(observed, GOLDEN.scenarios.E_REVOKED);
});

test("B13 the shared fixture's gate report is the one this SDK parses", () => {
  const home = enforcingHome();
  withEnvironment({ KSCOPE_ENTITLEMENT_HOME: home.entitlementHome }, () => {
    const status = gateStatus(FAKE_BINARY);
    assert.equal(status.enforcing, true);
    assert.equal(status.keyFile, home.keyFile);
  });
  // Same binary, no control file: the default build, and nothing is enforced.
  const plain = realpathSync(mkdtempSync(join(realpathSync(tmpdir()), "kscope-parity-plain-")));
  withEnvironment({ KSCOPE_ENTITLEMENT_HOME: plain }, () => {
    assert.equal(gateStatus(FAKE_BINARY).enforcing, false);
  });
});

test("B13 the key reaches the shared engine over MCP, and only when set", async () => {
  const home = enforcingHome();
  const withKey = await withEnvironment(
    { KALEIDOSCOPE_API_KEY: TEST_KEY, KSCOPE_ENTITLEMENT_HOME: home.entitlementHome },
    async () => {
      const descriptor = loadLaunchDescriptor(FAKE_BINARY, "test");
      await using session = await new PersistentKaleidoscopeSession(descriptor).connect();
      return JSON.parse(await session.searchRaw({ query: "__environment__" })) as Record<
        string,
        unknown
      >;
    },
  );
  assert.equal(withKey.api_key_seen, true);
  assert.equal(withKey.api_key_matches, true);
  assert.equal(withKey.secret, "absent");

  // The falsifier for the assertion above.
  const withoutKey = await withEnvironment(
    { KALEIDOSCOPE_API_KEY: undefined, KSCOPE_ENTITLEMENT_HOME: undefined },
    async () => {
      const descriptor = loadLaunchDescriptor(FAKE_BINARY, "test");
      await using session = await new PersistentKaleidoscopeSession(descriptor).connect();
      return JSON.parse(await session.searchRaw({ query: "__environment__" })) as Record<
        string,
        unknown
      >;
    },
  );
  assert.equal(withoutKey.api_key_seen, false);
  assert.equal(withoutKey.api_key_matches, false);
});

// ---------------------------------------------------------------------------
// B15 - the committed cross-language ROW golden, asserted from this side too.
//
// This replaces a rendezvous that never ran. `python/tests/test_parity.py` read
// `typescript/test/artifacts/parity-typescript.json` behind an `exists()` guard
// and fell through to a `print` when it was absent -- and nothing in this tree
// ever wrote that file, so the branch documented as "the only thing that can
// catch a divergence the committed golden was updated to match on one side
// only" took the else every time and reported green for its entire life.
//
// Making this side write the file would not have fixed it: whichever suite runs
// second is the only one that compares, a suite run alone compares against a
// stale file from a previous run, and the two run together race on a shared
// mutable path. So the rows are COMMITTED and each language asserts the whole
// set on its own, with no ordering, no staleness and no race.
//
// The row shape is Python's exactly, including the `<= 4096 + 64` diagnostic
// bound, which is the allowance for the redaction rewriting `api_key: x` (16 B)
// to `api_key=<redacted>` (18 B). A different predicate on one side would
// compare unequal while both SDKs behaved identically.
// ---------------------------------------------------------------------------

interface Row {
  readonly scenario: string;
  readonly reason: string;
  readonly code: string;
  readonly message: string;
  readonly diagnostic_length_bounded: boolean;
  readonly diagnostic_carries_marker: boolean;
}

const ROW_GOLDEN = JSON.parse(
  readFileSync(resolve(reference, "entitlement-parity-rows-v1.json"), "utf8"),
) as { contract_version: number; key_file_placeholder: string; rows: Row[] };

test("B15 this SDK's refusal rows match the committed cross-language golden", async () => {
  const rows: Row[] = [];
  for (const expected of ROW_GOLDEN.rows) {
    const identifier = expected.scenario;
    const home = enforcingHome();
    const row = await withEnvironment(
      { KALEIDOSCOPE_API_KEY: TEST_KEY, KSCOPE_ENTITLEMENT_HOME: home.entitlementHome },
      async () => {
        const descriptor = loadLaunchDescriptor(FAKE_BINARY, "test");
        const controller = new Controller(descriptor, { timeoutMs: 15_000 });
        try {
          await controller.searchRaw({
            _fixture_mode: "entitlement_refusal",
            _entitlement_code: identifier,
          });
        } catch (error) {
          assert.ok(
            error instanceof EntitlementError,
            `expected EntitlementError, got ${String(error)}`,
          );
          return {
            scenario: identifier,
            reason: error.reason,
            code: error.code,
            message: error.message.split(home.keyFile).join(ROW_GOLDEN.key_file_placeholder),
            diagnostic_length_bounded:
              Buffer.byteLength(error.diagnostic, "utf8") <= 4096 + 64,
            diagnostic_carries_marker: error.diagnostic.includes(
              `kscope-entitlement-refusal: ${identifier}`,
            ),
          } satisfies Row;
        }
        throw new Error(`${identifier} did not refuse`);
      },
    );
    rows.push(row);
  }

  // Written for a human diffing a failure. NOTHING is asserted from it: a file
  // written by the run being checked cannot check that run.
  const artifacts = resolve(here, "artifacts");
  mkdirSync(artifacts, { recursive: true });
  writeFileSync(
    resolve(artifacts, "parity-typescript.json"),
    `${JSON.stringify({ language: "typescript", rows }, null, 2)}\n`,
    "utf8",
  );

  assert.deepEqual(rows, ROW_GOLDEN.rows);
});

// ---------------------------------------------------------------------------
// B16 - the MCP path's cause chain, a per-PATH property and therefore NOT in
// the shared row golden.
//
// The golden's rows are produced by Python from the MCP path and asserted here
// from the NATIVE path, so a field that legitimately differs between the two
// paths cannot live in it -- putting `cause_present` there compared
// Python-over-MCP against TypeScript-over-native and failed for the right value
// on the wrong axis.
//
// On the MCP path there IS an exception to chain from: the transport failure
// the refusal was diagnosed out of. Python raised `... from exc`; this side
// constructed without a `cause`, so a caller walking the chain saw
// `McpError: Connection closed` in one language and nothing in the other, for
// the same refusal from the same engine. Both attach it now. The native path
// chains nothing in either language, and that is correct: there is no exception
// in hand there, only an exit code and a stderr buffer, and fabricating a cause
// would be worse than having none.
// ---------------------------------------------------------------------------

test("B16 the MCP path chains the transport failure as the cause", async () => {
  const home = enforcingHome();
  const error = await withEnvironment(
    { KALEIDOSCOPE_API_KEY: TEST_KEY, KSCOPE_ENTITLEMENT_HOME: home.entitlementHome },
    async () => {
      // The fixture selects which refusal to emit from the profile name.
      const descriptor = loadLaunchDescriptor(FAKE_BINARY, "refusal.E_REVOKED.cause");
      try {
        await new PersistentKaleidoscopeSession(descriptor).connect();
      } catch (caught) {
        return caught;
      }
      throw new Error("the session connected instead of refusing");
    },
  );
  assert.ok(error instanceof EntitlementError, `expected EntitlementError, got ${String(error)}`);
  assert.equal(error.reason, "E_REVOKED");
  // Presence only. The transport's own message belongs to the MCP SDK and would
  // drift; what must not drift is whether a caller can reach it at all.
  assert.notEqual(error.cause, undefined);
  assert.notEqual(error.cause, null);
});

// The falsifier for B16: the NATIVE path deliberately chains nothing, in both
// languages. Without this, B16 would pass just as well against an SDK that
// attached a fabricated cause everywhere, and the asymmetry it is really
// asserting would go unmeasured.
test("B16 the native path deliberately chains nothing", async () => {
  const home = enforcingHome();
  const error = await withEnvironment(
    { KALEIDOSCOPE_API_KEY: TEST_KEY, KSCOPE_ENTITLEMENT_HOME: home.entitlementHome },
    async () => {
      const descriptor = loadLaunchDescriptor(FAKE_BINARY, "test");
      try {
        await new Controller(descriptor, { timeoutMs: 15_000 }).searchRaw({
          _fixture_mode: "entitlement_refusal",
          _entitlement_code: "E_REVOKED",
        });
      } catch (caught) {
        return caught;
      }
      throw new Error("the native call returned instead of refusing");
    },
  );
  assert.ok(error instanceof EntitlementError);
  assert.equal(error.cause, undefined);
});
