import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Controller, loadLaunchDescriptor, resetGateStatusCache } from "../src/index.js";

export const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE_SOURCE = realpathSync(resolve(HERE, "fixtures/fake-engine.mjs"));
const reference = resolve(HERE, "../../reference");

export interface Golden {
  readonly bootstrap_environment: string[];
  readonly entitlement_environment: string[];
  readonly never_admitted: string[];
  readonly exit_codes: Record<string, number>;
  readonly refusal_marker_pattern: string;
  readonly refusal_identifiers: string[];
  readonly sdk_only_identifiers: string[];
  readonly missing_key_file_placeholder: string;
  readonly messages: Record<string, string>;
}

export const GOLDEN: Golden = JSON.parse(
  readFileSync(resolve(reference, "entitlement-contract-v1.json"), "utf8"),
) as Golden;

/** An obvious non-secret, matching the engine suite's KEY_A. */
export const TEST_KEY = `ksk_alpha.${"A".repeat(43)}`;
/** Syntactically well-formed and completely bogus: the engine must decide. */
export const BOGUS_KEY = `ksk_alpha.${"Z".repeat(43)}`;
/** Not well-formed at all. The SDK must still hand it to the engine. */
export const MALFORMED_KEY = "ksk_alpha.short";

export interface Engine {
  readonly command: string;
  readonly home: string;
  readonly entitlementHome: string;
  readonly keyFile: string;
  readonly invocationLog: string;
}

/**
 * Stage one fake engine in its own directory. The directory is the fixture's
 * only configuration channel, because the child receives no environment it
 * could be configured through -- which is the property under test.
 */
export function stageEngine(kind: string): Engine {
  const home = realpathSync(mkdtempSync(join(realpathSync(tmpdir()), "kscope-entitlement-")));
  const command = join(home, `kscope-${kind}.mjs`);
  copyFileSync(FIXTURE_SOURCE, command);
  chmodSync(command, 0o755);
  const entitlementHome = join(home, "entitlement");
  mkdirSync(entitlementHome, { recursive: true });
  resetGateStatusCache();
  return {
    command,
    home,
    entitlementHome,
    keyFile: join(entitlementHome, "api-key"),
    invocationLog: join(home, "invocations.log"),
  };
}

export function writeKeyFile(engine: Engine, key: string, mode: number): void {
  writeFileSync(engine.keyFile, `${key}\n`, "utf8");
  chmodSync(engine.keyFile, mode);
}

export function renderExpected(reason: string, keyFile: string | undefined): string {
  const template = GOLDEN.messages[reason] ?? GOLDEN.messages.E_UNKNOWN;
  return (template as string)
    .split("{key_file}")
    .join(keyFile ?? GOLDEN.missing_key_file_placeholder);
}

/**
 * Run `body` with these environment overrides in force, restoring afterwards.
 *
 * ASYNC-AWARE, deliberately. A synchronous `try/finally` around a function that
 * returns a promise restores the environment when the promise is CREATED, not
 * when it settles -- so the child spawns with the overrides (the spawn is
 * synchronous) but everything after the first await runs without them. That
 * cost a real defect: the gate was queried a second time on the error path,
 * after the restore, and reported a key_file for a directory that was no longer
 * configured.
 */
export async function withEnvironment<T>(
  overrides: Record<string, string | undefined>,
  body: () => T | Promise<T>,
): Promise<T> {
  const previous: Record<string, string | undefined> = {};
  for (const key of Object.keys(overrides)) previous[key] = process.env[key];
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  resetGateStatusCache();
  try {
    return await body();
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    resetGateStatusCache();
  }
}

export async function callEngine(
  engine: Engine,
  profile: string,
  payload: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const descriptor = loadLaunchDescriptor(engine.command, profile);
  const controller = new Controller(descriptor, { timeoutMs: 10_000 });
  return (await controller.searchRaw(payload)) as Record<string, unknown>;
}


/**
 * Drive the fake engine through the native `call` path with a CODE key.
 *
 * The parallel of `callEngine`, and the reason it exists separately: the point
 * of these tests is the route the key takes, and a helper that put the key in
 * `process.env` before spawning would be testing the environment route twice.
 */
export async function callEngineWithCodeKey(
  engine: Engine,
  profile: string,
  apiKey: string,
  payload: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const descriptor = loadLaunchDescriptor(engine.command, profile);
  const controller = new Controller(descriptor, { timeoutMs: 10_000, apiKey });
  return (await controller.searchRaw(payload)) as Record<string, unknown>;
}
