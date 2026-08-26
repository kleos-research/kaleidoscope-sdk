/**
 * The alpha entitlement seam: what the engine's gate needs, and how it refuses.
 *
 * Two invariants govern every function here.
 *
 * 1. The engine and the control plane are the only authorities. Everything in
 *    this file is a UX affordance. When a check cannot run it FAILS OPEN, and
 *    the engine still refuses. That is the opposite of a release gate's
 *    posture, which must fail CLOSED on absent evidence because it is an
 *    authority over an artefact nobody can re-inspect once it is published.
 *    The asymmetry is deliberate: this is a courtesy, not an authority.
 * 2. A refusal is never spelled as an answer. Nothing here returns empty,
 *    abstains, or lets a refusal reach the caller as a crash.
 */

// ---------------------------------------------------------------------------
// WHAT THIS SDK MUST NEVER DO WITH AN API KEY, AND WHY.
//
// This SDK CARRIES the credential and REPORTS the engine's verdict. It is never
// an authority on whether a key is good. Concretely, and permanently:
//
//   NO VALIDITY DECISION. No signature check, no prefix check, no length check,
//   no charset check, no checksum. `keyIsPresent` checks presence and nothing
//   else, and it is the only function allowed to look at a key at all.
//
//   NO EXPIRY ARITHMETIC. Nothing here parses a date out of a key, compares a
//   timestamp, or reasons about a grace window. E_KEY_EXPIRED and
//   E_GRACE_EXPIRED are identifiers the engine emits and this SDK renders.
//
//   NO VERDICT CACHING. `gateStatus` memoises what the engine says about its
//   own BUILD -- enforcing or not, and where the key file is. That report reads
//   no key. A key must never enter the memo's cache key: a cache retains every
//   key it is given for the life of the process, so that would pin the
//   credential in a module-level map.
//
// WHY, so nobody helpfully adds it:
//
//   This package is Apache-2.0 and trivially editable. Any validity rule here is
//   theatre against an adversary and a SECOND SOURCE OF TRUTH against everyone
//   else. When the engine's rule and this copy of it disagree, the SDK refuses a
//   key that works, or admits one that does not, and in both cases the user is
//   told something false by the layer that had no standing to say it. There is
//   one authority: the engine, and behind it the control plane.
//
//   Two things this makes CHEAPER, not more expensive: (a) an engine that adds a
//   key format needs no SDK release; (b) a refusal always names the real reason,
//   because the only component that can produce one is the only component that
//   knows.
//
// The permitted preflight is exactly this: is a key PRESENT and non-empty, and
// is it a thing that can be put in an environment variable at all. That saves a
// spawn and produces a better message. It decides nothing.
//
// The redaction rules in descriptor.ts match a key SHAPE. Redaction is not
// validation: a string that matches is masked whether or not it is a real key,
// a string that does not match is not treated as bad, and NOTHING BRANCHES ON
// THE RESULT. If you find yourself using the redaction regex to make a decision,
// you are writing the thing this block forbids.
//
// ON THE `apiKey` OPTION, AND THE ARGUMENT AGAINST ONE.
//
//   The engine's own source argues, in a comment, that an SDK could read a key
//   file and inject KALEIDOSCOPE_API_KEY into a child; that this would leave
//   every non-SDK caller still broken for a file-route user; and that it would
//   put key bytes in SDK memory for no benefit. One authority, one route, all
//   callers.
//
//   That comment is correct and this option does not contradict it. It argues
//   against the SDK READING THE KEY FILE, and this SDK does not: the file route
//   is the engine's and is never opened here. The benefit the comment says is
//   absent is the one this option supplies -- configuring the key in code, which
//   the file route cannot do at all. Precedence is unchanged, because a code key
//   becomes an environment value in the child and the engine's own
//   environment-before-file rule then ranks it correctly with no SDK
//   involvement.
//
//   The boundary that comment is really about still holds: `apiKey` configures
//   THIS SDK'S OWN CHILDREN. A harness that spawns the engine itself never
//   passes through this code and takes its key from the environment or the key
//   file, as before.
// ---------------------------------------------------------------------------

import { spawnSync } from "node:child_process";
import { statSync } from "node:fs";

import {
  ENTITLEMENT_ENVIRONMENT_KEYS,
  safeBootstrapEnvironment,
  ungatedEnvironment,
  validatedApiKey,
} from "./descriptor.js";
import { EntitlementError } from "./errors.js";

export const ENTITLEMENT_ENV_KEYS = ENTITLEMENT_ENVIRONMENT_KEYS;
export const API_KEY_VARIABLE = "KALEIDOSCOPE_API_KEY";

/**
 * The only machine-readable discriminator the SDK parses out of the engine's
 * stderr. It is the LAST line of every entitlement refusal, and that is
 * load-bearing: `boundedDiagnostic` keeps the last 4096 bytes, so a marker at
 * the head would not survive a flooded stderr.
 *
 * The SDK never matches on the engine's English prose. Prose gets edited, and a
 * substring match on it drifts silently with nothing to announce it.
 */
const MARKER = /^kscope-entitlement-refusal: ([A-Z][A-Z0-9_]{2,39})$/gmu;

/**
 * The nine identifiers the engine emits.
 *
 * E_UNKNOWN_KEY is the ninth, and this set carried only eight until an audit
 * found the gap. The engine distinguishes a key the control plane has never
 * issued from one it issued and revoked, and emits a distinct identifier for
 * each. An SDK that knew only eight collapsed the first into E_UNKNOWN -- whose
 * message blames a version skew between an engine and an SDK that were the same
 * version. A refusal spelled as the wrong answer: the user is told to upgrade,
 * and upgrading cannot help.
 *
 * The fix is not "add one more string". It is that the identifier set is frozen
 * in reference/entitlement-contract-v1.json and asserted from all three
 * implementations -- this SDK, the Python SDK, and the engine's own contract
 * test -- against that one file. A tenth identifier therefore cannot reach a
 * user through an SDK that has not been taught it: the three fail together, at
 * test time, instead of one of them degrading at run time.
 */
export const REFUSAL_IDENTIFIERS: ReadonlySet<string> = new Set([
  "E_NO_KEY",
  "E_KEY_FILE_UNUSABLE",
  "E_MALFORMED_KEY",
  "E_UNVERIFIED",
  "E_UNKNOWN_KEY",
  "E_REVOKED",
  "E_KEY_EXPIRED",
  "E_GRACE_EXPIRED",
  "E_CLOCK_BACKWARDS",
]);

/** The SDK-only pseudo-identifier. The engine never emits it. */
export const UNKNOWN_REFUSAL = "E_UNKNOWN";

const GATE_REPORT_KEYS: readonly string[] = [
  "status",
  "entitlement_build",
  "gated_commands",
  "entitlement_home",
  "key_file",
  "build_features",
  "marker",
];

export interface GateStatus {
  readonly enforcing: boolean;
  readonly keyFile: string | undefined;
}

const UNENFORCED: GateStatus = Object.freeze({ enforcing: false, keyFile: undefined });

const cache = new Map<string, GateStatus>();

/**
 * The variables the engine's own directory resolution reads. They belong in the
 * cache key because the gate report's `entitlement_home` and `key_file` are
 * derived from them: keyed on the path alone, a process that changed
 * KSCOPE_ENTITLEMENT_HOME would be served a key_file for the previous one, and
 * the resulting message would name a path the user never configured. Nothing
 * about that looks wrong from the outside, which is why the cache key has to
 * carry every input the cached answer was derived from.
 */
const DIRECTORY_VARIABLES = ["KSCOPE_ENTITLEMENT_HOME", "HOME", "APPDATA", "XDG_CONFIG_HOME"];

function cacheKey(command: string): string | undefined {
  try {
    const stat = statSync(command, { bigint: true });
    const directory = DIRECTORY_VARIABLES.map((name) => `${name}=${process.env[name] ?? ""}`).join("|");
    return `${command}|${stat.mtimeNs.toString()}|${stat.size.toString()}|${directory}`;
  } catch {
    // No stat, no memoisation. Failing to key the cache must not fail the call.
    return undefined;
  }
}

/**
 * Ask the engine whether it enforces the gate. UX only; never authority.
 *
 * Memoised on the binary (path, mtime, size) AND the directory variables the
 * report is derived from, so swapping either invalidates it.
 *
 * FAILS OPEN. `kscope gate` is a new command; an older engine answers it with a
 * usage error, and a future one may answer with keys this SDK does not know.
 * Either way the answer is {enforcing: false}, the preflight is skipped, and
 * the engine decides -- which is the whole point.
 */
export function gateStatus(command: string, timeoutMs = 10_000): GateStatus {
  const key = cacheKey(command);
  if (key !== undefined) {
    const hit = cache.get(key);
    if (hit !== undefined) return hit;
  }
  const status = probeGate(command, timeoutMs);
  if (key !== undefined) cache.set(key, status);
  return status;
}

/** Drop the memoised gate answers. Test seam; not part of the public promise. */
export function resetGateStatusCache(): void {
  cache.clear();
}

function probeGate(command: string, timeoutMs: number): GateStatus {
  let completed;
  try {
    completed = spawnSync(command, ["gate"], {
      encoding: "buffer",
      // `gate` reads no key -- it reports where the key file WOULD be and
      // whether this build enforces.
      env: ungatedEnvironment(),
      timeout: timeoutMs,
      maxBuffer: 64 * 1024,
      windowsHide: true,
    });
  } catch {
    return UNENFORCED;
  }
  if (completed.error || completed.status !== 0) return UNENFORCED;
  let parsed: unknown;
  try {
    parsed = JSON.parse(completed.stdout.toString("utf8"));
  } catch {
    return UNENFORCED;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return UNENFORCED;
  const report = parsed as Record<string, unknown>;
  const keys = Object.keys(report).sort();
  if (JSON.stringify(keys) !== JSON.stringify([...GATE_REPORT_KEYS].sort())) return UNENFORCED;
  // Exactly true, not truthy: a string "false" must not enable enforcement.
  if (report.entitlement_build !== true) return UNENFORCED;
  const keyFile = typeof report.key_file === "string" && report.key_file.length > 0
    ? report.key_file
    : undefined;
  return Object.freeze({
    enforcing: true,
    ...(keyFile === undefined ? {} : { keyFile }),
  }) as GateStatus;
}

/**
 * PRESENCE, never validity.
 *
 * True iff either KALEIDOSCOPE_API_KEY is set and non-empty after trimming, or
 * the gate report named a key file that is a regular file of non-zero size.
 *
 * This function never opens the key file, never checks its mode, never checks
 * the key's shape, prefix, length or charset, and never contacts anything. The
 * Python and TypeScript SDKs are Apache-2.0 and trivially editable; a validity
 * check here would be theatre and a second source of truth. A key file at mode
 * 0644 is PRESENT to the SDK and is refused by the engine with
 * E_KEY_FILE_UNUSABLE, which is the correct division of labour.
 *
 * The environment half is read through `safeBootstrapEnvironment()` rather than
 * off `process.env` directly, so this function sees exactly what the child will
 * see. Read directly, the two disagreed for one class of value: a key beginning
 * with `()` is dropped by the shellshock predicate on the way to the child,
 * while presence here said "set" -- so the SDK spawned, the engine saw no key
 * at all, and told the user to set a variable they had set. Asking the
 * allowlist makes the disagreement unrepresentable rather than merely fixed.
 *
 * `apiKey` is passed straight through to that same call, so presence and
 * delivery still cannot disagree: this asks the ONE function that builds the
 * child's environment what it would build, rather than reimplementing its
 * precedence rule.
 */
export function keyIsPresent(
  status: GateStatus,
  options: { apiKey?: string } = {},
): boolean {
  const built = safeBootstrapEnvironment(
    options.apiKey === undefined ? {} : { apiKey: options.apiKey },
  );
  const fromEnvironment = (built[API_KEY_VARIABLE] ?? "").trim();
  if (fromEnvironment.length > 0) return true;
  if (status.keyFile === undefined) return false;
  try {
    const stat = statSync(status.keyFile);
    return stat.isFile() && stat.size > 0;
  } catch {
    return false;
  }
}

/**
 * Refuse before spawning a gated command when nothing at all is configured, and
 * return the gate status the caller should quote for the rest of this call.
 *
 * The only case this fires on is a user who exported nothing and wrote no file.
 * It never demands the environment variable, so it cannot break the key-file
 * route.
 *
 * It RETURNS the status rather than being asked again later, so the `key_file`
 * a refusal names is the one that was in force when the command ran. Asking
 * twice let the two answers differ -- caught by a parity test that read an
 * empty path where the golden had one -- and a message naming a path the user
 * never configured is a refusal spelled as the wrong answer.
 */
export function entitlementPreflight(
  command: string,
  options: { apiKey?: string } = {},
): GateStatus {
  const status = gateStatus(command);
  if (!status.enforcing) return status;
  const apiKey = validatedApiKey(options.apiKey);
  if (keyIsPresent(status, apiKey === undefined ? {} : { apiKey })) return status;
  throw new EntitlementError("E_NO_KEY", {
    ...(status.keyFile === undefined ? {} : { keyFile: status.keyFile }),
  });
}

/**
 * Which entitlement refusal this is, or null if it is not one.
 *
 * Reads only the marker line. An exit code of 4 with no recognisable marker is
 * still an entitlement refusal -- from an engine newer than this SDK -- and is
 * reported as E_UNKNOWN rather than as a crash.
 */
export function classifyRefusal(
  stderr: Buffer | string | null | undefined,
  code: number | null = null,
): string | null {
  const text = Buffer.isBuffer(stderr) ? stderr.toString("utf8") : (stderr ?? "");
  let last: string | undefined;
  MARKER.lastIndex = 0;
  for (const match of text.matchAll(MARKER)) last = match[1];
  if (last !== undefined) {
    return REFUSAL_IDENTIFIERS.has(last) ? last : UNKNOWN_REFUSAL;
  }
  if (code === 4) return UNKNOWN_REFUSAL;
  return null;
}
