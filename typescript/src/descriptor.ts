import {
  accessSync,
  closeSync,
  openSync,
  readFileSync,
  readSync,
  realpathSync,
  statSync,
} from "node:fs";
import { constants as fsConstants } from "node:fs";
import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";
import { spawnSync } from "node:child_process";

import { ChildProcessError, DescriptorError, MissingBinaryError } from "./errors.js";
import { installedEnginePath, installedManagerPath } from "./distribution.js";

export const EXPECTED_TOOLS = ["search", "remember"] as const;
const EXPECTED_KEYS = [
  "args",
  "command",
  "environment",
  "tools",
  "transport",
  "version",
] as const;
const PROFILE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MAX_MANAGER_OUTPUT_BYTES = 64 * 1024;
export const MAX_DIAGNOSTIC_BYTES = 4096;

/**
 * Conventional, non-secret process/bootstrap variables. Nothing here is a
 * credential and nothing here is Kaleidoscope-specific.
 *
 * XDG_CONFIG_HOME was added 2026-08-22. It is not an entitlement variable; it
 * was always missing. On Linux the engine resolves its config directory from
 * $XDG_CONFIG_HOME in preference to $HOME/.config, so without it an
 * SDK-spawned engine and a shell-run engine read two different directories.
 */
export const BOOTSTRAP_ENVIRONMENT_KEYS = [
  "APPDATA",
  "HOME",
  "HOMEDRIVE",
  "HOMEPATH",
  "LOCALAPPDATA",
  "LOGNAME",
  "PATH",
  "PATHEXT",
  "SHELL",
  "SYSTEMDRIVE",
  "SYSTEMROOT",
  "TEMP",
  "TERM",
  "TMPDIR",
  "USER",
  "USERNAME",
  "USERPROFILE",
  "XDG_CONFIG_HOME",
] as const;

/**
 * The alpha entitlement variables, admitted BY NAME and by name only.
 *
 * This is an allowlist, so naming two entries does not weaken protection of
 * anything else: AZURE_OPENAI_API_KEY, SUPABASE_SECRET_KEY and every other
 * variable in the caller's environment remain stripped because they are not named
 * here. A prefix rule (KALEIDOSCOPE_*) would readmit them and is forbidden; the
 * KALEIDOSCOPE_TEST_SECRET and KSCOPE_ENTITLEMENT_PROBE canaries in both test
 * suites exist to fail exactly that shortcut.
 *
 * The admission test is not "is it a Kaleidoscope variable" and not "does it look
 * harmless". It is: the published entitlement contract
 * (reference/entitlement-contract-v1.json) says the engine reads this one, AND a
 * supported SDK flow fails without it. Two names pass that test:
 *
 *   KALEIDOSCOPE_API_KEY -- the alpha credential the entitlement gate
 *   authenticates. Every gated command refuses without it, so no SDK path works
 *   without it.
 *
 *   KSCOPE_ENTITLEMENT_HOME -- selects the entitlement directory, and therefore
 *   the key file the gate falls back to when no API key is in the environment.
 *   Without it an SDK-spawned engine and a shell-run engine can disagree about
 *   where the key lives.
 *
 * Three names that look like they belong here and do not. Each is in the
 * never_admitted list of the same published contract, and the reason differs in
 * each case -- which is the point: "not admitted" is a conclusion reached per
 * name, never a category.
 *
 *   KSCOPE_ENTITLEMENT_PROBE redirects part of the engine's entitlement check
 *   to a caller-named path. Handing a child a caller-controlled path to
 *   something that will be given the API key is the shape of an attack, and it
 *   buys nothing: a supported install needs no override.
 *
 *   KALEIDOSCOPE_CONTROL_PLANE_ORIGIN was admitted here for a while, on the
 *   assumption that handing it over would redirect where a key is checked. The
 *   published contract says otherwise: it sits in never_admitted beside the two
 *   other names here and beside the plain secrets. Forwarding a name the
 *   contract does not admit changes nothing a caller can observe, while
 *   implying a redirection capability the contract does not offer. It was one
 *   name over the minimum and the justification for it was simply wrong.
 *
 *   KSCOPE_PROFILE_HOME is the Rust manager's documented, non-secret profile
 *   registry override. The manager honours it; the SDKs have never forwarded it
 *   and still do not.
 *
 * The rule the three share: a name earns a place here by having a documented
 * consumer and a demonstrated failure mode, not by being adjacent to one.
 *
 * Widening this list is a deliberate, reviewed edit in three places at once --
 * this list, its twin in the other language, and
 * reference/entitlement-contract-v1.json -- never a prefix and never a pattern.
 */
export const ENTITLEMENT_ENVIRONMENT_KEYS = [
  "KALEIDOSCOPE_API_KEY",
  "KSCOPE_ENTITLEMENT_HOME",
] as const;

/**
 * The one name a programmatic key rides in. It is already in the list above.
 */
export const API_KEY_VARIABLE_NAME = "KALEIDOSCOPE_API_KEY";

export const SAFE_ENVIRONMENT_KEYS = [
  ...BOOTSTRAP_ENVIRONMENT_KEYS,
  ...ENTITLEMENT_ENVIRONMENT_KEYS,
] as const;

export interface LaunchDescriptor {
  readonly version: 1;
  readonly transport: "stdio";
  readonly command: string;
  readonly args: readonly ["mcp", "--profile", string];
  readonly tools: typeof EXPECTED_TOOLS;
  readonly environment: Readonly<Record<string, never>>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Build the child environment from a closed, by-name allowlist.
 *
 * Two groups, both literal: conventional process/bootstrap variables
 * (`BOOTSTRAP_ENVIRONMENT_KEYS`), and the two alpha entitlement variables
 * (`ENTITLEMENT_ENVIRONMENT_KEYS`), one of which -- KALEIDOSCOPE_API_KEY -- is
 * a credential and is passed deliberately, because the engine's entitlement
 * gate reads it and no SDK path works without it.
 *
 * The promise this makes is narrower than "never credentials" and it is the
 * one that is actually kept: **only the names listed above are copied.** Every
 * other variable in the caller's environment -- other providers' API keys, a
 * Supabase service-role key that bypasses row-level security, anything in a
 * .env file -- is not copied, because it is not named. Widening this list is a
 * deliberate, reviewed edit to two literal arrays and to
 * reference/entitlement-contract-v1.json, never a prefix or a pattern.
 *
 * `apiKey` is the programmatic route. **The allowlist does not grow to carry
 * it**: the value is placed in KALEIDOSCOPE_API_KEY, a name already admitted,
 * replacing whatever the caller's own environment held. The allowlist
 * is still 20 names and the shared contract is untouched. `process.env` is never
 * mutated, so the key is scoped to the children this SDK spawns and reaches no
 * other subprocess the caller's process starts.
 */
export function safeBootstrapEnvironment(
  options: { apiKey?: string } = {},
): Record<string, string> {
  const safe: Record<string, string> = {};
  for (const key of SAFE_ENVIRONMENT_KEYS) {
    const value = process.env[key];
    // Shellshock-style exported function definitions are never a value we want
    // to hand a child.
    if (value !== undefined && !value.startsWith("()")) safe[key] = value;
  }
  if (options.apiKey !== undefined) {
    // The shellshock `()` predicate is deliberately NOT applied to this value.
    // It exists to stop an exported function definition INHERITED from the
    // caller's environment being laundered into a child. A value handed over as
    // a string was not inherited from anywhere; dropping it here would silently
    // discard a key the caller explicitly passed, and the engine would then
    // report E_NO_KEY for a key that WAS supplied -- a refusal spelled as the
    // wrong answer.
    safe[API_KEY_VARIABLE_NAME] = options.apiKey;
  }
  return safe;
}

/**
 * The same allowlist, minus the credential, for children that read no key.
 *
 * NOT a second allowlist. It is `safeBootstrapEnvironment()` with one name
 * removed, so it can only ever be a subset. Used by the ungated spawn sites
 * (`profile launch`, `profile show`, `schema`, `gate`) and by the manager, none
 * of which reads KALEIDOSCOPE_API_KEY: the engine's gated command list is
 * ["mcp","context","call","serve"], and the gate report reads no key.
 *
 * Narrowing is the only direction this can move, and it is done by removing a
 * name from the ONE list above -- never by adding to a second one.
 */
export function ungatedEnvironment(): Record<string, string> {
  const safe = safeBootstrapEnvironment();
  delete safe[API_KEY_VARIABLE_NAME];
  return safe;
}

/**
 * PRESENCE and TRANSPORT only. Never validity. See entitlement.ts's block.
 *
 * Checked: it is a string; it is not empty after trim; it contains no NUL and
 * no newline. The last two are not opinions about keys -- a NUL cannot be put
 * in an environment variable by the OS at all, and a newline splits the value
 * on the platforms that parse env blocks textually.
 *
 * NOT checked, and must never be: prefix, length, charset, checksum, expiry.
 */
export function validatedApiKey(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string") {
    throw new DescriptorError("apiKey must be a string or undefined");
  }
  if (value.trim().length === 0) {
    // An explicitly supplied empty string is a CALLER error, not a bad key.
    // Falling back to the environment here would make "I passed a key" and "I
    // passed nothing" indistinguishable -- a refusal spelled as an answer.
    throw new DescriptorError(
      "apiKey was supplied but is empty; omit it to use the environment",
    );
  }
  if (/[\0\n\r]/u.test(value)) {
    throw new DescriptorError("apiKey must not contain a newline or NUL");
  }
  return value;
}

/**
 * The code points both SDKs strip from the ends of a diagnostic.
 *
 * Neither language's built-in is usable here, because the two disagree on two
 * classes and the disagreement is silent. Python's `str.strip()` treats the
 * file/group/record/unit separators U+001C-U+001F as whitespace and U+FEFF as
 * not; JavaScript's `String.trim()` does exactly the reverse. Measured over 25
 * differential cases, a trailing U+001C and a trailing U+FEFF were the only two
 * that produced different diagnostics from identical child bytes -- a parity
 * divergence no test in either tree could see, because the shared case file was
 * read by one language only.
 *
 * So the set is written out: the UNION of both languages' notions, pinned in
 * reference/entitlement-contract-v1.json and asserted from both sides. The
 * union rather than the intersection, because a diagnostic is display text and
 * stripping one separator too many is harmless, whereas the two built-ins
 * disagreeing is exactly the defect being closed.
 *
 * Written as code points, not as literal characters: several of these are
 * invisible, and a source file carrying them raw cannot be reviewed.
 */
export const DIAGNOSTIC_EDGE_CODE_POINTS: readonly number[] = Object.freeze([
  // Agreed by both languages.
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680,
  0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008,
  0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
  // Python only: str.isspace() is true for these; String.trim() is not.
  0x1c, 0x1d, 0x1e, 0x1f,
  // JavaScript only: trim() strips the BOM; Python's strip() does not.
  0xfeff,
]);

const EDGE: ReadonlySet<string> = new Set(
  DIAGNOSTIC_EDGE_CODE_POINTS.map((point) => String.fromCodePoint(point)),
);

function stripDiagnosticEdges(text: string): string {
  let start = 0;
  let end = text.length;
  while (start < end && EDGE.has(text.charAt(start))) start += 1;
  while (end > start && EDGE.has(text.charAt(end - 1))) end -= 1;
  return text.slice(start, end);
}

/**
 * The SHAPE of an alpha key, for redaction only.
 *
 * One pattern, no length arithmetic. It matches the full 53-character key and
 * also a key sliced in half by the 4096-byte diagnostic bound, which a `{43}`
 * rule would miss. Pinned in reference/redaction-contract-v1.json and asserted
 * from both SDKs.
 */
export const API_KEY_SHAPE_PATTERN = "ksk_alpha\\.[A-Za-z0-9_-]*";

/**
 * The last `MAX_DIAGNOSTIC_BYTES` of a child's stderr, redacted.
 *
 * Truncation is in BYTES, not UTF-16 code units: Python's `_bounded_diagnostic`
 * slices bytes and then decodes with errors="replace", and the two SDKs have to
 * produce the same string from the same child. Keeping the **tail** is what
 * makes the entitlement marker line survive a flooded stderr, because the
 * engine prints that line last.
 */
export function boundedDiagnostic(value: string | Buffer | null | undefined): string {
  const raw = Buffer.isBuffer(value) ? value : Buffer.from(value ?? "", "utf8");
  return (
    stripDiagnosticEdges(
      raw.subarray(Math.max(0, raw.length - MAX_DIAGNOSTIC_BYTES)).toString("utf8"),
    )
      // Shape first: an alpha key is masked wherever it appears, including
      // inside prose and inside JSON, where the name rule below cannot see it.
      // REDACTION IS NOT VALIDATION -- a string that matches is masked whether
      // or not it is a real key, and nothing branches on whether it matched.
      .replace(new RegExp(API_KEY_SHAPE_PATTERN, "gu"), "<redacted>")
      .replace(
        /(token|secret|password|authorization|api[_-]?key)\s*[:=]\s*\S+/giu,
        "$1=<redacted>",
      )
  );
}

export function validateProfileName(value: unknown): string {
  if (typeof value !== "string" || !PROFILE.test(value)) {
    throw new DescriptorError("descriptor profile name is not portable");
  }
  return value;
}

function canonicalExecutable(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || !isAbsolute(value)) {
    throw new DescriptorError("descriptor command must be an absolute string");
  }
  let resolved: string;
  try {
    resolved = realpathSync(value);
    const stat = statSync(resolved);
    accessSync(resolved, fsConstants.X_OK);
    if (!stat.isFile()) throw new Error("not a file");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new MissingBinaryError("Kaleidoscope executable does not exist", { cause: error });
    }
    throw new DescriptorError("descriptor command must be a regular executable", { cause: error });
  }
  if (resolved !== value) {
    throw new DescriptorError("descriptor command must already be canonical and non-symlinked");
  }
  return value;
}

export function parseLaunchDescriptor(value: unknown): LaunchDescriptor {
  if (!isRecord(value)) throw new DescriptorError("launch descriptor must be an object");
  const keys = Object.keys(value).sort();
  if (JSON.stringify(keys) !== JSON.stringify(EXPECTED_KEYS)) {
    throw new DescriptorError("descriptor fields differ from the closed v1 shape");
  }
  if (value.version !== 1) throw new DescriptorError("descriptor version must be exactly 1");
  if (value.transport !== "stdio") {
    throw new DescriptorError("descriptor transport must be exactly stdio");
  }
  const command = canonicalExecutable(value.command);
  if (
    !Array.isArray(value.args) ||
    value.args.length !== 3 ||
    value.args[0] !== "mcp" ||
    value.args[1] !== "--profile"
  ) {
    throw new DescriptorError("descriptor args must be ['mcp', '--profile', NAME]");
  }
  const profile = validateProfileName(value.args[2]);
  if (
    !Array.isArray(value.tools) ||
    value.tools.length !== 2 ||
    value.tools[0] !== EXPECTED_TOOLS[0] ||
    value.tools[1] !== EXPECTED_TOOLS[1]
  ) {
    throw new DescriptorError("descriptor tools must be exactly ['search', 'remember']");
  }
  if (!isRecord(value.environment) || Object.keys(value.environment).length !== 0) {
    throw new DescriptorError("descriptor environment must be exactly empty");
  }
  const args: readonly ["mcp", "--profile", string] = Object.freeze([
    "mcp",
    "--profile",
    profile,
  ]);
  return Object.freeze({
    version: 1,
    transport: "stdio",
    command,
    args,
    tools: EXPECTED_TOOLS,
    environment: Object.freeze({}),
  });
}

export function readLaunchDescriptor(path: string): LaunchDescriptor {
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new DescriptorError(`cannot read launch descriptor: ${path}`, { cause: error });
  }
  return parseLaunchDescriptor(value);
}

export function executableSha256(path: string): string {
  const command = canonicalExecutable(path);
  const handle = openSync(command, "r");
  const digest = createHash("sha256");
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  try {
    for (;;) {
      const count = readSync(handle, buffer, 0, buffer.length, null);
      if (count === 0) break;
      digest.update(buffer.subarray(0, count));
    }
  } finally {
    closeSync(handle);
  }
  return digest.digest("hex");
}

export function resolveBinary(path?: string, expectedSha256?: string): string {
  const command = canonicalExecutable(path ?? installedEnginePath());
  if (expectedSha256 !== undefined && executableSha256(command) !== expectedSha256.toLowerCase()) {
    throw new DescriptorError("Kaleidoscope executable SHA-256 does not match the caller's pin");
  }
  return command;
}

export function resolveManager(path?: string, expectedSha256?: string): string {
  const command = canonicalExecutable(path ?? installedManagerPath());
  if (expectedSha256 !== undefined && executableSha256(command) !== expectedSha256.toLowerCase()) {
    throw new DescriptorError("Kaleidoscope manager SHA-256 does not match the caller's pin");
  }
  return command;
}

export interface LoadLaunchDescriptorOptions {
  readonly expectedSha256?: string;
  readonly timeoutMs?: number;
}

export function loadLaunchDescriptor(
  binary: string,
  profile: string,
  options: LoadLaunchDescriptorOptions = {},
): LaunchDescriptor {
  const command = resolveBinary(binary, options.expectedSha256);
  validateProfileName(profile);
  const completed = spawnSync(command, ["profile", "launch", profile], {
    encoding: "utf8",
    // `profile launch` is not a gated command, so it gets no credential.
    env: ungatedEnvironment(),
    timeout: options.timeoutMs ?? 10_000,
    maxBuffer: MAX_MANAGER_OUTPUT_BYTES,
    windowsHide: true,
  });
  if (completed.error) {
    throw new ChildProcessError("profile launch could not complete", { cause: completed.error });
  }
  if (completed.status !== 0) {
    const diagnostic = boundedDiagnostic(completed.stderr);
    throw new ChildProcessError(
      `profile launch exited ${completed.status ?? "without status"}${diagnostic ? `: ${diagnostic}` : ""}`,
    );
  }
  let value: unknown;
  try {
    value = JSON.parse(completed.stdout);
  } catch (error) {
    throw new DescriptorError("profile launch did not return valid JSON", { cause: error });
  }
  const descriptor = parseLaunchDescriptor(value);
  if (descriptor.command !== command || descriptor.args[2] !== profile) {
    throw new DescriptorError("profile launch changed the requested command or profile");
  }
  return descriptor;
}

export function mcpStdioConfig(descriptor: LaunchDescriptor): {
  command: string;
  args: string[];
} {
  // An empty descriptor environment means "add no authority". Omitting env
  // lets the MCP SDK inherit only its audited HOME/PATH bootstrap allowlist.
  return { command: descriptor.command, args: [...descriptor.args] };
}
