import { spawn, spawnSync } from "node:child_process";
import { isAbsolute } from "node:path";

import {
  boundedDiagnostic,
  resolveBinary,
  safeBootstrapEnvironment,
  ungatedEnvironment,
  validatedApiKey,
  validateProfileName,
  type LaunchDescriptor,
} from "./descriptor.js";
import { classifyRefusal, entitlementPreflight } from "./entitlement.js";
import {
  ChildProcessError,
  DeadlineExceededError,
  DescriptorError,
  EntitlementError,
  NativeRefusalError,
  OutputLimitError,
  ProcessCancelledError,
  ProtocolContractError,
} from "./errors.js";

const OPERATOR_OPERATIONS = new Set([
  "feedback",
  "memory_lifecycle",
  "memory_import",
  "address_maintenance",
  "maintenance",
  "ontology",
  "doctor",
]);
const PROFILE_KEYS = [
  "durability",
  "journal",
  "name",
  "principal_id",
  "root",
  "version",
  "workspace_id",
] as const;

export interface Profile {
  readonly version: 1;
  readonly name: string;
  readonly root: string;
  readonly workspace_id: string;
  readonly principal_id: string;
  readonly journal: string;
  readonly durability: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseJson(text: string | Buffer, label: string): unknown {
  try {
    return JSON.parse(Buffer.isBuffer(text) ? text.toString("utf8") : text);
  } catch (error) {
    throw new ProtocolContractError(`${label} did not return one JSON value`, { cause: error });
  }
}

export function parseProfile(value: unknown): Profile {
  if (!isRecord(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(PROFILE_KEYS)) {
    throw new DescriptorError("profile differs from the closed v1 shape");
  }
  if (value.version !== 1) throw new DescriptorError("profile version must be exactly 1");
  const name = validateProfileName(value.name);
  const fields = ["root", "workspace_id", "principal_id", "journal", "durability"] as const;
  for (const field of fields) {
    if (typeof value[field] !== "string" || value[field].length === 0) {
      throw new DescriptorError(`profile ${field} is invalid`);
    }
  }
  if (!isAbsolute(value.root as string)) throw new DescriptorError("profile root must be absolute");
  return Object.freeze({
    version: 1,
    name,
    root: value.root as string,
    workspace_id: value.workspace_id as string,
    principal_id: value.principal_id as string,
    journal: value.journal as string,
    durability: value.durability as string,
  });
}

export function loadProfile(binary: string, name: string, timeoutMs = 10_000): Profile {
  const command = resolveBinary(binary);
  validateProfileName(name);
  const completed = spawnSync(command, ["profile", "show", name], {
    encoding: "utf8",
    // `profile show` is not a gated command.
    env: ungatedEnvironment(),
    timeout: timeoutMs,
    maxBuffer: 64 * 1024,
    windowsHide: true,
  });
  if (completed.error) {
    throw new ChildProcessError("profile show could not complete", { cause: completed.error });
  }
  if (completed.status !== 0) throw new ChildProcessError(`profile show exited ${completed.status}`);
  const profile = parseProfile(parseJson(completed.stdout, "profile show"));
  if (profile.name !== name) throw new ProtocolContractError("profile show changed the name");
  return profile;
}

export function schema(binary: string, operation?: string, timeoutMs = 10_000): string {
  const command = resolveBinary(binary);
  if (
    operation !== undefined &&
    operation !== "search" &&
    operation !== "remember" &&
    !OPERATOR_OPERATIONS.has(operation)
  ) {
    throw new RangeError(`unknown public operation ${JSON.stringify(operation)}`);
  }
  const completed = spawnSync(command, ["schema", ...(operation ? [operation] : [])], {
    encoding: "utf8",
    // `schema` is not a gated command.
    env: ungatedEnvironment(),
    timeout: timeoutMs,
    maxBuffer: 1024 * 1024,
    windowsHide: true,
  });
  if (completed.error) throw new ChildProcessError("schema could not complete", { cause: completed.error });
  if (completed.status !== 0) throw new ChildProcessError(`schema exited ${completed.status}`);
  return completed.stdout;
}

function sortJson(value: unknown, active = new Set<object>()): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("JSON numbers must be finite");
    return value;
  }
  if (typeof value !== "object") throw new TypeError("native arguments contain a non-JSON value");
  if (active.has(value)) throw new TypeError("native arguments contain a JSON cycle");
  active.add(value);
  try {
    if (Array.isArray(value)) return value.map((item) => sortJson(item, active));
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("native arguments contain a non-plain JSON object");
    }
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, sortJson((value as Record<string, unknown>)[key], active)]),
    );
  } finally {
    active.delete(value);
  }
}

function encodePayload(arguments_: Record<string, unknown>): Buffer {
  let text: string | undefined;
  try {
    text = JSON.stringify(sortJson(arguments_));
  } catch (error) {
    throw new ProtocolContractError("native arguments are not JSON serializable", { cause: error });
  }
  if (text === undefined) throw new ProtocolContractError("native arguments are not JSON serializable");
  return Buffer.from(text, "utf8");
}

interface AttemptResult {
  readonly code: number | null;
  readonly stdout: Buffer;
  readonly stderr: Buffer;
}

interface AttemptOptions {
  readonly timeoutMs: number;
  readonly signal?: AbortSignal;
  readonly stdoutLimit: number;
  readonly stderrLimit: number;
  readonly apiKey?: string;
}

function runAttempt(
  command: string,
  args: readonly string[],
  payload: Buffer,
  options: AttemptOptions,
): Promise<AttemptResult> {
  return new Promise((resolve, reject) => {
    if (options.signal?.aborted) {
      reject(new ProcessCancelledError("native call was cancelled before launch"));
      return;
    }
    const child = spawn(command, args, {
      // `call` IS gated, so this is the one native spawn that gets a key.
      env: safeBootstrapEnvironment(
        options.apiKey === undefined ? {} : { apiKey: options.apiKey },
      ),
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let terminalError: Error | undefined;
    let settled = false;
    let forceKill: NodeJS.Timeout | undefined;

    const terminate = (): void => {
      child.kill("SIGTERM");
      forceKill = setTimeout(() => child.kill("SIGKILL"), 1_000);
      forceKill.unref();
    };
    const fail = (error: Error): void => {
      if (terminalError) return;
      terminalError = error;
      terminate();
    };
    child.stdout.on("data", (raw: Buffer | string) => {
      const chunk = Buffer.from(raw);
      stdoutBytes += chunk.length;
      if (stdoutBytes > options.stdoutLimit) {
        fail(new OutputLimitError(`native stdout exceeded ${options.stdoutLimit} bytes`));
      } else {
        stdout.push(chunk);
      }
    });
    child.stderr.on("data", (raw: Buffer | string) => {
      const chunk = Buffer.from(raw);
      stderrBytes += chunk.length;
      if (stderrBytes > options.stderrLimit) {
        fail(new OutputLimitError(`native stderr exceeded ${options.stderrLimit} bytes`));
      } else {
        stderr.push(chunk);
      }
    });
    const timeout = setTimeout(() => {
      fail(new DeadlineExceededError("native call timed out after send; outcome may be uncertain"));
    }, options.timeoutMs);
    timeout.unref();
    const onAbort = (): void => fail(new ProcessCancelledError("native call was cancelled"));
    options.signal?.addEventListener("abort", onAbort, { once: true });

    const cleanup = (): void => {
      clearTimeout(timeout);
      if (forceKill) clearTimeout(forceKill);
      options.signal?.removeEventListener("abort", onAbort);
    };
    child.once("error", (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new ChildProcessError("native child could not start", { cause: error }));
    });
    child.once("close", (code) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (terminalError) {
        reject(terminalError);
      } else {
        resolve({ code, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) });
      }
    });
    child.stdin.on("error", () => undefined);
    child.stdin.end(payload);
  });
}

export interface NativeCallOptions {
  readonly signal?: AbortSignal;
}

class NativeCaller {
  readonly descriptor: LaunchDescriptor;
  readonly timeoutMs: number;
  readonly attempts: number;
  readonly stdoutLimit: number;
  readonly stderrLimit: number;
  /** Validated for TRANSPORT at construction; never rendered by any repr. */
  readonly #apiKey: string | undefined;

  constructor(
    descriptor: LaunchDescriptor,
    options: {
      timeoutMs?: number;
      attempts: number;
      stdoutLimit?: number;
      stderrLimit?: number;
      apiKey?: string;
    },
  ) {
    this.descriptor = descriptor;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.attempts = options.attempts;
    this.stdoutLimit = options.stdoutLimit ?? 8 * 1024 * 1024;
    this.stderrLimit = options.stderrLimit ?? 64 * 1024;
    this.#apiKey = validatedApiKey(options.apiKey);
  }

  protected get apiKey(): string | undefined {
    return this.#apiKey;
  }

  async callNative(
    operation: string,
    arguments_: Record<string, unknown>,
    options: NativeCallOptions = {},
  ): Promise<unknown> {
    // Before the attempt loop, so a completely unconfigured caller never spawns
    // the engine at all. Fails open on an engine with no gate.
    const gate = entitlementPreflight(
      this.descriptor.command,
      this.#apiKey === undefined ? {} : { apiKey: this.#apiKey },
    );
    const payload = encodePayload(arguments_);
    const deadline = performance.now() + this.timeoutMs;
    let lastFailure: Error | undefined;
    for (let attempt = 0; attempt < this.attempts; attempt += 1) {
      const remaining = deadline - performance.now();
      if (remaining <= 0) break;
      const attemptsLeft = this.attempts - attempt;
      try {
        const result = await runAttempt(
          this.descriptor.command,
          ["call", "--profile", this.descriptor.args[2], operation],
          payload,
          {
            timeoutMs: remaining / attemptsLeft,
            stdoutLimit: this.stdoutLimit,
            stderrLimit: this.stderrLimit,
            ...(this.#apiKey === undefined ? {} : { apiKey: this.#apiKey }),
            ...(options.signal === undefined ? {} : { signal: options.signal }),
          },
        );
        if (result.code !== 0) {
          // An entitlement refusal is deterministic: the second spawn refuses
          // identically, and reporting it as "native call crashed" would call a
          // deliberate refusal a crash. Classified before the JSON parse
          // because the engine writes nothing to stdout when it refuses.
          const reason = classifyRefusal(result.stderr, result.code);
          if (reason !== null) {
            const keyFile = gate.keyFile;
            throw new EntitlementError(reason, {
              diagnostic: boundedDiagnostic(result.stderr),
              ...(keyFile === undefined ? {} : { keyFile }),
            });
          }
        }
        let parsed: unknown;
        try {
          parsed = JSON.parse(result.stdout.toString("utf8"));
        } catch (error) {
          if (result.code === 0) {
            throw new ProtocolContractError("native child returned non-JSON on success", {
              cause: error,
            });
          }
          lastFailure = new ChildProcessError(
            `native child exited ${result.code ?? "without status"} before a JSON response`,
          );
          continue;
        }
        if (result.code !== 0) throw new NativeRefusalError(operation, parsed);
        return parsed;
      } catch (error) {
        if (
          // Declared, not load-bearing today: EntitlementError extends
          // IntegrationError rather than ChildProcessError, so removing this
          // line changes no outcome -- measured, by removing it and watching
          // the non-retry test stay green. It is here so a future change that
          // reparents EntitlementError cannot silently make a deterministic
          // refusal retryable. What actually proves the property is the spawn
          // counter in the non-retry test, with a control that reads 2.
          error instanceof EntitlementError ||
          error instanceof NativeRefusalError ||
          error instanceof OutputLimitError ||
          error instanceof ProcessCancelledError ||
          error instanceof ProtocolContractError
        ) {
          throw error;
        }
        if (error instanceof DeadlineExceededError || error instanceof ChildProcessError) {
          lastFailure = error;
          continue;
        }
        throw error;
      }
    }
    if (lastFailure instanceof DeadlineExceededError) {
      throw new DeadlineExceededError(
        "native call exhausted its original deadline after one bounded retry",
        { cause: lastFailure },
      );
    }
    throw new ChildProcessError(
      `native call crashed before a response after ${this.attempts - 1} bounded retries`,
      { cause: lastFailure },
    );
  }
}

export class Controller extends NativeCaller {
  constructor(
    descriptor: LaunchDescriptor,
    options: {
      timeoutMs?: number;
      stdoutLimit?: number;
      stderrLimit?: number;
      apiKey?: string;
    } = {},
  ) {
    super(descriptor, { ...options, attempts: 2 });
  }

  searchRaw(arguments_: Record<string, unknown>, options?: NativeCallOptions): Promise<unknown> {
    return this.callNative("search", arguments_, options);
  }

  rememberRaw(arguments_: Record<string, unknown>, options?: NativeCallOptions): Promise<unknown> {
    return this.callNative("remember", arguments_, options);
  }
}

export class Operator extends NativeCaller {
  constructor(
    descriptor: LaunchDescriptor,
    options: { timeoutMs?: number; apiKey?: string } = {},
  ) {
    super(descriptor, { ...options, attempts: 1 });
  }

  call(
    operation: string,
    arguments_: Record<string, unknown>,
    options?: NativeCallOptions,
  ): Promise<unknown> {
    if (!OPERATOR_OPERATIONS.has(operation)) {
      throw new RangeError(`${JSON.stringify(operation)} is not in the operator namespace`);
    }
    return this.callNative(operation, arguments_, options);
  }
}
