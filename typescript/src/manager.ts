import { spawnSync } from "node:child_process";

import { boundedDiagnostic, resolveBinary, ungatedEnvironment } from "./descriptor.js";
import {
  ChildProcessError,
  DeadlineExceededError,
  ManagerCommandError,
  OutputLimitError,
  ProtocolContractError,
} from "./errors.js";

export const ACCOUNT_ENVIRONMENT_KEYS = [
  "KALEIDOSCOPE_ACCOUNT_ORIGIN",
  "KALEIDOSCOPE_ACCOUNT_ISSUER",
  "KALEIDOSCOPE_ACCOUNT_AUDIENCE",
  "KALEIDOSCOPE_ACCOUNT_CLIENT_ID",
] as const;
type AccountEnvironmentKey = (typeof ACCOUNT_ENVIRONMENT_KEYS)[number];
const MANAGER_CONTEXT_KEYS = ["KALEIDOSCOPE_CONFIG_HOME", "KALEIDOSCOPE_USER_HOME"] as const;
const PROVIDER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const STATUS_KEYS = ["account_id", "device_id", "stale", "state", "version"] as const;
const MAX_MANAGER_OUTPUT_BYTES = 64 * 1024;

export interface ManagerAccountCommand {
  readonly arguments: readonly string[];
}

function command(...arguments_: string[]): ManagerAccountCommand {
  return Object.freeze({ arguments: Object.freeze(arguments_) });
}

function uuid(value: string, label: string): string {
  if (!UUID.test(value)) throw new TypeError(`${label} must be a UUID`);
  return value.toLowerCase();
}

function assertAccountCommand(accountCommand: ManagerAccountCommand): readonly string[] {
  const arguments_ = accountCommand.arguments;
  const rendered = JSON.stringify(arguments_);
  const fixed = new Set([
    JSON.stringify(["status", "--json"]),
    JSON.stringify(["login"]),
    JSON.stringify(["login", "--device"]),
    JSON.stringify(["logout"]),
    JSON.stringify(["logout", "--all-devices"]),
    JSON.stringify(["logout", "--local-only"]),
    JSON.stringify(["account", "identities"]),
    JSON.stringify(["account", "revoke-session"]),
    JSON.stringify(["devices", "list"]),
  ]);
  if (fixed.has(rendered)) return arguments_;
  if (
    arguments_.length === 3 &&
    arguments_[0] === "account" &&
    arguments_[1] === "link" &&
    typeof arguments_[2] === "string" &&
    PROVIDER.test(arguments_[2])
  ) {
    return arguments_;
  }
  if (
    arguments_.length === 3 &&
    ((arguments_[0] === "account" && arguments_[1] === "unlink") ||
      (arguments_[0] === "devices" && arguments_[1] === "revoke")) &&
    typeof arguments_[2] === "string" &&
    UUID.test(arguments_[2])
  ) {
    return arguments_;
  }
  throw new TypeError("arguments are not a closed manager account command");
}

export const accountCommands = Object.freeze({
  status: (): ManagerAccountCommand => command("status", "--json"),
  login: (options: { device?: boolean } = {}): ManagerAccountCommand =>
    options.device === true ? command("login", "--device") : command("login"),
  logout: (
    options: { allDevices?: boolean; localOnly?: boolean } = {},
  ): ManagerAccountCommand => {
    if (options.allDevices === true && options.localOnly === true) {
      throw new TypeError("allDevices and localOnly are mutually exclusive");
    }
    if (options.allDevices === true) return command("logout", "--all-devices");
    if (options.localOnly === true) return command("logout", "--local-only");
    return command("logout");
  },
  link: (provider: string): ManagerAccountCommand => {
    if (!PROVIDER.test(provider)) throw new TypeError("provider must be a portable identifier");
    return command("account", "link", provider);
  },
  unlink: (externalIdentityId: string): ManagerAccountCommand =>
    command("account", "unlink", uuid(externalIdentityId, "externalIdentityId")),
  identities: (): ManagerAccountCommand => command("account", "identities"),
  revokeSession: (): ManagerAccountCommand => command("account", "revoke-session"),
  devices: (): ManagerAccountCommand => command("devices", "list"),
  revokeDevice: (deviceId: string): ManagerAccountCommand =>
    command("devices", "revoke", uuid(deviceId, "deviceId")),
});

export type AccountState = "signed_out" | "online" | "offline_stale" | "revoked";

export interface AccountStatus {
  readonly version: 1;
  readonly state: AccountState;
  readonly account_id: string | null;
  readonly device_id: string | null;
  readonly stale: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function parseAccountStatus(value: unknown): AccountStatus {
  if (
    !isRecord(value) ||
    JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(STATUS_KEYS) ||
    value.version !== 1 ||
    typeof value.stale !== "boolean" ||
    typeof value.state !== "string" ||
    !["signed_out", "online", "offline_stale", "revoked"].includes(value.state)
  ) {
    throw new ProtocolContractError("manager status differs from the closed v1 shape");
  }
  if ((value.account_id === null) !== (value.device_id === null)) {
    throw new ProtocolContractError("manager status has a partial account identity");
  }
  let accountId: string | null;
  let deviceId: string | null;
  if (value.account_id === null && value.device_id === null) {
    accountId = null;
    deviceId = null;
  } else if (typeof value.account_id === "string" && typeof value.device_id === "string") {
    try {
      accountId = uuid(value.account_id, "account_id");
      deviceId = uuid(value.device_id, "device_id");
    } catch (error) {
      throw new ProtocolContractError("manager status has an invalid account identity", {
        cause: error,
      });
    }
  } else {
    throw new ProtocolContractError("manager status has an invalid account identity");
  }
  const state = value.state as AccountState;
  if ((state === "signed_out" || state === "revoked") && (accountId !== null || value.stale)) {
    throw new ProtocolContractError("signed-out manager status retained account state");
  }
  if (state === "online" && (accountId === null || value.stale)) {
    throw new ProtocolContractError("online manager status is internally inconsistent");
  }
  if (state === "offline_stale" && (accountId === null || !value.stale)) {
    throw new ProtocolContractError("offline manager status is internally inconsistent");
  }
  return Object.freeze({
    version: 1,
    state,
    account_id: accountId,
    device_id: deviceId,
    stale: value.stale,
  });
}

export interface ManagerAccountClientOptions {
  readonly timeoutMs?: number;
  readonly accountEnvironment?: Readonly<Partial<Record<AccountEnvironmentKey, string>>>;
}

export class ManagerAccountClient {
  readonly manager: string;
  readonly timeoutMs: number;
  readonly environment: Readonly<Record<string, string>>;

  constructor(manager: string, options: ManagerAccountClientOptions = {}) {
    this.manager = resolveBinary(manager);
    this.timeoutMs = options.timeoutMs ?? 30_000;
    if (!(this.timeoutMs > 0)) throw new RangeError("timeoutMs must be positive");
    const source: Record<string, string> = {};
    if (options.accountEnvironment === undefined) {
      for (const key of ACCOUNT_ENVIRONMENT_KEYS) {
        const value = process.env[key];
        if (value !== undefined) source[key] = value;
      }
    } else {
      for (const [key, value] of Object.entries(options.accountEnvironment)) {
        if (!(ACCOUNT_ENVIRONMENT_KEYS as readonly string[]).includes(key)) {
          throw new TypeError(`unsupported account environment key ${JSON.stringify(key)}`);
        }
        if (value !== undefined) source[key] = value;
      }
    }
    for (const [key, value] of Object.entries(source)) {
      if (value.length === 0 || value.includes("\0")) {
        throw new TypeError(`${key} must be a non-empty string`);
      }
    }
    // The manager binary runs account commands only. None is in the engine's
    // gated command list and nothing in the manager reads KALEIDOSCOPE_API_KEY.
    const environment = ungatedEnvironment();
    // The same shellshock predicate `safeBootstrapEnvironment` applies, applied
    // to these merges too. Without it the six manager keys reached the child
    // past the guard that function's own comment says covers every value handed
    // to a child -- an allowlisted name carrying an exported function
    // definition. The SDK never execs a shell, so this was never exploitable
    // here; it was a hole in a stated invariant, which is the thing that goes
    // unnoticed until something downstream does exec one.
    for (const key of MANAGER_CONTEXT_KEYS) {
      const value = process.env[key];
      if (value !== undefined && !value.startsWith("()")) environment[key] = value;
    }
    for (const [key, value] of Object.entries(source)) {
      if (!value.startsWith("()")) environment[key] = value;
    }
    this.environment = Object.freeze(environment);
  }

  argv(accountCommand: ManagerAccountCommand): readonly string[] {
    return Object.freeze([this.manager, ...assertAccountCommand(accountCommand)]);
  }

  invoke(
    accountCommand: ManagerAccountCommand,
    options: { interactive?: boolean } = {},
  ): Record<string, unknown> {
    const arguments_ = assertAccountCommand(accountCommand);
    const completed = spawnSync(this.manager, arguments_, {
      encoding: "utf8",
      env: this.environment,
      maxBuffer: MAX_MANAGER_OUTPUT_BYTES,
      stdio: ["ignore", "pipe", options.interactive === true ? "inherit" : "pipe"],
      timeout: this.timeoutMs,
      windowsHide: true,
    });
    if (completed.error) {
      const code = (completed.error as NodeJS.ErrnoException).code;
      if (code === "ETIMEDOUT") {
        throw new DeadlineExceededError("manager account command timed out", {
          cause: completed.error,
        });
      }
      if (code === "ENOBUFS") {
        throw new OutputLimitError("manager account output exceeded 65536 bytes", {
          cause: completed.error,
        });
      }
      throw new ChildProcessError("manager account command could not start", {
        cause: completed.error,
      });
    }
    if (completed.status !== 0) {
      throw new ManagerCommandError(
        arguments_,
        completed.status ?? -1,
        boundedDiagnostic(completed.stderr),
      );
    }
    let value: unknown;
    try {
      value = JSON.parse(completed.stdout);
    } catch (error) {
      throw new ProtocolContractError("manager account command did not return one JSON value", {
        cause: error,
      });
    }
    if (!isRecord(value) || value.version !== 1) {
      throw new ProtocolContractError("manager account command did not return a v1 object");
    }
    return value;
  }

  status(): AccountStatus {
    return parseAccountStatus(this.invoke(accountCommands.status()));
  }

  login(options: { device?: boolean } = {}): Record<string, unknown> {
    return this.invoke(accountCommands.login(options), { interactive: true });
  }

  logout(options: { allDevices?: boolean; localOnly?: boolean } = {}): Record<string, unknown> {
    return this.invoke(accountCommands.logout(options));
  }

  link(provider: string): Record<string, unknown> {
    return this.invoke(accountCommands.link(provider), { interactive: true });
  }

  unlink(externalIdentityId: string): Record<string, unknown> {
    return this.invoke(accountCommands.unlink(externalIdentityId));
  }

  identities(): Record<string, unknown> {
    return this.invoke(accountCommands.identities());
  }

  /** Revoke only the current token family; this does not deactivate an account. */
  revokeSession(): Record<string, unknown> {
    return this.invoke(accountCommands.revokeSession());
  }

  devices(): Record<string, unknown> {
    return this.invoke(accountCommands.devices());
  }

  revokeDevice(deviceId: string): Record<string, unknown> {
    return this.invoke(accountCommands.revokeDevice(deviceId));
  }
}
