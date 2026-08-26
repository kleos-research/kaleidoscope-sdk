import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  accountCommands,
  ManagerAccountClient,
  ManagerCommandError,
} from "../src/index.js";
import { FAKE_MANAGER } from "./helpers.js";

const GOLDEN = JSON.parse(
  readFileSync(new URL("../../reference/manager-account-golden.json", import.meta.url), "utf8"),
) as {
  commands: Record<string, string[]>;
  signed_out: Record<string, unknown>;
};
const ACCOUNT_ENVIRONMENT = {
  KALEIDOSCOPE_ACCOUNT_ORIGIN: "https://account.example.invalid/",
  KALEIDOSCOPE_ACCOUNT_ISSUER: "https://issuer.example.invalid/",
  KALEIDOSCOPE_ACCOUNT_AUDIENCE: "kaleidoscope-fixture",
  KALEIDOSCOPE_ACCOUNT_CLIENT_ID: "kaleidoscope-native-fixture",
};
const EXTERNAL_IDENTITY = "55555555-5555-4555-8555-555555555555";
const DEVICE_ID = "33333333-3333-4333-8333-333333333333";

test("account command builders match the authoritative manager CLI", () => {
  const commands = {
    status: accountCommands.status().arguments,
    login_loopback: accountCommands.login().arguments,
    login_device: accountCommands.login({ device: true }).arguments,
    logout_current: accountCommands.logout().arguments,
    logout_all: accountCommands.logout({ allDevices: true }).arguments,
    logout_local: accountCommands.logout({ localOnly: true }).arguments,
    link_github: accountCommands.link("github").arguments,
    identities: accountCommands.identities().arguments,
    unlink: accountCommands.unlink(EXTERNAL_IDENTITY).arguments,
    revoke_session: accountCommands.revokeSession().arguments,
    devices: accountCommands.devices().arguments,
    revoke_device: accountCommands.revokeDevice(DEVICE_ID).arguments,
  };
  assert.deepEqual(commands, GOLDEN.commands);
  assert.throws(
    () => accountCommands.logout({ allDevices: true, localOnly: true }),
    /mutually exclusive/u,
  );
  assert.throws(() => accountCommands.link("not a provider"), /provider/u);
  assert.throws(() => accountCommands.revokeDevice("not-a-uuid"), /UUID/u);
  assert.throws(
    () =>
      new ManagerAccountClient(FAKE_MANAGER, {
        accountEnvironment: ACCOUNT_ENVIRONMENT,
      }).invoke({ arguments: ["call", "--profile", "default", "search"] }),
    /closed manager account command/u,
  );
});

test("signed-out status and account calls use only the manager", () => {
  const directory = mkdtempSync(join(tmpdir(), "kaleidoscope-manager-account-"));
  const sentinel = join(directory, "sentinel.bin");
  writeFileSync(sentinel, "unchanged-local-memory");
  const saved = {
    KSCOPE_ROOT: process.env.KSCOPE_ROOT,
    KSCOPE_WORKSPACE: process.env.KSCOPE_WORKSPACE,
    KSCOPE_PRINCIPAL: process.env.KSCOPE_PRINCIPAL,
    KSCOPE_JOURNAL: process.env.KSCOPE_JOURNAL,
    KALEIDOSCOPE_TOKEN: process.env.KALEIDOSCOPE_TOKEN,
  };
  Object.assign(process.env, {
    KSCOPE_ROOT: directory,
    KSCOPE_WORKSPACE: "wsp_should-not-cross-manager-boundary",
    KSCOPE_PRINCIPAL: "usr_should-not-cross-manager-boundary",
    KSCOPE_JOURNAL: "journal:should-not-cross-manager-boundary",
    KALEIDOSCOPE_TOKEN: "manager-token-should-not-be-inherited",
  });
  try {
    const client = new ManagerAccountClient(FAKE_MANAGER, {
      accountEnvironment: ACCOUNT_ENVIRONMENT,
    });
    assert.deepEqual(client.status(), GOLDEN.signed_out);
    assert.equal(client.login().status, "signed_in");
    assert.equal(client.login({ device: true }).status, "signed_in");
    assert.equal(client.logout().status, "already_signed_out");
    assert.equal(client.logout({ allDevices: true }).status, "already_signed_out");
    assert.equal(client.logout({ localOnly: true }).status, "already_signed_out");
    assert.equal(client.link("github").status, "fresh_auth_required");
    const identities = client.identities().external_identities as Array<Record<string, unknown>>;
    assert.equal(identities.at(0)?.external_identity_id, EXTERNAL_IDENTITY);
    assert.equal(client.unlink(EXTERNAL_IDENTITY).status, "unlinked");
    assert.equal(client.revokeSession().status, "already_signed_out");
    assert.deepEqual(client.devices().devices, []);
    assert.equal(client.revokeDevice(DEVICE_ID).device_id, DEVICE_ID);
    assert.equal(readFileSync(sentinel, "utf8"), "unchanged-local-memory");
    assert.deepEqual(readdirSync(directory), ["sentinel.bin"]);
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    rmSync(directory, { recursive: true, force: true });
  }
});

test("provider-not-configured diagnostics are redacted", () => {
  assert.throws(
    () => new ManagerAccountClient(FAKE_MANAGER, { accountEnvironment: {} }).status(),
    (error: unknown) => {
      assert.ok(error instanceof ManagerCommandError);
      assert.equal(error.returnCode, 2);
      assert.deepEqual(error.arguments, ["status", "--json"]);
      assert.match(error.message, /account provider is not configured/u);
      assert.match(error.message, /authorization=<redacted>/u);
      assert.doesNotMatch(error.message, /fixture-sensitive-value/u);
      return true;
    },
  );
});
