import { realpathSync } from "node:fs";

import { accountCommands, ManagerAccountClient } from "../typescript/src/index.js";

const ACCOUNT_ENVIRONMENT = {
  KALEIDOSCOPE_ACCOUNT_ORIGIN: "https://account.example.invalid/",
  KALEIDOSCOPE_ACCOUNT_ISSUER: "https://issuer.example.invalid/",
  KALEIDOSCOPE_ACCOUNT_AUDIENCE: "kaleidoscope-fixture",
  KALEIDOSCOPE_ACCOUNT_CLIENT_ID: "kaleidoscope-native-fixture",
};
const EXTERNAL_IDENTITY = "55555555-5555-4555-8555-555555555555";
const DEVICE_ID = "33333333-3333-4333-8333-333333333333";

function option(name: string): string {
  const index = process.argv.indexOf(name);
  const value = process.argv[index + 1];
  if (index < 0 || value === undefined) throw new Error(`missing ${name}`);
  return value;
}

const client = new ManagerAccountClient(realpathSync(option("--manager")), {
  accountEnvironment: ACCOUNT_ENVIRONMENT,
});
const commands = [
  accountCommands.status(),
  accountCommands.login(),
  accountCommands.login({ device: true }),
  accountCommands.logout(),
  accountCommands.logout({ allDevices: true }),
  accountCommands.logout({ localOnly: true }),
  accountCommands.link("github"),
  accountCommands.identities(),
  accountCommands.unlink(EXTERNAL_IDENTITY),
  accountCommands.revokeSession(),
  accountCommands.devices(),
  accountCommands.revokeDevice(DEVICE_ID),
];
const status = client.status();
const results = [
  client.login(),
  client.login({ device: true }),
  client.logout(),
  client.logout({ allDevices: true }),
  client.logout({ localOnly: true }),
  client.link("github"),
  client.identities(),
  client.unlink(EXTERNAL_IDENTITY),
  client.revokeSession(),
  client.devices(),
  client.revokeDevice(DEVICE_ID),
];
const forbidden = new Set(["--engine", "mcp", "call", "search", "remember"]);
console.log(
  JSON.stringify({
    status: status.state,
    stale: status.stale,
    account_identity_present: status.account_id !== null,
    command_count: commands.length,
    invocation_count: results.length + 1,
    engine_or_mcp_arguments_present: commands.some((item) =>
      item.arguments.some((value) => forbidden.has(value)),
    ),
  }),
);
