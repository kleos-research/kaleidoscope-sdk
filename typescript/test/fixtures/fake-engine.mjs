#!/usr/bin/env node
// Test-only process fixture standing in for a gated `kscope`. It is not a
// memory implementation, a shim, or anything a user ever runs.
//
// EVERYTHING it does is decided by argv and by its own filename, never by an
// environment variable it was handed -- because the whole point of the SDK
// boundary under test is that the child receives almost no environment, so a
// control variable could not reach it. Tests copy this file to a temporary
// directory under a name that encodes the configuration:
//
//   kscope-gated          `gate` answers status "enforcing"
//   kscope-ungated        `gate` answers status "absent" (no gate compiled in)
//   kscope-gatebroken     `gate` exits 2, as an engine older than the command
//   ...-nokeyfile         `gate` answers enforcing with a null key_file
//
// and encode per-invocation behaviour in the profile name, which is the only
// caller-controlled string that reaches a gated command's argv:
//
//   refuse.<IDENTIFIER>   refuse with the engine's prose plus the marker tail
//                         line, nothing on stdout, exit 4
//   plainfail             refuse WITHOUT a marker line, exit 2 (the control)
//
// Everything else runs and reports what it saw.

import { appendFileSync, existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, basename } from "node:path";
import { realpathSync } from "node:fs";

const self = realpathSync(process.argv[1]);
const home = dirname(self);
const name = basename(self);
const entitlementHome = join(home, "entitlement");
const keyFile = join(entitlementHome, "api-key");
const invocationLog = join(home, "invocations.log");

const argv = process.argv.slice(2);

function record(what) {
  appendFileSync(invocationLog, `${what}\n`, "utf8");
}

function environmentNames() {
  return Object.keys(process.env).sort();
}

function gate() {
  if (name.includes("gatebroken")) {
    process.stderr.write("kscope: unrecognised command 'gate'\n");
    process.exit(2);
  }
  const enforcing = !name.includes("ungated");
  const suppressKeyFile = name.includes("nokeyfile");
  const report = enforcing
    ? {
        status: "enforcing",
        entitlement_build: true,
        gated_commands: ["mcp", "context", "call", "serve"],
        entitlement_home: suppressKeyFile ? null : entitlementHome,
        key_file: suppressKeyFile ? null : keyFile,
        build_features: "bundled-model,entitlement",
        marker: "kaleidoscope.alpha-entitlement-gate.v1:present",
      }
    : {
        status: "absent",
        entitlement_build: false,
        gated_commands: [],
        entitlement_home: null,
        key_file: null,
        build_features: "bundled-model",
        marker: "kaleidoscope.alpha-entitlement-gate.v1:absent",
      };
  process.stdout.write(`${JSON.stringify(report)}\n`);
  process.exit(0);
}

// The engine's own prose, in the engine's register, deliberately including the
// instructional `KALEIDOSCOPE_API_KEY=ksk_alpha....` line the SDK's redaction
// destroys -- that destruction is why the SDK carries its own message.
function refuse(identifier) {
  process.stderr.write(
    `kscope: this build requires an alpha entitlement and refused (${identifier}).\n` +
      "Ask the alpha owner for a key, then export it:\n" +
      "KALEIDOSCOPE_API_KEY=ksk_alpha....\n" +
      "Your local vault data is intact and unchanged.\n" +
      `kscope-entitlement-refusal: ${identifier}\n`,
  );
  process.exit(4);
}

function plainFailure() {
  process.stderr.write(
    "kscope: refused, nothing applied: --profile names no configured profile\n",
  );
  process.exit(2);
}

function keyFileSeen() {
  try {
    return statSync(keyFile).isFile();
  } catch {
    return false;
  }
}

function profileLaunch(profile) {
  process.stdout.write(
    `${JSON.stringify({
      version: 1,
      transport: "stdio",
      command: self,
      args: ["mcp", "--profile", profile],
      tools: ["search", "remember"],
      environment: {},
    })}\n`,
  );
}

function profileShow(profile) {
  process.stdout.write(
    `${JSON.stringify({
      version: 1,
      name: profile,
      root: "/tmp/fake-kaleidoscope-vault",
      workspace_id: "wsp_fixture",
      principal_id: "usr_fixture",
      journal: "journal:fixture",
      durability: "process-local",
    })}\n`,
  );
}

function dispatchGatedProfile(profile, kind) {
  record(`${kind} ${profile}`);
  if (profile.startsWith("refuse.")) refuse(profile.slice("refuse.".length));
  if (profile === "plainfail") plainFailure();
}

function nativeCall(profile, operation) {
  const raw = readFileSync(0);
  let payload = {};
  try {
    payload = JSON.parse(raw.toString("utf8"));
  } catch {
    process.stderr.write("kscope: invalid fixture JSON\n");
    process.exit(2);
  }
  const counter = typeof payload.marker === "string" ? payload.marker : undefined;
  let invocation = 1;
  if (counter !== undefined) {
    if (existsSync(counter)) invocation = Number(readFileSync(counter, "utf8")) + 1;
    writeFileSync(counter, String(invocation), "utf8");
  }
  dispatchGatedProfile(profile, "call");
  if (profile === "crashonce" && invocation === 1) process.exit(19);

  const apiKey = process.env.KALEIDOSCOPE_API_KEY;
  process.stdout.write(
    `${JSON.stringify({
      status: "accepted",
      operation,
      invocation,
      pid: process.pid,
      // Never the value: a boolean comparison keeps the fixture free of any
      // key-shaped literal in its output.
      api_key_seen: apiKey !== undefined && apiKey.length > 0,
      api_key_matches:
        typeof payload.expect_api_key === "string" && apiKey === payload.expect_api_key,
      key_file_seen: keyFileSeen(),
      environment_names: environmentNames(),
      // Values are reported so a test can prove no forbidden VALUE arrived
      // under a renamed key. The API key's own value is excluded, because a
      // fixture that echoed a credential would be the wrong lesson.
      environment_values: Object.entries(process.env)
        .filter(([key]) => key !== "KALEIDOSCOPE_API_KEY")
        .map(([, value]) => value),
    })}\n`,
  );
}

function mcp(profile) {
  dispatchGatedProfile(profile, "mcp");
  // No non-refusing MCP mode: a real MCP conversation is exercised against the
  // shared Python fixture, which both SDKs already drive.
  process.stderr.write("kscope: fixture MCP mode only models refusal\n");
  process.exit(2);
}

if (argv.length === 1 && argv[0] === "gate") {
  gate();
} else if (argv.length === 3 && argv[0] === "profile" && argv[1] === "launch") {
  profileLaunch(argv[2]);
} else if (argv.length === 3 && argv[0] === "profile" && argv[1] === "show") {
  profileShow(argv[2]);
} else if ((argv.length === 1 || argv.length === 2) && argv[0] === "schema") {
  process.stdout.write(`fixture schema ${argv[1] ?? "all"}\n`);
} else if (argv.length === 4 && argv[0] === "call" && argv[1] === "--profile") {
  nativeCall(argv[2], argv[3]);
} else if (argv.length === 3 && argv[0] === "mcp" && argv[1] === "--profile") {
  mcp(argv[2]);
} else {
  process.stderr.write(`kscope: unsupported fixture invocation ${JSON.stringify(argv)}\n`);
  process.exit(2);
}
