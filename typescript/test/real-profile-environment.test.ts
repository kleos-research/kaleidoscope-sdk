import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  loadLaunchDescriptor,
  loadProfile,
  mcpStdioConfig,
  PersistentKaleidoscopeSession,
  safeBootstrapEnvironment,
} from "../src/index.js";

const realBinary = process.env.KSCOPE_TEST_REAL_BINARY;
const realHome = process.env.KSCOPE_TEST_REAL_HOME;
const realProfile = process.env.KSCOPE_TEST_REAL_PROFILE ?? "dx07-live";
const reference = resolve(dirname(fileURLToPath(import.meta.url)), "../../reference");

test(
  "real profile resolves through HOME without inheriting canaries",
  { skip: !realBinary || !realHome },
  async () => {
    assert.ok(realBinary && realHome);
    const previous = {
      HOME: process.env.HOME,
      KSCOPE_PROFILE_HOME: process.env.KSCOPE_PROFILE_HOME,
      OPENAI_API_KEY: process.env.OPENAI_API_KEY,
      ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY,
      AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
      KALEIDOSCOPE_API_KEY: process.env.KALEIDOSCOPE_API_KEY,
      KALEIDOSCOPE_CONTROL_PLANE_ORIGIN: process.env.KALEIDOSCOPE_CONTROL_PLANE_ORIGIN,
      KSCOPE_ENTITLEMENT_HOME: process.env.KSCOPE_ENTITLEMENT_HOME,
      KSCOPE_ENTITLEMENT_PROBE: process.env.KSCOPE_ENTITLEMENT_PROBE,
    };
    const canary = "dx07-secret-" + "canary-value";
    try {
      process.env.HOME = realHome;
      process.env.KSCOPE_PROFILE_HOME = resolve(realHome, "wrong-profile-home");
      process.env.OPENAI_API_KEY = canary;
      process.env.ANTHROPIC_API_KEY = canary;
      process.env.AWS_SECRET_ACCESS_KEY = canary;
      process.env.KALEIDOSCOPE_API_KEY = "ksk_alpha." + "A".repeat(43);
      // Never read: the assertion below is that this name is STRIPPED, so any
      // string does. It is deliberately an unresolvable `.invalid` host -- a
      // real origin in a test fixture is infrastructure disclosure that buys
      // the test nothing.
      process.env.KALEIDOSCOPE_CONTROL_PLANE_ORIGIN = "https://control.example.invalid";
      process.env.KSCOPE_ENTITLEMENT_HOME = resolve(realHome, "entitlement");
      // Admitted by name would be a prefix rule's answer here. It is not.
      process.env.KSCOPE_ENTITLEMENT_PROBE = canary;

      const childEnvironment = safeBootstrapEnvironment();
      assert.equal(childEnvironment.HOME, realHome);
      // The two entitlement variables are expected PRESENT: without them the
      // engine's gate refuses every command this test then runs.
      for (const admitted of [
        "KALEIDOSCOPE_API_KEY",
        "KSCOPE_ENTITLEMENT_HOME",
      ]) {
        assert.notEqual(childEnvironment[admitted], undefined, `${admitted} was stripped`);
      }
      for (const forbidden of [
        "KSCOPE_PROFILE_HOME",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "KSCOPE_ENTITLEMENT_PROBE",
        // Moved here from the admitted list. Nothing consumes it: the engine
        // fixes its control-plane origin when it is built and constructs the
        // environment of anything it spawns, so an inherited value could not
        // redirect it. This test is skip-gated on a real binary, so the stale
        // assertion that it was ADMITTED would not have failed until somebody
        // enabled the test -- a false claim parked behind a skip.
        "KALEIDOSCOPE_CONTROL_PLANE_ORIGIN",
      ]) {
        assert.equal(childEnvironment[forbidden], undefined);
        assert.ok(!Object.values(childEnvironment).includes(canary));
      }

      const pin = JSON.parse(readFileSync(resolve(reference, "binary-pin.json"), "utf8")) as {
        sha256: string;
      };
      const descriptor = loadLaunchDescriptor(realBinary, realProfile, {
        expectedSha256: pin.sha256,
      });
      assert.deepEqual(descriptor.environment, {});
      assert.deepEqual(mcpStdioConfig(descriptor), {
        command: descriptor.command,
        args: [...descriptor.args],
      });
      assert.equal(loadProfile(realBinary, realProfile).name, realProfile);

      const session = new PersistentKaleidoscopeSession(descriptor);
      await session.connect();
      await session.close();
    } finally {
      for (const [key, value] of Object.entries(previous)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    }
  },
);
