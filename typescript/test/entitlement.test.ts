import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import test from "node:test";

import {
  boundedDiagnostic,
  BOOTSTRAP_ENVIRONMENT_KEYS,
  safeBootstrapEnvironment,
  ChildProcessError,
  classifyRefusal,
  ENTITLEMENT_ENVIRONMENT_KEYS,
  ENTITLEMENT_MESSAGES,
  EntitlementError,
  entitlementPreflight,
  gateStatus,
  keyIsPresent,
  loadLaunchDescriptor,
  loadProfile,
  MAX_DIAGNOSTIC_BYTES,
  API_KEY_SHAPE_PATTERN,
  ungatedEnvironment,
  validatedApiKey,
  PersistentKaleidoscopeSession,
  SAFE_ENVIRONMENT_KEYS,
  schema,
} from "../src/index.js";
import {
  BOGUS_KEY,
  callEngine,
  callEngineWithCodeKey,
  GOLDEN,
  HERE,
  MALFORMED_KEY,
  renderExpected,
  stageEngine,
  TEST_KEY,
  withEnvironment,
  writeKeyFile,
} from "./entitlementHelpers.js";

// ---------------------------------------------------------------- B1 / B2 / B3

test("B1 the entitlement key reaches the engine, and only when it is set", async () => {
  const engine = stageEngine("gated");
  const withKey = await withEnvironment({ KALEIDOSCOPE_API_KEY: TEST_KEY }, () =>
    callEngine(engine, "test", { expect_api_key: TEST_KEY }),
  );
  assert.equal(withKey.api_key_seen, true);
  assert.equal(withKey.api_key_matches, true);

  // The falsifier: with the variable unset the same fixture must report false,
  // so a fixture hardcoding `true` cannot pass the assertion above. A key file
  // keeps the preflight satisfied without putting the key in the environment.
  writeKeyFile(engine, TEST_KEY, 0o600);
  const withoutKey = await withEnvironment({ KALEIDOSCOPE_API_KEY: undefined }, () =>
    callEngine(engine, "test", { expect_api_key: TEST_KEY }),
  );
  assert.equal(withoutKey.api_key_seen, false);
  assert.equal(withoutKey.api_key_matches, false);
  assert.equal(withoutKey.key_file_seen, true);
});

test("B2 no other environment variable reaches the child", async () => {
  const engine = stageEngine("gated");
  const canary = "must-not-reach-child";
  const forbidden = [
    "KALEIDOSCOPE_TEST_SECRET",
    "AZURE_OPENAI_API_KEY",
    "SUPABASE_SECRET_KEY",
    "OPENAI_API_KEY",
    "KSCOPE_PROFILE_HOME",
    "KALEIDOSCOPE_TOKEN",
    // The sharp one: a KSCOPE_* entitlement-family name that is deliberately
    // not admitted. A prefix-based widening passes every other assertion here
    // and fails on this one.
    "KSCOPE_ENTITLEMENT_PROBE",
  ];
  const overrides: Record<string, string | undefined> = { KALEIDOSCOPE_API_KEY: TEST_KEY };
  for (const key of forbidden) overrides[key] = canary;

  const result = await withEnvironment(overrides, () => callEngine(engine, "test"));
  const names = result.environment_names as string[];
  assert.ok(names.length > 0, "the fixture must actually report the names it received");
  for (const key of forbidden) assert.ok(!names.includes(key), `${key} reached the child`);
  // Not satisfiable by a leak of any name at all, named or not. The one
  // exception is self-injected rather than inherited: on macOS CoreFoundation
  // writes __CF_USER_TEXT_ENCODING into every CF-linked process's own
  // environment, and `env -i node -p Object.keys(process.env)` prints it with
  // nothing else -- so it is a property of the fixture being a node process,
  // not of the boundary under test.
  const selfInjected = new Set(["__CF_USER_TEXT_ENCODING"]);
  const admitted = new Set<string>(SAFE_ENVIRONMENT_KEYS);
  for (const name of names) {
    if (selfInjected.has(name)) continue;
    assert.ok(admitted.has(name), `unadmitted ${name} reached the child`);
  }
  assert.ok(names.includes("KALEIDOSCOPE_API_KEY"), "the key itself must be admitted");
  // And no forbidden VALUE reached the child under any name at all, which no
  // rename or aliasing can satisfy.
  const values = result.environment_values as string[];
  assert.ok(!values.includes(canary), "a forbidden value reached the child");
});

test("B3 the allowlist matches the shared golden", () => {
  assert.deepEqual([...BOOTSTRAP_ENVIRONMENT_KEYS], GOLDEN.bootstrap_environment);
  assert.deepEqual([...ENTITLEMENT_ENVIRONMENT_KEYS], GOLDEN.entitlement_environment);
  assert.deepEqual(
    [...SAFE_ENVIRONMENT_KEYS],
    [...GOLDEN.bootstrap_environment, ...GOLDEN.entitlement_environment],
  );
  const admitted = new Set<string>(SAFE_ENVIRONMENT_KEYS);
  for (const never of GOLDEN.never_admitted) {
    assert.ok(!admitted.has(never), `${never} must never be admitted`);
  }
  // Eighteen bootstrap names plus TWO entitlement names. It was 21 until an
  // audit asked what actually consumes KALEIDOSCOPE_CONTROL_PLANE_ORIGIN and
  // the answer was nothing: the engine fixes its control-plane origin when it
  // is built and constructs the environment of anything it spawns, so an
  // inherited value could not redirect it. Forwarding the name was inert and
  // implied a capability that does not exist. It is now in the golden's
  // `never_admitted` list, so the loop above states its exclusion positively
  // rather than leaving it to this count.
  assert.equal(SAFE_ENVIRONMENT_KEYS.length, 20);
  assert.ok(GOLDEN.never_admitted.includes("KALEIDOSCOPE_CONTROL_PLANE_ORIGIN"));
});

// --------------------------------------------------------------------- B4 / B5

test("B4 every refusal surfaces as the typed error with the exact message", async (context) => {
  for (const identifier of GOLDEN.refusal_identifiers) {
    await context.test(`${identifier} on the native path`, async () => {
      const engine = stageEngine("gated");
      const error = await withEnvironment({ KALEIDOSCOPE_API_KEY: TEST_KEY }, async () => {
        try {
          await callEngine(engine, `refuse.${identifier}`);
        } catch (caught) {
          return caught;
        }
        return undefined;
      });
      assert.ok(error instanceof EntitlementError, `${identifier} did not raise EntitlementError`);
      assert.equal(error.code, "entitlement");
      assert.equal(error.reason, identifier);
      assert.equal(error.keyFile, engine.keyFile);
      assert.equal(error.message, renderExpected(identifier, engine.keyFile));
      assert.ok(error.diagnostic.length > 0, "the engine diagnostic must be attached");
      assert.ok(Buffer.byteLength(error.diagnostic, "utf8") <= MAX_DIAGNOSTIC_BYTES + 64);
      // Evidence, never instruction: the engine's own instructional line is
      // redacted, which is exactly why the SDK carries its own message.
      assert.ok(error.diagnostic.includes("KALEIDOSCOPE_API_KEY=<redacted>"));
    });

    await context.test(`${identifier} on the MCP path`, async () => {
      const engine = stageEngine("gated");
      const error = await withEnvironment({ KALEIDOSCOPE_API_KEY: TEST_KEY }, async () => {
        const descriptor = loadLaunchDescriptor(engine.command, `refuse.${identifier}`);
        try {
          await new PersistentKaleidoscopeSession(descriptor, { timeoutMs: 5_000 }).connect();
        } catch (caught) {
          return caught;
        }
        return undefined;
      });
      assert.ok(error instanceof EntitlementError, `${identifier} did not raise EntitlementError`);
      assert.equal(error.reason, identifier);
      assert.equal(error.message, renderExpected(identifier, engine.keyFile));
      assert.ok(error.diagnostic.length > 0);
    });
  }
});

test("B5 a non-entitlement failure is unchanged", async (context) => {
  await context.test("native path", async () => {
    const engine = stageEngine("gated");
    const error = await withEnvironment({ KALEIDOSCOPE_API_KEY: TEST_KEY }, async () => {
      try {
        await callEngine(engine, "plainfail");
      } catch (caught) {
        return caught;
      }
      return undefined;
    });
    assert.ok(!(error instanceof EntitlementError), "a plain refusal must not be an entitlement one");
    assert.ok(error instanceof ChildProcessError);
  });

  await context.test("MCP path", async () => {
    const engine = stageEngine("gated");
    const error = await withEnvironment({ KALEIDOSCOPE_API_KEY: TEST_KEY }, async () => {
      const descriptor = loadLaunchDescriptor(engine.command, "plainfail");
      try {
        await new PersistentKaleidoscopeSession(descriptor, { timeoutMs: 5_000 }).connect();
      } catch (caught) {
        return caught;
      }
      return undefined;
    });
    assert.ok(error instanceof Error);
    assert.ok(!(error instanceof EntitlementError));
  });
});

// --------------------------------------------------------------------------- B6

test("B6 the SDK performs no local validation", async (context) => {
  await context.test("a well-formed but bogus key still reaches the engine", async () => {
    const engine = stageEngine("gated");
    const error = await withEnvironment({ KALEIDOSCOPE_API_KEY: BOGUS_KEY }, async () => {
      try {
        await callEngine(engine, "refuse.E_UNVERIFIED");
      } catch (caught) {
        return caught;
      }
      return undefined;
    });
    // The marker is what distinguishes "refused there" from "refused here".
    assert.ok(existsSync(engine.invocationLog), "the engine child never ran");
    assert.ok(error instanceof EntitlementError);
    assert.equal(error.reason, "E_UNVERIFIED");
    assert.notEqual(error.reason, "E_NO_KEY");
    assert.notEqual(error.reason, "E_MALFORMED_KEY");
  });

  await context.test("a malformed key is judged by the engine, not the SDK", async () => {
    const engine = stageEngine("gated");
    const error = await withEnvironment({ KALEIDOSCOPE_API_KEY: MALFORMED_KEY }, async () => {
      try {
        await callEngine(engine, "refuse.E_MALFORMED_KEY");
      } catch (caught) {
        return caught;
      }
      return undefined;
    });
    assert.ok(existsSync(engine.invocationLog), "the SDK decided the key's shape itself");
    assert.ok(error instanceof EntitlementError);
    assert.equal(error.reason, "E_MALFORMED_KEY");
  });

  await context.test("keyIsPresent never opens, parses or judges the key", async () => {
    const engine = stageEngine("gated");
    const status = gateStatus(engine.command);
    assert.equal(status.enforcing, true);
    // A garbage key file of non-zero size is PRESENT. Validity is not the
    // SDK's to decide; the engine refuses it with E_KEY_FILE_UNUSABLE.
    writeKeyFile(engine, "not-a-key-at-all", 0o644);
    await withEnvironment({ KALEIDOSCOPE_API_KEY: undefined }, () => {
      assert.equal(keyIsPresent(status), true);
    });
  });
});

// --------------------------------------------------------------------------- B7

test("B7 the key file route works with no key in the environment", async (context) => {
  await context.test("a 0600 key file is enough to reach the engine", async () => {
    const engine = stageEngine("gated");
    writeKeyFile(engine, TEST_KEY, 0o600);
    const result = await withEnvironment({ KALEIDOSCOPE_API_KEY: undefined }, () =>
      callEngine(engine, "test"),
    );
    // A real envelope, not "no exception was raised".
    assert.equal(result.status, "accepted");
    assert.equal(result.operation, "search");
    assert.equal(result.key_file_seen, true);
    assert.equal(result.api_key_seen, false);
  });

  await context.test("a 0644 key file is refused by the ENGINE, not renamed E_NO_KEY", async () => {
    const engine = stageEngine("gated");
    writeKeyFile(engine, TEST_KEY, 0o644);
    const error = await withEnvironment({ KALEIDOSCOPE_API_KEY: undefined }, async () => {
      try {
        await callEngine(engine, "refuse.E_KEY_FILE_UNUSABLE");
      } catch (caught) {
        return caught;
      }
      return undefined;
    });
    assert.ok(error instanceof EntitlementError);
    assert.equal(error.reason, "E_KEY_FILE_UNUSABLE");
    assert.notEqual(error.reason, "E_NO_KEY");
    assert.equal(error.message, renderExpected("E_KEY_FILE_UNUSABLE", engine.keyFile));
  });

  await context.test("the ungated spawn sites still work with nothing configured", async () => {
    const engine = stageEngine("gated");
    await withEnvironment({ KALEIDOSCOPE_API_KEY: undefined }, () => {
      // profile launch, profile show and schema are on the engine's permanent
      // never-gate list. A preflight on them would break keyless descriptor
      // loading, which the engine deliberately permits.
      const descriptor = loadLaunchDescriptor(engine.command, "test");
      assert.equal(descriptor.args[2], "test");
      assert.equal(loadProfile(engine.command, "test").name, "test");
      assert.ok(schema(engine.command).length >= 0);
    });
  });
});

// --------------------------------------------------------------------------- B8

test("B8 the preflight fires, and fails open", async (context) => {
  await context.test("gated with nothing configured: refuse without spawning", async () => {
    const engine = stageEngine("gated");
    const error = await withEnvironment({ KALEIDOSCOPE_API_KEY: undefined }, async () => {
      try {
        await callEngine(engine, "test");
      } catch (caught) {
        return caught;
      }
      return undefined;
    });
    assert.ok(error instanceof EntitlementError);
    assert.equal(error.reason, "E_NO_KEY");
    assert.equal(error.message, renderExpected("E_NO_KEY", engine.keyFile));
    assert.ok(!existsSync(engine.invocationLog), "the gated command was spawned anyway");
  });

  await context.test("an ungated engine is never blocked", async () => {
    const engine = stageEngine("ungated");
    const status = gateStatus(engine.command);
    assert.equal(status.enforcing, false);
    const result = await withEnvironment({ KALEIDOSCOPE_API_KEY: undefined }, () =>
      callEngine(engine, "test"),
    );
    assert.equal(result.status, "accepted");
  });

  await context.test("an engine that cannot answer `gate` is never blocked", async () => {
    const engine = stageEngine("gatebroken");
    assert.equal(gateStatus(engine.command).enforcing, false);
    const result = await withEnvironment({ KALEIDOSCOPE_API_KEY: undefined }, () =>
      callEngine(engine, "test"),
    );
    assert.equal(result.status, "accepted");
  });

  await context.test("a gate report with no key_file still refuses, with the placeholder", async () => {
    const engine = stageEngine("gated-nokeyfile");
    const status = gateStatus(engine.command);
    assert.equal(status.enforcing, true);
    assert.equal(status.keyFile, undefined);
    await withEnvironment({ KALEIDOSCOPE_API_KEY: undefined }, () => {
      assert.throws(
        () => entitlementPreflight(engine.command),
        (error: unknown) =>
          error instanceof EntitlementError &&
          error.reason === "E_NO_KEY" &&
          error.message === renderExpected("E_NO_KEY", undefined) &&
          error.message.includes(GOLDEN.missing_key_file_placeholder),
      );
    });
  });
});

// --------------------------------------------------------------------------- B9

test("B9 boundedDiagnostic truncates BYTES, exactly as Python does", () => {
  const cases = JSON.parse(
    readFileSync(resolve(HERE, "fixtures/bounded-diagnostic-cases.json"), "utf8"),
  ) as { max_diagnostic_bytes: number; cases: { name: string; input_base64: string; expected: string }[] };
  assert.equal(cases.max_diagnostic_bytes, MAX_DIAGNOSTIC_BYTES);
  assert.ok(cases.cases.length >= 5);
  for (const item of cases.cases) {
    const input = Buffer.from(item.input_base64, "base64");
    assert.equal(boundedDiagnostic(input), item.expected, `case ${JSON.stringify(item.name)}`);
  }
});

test("B9 the marker survives redaction and truncation", () => {
  const flood = Buffer.from(`${"api_key: hunter2\n".repeat(512)}kscope-entitlement-refusal: E_REVOKED\n`, "utf8");
  assert.ok(flood.length > MAX_DIAGNOSTIC_BYTES, "the flood must exceed the bound");
  // Classification runs on the RAW bytes, never on the redacted text.
  assert.equal(classifyRefusal(flood, null), "E_REVOKED");
  const diagnostic = boundedDiagnostic(flood);
  assert.ok(diagnostic.includes("kscope-entitlement-refusal: E_REVOKED"));
  // The masking pattern needs one of five words immediately before the
  // separator, and `refusal` is not one of them. Proved, not assumed.
  assert.ok(!diagnostic.includes("refusal=<redacted>"));
  assert.ok(diagnostic.includes("api_key=<redacted>"), "the redaction must still fire");
});

test("B9 classification is marker-driven, never prose-driven", () => {
  const prose = Buffer.from(
    "kscope: this build requires an alpha entitlement and KALEIDOSCOPE_API_KEY is not set.\n",
    "utf8",
  );
  // Real engine prose, no marker, no exit 4: not an entitlement refusal as far
  // as the SDK is concerned. Matching prose is what drifts silently.
  assert.equal(classifyRefusal(prose, 2), null);
  // Exit 4 with no recognisable marker is still an entitlement refusal, from an
  // engine newer than this SDK. Never a crash, never silence.
  assert.equal(classifyRefusal(prose, 4), "E_UNKNOWN");
  // An identifier this SDK does not know maps to E_UNKNOWN, not to null.
  assert.equal(
    classifyRefusal(Buffer.from("kscope-entitlement-refusal: E_FROM_THE_FUTURE\n"), 4),
    "E_UNKNOWN",
  );
  // The LAST marker wins.
  assert.equal(
    classifyRefusal(
      Buffer.from(
        "kscope-entitlement-refusal: E_NO_KEY\nkscope-entitlement-refusal: E_REVOKED\n",
      ),
      4,
    ),
    "E_REVOKED",
  );
  assert.equal(classifyRefusal(Buffer.alloc(0), 0), null);
  // The pattern in source and the pattern in the golden are the same pattern.
  assert.equal(
    GOLDEN.refusal_marker_pattern,
    "^kscope-entitlement-refusal: ([A-Z][A-Z0-9_]{2,39})$",
  );
});

// -------------------------------------------------------------------------- B10

test("B10 the messages match the shared golden", () => {
  const expectedKeys = [...GOLDEN.refusal_identifiers, ...GOLDEN.sdk_only_identifiers].sort();
  assert.deepEqual(Object.keys(ENTITLEMENT_MESSAGES).sort(), expectedKeys);
  for (const [identifier, template] of Object.entries(ENTITLEMENT_MESSAGES)) {
    assert.equal(template, GOLDEN.messages[identifier], `message ${identifier} drifted`);
    assert.ok(
      template.endsWith("Your local vault data is intact and unchanged."),
      `${identifier} does not end with the intact sentence`,
    );
    assert.ok(!template.endsWith("\n"), `${identifier} has a trailing newline`);
  }
  const withPlaceholder = Object.entries(ENTITLEMENT_MESSAGES)
    .filter(([, template]) => template.includes("{key_file}"))
    .map(([identifier]) => identifier)
    .sort();
  // Five, since the code route was added. It used to be two: the three
  // replacement templates said "or the key file" in prose and named no path,
  // so a user told to write a replacement to a file was not told which file.
  assert.deepEqual(withPlaceholder, [
    "E_KEY_EXPIRED",
    "E_KEY_FILE_UNUSABLE",
    "E_NO_KEY",
    "E_REVOKED",
    "E_UNKNOWN_KEY",
  ]);
});

// -------------------------------------------------------------------------- B12

test("B12 the native path does not retry an entitlement refusal", async () => {
  const engine = stageEngine("gated");
  const counter = join(engine.home, "attempts");
  const error = await withEnvironment({ KALEIDOSCOPE_API_KEY: TEST_KEY }, async () => {
    try {
      await callEngine(engine, "refuse.E_REVOKED", { marker: counter });
    } catch (caught) {
      return caught;
    }
    return undefined;
  });
  assert.ok(error instanceof EntitlementError);
  assert.equal(readFileSync(counter, "utf8"), "1", "the deterministic refusal was retried");

  // The control: the same Controller, with attempts=2, does retry a crash. A
  // counter that could never read 2 would prove nothing about the 1 above.
  const control = stageEngine("gated");
  const controlCounter = join(control.home, "attempts");
  const result = await withEnvironment({ KALEIDOSCOPE_API_KEY: TEST_KEY }, () =>
    callEngine(control, "crashonce", { marker: controlCounter }),
  );
  assert.equal(result.invocation, 2);
  assert.equal(readFileSync(controlCounter, "utf8"), "2");
});

// --------------------------------------------------------------------- B17
// Presence and the spawn agree about the API key.
//
// `safeBootstrapEnvironment` drops values beginning with `()`, so such a key
// never reaches the child. `keyIsPresent` read `process.env` directly and said
// "set" anyway: the SDK spawned, the engine saw no key at all, and told the
// user to set a variable they HAD set. The two now read the same source, so the
// disagreement is unrepresentable rather than merely fixed.
//
// This is emphatically NOT the SDK judging the key. It judges nothing about the
// value; it asks only "will the child receive this", which is a fact about the
// SDK's own allowlist, not about the credential.

test("B17 presence agrees with the spawn on a shellshock-shaped key", () => {
  const engine = stageEngine("gated");
  withEnvironment(
    {
      KALEIDOSCOPE_API_KEY: "() { :; }; echo shellshock",
      KSCOPE_ENTITLEMENT_HOME: engine.entitlementHome,
    },
    () => {
      const status = gateStatus(engine.command);
      assert.equal(status.enforcing, true);
      assert.equal(safeBootstrapEnvironment().KALEIDOSCOPE_API_KEY, undefined);
      assert.equal(keyIsPresent(status), false, "presence said set for a value the spawn drops");
      assert.throws(
        () => entitlementPreflight(engine.command),
        (error: unknown) => error instanceof EntitlementError && error.reason === "E_NO_KEY",
      );
    },
  );
});

test("B17 a normal key is still present", () => {
  // The falsifier: presence must not have become false for everything.
  const engine = stageEngine("gated");
  withEnvironment(
    { KALEIDOSCOPE_API_KEY: TEST_KEY, KSCOPE_ENTITLEMENT_HOME: engine.entitlementHome },
    () => {
      const status = gateStatus(engine.command);
      assert.equal(keyIsPresent(status), true);
      entitlementPreflight(engine.command); // must not throw
    },
  );
});

// ------------------------------------------------------- the programmatic key

test("a code key reaches the engine with the environment cleared", async () => {
  const engine = stageEngine("codekey");

  const report = await withEnvironment({ KALEIDOSCOPE_API_KEY: undefined }, () =>
    callEngineWithCodeKey(engine, "test", TEST_KEY, { expect_api_key: TEST_KEY }),
  );

  // Both halves together. A build that delivered nothing fails the first; a
  // build that delivered it by widening the door fails the second.
  assert.equal(report.api_key_matches, true);
  const names = new Set(report.environment_names as string[]);
  for (const decoy of GOLDEN.never_admitted) assert.equal(names.has(decoy), false, decoy);
});

test("a code key beats an ambient one, and the environment still works", async () => {
  const engine = stageEngine("codekey-precedence");

  // Direction one: code wins over a DIFFERENT ambient value.
  const coded = await withEnvironment({ KALEIDOSCOPE_API_KEY: BOGUS_KEY }, () =>
    callEngineWithCodeKey(engine, "test", TEST_KEY, { expect_api_key: TEST_KEY }),
  );
  assert.equal(coded.api_key_matches, true);

  // Direction two: with no code key the ambient one is still used. A build that
  // always preferred the code key -- including when it is absent -- passes the
  // first assertion and fails this one.
  const ambient = await withEnvironment({ KALEIDOSCOPE_API_KEY: TEST_KEY }, () =>
    callEngine(engine, "test", { expect_api_key: TEST_KEY }),
  );
  assert.equal(ambient.api_key_matches, true);
});

test("no code key reproduces today's environment exactly", () => {
  const before = safeBootstrapEnvironment();
  const after = safeBootstrapEnvironment({});
  assert.deepEqual(before, after);
  assert.equal(SAFE_ENVIRONMENT_KEYS.length, 20);
});

test("the ungated environment is a strict subset", async () => {
  await withEnvironment({ KALEIDOSCOPE_API_KEY: TEST_KEY }, () => {
    const full = new Set(Object.keys(safeBootstrapEnvironment()));
    const ungated = new Set(Object.keys(ungatedEnvironment()));
    assert.equal(ungated.has("KALEIDOSCOPE_API_KEY"), false);
    assert.equal(full.has("KALEIDOSCOPE_API_KEY"), true);
    for (const name of ungated) assert.equal(full.has(name), true, name);
    assert.equal(ungated.size, full.size - 1);
  });
});

test("an empty code key is a usage error, never a silent fallback", async () => {
  const engine = stageEngine("codekey-empty");
  await withEnvironment({ KALEIDOSCOPE_API_KEY: TEST_KEY }, () => {
    for (const empty of ["", "   ", "\t"]) {
      assert.throws(() => validatedApiKey(empty), /empty/u);
    }
    // The falsifier: a real key is still accepted, so the guard is not
    // refusing everything.
    assert.equal(validatedApiKey(TEST_KEY), TEST_KEY);
    // ...and the SDK still makes NO validity judgement.
    assert.equal(validatedApiKey(MALFORMED_KEY), MALFORMED_KEY);
    assert.equal(engine.command.length > 0, true);
  });
});

test("the key shape is redacted in five stderr forms", () => {
  const forms: Record<string, string> = {
    environment: `KALEIDOSCOPE_API_KEY=${TEST_KEY}\n`,
    named: `token=${TEST_KEY}\n`,
    prose: `kscope: refused key ${TEST_KEY} is unknown\n`,
    json: JSON.stringify({ api_key: TEST_KEY }),
    commandLine: `failed: kscope call --api-key ${TEST_KEY}\n`,
  };
  for (const [label, text] of Object.entries(forms)) {
    const diagnostic = boundedDiagnostic(text);
    assert.equal(diagnostic.includes(TEST_KEY), false, label);
    assert.equal(diagnostic.includes("A".repeat(20)), false, label);
    assert.equal(diagnostic.includes("<redacted>"), true, label);
  }

  // A key sliced in half by the byte bound is still masked; a `{43}` rule would
  // pass every case above and fail this one.
  const truncated = boundedDiagnostic("x".repeat(4090) + TEST_KEY + " trailing");
  assert.equal(truncated.includes("A".repeat(12)), false);
  assert.equal(truncated.includes("trailing"), true);

  // Redaction is not validation: nothing branches on whether it matched.
  assert.equal(
    boundedDiagnostic("kscope: the vault root is not a Kaleidoscope vault"),
    "kscope: the vault root is not a Kaleidoscope vault",
  );
});

test("the shared contract pins the redaction pattern both SDKs use", () => {
  const declared = (GOLDEN as unknown as { redaction_patterns: string[] }).redaction_patterns;
  assert.deepEqual(declared, [API_KEY_SHAPE_PATTERN]);
});

test("the amended message templates name the code route in both languages", () => {
  for (const [identifier, template] of Object.entries(ENTITLEMENT_MESSAGES)) {
    assert.equal(template, GOLDEN.messages[identifier], identifier);
    if (template.includes("KALEIDOSCOPE_API_KEY")) {
      assert.equal(template.includes("api_key="), true, identifier);
      assert.equal(template.includes("{key_file}"), true, identifier);
    }
  }
});
