import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

import {
  loadLaunchDescriptor,
  loadProfile,
  PersistentKaleidoscopeSession,
  safeBootstrapEnvironment,
} from "../typescript/src/index.js";

const FORBIDDEN_CHILD_KEYS = [
  "ANTHROPIC_API_KEY",
  "AWS_SECRET_ACCESS_KEY",
  "KALEIDOSCOPE_TOKEN",
  "KSCOPE_JOURNAL",
  "KSCOPE_PRINCIPAL",
  "KSCOPE_PROFILE_HOME",
  "KSCOPE_ROOT",
  "KSCOPE_WORKSPACE",
  "OPENAI_API_KEY",
] as const;

interface Arguments {
  readonly engine: string;
  readonly expectedSha256: string;
  readonly profile: string;
}

function parseArguments(argv: string[]): Arguments {
  const take = (name: string): string => {
    const index = argv.indexOf(name);
    if (index < 0 || index + 1 >= argv.length) throw new Error(`${name} is required`);
    return argv[index + 1] as string;
  };
  return {
    engine: take("--engine"),
    expectedSha256: take("--expected-sha256"),
    profile: take("--profile"),
  };
}

function matchingPids(engine: string, profile: string): Set<number> {
  const output = execFileSync("ps", ["-axo", "pid=,ppid=,command="], {
    encoding: "utf8",
    timeout: 5_000,
  });
  const marker = `mcp --profile ${profile}`;
  const matches = new Set<number>();
  for (const raw of output.split("\n")) {
    const fields = raw.trim().split(/\s+/, 3);
    if (fields.length !== 3) continue;
    const firstSpace = raw.trim().indexOf(" ");
    const afterPid = raw.trim().slice(firstSpace).trimStart();
    const secondSpace = afterPid.indexOf(" ");
    const command = afterPid.slice(secondSpace).trimStart();
    if (command.includes(engine) && command.includes(marker)) {
      matches.add(Number(fields[0]));
    }
  }
  return matches;
}

async function waitForPids(engine: string, profile: string, expected: number): Promise<Set<number>> {
  const deadline = performance.now() + 5_000;
  let observed = new Set<number>();
  while (performance.now() < deadline) {
    observed = matchingPids(engine, profile);
    if (observed.size === expected) return observed;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(
    `expected ${expected} engine process(es) for the profile, observed ${observed.size}`,
  );
}

async function readInput(): Promise<{ memory_id: string }> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { memory_id?: unknown };
  assert.equal(typeof parsed.memory_id, "string");
  return { memory_id: parsed.memory_id as string };
}

async function main(): Promise<void> {
  const args = parseArguments(process.argv.slice(2));
  const input = await readInput();
  const safeEnvironment = safeBootstrapEnvironment();
  for (const key of FORBIDDEN_CHILD_KEYS) assert.equal(safeEnvironment[key], undefined);

  const descriptor = loadLaunchDescriptor(args.engine, args.profile, {
    expectedSha256: args.expectedSha256,
  });
  assert.equal(loadProfile(args.engine, args.profile).name, args.profile);

  const first = new PersistentKaleidoscopeSession(descriptor);
  await first.connect();
  const firstPids = await waitForPids(args.engine, args.profile, 1);
  try {
    const addressed = await first.searchText({ memory_id: input.memory_id });
    assert.ok(addressed.startsWith(`Memory | ${input.memory_id}\n`));
    const ranked = await first.searchText({
        query: "DX-10B TypeScript persistent MCP",
        top_k: 5,
        maximum_context_bytes: 8192,
        ledger: true,
      });
    assert.ok(ranked.includes(`# DX-10B persistent MCP probe`));
  } finally {
    await first.close();
  }
  await waitForPids(args.engine, args.profile, 0);

  const second = new PersistentKaleidoscopeSession(descriptor);
  await second.connect();
  const secondPids = await waitForPids(args.engine, args.profile, 1);
  assert.notDeepEqual(firstPids, secondPids);
  try {
    const addressed = await second.searchText({ memory_id: input.memory_id });
    assert.ok(addressed.startsWith(`Memory | ${input.memory_id}\n`));
  } finally {
    await second.close();
  }
  await waitForPids(args.engine, args.profile, 0);

  process.stdout.write(
    JSON.stringify({
      calls: 3,
      processes_distinct: true,
      restart_persisted: true,
      sessions: 2,
      teardown: true,
      tools: ["search", "remember"],
    }),
  );
}

await main();
