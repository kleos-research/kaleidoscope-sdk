#!/usr/bin/env node
import { spawnSync } from "node:child_process";

import { installedEnginePath } from "../dist/src/distribution.js";

function fail(message, code) {
  process.stderr.write(`kscope: ${message}\n`);
  process.exit(code);
}

let engine;
try {
  engine = installedEnginePath();
} catch (error) {
  fail(error instanceof Error ? error.message : String(error), 127);
}

const completed = spawnSync(engine, process.argv.slice(2), {
  stdio: "inherit",
  windowsHide: true,
});
if (completed.error) fail(`could not execute the installed engine: ${completed.error.message}`, 126);
if (completed.signal) process.kill(process.pid, completed.signal);
process.exit(completed.status ?? 1);
