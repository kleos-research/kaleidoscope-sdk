#!/usr/bin/env node
import { spawnSync } from "node:child_process";

import { installedPayloadPaths } from "../dist/src/distribution.js";

function fail(message, code) {
  process.stderr.write(`kaleidoscope: ${message}\n`);
  process.exit(code);
}

let payload;
try {
  payload = installedPayloadPaths();
} catch (error) {
  fail(error instanceof Error ? error.message : String(error), 127);
}

const arguments_ = process.argv.slice(2);
const managerArguments =
  arguments_.length === 0 || ["-h", "--help", "-V", "--version"].includes(arguments_[0])
    ? arguments_
    : ["--engine", payload.engine, ...arguments_];
const completed = spawnSync(payload.manager, managerArguments, {
  stdio: "inherit",
  windowsHide: true,
});
if (completed.error) fail(`could not execute the installed manager: ${completed.error.message}`, 126);
if (completed.signal) process.kill(process.pid, completed.signal);
process.exit(completed.status ?? 1);
