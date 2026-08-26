import assert from "node:assert/strict";
import test from "node:test";

import {
  installedPayloadPaths,
  MissingPlatformPackageError,
  NATIVE_PACKAGE_TARGETS,
  selectedNativePackage,
  UnsupportedPlatformError,
} from "../src/index.js";

test("package selection advertises only the natively exercised target", () => {
  assert.deepEqual(NATIVE_PACKAGE_TARGETS, [
    {
      platform: "darwin",
      arch: "arm64",
      packageName: "@kleos-research/kaleidoscope-darwin-arm64",
    },
  ]);
  assert.equal(
    selectedNativePackage("darwin", "arm64"),
    "@kleos-research/kaleidoscope-darwin-arm64",
  );
  assert.throws(() => selectedNativePackage("linux", "x64"), UnsupportedPlatformError);
  assert.throws(() => selectedNativePackage("win32", "arm64"), UnsupportedPlatformError);
});

test("missing optional companion is a typed installation failure", () => {
  assert.throws(() => installedPayloadPaths(), MissingPlatformPackageError);
});
