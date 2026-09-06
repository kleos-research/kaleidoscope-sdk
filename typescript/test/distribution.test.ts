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
  // Which typed failure arrives depends on the host, and both are the point.
  // On the one target this package advertises, the companion is genuinely not
  // installed -- nothing in this repository installs it -- so the locator must
  // say so by type. On any other host the platform is refused before a
  // companion is looked for at all.
  //
  // Asserting only the first made this test pass on the author's Mac and fail
  // on CI's Linux: a test that described a machine rather than the code.
  const expected =
    process.platform === "darwin" && process.arch === "arm64"
      ? MissingPlatformPackageError
      : UnsupportedPlatformError;
  assert.throws(() => installedPayloadPaths(), expected);
});
