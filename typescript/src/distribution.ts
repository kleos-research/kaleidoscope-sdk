import { accessSync, realpathSync, statSync } from "node:fs";
import { constants as fsConstants } from "node:fs";
import { createRequire } from "node:module";

/** One complete, natively exercised package coordinate. */
export interface NativePackageTarget {
  readonly platform: NodeJS.Platform;
  readonly arch: string;
  readonly packageName: string;
}

/** Paths supplied by the platform companion package. */
export interface InstalledPayloadPaths {
  readonly manager: string;
  readonly engine: string;
  readonly manifest: string;
}

export class UnsupportedPlatformError extends Error {
  override readonly name = "UnsupportedPlatformError";
}

export class MissingPlatformPackageError extends Error {
  override readonly name = "MissingPlatformPackageError";
}

export class InvalidPlatformPackageError extends Error {
  override readonly name = "InvalidPlatformPackageError";
}

// A coordinate appears here only after native package conformance. The release
// assembler and package metadata are tested against this exact exported table;
// adding a cross-compiled or scaffold-only target would turn installation
// coordinates into a false support claim.
export const NATIVE_PACKAGE_TARGETS: readonly NativePackageTarget[] = Object.freeze([
  Object.freeze({
    platform: "darwin" as const,
    arch: "arm64",
    packageName: "@kleos-research/kaleidoscope-darwin-arm64",
  }),
]);

const TARGET_BY_KEY = new Map(
  NATIVE_PACKAGE_TARGETS.map((target) => [`${target.platform}/${target.arch}`, target]),
);

export function selectedNativePackage(
  platform: NodeJS.Platform = process.platform,
  arch: string = process.arch,
): string {
  const target = TARGET_BY_KEY.get(`${platform}/${arch}`);
  if (target === undefined) {
    const supported = NATIVE_PACKAGE_TARGETS.map(
      (candidate) => `${candidate.platform}/${candidate.arch}`,
    ).join(", ");
    throw new UnsupportedPlatformError(
      `Kaleidoscope has no natively tested package for ${platform}/${arch}; supported: ${supported}`,
    );
  }
  return target.packageName;
}

function canonicalPackageFile(path: string, label: string, executable: boolean): string {
  let resolved: string;
  try {
    resolved = realpathSync(path);
    const metadata = statSync(resolved);
    if (!metadata.isFile()) throw new Error("not a regular file");
    if (executable) accessSync(resolved, fsConstants.X_OK);
  } catch (error) {
    throw new InvalidPlatformPackageError(
      `installed platform package has no valid ${label}`,
      { cause: error },
    );
  }
  return resolved;
}

/** Resolve the installed manager and engine without executing package code. */
export function installedPayloadPaths(): InstalledPayloadPaths {
  const packageName = selectedNativePackage();
  const require = createRequire(import.meta.url);
  let payload: unknown;
  try {
    payload = require(packageName);
  } catch (error) {
    throw new MissingPlatformPackageError(
      `${packageName} is missing; reinstall without --omit=optional or install that exact companion`,
      { cause: error },
    );
  }
  if (
    typeof payload !== "object" ||
    payload === null ||
    Array.isArray(payload) ||
    Object.keys(payload).sort().join(",") !== "engine,manager,manifest"
  ) {
    throw new InvalidPlatformPackageError(
      `${packageName} does not export the closed manager/engine/manifest locator`,
    );
  }
  const located = payload as Record<string, unknown>;
  if (
    typeof located.manager !== "string" ||
    typeof located.engine !== "string" ||
    typeof located.manifest !== "string"
  ) {
    throw new InvalidPlatformPackageError(`${packageName} exports invalid payload paths`);
  }
  return Object.freeze({
    manager: canonicalPackageFile(located.manager, "kaleidoscope manager", true),
    engine: canonicalPackageFile(located.engine, "kscope engine", true),
    manifest: canonicalPackageFile(located.manifest, "signed release manifest", false),
  });
}

export function installedManagerPath(): string {
  return installedPayloadPaths().manager;
}

export function installedEnginePath(): string {
  return installedPayloadPaths().engine;
}
