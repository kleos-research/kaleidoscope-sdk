#!/usr/bin/env python3
"""Ask the registry whether what this repository says about published packages is true.

Every other test here compares a file in this repository to another file in this
repository, which is how `reference/binary-pin.json` came to pin an engine build
that no user can install while the suite stayed green: the pin agreed with the
contract beside it, and neither was ever compared to the thing on npm.

Two questions, both answered against the live registry:

  1. Does the pinned executable digest match the engine a user installs today?
     The pin describes one platform, and which one is not a guess -- the contract
     it was generated with records the target triple.

  2. Does every version this repository pins actually exist? `optionalDependencies`
     in `typescript/package.json` names a platform package version, and a version
     that was never published turns `npm install` into a resolution failure for
     everyone.

Both are network questions, so this is not part of the offline test suite. It is
its own CI job, and it is meant to fail when the answer is no.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# The npm platform package that carries the executable for each Rust target.
# Kept here rather than derived, because the mapping is a packaging decision
# rather than a property of the triple.
PLATFORM_PACKAGE = {
    "aarch64-apple-darwin": "darwin-arm64",
    "x86_64-apple-darwin": "darwin-x64",
    "aarch64-unknown-linux-gnu": "linux-arm64",
    "x86_64-unknown-linux-gnu": "linux-x64",
}


def registry_metadata(package: str) -> dict:
    url = f"https://registry.npmjs.org/{package.replace('/', '%2f')}"
    with urllib.request.urlopen(url, timeout=30) as response:
        return json.load(response)


def sha256_of(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_pin_describes_published_engine() -> list[str]:
    """The pinned executable digest, against the engine `latest` resolves to."""
    pin = json.loads((REPO / "reference" / "binary-pin.json").read_text())
    contract = json.loads((REPO / "reference" / "kaleidoscope-public-contract.json").read_text())
    triple = contract["target"]["triple"]

    package = PLATFORM_PACKAGE.get(triple)
    if package is None:
        return [f"no npm platform package is known for target triple {triple}"]

    name = f"@kleos-research/kaleidoscope-{package}"
    metadata = registry_metadata(name)
    version = metadata["dist-tags"]["latest"]
    tarball_url = metadata["versions"][version]["dist"]["tarball"]

    with tempfile.TemporaryDirectory() as directory:
        workspace = Path(directory)
        archive = workspace / "package.tgz"
        with urllib.request.urlopen(tarball_url, timeout=60) as response, archive.open("wb") as out:
            shutil.copyfileobj(response, out)
        with tarfile.open(archive) as tar:
            member = tar.getmember("package/bin/kscope")
            extracted = tar.extractfile(member)
            if extracted is None:
                return [f"{name}@{version} carries no package/bin/kscope"]
            executable = workspace / "kscope"
            with executable.open("wb") as out:
                shutil.copyfileobj(extracted, out)
            published = sha256_of(executable)

    pinned = pin["sha256"]
    print(f"  target triple      {triple}")
    print(f"  published          {name}@{version}  {published}")
    print(f"  pinned             {pinned}")
    if published == pinned:
        return []
    return [
        f"reference/binary-pin.json pins {pinned}, but {name}@{version} ships {published}. "
        "Regenerate the pin and the contract together with the engine repository's "
        "the engine's release contract generator against the release candidate. Do not edit the "
        "digest by hand: a pin that agrees with the registry while describing evidence nobody "
        "produced is worse than one that is visibly stale."
    ]


def check_pinned_versions_exist() -> list[str]:
    """Every dependency version named in typescript/package.json, against the registry."""
    manifest = json.loads((REPO / "typescript" / "package.json").read_text())
    problems = []
    for section in ("dependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in (manifest.get(section) or {}).items():
            version = spec.lstrip("^~")
            try:
                metadata = registry_metadata(name)
            except Exception as error:  # noqa: BLE001 - the message is the finding
                problems.append(f"{section}: {name} could not be read from the registry ({error})")
                continue
            available = sorted(metadata.get("versions", {}))
            if version in available:
                print(f"  ok       {name}@{version}")
            else:
                print(f"  MISSING  {name}@{version}   (published: {', '.join(available) or 'nothing'})")
                problems.append(
                    f"{section}: {name}@{version} has never been published. "
                    f"Published versions are: {', '.join(available) or 'none'}."
                )
    return problems


def main() -> int:
    problems: list[str] = []

    print("Does the pin describe the engine users install?")
    problems.extend(check_pin_describes_published_engine())

    print("\nDoes every pinned dependency version exist?")
    problems.extend(check_pinned_versions_exist())

    if problems:
        print("\nThis repository states something about a published package that is not true:\n", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}\n", file=sys.stderr)
        return 1

    print("\nEvery claim checked here matches the registry.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
