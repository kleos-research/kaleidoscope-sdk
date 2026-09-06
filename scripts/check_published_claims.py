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

     Which digest is the claim depends on what the pin carries. A pin synced from
     an engine release (`scripts/sync_from_release.py`) records
     `published_executables`: the engine repository's own statement of what it
     put inside each platform package. That statement was made in a private
     repository and is repeated here; this is the only place it meets the public
     registry, and it does so with no token. The pin's `sha256` is a different
     number on purpose -- the digest of the ungated build the contract was
     generated from -- so it is printed beside the verdict and never compared to
     the registry when the published digest is there to compare instead. A pin
     with no `published_executables` is one no release has been synced into, and
     for that pin `sha256` remains the only claim there is to check.

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

# The npm platform package that carries the executable for each Rust target
# lives in the sync script, which writes the pin this script reads; importing
# it is what keeps the writer and the reader from disagreeing about a slug.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sync_from_release import PLATFORM_PACKAGE  # noqa: E402


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
    """The pin's claim about the shipped executable, against the package on the registry."""
    pin = json.loads((REPO / "reference" / "binary-pin.json").read_text())
    contract = json.loads((REPO / "reference" / "kaleidoscope-public-contract.json").read_text())
    triple = contract["target"]["triple"]

    package = PLATFORM_PACKAGE.get(triple)
    if package is None:
        return [f"no npm platform package is known for target triple {triple}"]

    name = f"@kleos-research/kaleidoscope-{package}"
    metadata = registry_metadata(name)
    # A synced pin says which version the release published, so that is the
    # version whose executable is the claim; `latest` is the fallback for a pin
    # that predates the sync and makes no statement about versions at all.
    version = pin.get("release_version") or metadata["dist-tags"]["latest"]
    if version not in metadata.get("versions", {}):
        return [
            f"reference/binary-pin.json says release {version} published {name}, but the "
            f"registry has no such version"
        ]
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
            published_bytes = executable.stat().st_size

    print(f"  target triple      {triple}")
    print(f"  published          {name}@{version}  {published}  ({published_bytes} bytes)")
    print(f"  contract build     {pin['sha256']}")

    claimed = pin.get("published_executables")
    if claimed is not None:
        entry = claimed.get(package)
        if entry is None:
            return [
                f"reference/binary-pin.json carries published_executables but no {package} "
                f"entry, while the contract beside it describes {triple}; the release that "
                f"generated the contract did not ship the platform it describes"
            ]
        print(f"  claimed published  {entry['sha256']}  ({entry['bytes']} bytes)")
        problems = []
        if entry["sha256"] != published:
            problems.append(
                f"reference/binary-pin.json says the engine release put {entry['sha256']} "
                f"inside {name}@{version}, but the registry's copy hashes to {published}. "
                "The private repository's statement and the public package disagree; "
                "regenerate from the release that was actually published rather than "
                "editing either side."
            )
        if entry["bytes"] != published_bytes:
            problems.append(
                f"reference/binary-pin.json says the executable inside {name}@{version} is "
                f"{entry['bytes']} bytes; the registry's copy is {published_bytes}."
            )
        return problems

    pinned = pin["sha256"]
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
