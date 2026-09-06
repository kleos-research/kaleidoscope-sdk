#!/usr/bin/env python3
"""Take an engine release's assets into this repository, and prove the tree still agrees with itself.

Truth about the engine is PUSHED here, never typed. The engine repository is
private; this one is public. An engine release produces one directory of
release assets -- a manifest, the generated public contract, its provenance
record, the shipped `kscope --help`, the instruction assets -- and the engine's
release job opens a pull request here carrying whatever this script derives
from them. A human approves a generated diff and retypes nothing.

Two modes, and the split between them is the design:

    python3 scripts/sync_from_release.py --apply --release DIR
    python3 scripts/sync_from_release.py --check

`--apply` is the WRITER. It re-hashes every asset the manifest names, refuses
the whole directory on the first digest that disagrees, and only then vendors
the contract into `reference/` and rewrites the files that derive from it. It
is the only thing that should ever change `reference/binary-pin.json`.

`--check` is what CI runs, on every push, OFFLINE: no token, no network, no
release directory. It recomputes every derived value from the committed pin,
the committed vendored contract and the committed package manifests, and exits
1 naming each disagreement. Two years of green tests taught this repository
that a pin which agrees with the file beside it proves only that somebody
edited both; the check exists so that the repository's own consistency is
something a machine asserts rather than something a reviewer assumes.

WHAT THE PIN SAYS, AND THE ONE DISTINCTION IT MUST KEEP HONEST
---------------------------------------------------------------
`reference/binary-pin.json` carries two different executable digests, and they
are not the same number on purpose:

* `sha256` (and `isolated_distribution_candidate_sha256`, which the golden
  tests require to be equal to it) is `executable.sha256` from the public
  contract: the digest of the UNGATED build the contract was generated from.
  The provenance file beside the contract records exactly that. It is what
  the conformance runners hand the engine to verify against, and it is NOT
  what a user downloads.
* `published_executables` is the manifest's `executables` map: the digest and
  size of `package/bin/kscope` inside each platform package the release
  actually built. That IS what npm ships, and `scripts/check_published_claims.py`
  holds it against the registry.

Writing the published digest into `sha256` would make the golden tests pass
against the registry while describing a build the contract was never generated
from. Keeping the two apart is the whole point of carrying both.

`release_version` is recorded in the pin too, although the manifest is not the
only place it lives: without it the offline check could not say what the
platform package pins in `typescript/package.json` are supposed to equal.

WHAT --apply DOES NOT TOUCH
---------------------------
The client packages' own version fields -- `"version"` in
`typescript/package.json` and `project.version` in `python/pyproject.toml` --
are left alone. The platform packages carry the engine's release version,
because the engine builds and publishes them; that is a derived fact and the
`optionalDependencies` pins follow it. Whether the CLIENTS adopt the engine's
version line, or keep their own, is an open product decision that a sync
script has no business making silently. When it is made, it is made here, in
one place, with a comment saying why.

`shared_vault_runtime_sha256` is kept exactly as the tree had it: the release
manifest does not describe the shared vault runtime, and a sync that blanked
the field, or read it from a key no manifest carries, would be asserting
something it did not know. A tree whose pin lacks it is refused before anything
is written, because the check would refuse the result anyway.

THE ONE THING --apply NEEDS THE NETWORK FOR
-------------------------------------------
`typescript/package-lock.json` has to RESOLVE the platform package -- version,
tarball URL, integrity -- or `npm ci` refuses the pair, and that resolution is
a fact about the registry that no release asset carries. So after rewriting
the pins, `--apply` runs `npm install --package-lock-only` in `typescript/`,
which reads package metadata and downloads nothing. The engine's release job
has just published to that registry, so it can. `--skip-lockfile-refresh`
leaves the lockfile's platform entry as it was for an offline run (the tests
use it); the check then says, without failing, that `npm ci` will refuse the
tree until the entry is resolved, because that is a job for the network and
not for a hand.
"""

from __future__ import annotations

import argparse
from datetime import date
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

MANIFEST_SCHEMA = "kaleidoscope.release-manifest.v1"
CONTRACT_SCHEMA = "kaleidoscope.public-contract.v1"
PROVENANCE_SCHEMA = "kaleidoscope.public-contract-provenance.v1"

MANIFEST_NAME = "release.json"
CONTRACT_NAME = "kaleidoscope-public-contract.json"
PROVENANCE_NAME = "kaleidoscope-public-contract.provenance.json"

#: Paths inside a repository root, relative so they are printable in a public
#: CI log and so a test can point the script at a copy of the tree.
PIN_PATH = "reference/binary-pin.json"
CONTRACT_PATH = "reference/" + CONTRACT_NAME
PACKAGE_JSON_PATH = "typescript/package.json"
PACKAGE_LOCK_PATH = "typescript/package-lock.json"

#: The npm scope every platform package lives under. A package named with this
#: prefix in `optionalDependencies` is a claim that the engine published it at
#: the pinned version; nothing else in that section is.
PLATFORM_PACKAGE_PREFIX = "@kleos-research/kaleidoscope-"

#: The npm platform package slug that carries the executable for each Rust
#: target. Kept here rather than derived, because the mapping is a packaging
#: decision rather than a property of the triple. `check_published_claims.py`
#: imports this table so the two scripts cannot disagree about it.
PLATFORM_PACKAGE = {
    "aarch64-apple-darwin": "darwin-arm64",
    "x86_64-apple-darwin": "darwin-x64",
    "aarch64-unknown-linux-gnu": "linux-arm64",
    "x86_64-unknown-linux-gnu": "linux-x64",
}

#: Where each manifest entry's file must be inside the release directory. The
#: release manifest's schema pins these as constants, and this reader holds
#: the manifest to the same constants instead of following `path` as an
#: address: an address can point outside the directory, and two roles'
#: addresses can be swapped so that every digest still re-hashes while the
#: wrong file lands under the wrong name. Both are refused by name.
ASSET_PATHS = {
    "public_contract": CONTRACT_NAME,
    "cli_help": "kscope-help.txt",
    "instruction_assets.skill": "instructions/SKILL.md",
    "instruction_assets.agents": "instructions/AGENTS.md",
    "instruction_assets.claude": "instructions/CLAUDE.md",
    "instruction_assets.cursor": "instructions/cursor-kaleidoscope.mdc",
}

#: The four digests the pin carries that are not release-level facts: written
#: by `--apply`, required to be 64-hex by `--check`, and refused before a
#: write if the pin about to be written would fail that.
PIN_DIGEST_FIELDS = (
    "sha256",
    "shared_vault_runtime_sha256",
    "isolated_distribution_candidate_sha256",
    "public_contract_sha256",
)

HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

#: One line of a package manifest that pins a platform package. The version is
#: rewritten in place, textually, so that every other byte of the file --
#: including the single-line `"files"` array a JSON re-serialiser would unfold
#: -- survives the sync untouched. The result is re-parsed and compared to the
#: intended structure before it is written, so a substitution that reached
#: anything else fails loudly rather than landing.
PLATFORM_PIN_LINE = re.compile(
    r'^(?P<lead>\s*"' + re.escape(PLATFORM_PACKAGE_PREFIX) + r'[A-Za-z0-9-]+":\s*)"[^"]*"(?P<tail>,?)$'
)


class SyncError(Exception):
    """A release directory or a tree that cannot be taken as it stands."""


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path, what: str) -> dict:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SyncError(f"{what} is missing: {path.name}") from None
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SyncError(f"{what} is not JSON ({path.name}): {error}") from None
    if not isinstance(loaded, dict):
        raise SyncError(f"{what} is not a JSON object: {path.name}")
    return loaded


def _hex(value: object, width: int) -> bool:
    pattern = HEX_40 if width == 40 else HEX_64
    return isinstance(value, str) and bool(pattern.match(value))


# ---------------------------------------------------------------------------
# Reading a release directory
# ---------------------------------------------------------------------------


def verify_release(release: Path) -> tuple[dict, list[str]]:
    """Read the manifest and re-hash every asset it names.

    Returns the manifest and the list of disagreements. Nothing is written by
    this function, and `--apply` writes nothing while the list is non-empty:
    a release directory is taken whole or not at all, because a pin rewritten
    from a manifest whose contract digest was wrong is a pin that describes
    nothing.

    The `executables` digests cannot be re-hashed here. They are digests of
    files inside npm platform packages, which are not release assets; they are
    checked in shape here and against the registry by
    `check_published_claims.py`.
    """

    problems: list[str] = []
    manifest = read_json(release / MANIFEST_NAME, "release manifest")

    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        problems.append(
            f"{MANIFEST_NAME}: schema_version is {manifest.get('schema_version')!r}, "
            f"this script reads {MANIFEST_SCHEMA!r}"
        )
    if not isinstance(manifest.get("release_version"), str) or not manifest["release_version"]:
        problems.append(f"{MANIFEST_NAME}: release_version is missing or empty")
    if not _hex(manifest.get("source_commit"), 40):
        problems.append(f"{MANIFEST_NAME}: source_commit is not a 40-hex commit id")
    if not isinstance(manifest.get("released_on"), str) or not ISO_DATE.match(manifest["released_on"]):
        problems.append(f"{MANIFEST_NAME}: released_on is not an ISO date")
    else:
        # The shape and the calendar are two checks; `2026-13-45` has the shape.
        try:
            date.fromisoformat(manifest["released_on"])
        except ValueError:
            problems.append(f"{MANIFEST_NAME}: released_on {manifest['released_on']!r} is not a calendar date")

    # Every digest the manifest states about a file in the directory, re-hashed.
    hashed: list[tuple[str, dict]] = []
    contract_entry = manifest.get("public_contract")
    if isinstance(contract_entry, dict):
        hashed.append(("public_contract", contract_entry))
    else:
        problems.append(f"{MANIFEST_NAME}: public_contract is missing")
    cli_help = manifest.get("cli_help")
    if isinstance(cli_help, dict):
        hashed.append(("cli_help", cli_help))
    else:
        problems.append(f"{MANIFEST_NAME}: cli_help is missing")
    instruction_assets = manifest.get("instruction_assets")
    if isinstance(instruction_assets, dict):
        for key, entry in sorted(instruction_assets.items()):
            if isinstance(entry, dict):
                hashed.append((f"instruction_assets.{key}", entry))
            else:
                problems.append(f"{MANIFEST_NAME}: instruction_assets.{key} is not an object")
    else:
        problems.append(f"{MANIFEST_NAME}: instruction_assets is missing")

    for label, entry in hashed:
        relative = entry.get("path")
        expected = entry.get("sha256")
        fixed = ASSET_PATHS.get(label)
        if fixed is None:
            problems.append(f"{MANIFEST_NAME}: {label} is not an asset the release manifest defines")
            continue
        if relative != fixed:
            problems.append(f"{MANIFEST_NAME}: {label} names {relative!r}; the release manifest fixes it at {fixed!r}")
            continue
        if not _hex(expected, 64):
            problems.append(f"{MANIFEST_NAME}: {label} needs a 64-hex sha256")
            continue
        asset = release / relative
        if asset.is_symlink() or not asset.resolve().is_relative_to(release.resolve()):
            # A release asset is a file inside the directory. A link out of it
            # would hash, and vendor, something the release never shipped.
            problems.append(f"{label}: {relative} is not a file inside the release directory")
            continue
        if not asset.is_file():
            problems.append(f"{label}: {relative} is named by the manifest but is not in the release directory")
            continue
        actual = sha256_of(asset)
        if actual != expected:
            problems.append(
                f"{label}: {relative} hashes to {actual}, the manifest says {expected}"
            )

    if isinstance(contract_entry, dict):
        if contract_entry.get("schema_version") != CONTRACT_SCHEMA:
            problems.append(
                f"{MANIFEST_NAME}: public_contract.schema_version is "
                f"{contract_entry.get('schema_version')!r}, expected {CONTRACT_SCHEMA!r}"
            )
        if not isinstance(contract_entry.get("mcp_protocol_revision"), str):
            problems.append(f"{MANIFEST_NAME}: public_contract.mcp_protocol_revision is missing")

    # The contract itself: the executable digest it carries is the one the pin
    # will repeat, so its shape is checked before anything is derived from it,
    # and the manifest's protocol revision has to be one the contract admits.
    contract_asset = release / CONTRACT_NAME
    if contract_asset.is_file():
        try:
            contract = read_json(contract_asset, "public contract asset")
        except SyncError as error:
            problems.append(str(error))
        else:
            problems.extend(f"{CONTRACT_NAME}: {item}" for item in contract_shape_problems(contract))
            if isinstance(contract_entry, dict):
                revision = contract_entry.get("mcp_protocol_revision")
                if isinstance(revision, str):
                    problems.extend(
                        f"{MANIFEST_NAME}: {item}"
                        for item in protocol_revision_problems(contract, revision)
                    )
            # One release, one version. The contract records the version the
            # executable it observed reported; the manifest records the version
            # the release is. A contract from another build wrapped in this
            # release's manifest would otherwise pass every digest check.
            stated = contract_product_version(contract)
            if isinstance(manifest.get("release_version"), str) and stated != manifest["release_version"]:
                problems.append(
                    f"{MANIFEST_NAME}: release_version is {manifest['release_version']!r} but "
                    f"{CONTRACT_NAME} product.version is {stated!r}; the contract describes a different release"
                )

    # The provenance record is the document that says which build the contract's
    # executable digest describes. It is not digest-listed by the manifest, so
    # it is required to be present and to be what it says it is, and no more.
    try:
        provenance = read_json(release / PROVENANCE_NAME, "public contract provenance")
    except SyncError as error:
        problems.append(str(error))
    else:
        if provenance.get("schema_version") != PROVENANCE_SCHEMA:
            problems.append(
                f"{PROVENANCE_NAME}: schema_version is {provenance.get('schema_version')!r}, "
                f"expected {PROVENANCE_SCHEMA!r}"
            )

    executables = manifest.get("executables")
    if not isinstance(executables, dict):
        problems.append(f"{MANIFEST_NAME}: executables is missing")
    else:
        problems.extend(f"{MANIFEST_NAME}: {item}" for item in executables_shape_problems(executables))
        problems.extend(f"{MANIFEST_NAME}: {item}" for item in platform_problems(manifest.get("platforms"), executables))

    return manifest, problems


def platform_problems(rows: object, executables: dict) -> list[str]:
    """The platform rows, and the executables map reconciled with them.

    `executables` is the digest of what each BUILT platform's package holds
    and `platforms[].published` is what the release actually shipped; the pin
    repeats only the published ones, so the rows have to be well-formed and
    the two have to agree before anything is derived. A manifest digesting a
    package for a platform its own rows say was never built is two documents
    claiming to be one.
    """

    if not isinstance(rows, list):
        return ["platforms is not a list"]
    problems: list[str] = []
    seen: set[str] = set()
    built: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            problems.append("a platform row is not an object")
            continue
        slug = row.get("slug")
        if not isinstance(slug, str) or not slug:
            problems.append("a platform row has no slug")
            continue
        if slug in seen:
            problems.append(f"platform {slug!r} is listed twice")
        seen.add(slug)
        flags = {key: row.get(key) for key in ("built", "published", "native_build_runner")}
        for key, value in flags.items():
            if not isinstance(value, bool):
                problems.append(f"platform {slug!r} {key} is {value!r}, not true or false")
        if all(isinstance(value, bool) for value in flags.values()):
            if flags["published"] and not flags["built"]:
                problems.append(f"platform {slug!r} is published but not built")
            if flags["native_build_runner"] and not flags["built"]:
                problems.append(f"platform {slug!r} has a native build runner but was not built")
            if flags["built"]:
                built.add(slug)
    if set(executables) != built:
        problems.append(
            f"executables names {sorted(executables)} and the platform rows say {sorted(built)} "
            f"were built; the two must be the same set"
        )
    return problems


def published_slugs(manifest: dict) -> set[str]:
    """The platforms the manifest's rows say were published, and only those."""

    return {row["slug"] for row in manifest["platforms"] if row["published"]}


def contract_product_version(contract: dict) -> object:
    product = contract.get("product")
    return product.get("version") if isinstance(product, dict) else None


def contract_shape_problems(contract: dict) -> list[str]:
    problems: list[str] = []
    if contract.get("schema_version") != CONTRACT_SCHEMA:
        problems.append(
            f"schema_version is {contract.get('schema_version')!r}, expected {CONTRACT_SCHEMA!r}"
        )
    executable = contract.get("executable")
    if not isinstance(executable, dict) or not _hex(executable.get("sha256"), 64):
        problems.append("executable.sha256 is not a 64-hex digest")
    target = contract.get("target")
    if not isinstance(target, dict) or not isinstance(target.get("triple"), str):
        problems.append("target.triple is missing")
    return problems


def protocol_revision_problems(contract: dict, revision: str) -> list[str]:
    """The pinned MCP revision must be one the contract says the engine speaks."""

    protocol = (contract.get("mcp") or {}).get("protocol") if isinstance(contract.get("mcp"), dict) else None
    if not isinstance(protocol, dict):
        return ["the contract carries no mcp.protocol range to hold the revision against"]
    minimum = protocol.get("minimum")
    maximum = protocol.get("maximum")
    if not isinstance(minimum, str) or not isinstance(maximum, str):
        return ["the contract's mcp.protocol range is not a pair of revisions"]
    if not minimum <= revision <= maximum:
        return [
            f"mcp_protocol_revision {revision} is outside the contract's range "
            f"{minimum}..{maximum}"
        ]
    return []


def executables_shape_problems(executables: dict) -> list[str]:
    problems: list[str] = []
    for slug, entry in sorted(executables.items()):
        if not isinstance(entry, dict) or not _hex(entry.get("sha256"), 64):
            problems.append(f"executables.{slug}.sha256 is not a 64-hex digest")
        if not isinstance(entry, dict) or not isinstance(entry.get("bytes"), int) or entry["bytes"] <= 0:
            problems.append(f"executables.{slug}.bytes is not a positive integer")
    return problems


# ---------------------------------------------------------------------------
# Deriving the repository's files
# ---------------------------------------------------------------------------


def derived_pin(previous: dict, manifest: dict, contract: dict) -> dict:
    """The pin this release implies, given the pin the tree had before it.

    Field order is the order the file has always had, with the two fields this
    script introduced appended, so a reviewer's diff shows the values that
    changed and not a reshuffle.
    """

    executable_digest = contract["executable"]["sha256"]
    published = published_slugs(manifest)
    pin = {
        "source_commit": manifest["source_commit"],
        "sha256": executable_digest,
        # Kept from the tree, never read from the manifest: no release manifest
        # carries this field, and a lookup for one would be a lookup for
        # nothing wearing the name of a check.
        "shared_vault_runtime_sha256": previous.get("shared_vault_runtime_sha256"),
        "isolated_distribution_candidate_sha256": executable_digest,
        "public_contract_sha256": manifest["public_contract"]["sha256"],
        "mcp_protocol_revision": manifest["public_contract"]["mcp_protocol_revision"],
        "release_version": manifest["release_version"],
        # `executables` is every platform the release BUILT; the pin says
        # what was PUBLISHED, because that is what the registry check and the
        # platform package pins are held to. A built-but-unpublished platform
        # is a digest of something nobody can install.
        "published_executables": {
            slug: {"sha256": entry["sha256"], "bytes": entry["bytes"]}
            for slug, entry in sorted(manifest["executables"].items())
            if slug in published
        },
    }
    return pin


def pin_shape_problems(pin: dict) -> list[str]:
    """The pin's own fields, before anything is compared against them.

    Used by the check on the committed pin and by the writer on the pin it is
    about to write, so that an apply never leaves a malformed pin behind for
    the check to refuse one line later.
    """

    problems: list[str] = []
    if not _hex(pin.get("source_commit"), 40):
        problems.append("source_commit is not a 40-hex commit id")
    for field in PIN_DIGEST_FIELDS:
        if not _hex(pin.get(field), 64):
            problems.append(f"{field} is not a 64-hex digest")
    if not isinstance(pin.get("mcp_protocol_revision"), str):
        problems.append("mcp_protocol_revision is missing")
    return problems


def render_json(document: dict) -> str:
    return json.dumps(document, indent=2) + "\n"


def rewrite_platform_pins(text: str, version: str, what: str) -> tuple[str, dict]:
    """Set every platform package pin in a manifest's text to `version`.

    Returns the rewritten text and its parsed form. Which entries exist is a
    packaging decision this script does not make: a platform the release built
    but the client has not adopted stays absent, and one the client names is
    pinned to the release. The check mode is what notices when the client
    names a platform the release did not ship.
    """

    lines = text.split("\n")
    rewritten = []
    for line in lines:
        match = PLATFORM_PIN_LINE.match(line)
        if match:
            line = f'{match.group("lead")}"{version}"{match.group("tail")}'
        rewritten.append(line)
    result = "\n".join(rewritten)

    # The intended structure, computed independently of the textual edit.
    intended = json.loads(text)
    _set_platform_versions(intended, version)
    actual = json.loads(result)
    if actual != intended:
        raise SyncError(
            f"{what}: rewriting the platform package pins changed something else in "
            f"the file; refusing to write it"
        )
    return result, actual


def _set_platform_versions(document: dict, version: str) -> None:
    sections = [document.get("optionalDependencies")]
    packages = document.get("packages")
    if isinstance(packages, dict) and isinstance(packages.get(""), dict):
        sections.append(packages[""].get("optionalDependencies"))
    for section in sections:
        if not isinstance(section, dict):
            continue
        for name in list(section):
            if name.startswith(PLATFORM_PACKAGE_PREFIX):
                section[name] = version


def refresh_lockfile(root: Path) -> None:
    """Have npm resolve the platform package entries the sync just re-pinned.

    `--package-lock-only` writes the lockfile and nothing else: no
    `node_modules`, no scripts, no tarball. It is the one registry read the
    writer makes, and `--apply` makes it after the offline rewrite so that a
    refusal here leaves a tree the check can still describe.
    """

    try:
        completed = subprocess.run(
            ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
            cwd=root / "typescript",
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        raise SyncError(
            "npm is not on PATH, so the lockfile's platform package entry cannot be "
            "resolved; install npm, or pass --skip-lockfile-refresh and resolve it later"
        ) from None
    if completed.returncode != 0:
        raise SyncError(
            "npm could not resolve the platform package pins into the lockfile:\n"
            + completed.stderr.strip()
        )


def apply(root: Path, release: Path, *, refresh: bool) -> int:
    manifest, problems = verify_release(release)
    if problems:
        print(f"Refusing the release directory {release.name}; nothing was written:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    contract_asset = release / CONTRACT_NAME
    contract = read_json(contract_asset, "public contract asset")
    previous = read_json(root / PIN_PATH, "binary pin")

    # The pin this release implies, held to the check's own shape rules before
    # a byte is written: a tree whose previous pin lacked a field this script
    # carries forward would otherwise get four files written and a refusal.
    pin = derived_pin(previous, manifest, contract)
    malformed = pin_shape_problems(pin)
    if malformed:
        print(f"Refusing the release directory {release.name}; nothing was written:", file=sys.stderr)
        for problem in malformed:
            print(f"  - {PIN_PATH}: the pin this release would write has {problem}", file=sys.stderr)
        return 1

    package_text = (root / PACKAGE_JSON_PATH).read_text(encoding="utf-8")
    lock_text = (root / PACKAGE_LOCK_PATH).read_text(encoding="utf-8")
    version = manifest["release_version"]
    package_text, _ = rewrite_platform_pins(package_text, version, PACKAGE_JSON_PATH)
    lock_text, _ = rewrite_platform_pins(lock_text, version, PACKAGE_LOCK_PATH)

    # Everything above could refuse. From here on, write -- the contract first,
    # byte for byte, because the pin about to be written names its digest.
    shutil.copyfile(contract_asset, root / CONTRACT_PATH)
    (root / PIN_PATH).write_text(render_json(pin), encoding="utf-8")
    (root / PACKAGE_JSON_PATH).write_text(package_text, encoding="utf-8")
    (root / PACKAGE_LOCK_PATH).write_text(lock_text, encoding="utf-8")

    if refresh:
        refresh_lockfile(root)

    print(f"Applied release {version} ({manifest['source_commit'][:12]}, {manifest['released_on']}):")
    for path in (CONTRACT_PATH, PIN_PATH, PACKAGE_JSON_PATH, PACKAGE_LOCK_PATH):
        print(f"  wrote  {path}")
    if not refresh:
        print(f"  (the platform package entry in {PACKAGE_LOCK_PATH} was not resolved: --skip-lockfile-refresh)")
    print()
    # The writer's last act is the reader's only act. An apply that left the
    # tree inconsistent would otherwise be discovered by CI, one push later.
    return check(root)


# ---------------------------------------------------------------------------
# Checking the committed tree, offline
# ---------------------------------------------------------------------------


def check_problems(root: Path) -> list[str]:
    """Every way the committed files can disagree, as one line each."""

    problems: list[str] = []
    try:
        pin = read_json(root / PIN_PATH, "binary pin")
    except SyncError as error:
        return [f"{PIN_PATH}: {error}"]
    try:
        contract = read_json(root / CONTRACT_PATH, "vendored public contract")
    except SyncError as error:
        return [f"{CONTRACT_PATH}: {error}"]

    problems.extend(f"{CONTRACT_PATH}: {item}" for item in contract_shape_problems(contract))
    problems.extend(f"{PIN_PATH}: {item}" for item in pin_shape_problems(pin))
    if problems:
        # Shape failures make every comparison below a comparison against
        # nothing; say what is malformed and stop.
        return problems

    # 1. The vendored contract is the file the pin names.
    actual_contract_digest = sha256_of(root / CONTRACT_PATH)
    if actual_contract_digest != pin["public_contract_sha256"]:
        problems.append(
            f"{CONTRACT_PATH}: hashes to {actual_contract_digest}, but {PIN_PATH} "
            f"public_contract_sha256 says {pin['public_contract_sha256']}"
        )

    # 2. The pin's executable digest is the contract's, under both of its names.
    contract_digest = contract["executable"]["sha256"]
    if pin["sha256"] != contract_digest:
        problems.append(
            f"{PIN_PATH}: sha256 is {pin['sha256']}, but {CONTRACT_PATH} "
            f"executable.sha256 is {contract_digest}"
        )
    if pin["isolated_distribution_candidate_sha256"] != pin["sha256"]:
        problems.append(
            f"{PIN_PATH}: isolated_distribution_candidate_sha256 differs from sha256; "
            f"the golden tests require them equal"
        )

    # 3. The MCP revision is one the contract admits.
    problems.extend(
        f"{PIN_PATH}: {item}"
        for item in protocol_revision_problems(contract, pin["mcp_protocol_revision"])
    )

    # 4. The release-level fields, present together or absent together. Their
    # absence is the state of a tree no release has been synced into yet, and
    # that tree is still consistent; their presence is what makes the platform
    # package pins checkable at all.
    has_version = "release_version" in pin
    has_executables = "published_executables" in pin
    if has_version != has_executables:
        problems.append(
            f"{PIN_PATH}: release_version and published_executables are written together "
            f"by --apply; one without the other is a hand edit"
        )
        return problems
    if not has_version:
        return problems

    version = pin["release_version"]
    executables = pin["published_executables"]
    if not isinstance(version, str) or not version:
        problems.append(f"{PIN_PATH}: release_version is not a non-empty string")
    if not isinstance(executables, dict):
        problems.append(f"{PIN_PATH}: published_executables is not an object")
        return problems
    problems.extend(f"{PIN_PATH}: published_{item}" for item in executables_shape_problems(executables))
    # The vendored contract describes the release the pin names, by version.
    stated = contract_product_version(contract)
    if stated != version:
        problems.append(
            f"{CONTRACT_PATH}: product.version is {stated!r}, but {PIN_PATH} release_version "
            f"is {version!r}; the contract was generated from a different release"
        )

    # 5. The platform the contract describes is one the release shipped. A pin
    # for a platform nobody can install is the defect this repository's CI
    # first noticed against the registry; here it is noticed offline.
    triple = contract["target"]["triple"]
    described = PLATFORM_PACKAGE.get(triple)
    if described is None:
        problems.append(f"{CONTRACT_PATH}: no platform package is known for target triple {triple}")
    elif described not in executables:
        problems.append(
            f"{PIN_PATH}: the contract describes {triple} ({described}), but "
            f"published_executables has no entry for it"
        )

    # 6. Every platform package the client pins carries the release version
    # and was actually published by the release; the lockfile agrees.
    try:
        package = read_json(root / PACKAGE_JSON_PATH, "typescript package manifest")
        lock = read_json(root / PACKAGE_LOCK_PATH, "typescript lockfile")
    except SyncError as error:
        problems.append(str(error))
        return problems
    optional = package.get("optionalDependencies") or {}
    for name, pinned in sorted(optional.items()):
        if not name.startswith(PLATFORM_PACKAGE_PREFIX):
            continue
        slug = name[len(PLATFORM_PACKAGE_PREFIX):]
        if pinned != version:
            problems.append(
                f"{PACKAGE_JSON_PATH}: optionalDependencies pins {name} at {pinned}, "
                f"but {PIN_PATH} release_version is {version}"
            )
        if slug not in executables:
            problems.append(
                f"{PACKAGE_JSON_PATH}: optionalDependencies names {name}, which the "
                f"release did not publish ({PIN_PATH} published_executables has no "
                f"{slug} entry)"
            )
    lock_packages = lock.get("packages") or {}
    lock_optional = (lock_packages.get("") or {}).get("optionalDependencies") or {}
    if lock_optional != optional:
        problems.append(
            f"{PACKAGE_LOCK_PATH}: the root optionalDependencies differ from "
            f"{PACKAGE_JSON_PATH}; `npm ci` will refuse the pair"
        )
    # 7. The lockfile's resolution of each platform package. A resolved entry
    # at the wrong version is a disagreement. An UNRESOLVED entry is not: it is
    # what an offline --apply leaves behind, and resolving it is a registry
    # read, so it is reported on stdout rather than counted, and `npm ci` in
    # the TypeScript job is what refuses it.
    for name in sorted(optional):
        if not name.startswith(PLATFORM_PACKAGE_PREFIX):
            continue
        entry = lock_packages.get(f"node_modules/{name}") or {}
        resolved = entry.get("version")
        if resolved is None:
            print(
                f"note: {PACKAGE_LOCK_PATH} does not resolve {name}; `npm ci` will refuse "
                f"the tree until `npm install --package-lock-only` has been run in typescript/"
            )
        elif resolved != version:
            problems.append(
                f"{PACKAGE_LOCK_PATH}: resolves {name} at {resolved}, but {PIN_PATH} "
                f"release_version is {version}"
            )
    return problems


def check(root: Path) -> int:
    problems = check_problems(root)
    if problems:
        print("The committed release files disagree with each other:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print(
            "\nDo not edit these by hand. Regenerate them from a release directory with\n"
            "  python3 scripts/sync_from_release.py --apply --release DIR",
            file=sys.stderr,
        )
        return 1
    pin = read_json(root / PIN_PATH, "binary pin")
    summary = f"release {pin['release_version']}" if "release_version" in pin else "no release synced yet"
    print(
        f"{PIN_PATH}, {CONTRACT_PATH} and the platform package pins agree "
        f"({summary}, engine {pin['source_commit'][:12]})."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Vendor an engine release's assets, or check that the committed ones agree."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--apply", action="store_true", help="take the release directory named by --release")
    mode.add_argument("--check", action="store_true", help="offline: recompute every derived file and diff")
    parser.add_argument("--release", type=Path, help="the release-assets directory (with --apply)")
    parser.add_argument(
        "--skip-lockfile-refresh",
        action="store_true",
        help="with --apply: do not run npm to resolve the platform package into the lockfile",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO,
        help="repository root to read and write (default: this repository; the tests pass a copy)",
    )
    arguments = parser.parse_args(argv)

    root = arguments.root.resolve()
    try:
        if arguments.apply:
            if arguments.release is None:
                parser.error("--apply needs --release DIR")
            return apply(root, arguments.release.resolve(), refresh=not arguments.skip_lockfile_refresh)
        return check(root)
    except SyncError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
