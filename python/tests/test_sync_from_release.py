"""The release sync writes what the release said, and the check notices when it did not.

`scripts/sync_from_release.py --check` is a CI step. Like the poison scan, it
passes hardest when it is broken: a check that recomputes nothing reports the
same green as one that recomputes everything. So the half worth testing is the
red half -- a planted disagreement in a copy of the tree has to be reported, by
file -- and the writer is tested by what it leaves behind: a tree the check
accepts, a contract vendored byte for byte, a pin that keeps the two executable
digests apart, and version fields it was told not to touch left untouched.

No test here writes into the repository. Each copies the four files the script
reads into a temporary root and points the script at that root with `--root`;
the one test against the real tree only reads it. Every `--apply` here passes
`--skip-lockfile-refresh`: resolving the platform package into the lockfile is
the one registry read the writer makes, and this suite is offline.

The fixture release is built from the committed contract and a synthetic
manifest. Its commit id is computed rather than written down, because a bare
40-hex literal in a test file is what the poison scan's rule 6 exists to stop.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "sync_from_release.py"

#: The files the sync reads and writes, relative to a repository root.
SYNCED = (
    "reference/binary-pin.json",
    "reference/kaleidoscope-public-contract.json",
    "typescript/package.json",
    "typescript/package-lock.json",
)

#: The fixture release carries the committed release's version. The tests below
#: cannot refresh the lockfile (that needs the registry), so the committed
#: lockfile's resolution of the platform package survives an apply, and a
#: fixture at any other version disagrees with it. This was spelled "0.0.5",
#: which only held while the committed release was 0.0.5.
FIXTURE_VERSION = json.loads((ROOT / "reference" / "binary-pin.json").read_text())["release_version"]
#: The digest a fixture release claims for the darwin-arm64 executable. Any
#: 64-hex value would do; this one is distinct from the contract's executable
#: digest so a test can tell the two apart.
FIXTURE_PUBLISHED_SHA256 = hashlib.sha256(b"fixture published executable").hexdigest()
FIXTURE_PUBLISHED_BYTES = 22993280


def _run(*arguments: str, root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *arguments, "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )


def _apply(release: Path, root: Path) -> subprocess.CompletedProcess[str]:
    return _run("--apply", "--release", str(release), "--skip-lockfile-refresh", root=root)


def _copy_tree(destination: Path) -> Path:
    for relative in SYNCED:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    return destination


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _unresolve_platform_entry(root: Path) -> None:
    """Put the lockfile's platform entry into the shape npm leaves when it could not resolve it.

    Whether the committed lockfile resolves the platform package depends on
    whether a release has been synced into the tree. A test about what an
    OFFLINE apply leaves behind must not depend on that, so it starts from the
    unresolved shape either way.
    """

    lock_path = root / "typescript" / "package-lock.json"
    lock = json.loads(lock_path.read_text())
    lock["packages"]["node_modules/@kleos-research/kaleidoscope-darwin-arm64"] = {"optional": True}
    lock_path.write_text(json.dumps(lock, indent=2) + "\n")


def _build_release(directory: Path, *, contract_bytes: bytes | None = None) -> Path:
    """A release-assets directory shaped exactly like the engine's release job writes it."""

    directory.mkdir(parents=True)
    (directory / "instructions").mkdir()
    contract = directory / "kaleidoscope-public-contract.json"
    if contract_bytes is None:
        # The committed contract, re-labelled with the fixture's version: the
        # sync holds `product.version` to the manifest's `release_version`,
        # and what the committed contract says its version is depends on
        # which release, if any, has been synced into the tree.
        document = json.loads((ROOT / "reference" / "kaleidoscope-public-contract.json").read_text())
        document["product"]["version"] = FIXTURE_VERSION
        # And with the fixture's platform. The fixture publishes a darwin-arm64
        # executable only, and the sync requires the platform a contract
        # describes to be among the published executables. The committed
        # contract describes whichever build the real release's contract was
        # generated from -- darwin-arm64 at 0.0.5, linux-x64 at 0.0.7 -- so
        # leaving it untouched ties these tests to one release's build host.
        document["target"] = {"triple": "aarch64-apple-darwin"}
        contract_bytes = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    contract.write_bytes(contract_bytes)
    (directory / "kaleidoscope-public-contract.provenance.json").write_text(
        json.dumps(
            {"schema_version": "kaleidoscope.public-contract-provenance.v1"},
            indent=2,
        )
        + "\n"
    )
    (directory / "kscope-help.txt").write_text("kscope --help, fixture stand-in\n")
    instructions = {
        "skill": ("instructions/SKILL.md", ROOT / "skills" / "use-kaleidoscope" / "SKILL.md"),
        "agents": ("instructions/AGENTS.md", ROOT / "snippets" / "AGENTS.md"),
        "claude": ("instructions/CLAUDE.md", ROOT / "snippets" / "CLAUDE.md"),
        "cursor": ("instructions/cursor-kaleidoscope.mdc", ROOT / "snippets" / "cursor-kaleidoscope.mdc"),
    }
    for relative, source in instructions.values():
        shutil.copyfile(source, directory / relative)

    manifest = {
        "schema_version": "kaleidoscope.release-manifest.v1",
        "release_version": FIXTURE_VERSION,
        "source_commit": hashlib.sha1(b"fixture engine commit").hexdigest(),
        "released_on": "2026-08-30",
        "availability": "available_with_key",
        "channels": {
            "npm": {
                "entry_package": "@kleos-research/kaleidoscope",
                "platform_packages": {"darwin-arm64": "@kleos-research/kaleidoscope-darwin-arm64"},
            }
        },
        "platforms": [
            {
                "slug": "darwin-arm64",
                "os": "macOS",
                "architecture": "Apple Silicon",
                "triple": "aarch64-apple-darwin",
                "built": True,
                "published": True,
                "native_build_runner": True,
            }
        ],
        "executables": {
            "darwin-arm64": {"sha256": FIXTURE_PUBLISHED_SHA256, "bytes": FIXTURE_PUBLISHED_BYTES}
        },
        "public_contract": {
            "path": "kaleidoscope-public-contract.json",
            "sha256": _digest(contract),
            "schema_version": "kaleidoscope.public-contract.v1",
            "mcp_protocol_revision": "2025-11-25",
        },
        "cli_help": {"path": "kscope-help.txt", "sha256": _digest(directory / "kscope-help.txt")},
        "instruction_assets": {
            key: {"path": relative, "sha256": _digest(directory / relative)}
            for key, (relative, _) in instructions.items()
        },
    }
    (directory / "release.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return directory


def test_the_committed_tree_passes_the_offline_check() -> None:
    completed = _run("--check", root=ROOT)
    assert completed.returncode == 0, completed.stderr


def test_one_changed_byte_in_the_vendored_contract_fails_the_check_by_name(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path / "repository")
    contract = root / "reference" / "kaleidoscope-public-contract.json"
    original = contract.read_bytes()
    # The last byte is the trailing newline; flipping it to a space keeps the
    # file parseable, so the failure has to come from the digest and not from
    # a JSON decoder doing the check's job for it.
    assert original.endswith(b"\n")
    contract.write_bytes(original[:-1] + b" ")

    completed = _run("--check", root=root)
    assert completed.returncode == 1
    assert "reference/kaleidoscope-public-contract.json" in completed.stderr
    assert "public_contract_sha256" in completed.stderr
    # The message points at the regeneration path, not at the file to edit.
    assert "--apply --release" in completed.stderr


def test_a_platform_pin_that_drifts_from_the_release_version_fails_the_check(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path / "repository")
    release = _build_release(tmp_path / "release-assets")
    assert _apply(release, root).returncode == 0

    package = root / "typescript" / "package.json"
    text = package.read_text()
    assert f'"@kleos-research/kaleidoscope-darwin-arm64": "{FIXTURE_VERSION}"' in text
    package.write_text(
        text.replace(
            f'"@kleos-research/kaleidoscope-darwin-arm64": "{FIXTURE_VERSION}"',
            '"@kleos-research/kaleidoscope-darwin-arm64": "9.9.9"',
        )
    )

    completed = _run("--check", root=root)
    assert completed.returncode == 1
    assert "typescript/package.json" in completed.stderr
    assert "9.9.9" in completed.stderr
    # The lockfile still says the release version, so the pair is reported too.
    assert "typescript/package-lock.json" in completed.stderr


def test_apply_takes_the_release_whole_and_leaves_a_tree_the_check_accepts(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path / "repository")
    _unresolve_platform_entry(root)
    release = _build_release(tmp_path / "release-assets")
    before_package = json.loads((root / "typescript" / "package.json").read_text())

    completed = _apply(release, root)
    assert completed.returncode == 0, completed.stderr
    checked = _run("--check", root=root)
    assert checked.returncode == 0, checked.stderr
    # The lockfile's platform entry was left unresolved on purpose, and the
    # check says so without counting it: resolving it is a registry read.
    assert "does not resolve" in checked.stdout

    contract_asset = release / "kaleidoscope-public-contract.json"
    vendored = root / "reference" / "kaleidoscope-public-contract.json"
    assert vendored.read_bytes() == contract_asset.read_bytes()

    pin = json.loads((root / "reference" / "binary-pin.json").read_text())
    manifest = json.loads((release / "release.json").read_text())
    contract = json.loads(contract_asset.read_text())
    assert pin["source_commit"] == manifest["source_commit"]
    assert pin["public_contract_sha256"] == _digest(vendored)
    assert pin["mcp_protocol_revision"] == manifest["public_contract"]["mcp_protocol_revision"]
    assert pin["release_version"] == FIXTURE_VERSION
    # The two executable digests, kept apart. `sha256` is the contract's: the
    # ungated build the contract was generated from. `published_executables`
    # is the manifest's: what the platform package carries. Writing the second
    # into the first would satisfy the golden tests and describe nothing.
    assert pin["sha256"] == contract["executable"]["sha256"]
    assert pin["isolated_distribution_candidate_sha256"] == pin["sha256"]
    assert pin["published_executables"] == manifest["executables"]
    assert pin["published_executables"]["darwin-arm64"]["sha256"] != pin["sha256"]
    # The manifest carries no shared vault runtime digest, so the field is the
    # one the tree had before.
    committed = json.loads((ROOT / "reference" / "binary-pin.json").read_text())
    assert pin["shared_vault_runtime_sha256"] == committed["shared_vault_runtime_sha256"]

    package = json.loads((root / "typescript" / "package.json").read_text())
    lock = json.loads((root / "typescript" / "package-lock.json").read_text())
    assert package["optionalDependencies"] == {
        "@kleos-research/kaleidoscope-darwin-arm64": FIXTURE_VERSION
    }
    assert lock["packages"][""]["optionalDependencies"] == package["optionalDependencies"]
    # Whether the client adopts the engine's version line is a product decision
    # the sync script does not make; see its module docstring.
    assert package["version"] == before_package["version"]
    # Nothing but the pin lines changed. The single-line `files` array and
    # everything else the file says are as they were. (A subset rather than an
    # equality: when the committed tree already carries this release's version,
    # the sync is a no-op there, and that is correct.)
    changed = {
        key for key in set(package) | set(before_package) if package.get(key) != before_package.get(key)
    }
    assert changed <= {"optionalDependencies"}


def test_a_lockfile_that_resolves_the_platform_package_at_another_version_fails_the_check(
    tmp_path: Path,
) -> None:
    root = _copy_tree(tmp_path / "repository")
    release = _build_release(tmp_path / "release-assets")
    assert _apply(release, root).returncode == 0

    lock_path = root / "typescript" / "package-lock.json"
    lock = json.loads(lock_path.read_text())
    # What `npm install --package-lock-only` would have written, at a version
    # that is not the release's.
    lock["packages"]["node_modules/@kleos-research/kaleidoscope-darwin-arm64"] = {
        "version": "9.9.9",
        "optional": True,
    }
    lock_path.write_text(json.dumps(lock, indent=2) + "\n")

    completed = _run("--check", root=root)
    assert completed.returncode == 1
    assert "typescript/package-lock.json" in completed.stderr
    assert "9.9.9" in completed.stderr


def test_apply_refuses_a_release_whose_asset_digest_disagrees_and_writes_nothing(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path / "repository")
    before = {relative: (root / relative).read_bytes() for relative in SYNCED}
    release = _build_release(tmp_path / "release-assets")
    # The manifest was computed over the original contract; the asset now
    # differs from what the manifest says it is.
    contract = release / "kaleidoscope-public-contract.json"
    contract.write_bytes(contract.read_bytes()[:-1] + b" ")

    completed = _apply(release, root)
    assert completed.returncode == 1
    assert "kaleidoscope-public-contract.json" in completed.stderr
    assert "nothing was written" in completed.stderr
    assert {relative: (root / relative).read_bytes() for relative in SYNCED} == before


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("source_commit", "not-a-commit", "source_commit"),
        ("schema_version", "kaleidoscope.release-manifest.v0", "schema_version"),
        ("released_on", "yesterday", "released_on"),
    ],
)
def test_apply_refuses_a_malformed_manifest(
    tmp_path: Path, field: str, value: str, expected: str
) -> None:
    root = _copy_tree(tmp_path / "repository")
    release = _build_release(tmp_path / "release-assets")
    manifest_path = release / "release.json"
    manifest = json.loads(manifest_path.read_text())
    manifest[field] = value
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    completed = _apply(release, root)
    assert completed.returncode == 1
    assert expected in completed.stderr
