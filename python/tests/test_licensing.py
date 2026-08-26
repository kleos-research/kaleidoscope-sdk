"""The licence claim and the licence file must not be able to disagree.

WHY LICENSE IS NOT EDITED AND THE COPYRIGHT LINE LIVES IN NOTICE

LICENSE is the Apache License 2.0 verbatim, including its unfilled Appendix
("Copyright [yyyy] [name of copyright owner]"). That is deliberate. The
Appendix is a template the licence supplies for people applying it to their own
work, not a blank for the licensor to fill in. Editing it makes the file
diverge byte-for-byte from the canonical text that licence-detection tooling
matches against, for no legal gain.

The identifying copyright line therefore lives in NOTICE, which Section 4(d)
obliges every downstream redistributor to carry forward -- and NOTICE is kept
short for that same reason: everything added to it becomes a permanent burden
on everyone who ever redistributes this code. Maintainer rationale goes here,
in the test that fails when someone "fixes" LICENSE, not in the file that
propagates forever.

test_root_license_is_the_full_apache_2_text is the test that will go red.

THE DEFECT THESE TESTS EXIST TO PREVENT

The defect these tests exist to prevent is specific and has already happened
once in this project: a commit titled "license public SDK surfaces under
Apache-2.0" set `license = "Apache-2.0"` in three manifests. Metadata that
asserts a licence with no file behind it is worse than no claim at all, because
every downstream tool -- pip, npm, GitHub's licence detector, an SBOM generator
-- reports the claim and none of them checks it.

So: assert the files exist, assert the four claims agree, and assert each
distributable package actually ships the files it claims.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]

# The one spelling of the holder, used everywhere it appears. Exact-matched
# rather than pattern-matched: two spellings of one holder is the same class of
# defect as a claim with no holder, and a regex would accept both.
COPYRIGHT_HOLDER = "Kleos Research"
COPYRIGHT_LINE = "Copyright 2026 Kleos Research"

# The first line of the Apache-2.0 body, used as a cheap identity check. A file
# that merely mentions Apache is not the licence; this line only appears in it.
APACHE_TITLE = "Apache License"
APACHE_VERSION_LINE = "Version 2.0, January 2004"
APACHE_SPDX = "Apache-2.0"


def _licence_text(path: Path) -> str:
    assert path.is_file(), f"{path.relative_to(ROOT)} is claimed in metadata but does not exist"
    return path.read_text(encoding="utf-8")


def test_root_license_is_the_full_apache_2_text() -> None:
    text = _licence_text(ROOT / "LICENSE")
    assert APACHE_TITLE in text
    assert APACHE_VERSION_LINE in text
    # Section 9 is the last numbered section; its presence proves the file is
    # the whole licence and not an excerpt or a summary.
    assert "9. Accepting Warranty or Additional Liability" in text
    assert "http://www.apache.org/licenses/LICENSE-2.0" in text
    # The unfilled Appendix. Its presence is the evidence that nobody has
    # "helpfully" personalised the canonical text; see this module's docstring.
    assert "APPENDIX: How to apply the Apache License to your work." in text
    assert "Copyright [yyyy] [name of copyright owner]" in text
    # A summary, a stub or a truncation would pass every substring check above
    # if it happened to quote the right lines. The length would not.
    assert len(text) > 10_000, "LICENSE is too short to be the full licence text"


def test_every_package_copy_of_the_license_is_byte_identical_to_the_root() -> None:
    root = (ROOT / "LICENSE").read_bytes()
    for copy in (ROOT / "python" / "LICENSE", ROOT / "typescript" / "LICENSE"):
        assert copy.is_file(), f"{copy.relative_to(ROOT)} is missing"
        assert copy.read_bytes() == root, (
            f"{copy.relative_to(ROOT)} has drifted from the root LICENSE. "
            "Package copies exist so the licence travels in the published "
            "artefact; a copy that differs is a second source of truth."
        )


def test_notice_carries_a_copyright_line_and_the_engine_boundary() -> None:
    text = _licence_text(ROOT / "NOTICE")
    # Section 4(d) obliges redistributors to carry this forward, so it has to
    # name a holder and a year rather than the licence Appendix's
    # "[yyyy] [name of copyright owner]" template. Exact-matched, so a
    # placeholder year or a second spelling of the holder fails here.
    assert COPYRIGHT_LINE in text, (
        f"NOTICE must carry the copyright line {COPYRIGHT_LINE!r} verbatim; it "
        "is the only place in an Apache-2.0 distribution that names the holder"
    )
    # The whole point of publishing this tree is that the engine stays closed.
    # If NOTICE stops saying so, the Apache grant reads as covering the engine.
    flat = " ".join(text.split())
    assert "kscope" in text
    assert "does NOT cover" in flat
    assert "closed source" in flat
    assert "kscope licences" in flat, (
        "NOTICE must point at the engine's own in-executable attribution rather "
        "than appear to cover it"
    )
    assert "not part of this repository" in flat, (
        "NOTICE must state that the engine is outside this repository and outside "
        "the Apache grant"
    )


def test_every_package_copy_of_the_notice_is_byte_identical_to_the_root() -> None:
    root = (ROOT / "NOTICE").read_bytes()
    for copy in (ROOT / "python" / "NOTICE", ROOT / "typescript" / "NOTICE"):
        assert copy.is_file(), f"{copy.relative_to(ROOT)} is missing"
        assert copy.read_bytes() == root


def test_the_four_license_claims_agree_on_apache_2() -> None:
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text())
    pyproject = tomllib.loads((ROOT / "python" / "pyproject.toml").read_text())
    package_json = json.loads((ROOT / "typescript" / "package.json").read_text())
    conformance = json.loads((ROOT / "conformance" / "package.json").read_text())

    assert cargo["package"]["license"] == APACHE_SPDX
    assert pyproject["project"]["license"] == APACHE_SPDX
    assert package_json["license"] == APACHE_SPDX
    assert conformance["license"] == APACHE_SPDX
    # And the root file they are all claiming.
    assert APACHE_TITLE in (ROOT / "LICENSE").read_text()


def test_every_license_claim_names_a_copyright_holder() -> None:
    """A licence names terms; only a holder makes them enforceable.

    This is the half of the original defect that survived it. `9ed39bd` set
    `license = "Apache-2.0"` in three manifests and added the licence text, and
    for a while afterwards not one file in the tree -- manifest, NOTICE or
    source header -- said who held the copyright in it. Terms with no holder are
    a claim nobody can act on.

    Exact equality on one settled spelling, in every manifest, because "Kleos
    Research" and "Kleos Research Ltd" in two files is a second source of truth
    and a regex would accept both.
    """

    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text())
    pyproject = tomllib.loads((ROOT / "python" / "pyproject.toml").read_text())
    package_json = json.loads((ROOT / "typescript" / "package.json").read_text())
    conformance = json.loads((ROOT / "conformance" / "package.json").read_text())

    assert cargo["package"]["authors"] == [COPYRIGHT_HOLDER]
    assert [author["name"] for author in pyproject["project"]["authors"]] == [
        COPYRIGHT_HOLDER
    ]
    assert package_json["author"] == COPYRIGHT_HOLDER
    assert conformance["author"] == COPYRIGHT_HOLDER
    # And the one file Section 4(d) forces downstream to carry.
    assert COPYRIGHT_LINE in (ROOT / "NOTICE").read_text()


def test_each_published_package_declares_the_files_its_metadata_claims() -> None:
    """The DECLARATION half. The two tests after it are the delivery half.

    This one reads `license-files` and `files` and checks the named files exist.
    That is not proof of delivery -- `files` is an allowlist a typo fails open,
    and a build backend can drop a declared licence file without erroring. The
    name of this test used to say "ships", which is the substitution this
    module's docstring exists to forbid.
    """

    pyproject = tomllib.loads((ROOT / "python" / "pyproject.toml").read_text())
    declared = pyproject["project"]["license-files"]
    # An empty declaration would make the loop below iterate zero times and the
    # test pass while shipping nothing. Assert the content, then the files.
    assert declared, "pyproject declares no license-files at all"
    assert declared == ["LICENSE", "NOTICE"], declared
    for name in declared:
        assert (ROOT / "python" / name).is_file(), (
            f"pyproject declares license-files entry {name!r} but python/{name} does not exist; "
            "hatchling would build a wheel whose declared licence file is absent"
        )

    package_json = json.loads((ROOT / "typescript" / "package.json").read_text())
    shipped = package_json["files"]
    assert shipped, "typescript/package.json declares no files at all"
    for name in ("LICENSE", "NOTICE"):
        assert name in shipped, (
            f"typescript/package.json declares license {APACHE_SPDX} but does not list {name} "
            "in files, so the published tarball would omit it"
        )
        assert (ROOT / "typescript" / name).is_file()


def test_third_party_notices_names_every_directly_declared_dependency() -> None:
    """The drift guard that needs no toolchain.

    `scripts/third_party_notices.py --check` is the exact check, but it needs
    cargo. This one needs nothing, and it catches the failure that actually
    happens: somebody adds a dependency and does not regenerate the notices.
    Direct dependencies only -- transitives move on their own and are the
    generator's business, not this test's.
    """

    notices = _licence_text(ROOT / "THIRD_PARTY_NOTICES.md")

    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text())
    rust_direct = set(cargo.get("dependencies", {}))
    for table in cargo.get("target", {}).values():
        rust_direct |= set(table.get("dependencies", {}))

    package_json = json.loads((ROOT / "typescript" / "package.json").read_text())
    npm_direct = set(package_json.get("dependencies", {}))

    pyproject = tomllib.loads((ROOT / "python" / "pyproject.toml").read_text())
    python_direct = {
        re.split(r"[<>=!;\[ ]", requirement, maxsplit=1)[0]
        for requirement in pyproject["project"]["dependencies"]
    }
    python_direct = {name for name in python_direct if not name.startswith("kaleidoscope-memory-native")}

    declared = rust_direct | npm_direct | python_direct
    # Three manifests that between them declare nothing would make the
    # comprehension below empty and this test green. They do not; assert it.
    assert declared, "no direct dependency was read out of any of the three manifests"

    missing = sorted(name for name in declared if f"`{name}`" not in notices)
    assert not missing, (
        "THIRD_PARTY_NOTICES.md does not name these directly declared dependencies: "
        f"{missing}. Regenerate it: python3 scripts/third_party_notices.py"
    )


def test_third_party_notices_states_the_engine_is_out_of_scope() -> None:
    notices = _licence_text(ROOT / "THIRD_PARTY_NOTICES.md")
    assert "kscope licences" in notices, (
        "the engine carries its own attribution inside the executable; the "
        "notices file must point at it rather than appear to cover it"
    )
    assert "proprietary" in notices


# The Rust table's own preamble claims every row is object code that ships. The
# generator can only honour that claim by filtering, and the filter is the part
# that silently rots: `cargo metadata` with no `--filter-platform` resolves the
# union over every platform cargo knows, and a walk that follows proc-macro
# edges picks up a build-time closure. Both mistakes produce a *larger* table
# that looks more thorough and is wrong in the direction of over-claiming.
#
# Named in both directions so neither half can be satisfied by accident: seven
# crates that must be absent, three that must be present. A gutted table fails
# the second half; an unfiltered one fails the first.
LINKS_ON_NO_SHIPPED_TARGET = (
    "wasi",
    "wasm-bindgen",
    "android_system_properties",
    "r-efi",
    "hermit-abi",
    "uds_windows",
    # This crate's only dev-dependency. Reachable as a *normal* dependency of
    # uds_windows, so an unfiltered walk lists it as shipped object code.
    "tempfile",
)

BUILD_TIME_ONLY = ("syn", "quote", "proc-macro2", "unicode-ident")

LINKS_ON_EVERY_SHIPPED_TARGET = ("serde", "ring", "subtle")


def _rust_table_rows() -> list[str]:
    """The Rust table's rows only -- the npm and PyPI tables are separate."""

    lines = _licence_text(ROOT / "THIRD_PARTY_NOTICES.md").splitlines()
    start = next(
        index for index, line in enumerate(lines) if line.startswith("| Crate | Version |")
    )
    rows = []
    for line in lines[start + 2 :]:
        if not line.startswith("| `"):
            break
        rows.append(line)
    assert rows, "the Rust table in THIRD_PARTY_NOTICES.md has no rows at all"
    return rows


def _rust_crate_names() -> set[str]:
    return {row.split("`")[1] for row in _rust_table_rows()}


def test_the_rust_table_is_filtered_to_shipped_targets() -> None:
    listed = _rust_crate_names()

    for name in LINKS_ON_EVERY_SHIPPED_TARGET:
        assert name in listed, (
            f"THIRD_PARTY_NOTICES.md does not list `{name}`, which links into every "
            "shipped target. The table has been gutted, not filtered."
        )

    unshipped = sorted(name for name in LINKS_ON_NO_SHIPPED_TARGET if name in listed)
    assert not unshipped, (
        f"THIRD_PARTY_NOTICES.md lists {unshipped}, which link on no target this "
        "project ships. `cargo metadata` was run without --filter-platform. "
        "Regenerate: python3 scripts/third_party_notices.py"
    )

    build_only = sorted(name for name in BUILD_TIME_ONLY if name in listed)
    assert not build_only, (
        f"THIRD_PARTY_NOTICES.md lists {build_only}, which are reachable only "
        "through a proc-macro and link into a build-time plugin rather than the "
        "manager binary. The generator's proc-macro traversal cut was removed."
    )


def test_third_party_notices_says_which_targets_the_rust_table_covers() -> None:
    """A number in a table is only checkable if the table says what it counts.

    The three triples are the definition of the row set. Without them a reader
    cannot tell an under-filtered table from an over-filtered one, and neither
    can a reviewer.
    """

    notices = _licence_text(ROOT / "THIRD_PARTY_NOTICES.md")
    for triple in (
        "aarch64-apple-darwin",
        "x86_64-unknown-linux-gnu",
        "x86_64-pc-windows-msvc",
    ):
        assert triple in notices, (
            f"the Rust preamble does not name {triple}, so the table's scope is "
            "unstated"
        )


@pytest.mark.skipif(
    sys.version_info < (3, 11),
    reason="scripts/third_party_notices.py needs tomllib (Python 3.11+)",
)
def test_the_notices_generator_check_mode_agrees_with_the_committed_file() -> None:
    """The exact check, as opposed to the drift check above.

    Needs cargo on PATH. Skipped -- visibly, with a reason -- when it is absent,
    because a green suite on a machine with no toolchain must not be read as
    evidence that this ran.
    """

    script = ROOT / "scripts" / "third_party_notices.py"
    completed = subprocess.run(
        [sys.executable, str(script), "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0 and "cargo" in (completed.stderr or "").lower():
        pytest.skip(f"cargo unavailable: {completed.stderr.strip().splitlines()[-1]}")
    assert completed.returncode == 0, (
        "THIRD_PARTY_NOTICES.md has drifted from the manifests.\n"
        f"stdout: {completed.stdout}\nstderr: {completed.stderr}"
    )
    assert "matches the manifests" in completed.stdout


def test_the_built_wheel_actually_contains_the_licence_files() -> None:
    """The delivery half for Python: open the artefact, not the manifest.

    Skipped -- visibly -- when no build backend is importable, because a green
    suite on a machine that cannot build a wheel must not be read as evidence
    that a wheel was inspected.
    """

    import tempfile
    import zipfile

    with tempfile.TemporaryDirectory() as directory:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "build",
                "--wheel",
                "--no-isolation",
                "--outdir",
                directory,
                str(ROOT / "python"),
            ],
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            combined = f"{completed.stdout}\n{completed.stderr}".lower()
            for absent in ("hatchling", "no module named", "modulenotfounderror"):
                if absent in combined:
                    pytest.skip(
                        "no importable build backend for a --no-isolation wheel build"
                    )
            pytest.fail(f"wheel build failed:\n{completed.stdout}\n{completed.stderr}")

        wheels = sorted(Path(directory).glob("*.whl"))
        assert len(wheels) == 1, f"expected exactly one wheel, got {wheels}"
        with zipfile.ZipFile(wheels[0]) as archive:
            names = archive.namelist()

    for name in ("LICENSE", "NOTICE"):
        assert any(
            entry.endswith(f".dist-info/licenses/{name}") for entry in names
        ), (
            f"the built wheel does not carry {name}; pyproject declares it in "
            f"license-files but the artefact does not ship it. Entries: {names}"
        )


def test_the_npm_tarball_actually_contains_the_licence_files() -> None:
    """The delivery half for npm, read out of `npm pack` rather than `files`.

    The engine's own packaging script says why, in a comment on this exact
    field: `files` is an allowlist and a typo in it fails open. So the tarball
    member list is re-derived instead of trusted.
    """

    completed = subprocess.run(
        ["npm", "pack", "--dry-run", "--json"],
        cwd=ROOT / "typescript",
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        pytest.skip(f"npm unavailable or refused: {(completed.stderr or '').strip()[:200]}")

    payload = json.loads(completed.stdout)
    members = {entry["path"] for entry in payload[0]["files"]}
    assert members, "npm pack reported a tarball with no members"

    for name in ("LICENSE", "NOTICE"):
        assert name in members, (
            f"the npm tarball does not carry {name}; package.json claims "
            f"{APACHE_SPDX} and the published artefact would omit the licence. "
            f"Members: {sorted(members)}"
        )
