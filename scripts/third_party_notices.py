#!/usr/bin/env python3
"""Regenerate THIRD_PARTY_NOTICES.md from the three dependency manifests.

The file this writes is an attribution notice, not an inventory of everything a
developer installs. It therefore lists what a *user* ends up with:

* Rust -- every crate whose object code is statically linked into the
  `kaleidoscope` manager binary that ships inside a platform package, unioned
  over `SHIPPED_TARGETS`. This is the only place where third-party source is
  genuinely redistributed by us, so it is the only place where the MIT/BSD/ISC
  attribution clauses bind us rather than the registry.
* npm and PyPI -- the declared runtime dependencies. Neither published package
  vendors them; both resolve them from the registry at install time, so the
  listing is disclosure rather than attribution. Said plainly in the output.

Build-only crates (proc macros, `build.rs` helpers), everything reachable only
through one of them, and dev-dependencies are excluded: none of them
contributes bytes to a shipped artefact.

Usage:

    export PATH="$HOME/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin:$PATH"
    python3 scripts/third_party_notices.py            # rewrite the file
    python3 scripts/third_party_notices.py --check    # exit 1 if it is stale

`--check` needs cargo. `python/tests/test_licensing.py` does not: it asserts the
weaker property that every directly declared dependency is named in the file,
which is the drift that actually happens (someone adds a dependency and forgets
the notice) and which is checkable with no toolchain at all.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError as missing:  # pragma: no cover - interpreter selection
    raise SystemExit(
        "third_party_notices.py needs Python 3.11+ for tomllib; "
        "the package itself declares requires-python >= 3.11. "
        "Run it with the same interpreter the test suite uses "
        "(python/.venv/bin/python)."
    ) from missing

ROOT = Path(__file__).resolve().parents[1]
NOTICES = ROOT / "THIRD_PARTY_NOTICES.md"

#: The target triples a platform package is built for. The Rust table is the
#: union over these, and only these. Adding a shipped platform means adding its
#: triple here and regenerating; the table is then wrong by exactly one build,
#: loudly, rather than silently over-claiming forever.
SHIPPED_TARGETS = (
    "aarch64-apple-darwin",
    "x86_64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
)

HEADER = """# Third-party notices

Apache-2.0 covers everything in this repository -- the Rust manager, the Python
package, the TypeScript package, the integration examples, the conformance
probes, the reference goldens and the agent skill. See `LICENSE` and `NOTICE`;
`NOTICE` carries the authoritative statement of scope.

This file covers the third-party software that code carries or depends on. It
does **not** cover the `kscope` memory engine or any other proprietary
object-code payload delivered in a platform package: those are not part of this
repository and are not Apache-2.0. They are not licensed by this repository at
all -- separate terms apply to them, and their own third-party notices travel
with the payload rather than with this file.

Regenerate with `python3 scripts/third_party_notices.py`. `--check` fails if the
committed file has drifted from the manifests.
"""

RUST_PREAMBLE = """## Rust -- statically linked into the `kaleidoscope` manager binary

These crates are compiled into the manager executable that ships inside a
platform package, so their object code is redistributed and their attribution
terms bind this project directly. A given build links the subset its platform
selects.

This table is the union over the three shipped target triples
(aarch64-apple-darwin, x86_64-unknown-linux-gnu, x86_64-pc-windows-msvc) of
every non-dev, non-build, non-proc-macro crate reachable from the manager's
root package. Proc-macro and build-dependency crates run at build time and
leave no bytes in the artefact, so they carry no distribution obligation and
are excluded. So do the crates reachable *only* through a proc-macro -- `syn`,
`quote`, `proc-macro2`, `unicode-ident` and the rest of that closure link into
a build-time plugin, never into the executable.

Two exclusions are easy to lose, and losing either produces a table that reads
correct and over-claims. Without `--filter-platform`, `cargo metadata` reports
the union over every platform it knows -- 246 crates -- including `wasi`,
`wasm-bindgen`, `android_system_properties` and, reached through
`uds_windows`, this crate's sole dev-dependency. Without the proc-macro
traversal cut it reports 173, the extra 16 being that build-time closure.
Over-attribution is legally safe and factually wrong, and this preamble makes a
claim about linkage that either set of rows falsifies. Both cuts are the
generator's, not a hand edit; regenerate rather than prune.

**Open obligation, recorded here so the platform-package build can see it.**
Several of these crates are MIT, BSD-2/3-Clause or ISC, and those licences
require their notice to travel with every copy of the object code -- not merely
with the source repository. A committed markdown file in a source tree does not
reach a user who installs a platform package. The engine carries the notices it
has inside the executable (`kscope licences`) and says in that same output that
its own Rust dependency notices are not embedded yet -- so it has the identical
open obligation, not a solution to copy. The `kaleidoscope` manager has no
equivalent command at all. Whoever assembles a platform package must place this
attribution beside or inside the manager binary. This file is the content; it is
not yet the delivery, on either side of the boundary.
"""

NPM_PREAMBLE = """## npm -- resolved at install time, not vendored

The published `@kleos-research/kaleidoscope` tarball contains only first-party
files ({npm_files}). The packages below are declared dependencies that npm
fetches from the registry into the user's `node_modules`; we redistribute none
of them. They are listed for disclosure.
"""

PYPI_PREAMBLE = """## PyPI -- resolved at install time, not vendored

The published `kaleidoscope-memory` wheel contains only `src/kaleidoscope_memory`.
The distributions below are declared dependencies that pip resolves from the
index; we redistribute none of them. Optional extras are marked. Licence strings
are not restated here because pip records the authoritative metadata in the
installed environment and a copy in this file would silently go stale.
"""

FOOTER = """## How to read a licence expression

The strings above are SPDX expressions copied verbatim from each package's own
metadata. `OR` means the package offers a choice and this project takes it under
whichever term applies; `AND` means every named licence applies at once. Full
licence texts are distributed with each package by its registry.
"""


def _is_proc_macro(package: dict) -> bool:
    return any(target.get("kind") == ["proc-macro"] for target in package.get("targets", ()))


def _crates_for_target(target: str) -> set[tuple[str, str, str, str]]:
    """The non-dev, non-build, non-proc-macro closure of the root, for one triple.

    `--filter-platform` is the load-bearing flag. Without it `cargo metadata`
    resolves the union over every platform it knows about, which for this crate
    is 246 packages rather than 173 -- `wasi`, `wasm-bindgen`,
    `android_system_properties`, `r-efi`, three `windows-sys` majors, and (via
    `uds_windows`) `tempfile`, which is a dev-dependency here and links into no
    shipped artefact at all. Over-attribution is legally safe and factually
    wrong, and the preamble makes a claim about linkage that those rows falsify.
    """

    completed = subprocess.run(
        [
            "cargo",
            "metadata",
            "--offline",
            "--format-version",
            "1",
            "--all-features",
            "--filter-platform",
            target,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    metadata = json.loads(completed.stdout)
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    root_id = next(
        package["id"]
        for package in metadata["packages"]
        if package["name"] == "kaleidoscope-manager"
    )

    reached: set[str] = set()
    frontier = [root_id]
    while frontier:
        current = frontier.pop()
        if current in reached:
            continue
        reached.add(current)
        for dependency in nodes[current]["deps"]:
            # A `dep_kinds` entry with `kind: null` is the normal kind. Build
            # and dev edges are skipped at *every* level, not just the root's:
            # a crate reachable only through one of them contributes no bytes.
            kinds = {(entry.get("kind") or "normal") for entry in dependency["dep_kinds"]}
            if "normal" not in kinds:
                continue
            if _is_proc_macro(packages[dependency["pkg"]]):
                continue
            frontier.append(dependency["pkg"])

    rows = set()
    for package_id in reached:
        package = packages[package_id]
        if package["name"] == "kaleidoscope-manager":
            continue
        if _is_proc_macro(package):
            continue
        rows.add(
            (
                package["name"],
                package["version"],
                package.get("license") or "see package metadata",
                package.get("repository") or "",
            )
        )
    return rows


def cargo_runtime_crates() -> list[tuple[str, str, str, str]]:
    """The union, over the shipped triples, of what links into the manager."""

    rows: set[tuple[str, str, str, str]] = set()
    for target in SHIPPED_TARGETS:
        rows |= _crates_for_target(target)
    return sorted(rows)


def npm_runtime_packages() -> list[tuple[str, str, str]]:
    lock = json.loads((ROOT / "typescript" / "package-lock.json").read_text())
    manifest = json.loads((ROOT / "typescript" / "package.json").read_text())
    first_party = set(manifest.get("optionalDependencies", {}))
    rows = set()
    for path, entry in lock.get("packages", {}).items():
        if not path or entry.get("dev"):
            continue
        name = path.split("node_modules/")[-1]
        if name in first_party:
            # Our own platform package. Covered by its own notices, not ours.
            continue
        rows.add((name, entry.get("version") or "", entry.get("license") or "see package metadata"))
    return sorted(rows)


def _requirement_name(requirement: str) -> str:
    return re.split(r"[<>=!~;\[ ]", requirement, maxsplit=1)[0].strip()


def pypi_runtime_distributions() -> list[tuple[str, str, str]]:
    """(distribution name, version constraint, role).

    The name is its own column deliberately. Rendering only the full
    requirement string would make `mcp>=1.28.1,<3` the entry for `mcp`, and the
    drift test in python/tests/test_licensing.py looks for the declared *name*.
    A notices file that names a dependency only inside a version expression is
    one a reader -- and a checker -- can miss.
    """

    project = tomllib.loads((ROOT / "python" / "pyproject.toml").read_text())["project"]
    rows: list[tuple[str, str, str]] = []
    for requirement in project.get("dependencies", ()):
        name = _requirement_name(requirement)
        if name.startswith("kaleidoscope-memory-native"):
            # Our own platform wheel. Covered by its own notices, not ours.
            continue
        rows.append((name, requirement[len(name) :].strip() or "any", "required"))
    for extra, requirements in sorted(project.get("optional-dependencies", {}).items()):
        for requirement in requirements:
            name = _requirement_name(requirement)
            rows.append((name, requirement[len(name) :].strip() or "any", f"extra: {extra}"))
    return rows


def render() -> str:
    lines: list[str] = [HEADER, "", RUST_PREAMBLE, ""]
    lines.append("| Crate | Version | Licence | Upstream |")
    lines.append("| --- | --- | --- | --- |")
    for name, version, licence, repository in cargo_runtime_crates():
        lines.append(f"| `{name}` | {version} | {licence} | {repository} |")

    manifest = json.loads((ROOT / "typescript" / "package.json").read_text())
    npm_files = ", ".join(f"`{name}`" for name in manifest["files"])
    lines += ["", NPM_PREAMBLE.format(npm_files=npm_files), ""]
    lines.append("| Package | Version | Licence |")
    lines.append("| --- | --- | --- |")
    for name, version, licence in npm_runtime_packages():
        lines.append(f"| `{name}` | {version} | {licence} |")

    lines += ["", PYPI_PREAMBLE, ""]
    lines.append("| Distribution | Constraint | Role |")
    lines.append("| --- | --- | --- |")
    for name, constraint, role in pypi_runtime_distributions():
        lines.append(f"| `{name}` | `{constraint}` | {role} |")

    lines += ["", FOOTER]
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail instead of rewriting")
    arguments = parser.parse_args()

    rendered = render()
    if arguments.check:
        current = NOTICES.read_text() if NOTICES.exists() else ""
        if current != rendered:
            print(
                f"{NOTICES.name} is stale; run: python3 scripts/third_party_notices.py",
                file=sys.stderr,
            )
            return 1
        print(f"{NOTICES.name} matches the manifests")
        return 0

    NOTICES.write_text(rendered)
    print(f"wrote {NOTICES.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
