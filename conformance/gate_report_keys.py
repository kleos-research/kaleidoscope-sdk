#!/usr/bin/env python3
"""The gate facts in reference/entitlement-contract-v2.json, taken from the engine.

The engine owns what `kscope gate` prints, and its own tests hold the command
to that shape. This repository's record of it -- the
contract's `gate_report_keys`, and the marker and gated commands a build
reports -- is checked against a live `kscope gate` of the pinned engine, or
rewritten from one, and never edited by hand:

    python3 conformance/gate_report_keys.py --engine /absolute/path/to/kscope
    python3 conformance/gate_report_keys.py --engine /absolute/path/to/kscope --write

The first exits 1 naming each fact the engine disagrees with; the second takes
the engine's answer into the contract, touching no other byte of the file. An
ungated engine answers for `gate_report_keys` and `gate_marker_absent`; a gated
one for `gate_report_keys`, `gate_marker_present` and `gated_commands`. Run it
with both builds of an engine release before moving `binary-pin.json` to it.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "reference" / "entitlement-contract-v2.json"


def gate_report(engine: Path) -> dict:
    """`kscope gate`, run with nothing in the environment but a PATH, as the
    engine's own test and its release checks run it."""
    with tempfile.TemporaryDirectory() as scratch:
        completed = subprocess.run(
            [str(engine), "gate"],
            capture_output=True,
            env={"PATH": "/usr/bin:/bin"},
            cwd=scratch,
            timeout=30,
            check=False,
        )
    if completed.returncode != 0:
        raise SystemExit(f"{engine} gate exited {completed.returncode}: {completed.stderr.decode(errors='replace')}")
    report = json.loads(completed.stdout)
    if not isinstance(report, dict) or not isinstance(report.get("entitlement_build"), bool):
        raise SystemExit(f"{engine} gate did not print a gate report: {completed.stdout[:300]!r}")
    return report


def facts(report: dict) -> dict:
    """The contract's gate facts, as this engine states them."""
    stated = {"gate_report_keys": list(report)}
    if report["entitlement_build"]:
        stated["gate_marker_present"] = report["marker"]
        stated["gated_commands"] = list(report["gated_commands"])
    else:
        stated["gate_marker_absent"] = report["marker"]
    return stated


def render(key: str, value: object) -> str:
    """One top-level member in the contract's own layout: two spaces, and a
    list one string per line at four."""
    if isinstance(value, list):
        items = ",\n".join(f"    {json.dumps(item)}" for item in value)
        return f'  "{key}": [\n{items}\n  ]'
    return f'  "{key}": {json.dumps(value)}'


def rewrite(text: str, stated: dict, name: str) -> str:
    original = text
    for key, value in stated.items():
        member = re.compile(r'^  "' + re.escape(key) + r'": (?:\[\n(?:    "[^"\n]*",?\n)*  \]|"[^"\n]*")', re.MULTILINE)
        if len(member.findall(text)) != 1:
            raise SystemExit(f"{name}: `{key}` is not one member in the layout this script writes")
        text = member.sub(lambda _: render(key, value), text)
    before, after = json.loads(original), json.loads(text)
    changed = {k for k in set(before) | set(after) if before.get(k) != after.get(k)}
    if not changed <= set(stated):
        raise SystemExit(f"a rewrite reached {sorted(changed - set(stated))}; nothing was written")
    return text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--engine", type=Path, required=True, help="the kscope to ask")
    parser.add_argument("--write", action="store_true", help="take the engine's answer into the contract")
    parser.add_argument("--contract", type=Path, default=CONTRACT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    stated = facts(gate_report(args.engine))
    contract = args.contract
    text = contract.read_text(encoding="utf-8")
    recorded = json.loads(text)
    differ = {key: value for key, value in stated.items() if recorded.get(key) != value}
    if args.write:
        if differ:
            contract.write_text(rewrite(text, differ, contract.name), encoding="utf-8")
        print(f"{contract.name}: {', '.join(sorted(differ)) or 'nothing'} taken from {args.engine}")
        return 0
    for key, value in differ.items():
        print(f"{contract.name}: {key} is {json.dumps(recorded.get(key))}, {args.engine} gate says {json.dumps(value)}")
    if not differ:
        print(f"{contract.name} agrees with {args.engine} gate on {', '.join(sorted(stated))}")
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
