"""`conformance/gate_report_keys.py`: the contract's gate facts come from a live
`kscope gate`, checked or rewritten, and a rewrite touches nothing else.

The engine here is a stand-in that prints a gate report, so the test needs no
engine; the script is run against the pinned engine itself before a pin moves.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "conformance" / "gate_report_keys.py"
CONTRACT = ROOT / "reference" / "entitlement-contract-v1.json"
RECORDED = json.loads(CONTRACT.read_text(encoding="utf-8"))


def engine(tmp_path: Path, report: dict) -> Path:
    path = tmp_path / "kscope"
    path.write_text(
        f"#!{sys.executable}\nimport sys\nassert sys.argv[1:] == ['gate']\nprint({json.dumps(json.dumps(report))})\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def ungated(keys: list[str]) -> dict:
    values = {
        "status": "absent",
        "entitlement_build": False,
        "gated_commands": [],
        "entitlement_home": None,
        "key_file": None,
        "build_features": "bundled-model",
        "marker": RECORDED["gate_marker_absent"],
    }
    return {key: values.get(key, "extra") for key in keys}


def run(tmp_path: Path, report: dict, *flags: str) -> subprocess.CompletedProcess:
    contract = tmp_path / CONTRACT.name
    if not contract.exists():
        shutil.copyfile(CONTRACT, contract)
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--engine", str(engine(tmp_path, report)), "--contract", str(contract), *flags],
        capture_output=True,
        text=True,
        check=False,
    )


def test_an_engine_that_prints_the_recorded_keys_agrees(tmp_path: Path) -> None:
    result = run(tmp_path, ungated(RECORDED["gate_report_keys"]))
    assert result.returncode == 0, result.stdout + result.stderr


def test_a_key_the_engine_adds_is_a_difference(tmp_path: Path) -> None:
    result = run(tmp_path, ungated([*RECORDED["gate_report_keys"], "meaning"]))
    assert result.returncode == 1
    assert "gate_report_keys" in result.stdout


def test_write_takes_the_engines_keys_and_touches_nothing_else(tmp_path: Path) -> None:
    keys = [*RECORDED["gate_report_keys"], "meaning"]
    assert run(tmp_path, ungated(keys), "--write").returncode == 0
    written = (tmp_path / CONTRACT.name).read_text(encoding="utf-8")
    after = json.loads(written)
    assert after["gate_report_keys"] == keys
    assert {k: v for k, v in after.items() if k != "gate_report_keys"} == {
        k: v for k, v in RECORDED.items() if k != "gate_report_keys"
    }
    original = CONTRACT.read_text(encoding="utf-8").splitlines()
    changed = [line for line in written.splitlines() if line not in original]
    assert changed == ['    "marker",', '    "meaning"'], changed
    assert run(tmp_path, ungated(keys)).returncode == 0


def test_a_gated_engine_answers_for_its_marker_and_commands(tmp_path: Path) -> None:
    report = ungated(RECORDED["gate_report_keys"])
    report.update(
        status="enforcing",
        entitlement_build=True,
        gated_commands=RECORDED["gated_commands"],
        marker=RECORDED["gate_marker_present"],
    )
    assert run(tmp_path, report).returncode == 0
    report["gated_commands"] = [*RECORDED["gated_commands"], "search"]
    result = run(tmp_path, report)
    assert result.returncode == 1
    assert "gated_commands" in result.stdout
