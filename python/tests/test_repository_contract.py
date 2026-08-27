from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).parents[2]


def test_repository_contains_no_local_path_vault_identity_or_secret_poison() -> None:
    subprocess.run([sys.executable, ROOT / "scripts" / "poison_scan.py"], check=True)


def test_generated_public_contract_keeps_retired_operations_out_of_mcp() -> None:
    contract = json.loads((ROOT / "reference" / "kaleidoscope-public-contract.json").read_text())
    assert contract["release_assessment"] == {
        "bundled_model_required": True,
        "release_readiness_claimed": False,
        "status": "contract_only",
    }
    tools = {tool["name"] for tool in contract["mcp"]["tools"]}
    operator_only = set(contract["cli"]["operator_only_commands"])
    retired = set(contract["retired_operations"]["agent_tools"])
    assert tools == {"search", "remember"}
    assert not tools & operator_only
    assert not tools & retired


# Split from one function into two, because the two halves stopped describing
# the same mechanism. The Python client LOCATES a separately installed `kscope`
# at run time; the TypeScript client still resolves a platform companion
# package through `require`. Nothing in reference/ pins that, so no golden
# breaks -- but a divergence belongs in a test NAME, where the next reader meets
# it, rather than inside one assertion block that claims the two agree.


def test_the_python_facade_declares_no_native_companion_dependency() -> None:
    """The absence is the assertion.

    `kaleidoscope-memory-native-darwin-arm64` was a MANDATORY dependency here.
    Nothing in either repository built it and no index carried the name, so the
    facade could not resolve at all -- and a required name that resolves to
    nothing on a public index is a name somebody else can claim. It was removed;
    this test is what stops it, or any sibling of it, coming back.
    """

    python = tomllib.loads((ROOT / "python" / "pyproject.toml").read_text())
    declared = python["project"]["dependencies"]

    assert declared == ["mcp>=1.28.1,<3"], (
        "the Python client drives a separately installed `kscope`; it must not "
        f"declare a native payload dependency. Declared: {declared}"
    )
    for group, requirements in python["project"].get("optional-dependencies", {}).items():
        offenders = [item for item in requirements if "kaleidoscope" in item]
        assert not offenders, (
            f"optional-dependencies.{group} names {offenders}; an unregistered name "
            f"is the same squatting target in an extra as in `dependencies`"
        )


def test_registry_facades_share_one_final_name_and_version() -> None:
    python = tomllib.loads((ROOT / "python" / "pyproject.toml").read_text())
    typescript = json.loads((ROOT / "typescript" / "package.json").read_text())

    assert python["project"]["name"] == "kscope-memory"
    assert python["project"]["version"] == "0.1.0rc1"
    assert python["project"]["scripts"] == {
        "kaleidoscope": "kaleidoscope_memory.cli:manager_main",
        "kscope": "kaleidoscope_memory.cli:engine_main",
    }

    assert typescript["name"] == "@kleos-research/kaleidoscope"
    assert typescript["version"] == "0.1.0-rc.1"
    assert typescript["private"] is True
    assert typescript["bin"] == {
        "kaleidoscope": "./bin/kaleidoscope.js",
        "kscope": "./bin/kscope.js",
    }
    assert typescript["optionalDependencies"] == {
        "@kleos-research/kaleidoscope-darwin-arm64": "0.1.0-rc.1"
    }
