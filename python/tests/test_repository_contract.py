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


def test_registry_facades_share_one_final_name_version_and_native_coordinate() -> None:
    python = tomllib.loads((ROOT / "python" / "pyproject.toml").read_text())
    typescript = json.loads((ROOT / "typescript" / "package.json").read_text())

    assert python["project"]["name"] == "kaleidoscope-memory"
    assert python["project"]["version"] == "0.1.0rc1"
    assert python["project"]["scripts"] == {
        "kaleidoscope": "kaleidoscope_memory.cli:manager_main",
        "kscope": "kaleidoscope_memory.cli:engine_main",
    }
    assert (
        "kaleidoscope-memory-native-darwin-arm64==0.1.0rc1; "
        "sys_platform == 'darwin' and platform_machine == 'arm64'"
    ) in python["project"]["dependencies"]

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
