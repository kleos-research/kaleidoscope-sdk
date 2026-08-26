from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from kaleidoscope_memory.descriptor import (
    load_launch_descriptor,
    safe_bootstrap_environment,
)
from kaleidoscope_memory.native import load_profile, mcp_stdio_config
from kaleidoscope_memory.session import PersistentKaleidoscopeSession

ROOT = Path(__file__).parents[2]
REAL_BINARY = os.environ.get("KSCOPE_TEST_REAL_BINARY")
REAL_HOME = os.environ.get("KSCOPE_TEST_REAL_HOME")
REAL_PROFILE = os.environ.get("KSCOPE_TEST_REAL_PROFILE", "dx07-live")


@pytest.mark.skipif(
    not REAL_BINARY or not REAL_HOME,
    reason="set KSCOPE_TEST_REAL_BINARY and KSCOPE_TEST_REAL_HOME for the local binary lane",
)
@pytest.mark.asyncio
async def test_real_profile_resolves_through_home_without_inheriting_canaries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    assert REAL_BINARY is not None and REAL_HOME is not None
    canary = "dx07-secret-" + "canary-value"
    monkeypatch.setenv("HOME", REAL_HOME)
    monkeypatch.setenv("KSCOPE_PROFILE_HOME", str(tmp_path / "wrong-profile-home"))
    monkeypatch.setenv("OPENAI_API_KEY", canary)
    monkeypatch.setenv("ANTHROPIC_API_KEY", canary)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", canary)

    monkeypatch.setenv("KALEIDOSCOPE_API_KEY", "ksk_alpha." + "A" * 43)
    monkeypatch.setenv("KSCOPE_ENTITLEMENT_HOME", str(tmp_path / "entitlement"))
    monkeypatch.setenv("KSCOPE_ENTITLEMENT_PROBE", str(tmp_path / "attacker-probe"))

    child_environment = safe_bootstrap_environment()
    assert child_environment["HOME"] == REAL_HOME
    for forbidden in (
        "KSCOPE_PROFILE_HOME",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        # A KSCOPE_* entitlement-family name that is deliberately not admitted.
        "KSCOPE_ENTITLEMENT_PROBE",
        # Nothing consumes it: the engine fixes its control-plane origin when
        # it is built and constructs the environment of anything it spawns, so
        # an inherited value could not redirect it. It was admitted until an
        # audit went looking for a consumer and found none.
        "KALEIDOSCOPE_CONTROL_PLANE_ORIGIN",
    ):
        assert forbidden not in child_environment
        assert canary not in child_environment.values()
    # The TWO that ARE admitted, by name. (This comment said "three" while the
    # tuple held two, which is how the extra name went unnoticed for as long as
    # it did.)
    for expected in ("KALEIDOSCOPE_API_KEY", "KSCOPE_ENTITLEMENT_HOME"):
        assert expected in child_environment
    # This lane is skipped unless two variables are set, and a skipped test
    # reporting green is the defect class this repository names. The parity
    # assertions that must ALWAYS run live in tests/test_entitlement.py::
    # test_no_other_environment_variable_reaches_the_child; these are a bonus.

    pin = json.loads((ROOT / "reference" / "binary-pin.json").read_text())
    descriptor = load_launch_descriptor(
        REAL_BINARY,
        REAL_PROFILE,
        expected_sha256=pin["sha256"],
    )
    assert descriptor.environment == {}
    assert mcp_stdio_config(descriptor) == {
        "command": descriptor.command,
        "args": list(descriptor.args),
    }
    assert load_profile(REAL_BINARY, REAL_PROFILE).name == REAL_PROFILE

    async with PersistentKaleidoscopeSession(descriptor):
        pass
