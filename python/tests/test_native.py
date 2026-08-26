from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Mapping

import pytest

from kaleidoscope_memory.acquisition import ControllerTurn
from kaleidoscope_memory.descriptor import load_launch_descriptor
from kaleidoscope_memory.errors import (
    DuplicateSearchError,
    NativeRefusalError,
    OutputLimitError,
    ProtocolError,
)
from kaleidoscope_memory.native import (
    Controller,
    Operator,
    load_profile,
    mcp_stdio_config,
    schema,
)

REFERENCE = Path(__file__).parents[2] / "reference"


def native_golden() -> dict[str, Any]:
    return json.loads((REFERENCE / "native-controller-golden.json").read_text())


@pytest.mark.asyncio
async def test_controller_returns_parsed_native_json(fake_binary: Path) -> None:
    descriptor = load_launch_descriptor(fake_binary, "native")
    golden = native_golden()
    result = await Controller(descriptor).search_raw(golden["request"])
    assert result == golden["success"]


@pytest.mark.asyncio
async def test_pre_response_crash_retries_once_with_identical_payload(
    fake_binary: Path, tmp_path: Path
) -> None:
    descriptor = load_launch_descriptor(fake_binary, "native")
    marker = tmp_path / "crash-count"
    arguments = {"_fixture_mode": "crash_once", "marker": str(marker), "query": "same bytes"}
    result = await Controller(descriptor, timeout_seconds=2).search_raw(arguments)
    encoded = json.dumps(arguments, sort_keys=True, separators=(",", ":")).encode()
    import hashlib

    assert result["invocation"] == native_golden()["retry"]["maximum_attempts"]
    assert result["payload_sha256"] == hashlib.sha256(encoded).hexdigest()
    assert marker.read_text() == "2"


@pytest.mark.asyncio
async def test_uncertain_timeout_retries_once_inside_original_deadline(
    fake_binary: Path, tmp_path: Path
) -> None:
    descriptor = load_launch_descriptor(fake_binary, "native")
    marker = tmp_path / "timeout-count"
    result = await Controller(descriptor, timeout_seconds=1).search_raw(
        {"_fixture_mode": "timeout_once", "marker": str(marker)}
    )
    assert result["invocation"] == 2
    assert marker.read_text() == "2"


@pytest.mark.asyncio
async def test_native_refusal_and_protocol_error_are_not_retried(
    fake_binary: Path, tmp_path: Path
) -> None:
    descriptor = load_launch_descriptor(fake_binary, "native")
    refusal_marker = tmp_path / "refusal-count"
    with pytest.raises(NativeRefusalError) as refusal:
        await Controller(descriptor).remember_raw(
            {"_fixture_mode": "refuse", "marker": str(refusal_marker)}
        )
    assert refusal.value.response == {"status": "refused", "code": "invalid_schema"}
    assert refusal_marker.read_text() == "1"

    invalid_marker = tmp_path / "invalid-count"
    with pytest.raises(ProtocolError):
        await Controller(descriptor).search_raw(
            {"_fixture_mode": "invalid_json", "marker": str(invalid_marker)}
        )
    assert invalid_marker.read_text() == "1"


@pytest.mark.asyncio
async def test_non_json_arguments_fail_before_process_launch(fake_binary: Path) -> None:
    descriptor = load_launch_descriptor(fake_binary, "native")
    with pytest.raises(ProtocolError, match="closed JSON"):
        await Controller(descriptor).search_raw({"query": float("nan")})
    with pytest.raises(ProtocolError, match="closed JSON"):
        await Controller(descriptor).search_raw({"query": {"not-json"}})


@pytest.mark.asyncio
async def test_stderr_flood_is_bounded_and_not_retried(fake_binary: Path, tmp_path: Path) -> None:
    descriptor = load_launch_descriptor(fake_binary, "native")
    marker = tmp_path / "flood-count"
    with pytest.raises(OutputLimitError):
        await Controller(descriptor, stderr_limit=1024).search_raw(
            {"_fixture_mode": "stderr_flood", "marker": str(marker)}
        )
    assert marker.read_text() == "1"


@pytest.mark.asyncio
async def test_cancellation_terminates_the_child(fake_binary: Path, tmp_path: Path) -> None:
    descriptor = load_launch_descriptor(fake_binary, "native")
    marker = tmp_path / "cancel-count"
    task = asyncio.create_task(
        Controller(descriptor, timeout_seconds=10).search_raw(
            {"_fixture_mode": "sleep", "marker": str(marker)}
        )
    )
    for _ in range(50):
        if marker.exists() and marker.read_text() == "1":
            break
        await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert marker.read_text() == "1"


@pytest.mark.asyncio
async def test_operator_is_explicit_and_has_no_automatic_retry(fake_binary: Path) -> None:
    descriptor = load_launch_descriptor(fake_binary, "native")
    result = await Operator(descriptor).call("doctor", {})
    assert result["operation"] == "doctor"
    with pytest.raises(ValueError, match="operator"):
        await Operator(descriptor).call("search", {})


def test_load_profile_and_stdio_config_share_the_profile_descriptor(fake_binary: Path) -> None:
    descriptor = load_launch_descriptor(fake_binary, "native")
    profile = load_profile(fake_binary, "native")
    assert profile.name == descriptor.profile
    assert mcp_stdio_config(descriptor) == {
        "command": str(fake_binary),
        "args": ["mcp", "--profile", "native"],
    }
    assert schema(fake_binary, "search") == "fixture schema search\n"
    with pytest.raises(ValueError, match="unknown public operation"):
        schema(fake_binary, "not-public")


class CountingController:
    def __init__(self) -> None:
        self.calls = 0

    async def search_raw(self, arguments: Mapping[str, Any]) -> Any:
        self.calls += 1
        return {"selected_hits": [], "query": arguments["query"]}


@pytest.mark.asyncio
async def test_controller_turn_proves_no_second_model_facing_search() -> None:
    controller = CountingController()
    turn = ControllerTurn(controller)
    assert await turn.search_raw_once({"query": "one"}) == {
        "selected_hits": [],
        "query": "one",
    }
    assert turn.model_mcp_tools == ("remember",)
    with pytest.raises(DuplicateSearchError):
        await turn.search_raw_once({"query": "two"})
    assert controller.calls == 1
