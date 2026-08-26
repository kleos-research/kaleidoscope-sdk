from __future__ import annotations

import asyncio
import hashlib
import json
import tomllib
from pathlib import Path

import pytest

from kaleidoscope_memory.acquisition import refused_batch_items
from kaleidoscope_memory.descriptor import LaunchDescriptor
from kaleidoscope_memory.errors import (
    ChildProcessError,
    DeadlineExceededError,
    DescriptorError,
    DuplicateSearchError,
    EntitlementError,
    MissingBinaryError,
    ManagerCommandError,
    NativeRefusalError,
    OutputLimitError,
    ProtocolError,
    ToolRefusalError,
)
from kaleidoscope_memory.host_configs import (
    render_claude_code_config,
    render_codex_config,
    render_cursor_config,
    render_opencode_beta_v2_config,
    render_opencode_stable_v1_config,
)

REFERENCE = Path(__file__).parents[2] / "reference"


def _json(name: str) -> object:
    return json.loads((REFERENCE / name).read_text())


def _descriptor(command: Path) -> tuple[LaunchDescriptor, dict[str, object]]:
    template = _json("dx03-launch-descriptor.template.json")
    assert isinstance(template, dict)
    instantiated = {**template, "command": str(command)}
    return LaunchDescriptor.from_mapping(instantiated), template


def _normalize(value: object, command: str) -> object:
    if value == command:
        return "__KSCOPE_BINARY__"
    if isinstance(value, list):
        return [_normalize(item, command) for item in value]
    if isinstance(value, dict):
        return {key: _normalize(item, command) for key, item in value.items()}
    return value


def test_python_consumes_the_shared_descriptor_template_and_binary_pin(fake_binary: Path) -> None:
    descriptor, template = _descriptor(fake_binary)
    pin = _json("binary-pin.json")
    contract = _json("kaleidoscope-public-contract.json")
    assert isinstance(pin, dict)
    assert isinstance(contract, dict)
    assert _normalize(descriptor.as_dict(), descriptor.command) == template
    assert len(pin["source_commit"]) == 40
    assert set(pin["source_commit"]) <= set("0123456789abcdef")
    assert len(pin["sha256"]) == 64
    assert set(pin["sha256"]) <= set("0123456789abcdef")
    assert len(pin["shared_vault_runtime_sha256"]) == 64
    assert pin["isolated_distribution_candidate_sha256"] == pin["sha256"]
    assert len(pin["isolated_distribution_candidate_sha256"]) == 64
    assert contract["executable"]["sha256"] == pin["sha256"]
    contract_bytes = (REFERENCE / "kaleidoscope-public-contract.json").read_bytes()
    assert hashlib.sha256(contract_bytes).hexdigest() == pin["public_contract_sha256"]


def test_python_host_renderers_match_the_shared_golden(fake_binary: Path) -> None:
    descriptor, _ = _descriptor(fake_binary)
    golden = _json("host-config-golden.json")
    assert isinstance(golden, dict)
    assert _normalize(json.loads(render_claude_code_config(descriptor)), descriptor.command) == golden["claude_code"]
    assert _normalize(json.loads(render_cursor_config(descriptor)), descriptor.command) == golden["cursor"]
    assert _normalize(json.loads(render_opencode_stable_v1_config(descriptor)), descriptor.command) == golden["opencode_stable_v1"]
    assert _normalize(json.loads(render_opencode_beta_v2_config(descriptor)), descriptor.command) == golden["opencode_beta_v2"]

    codex = tomllib.loads(render_codex_config(descriptor))["mcp_servers"]["kaleidoscope"]
    expected = golden["codex"]
    for key in (
        "enabled",
        "required",
        "startup_timeout_sec",
        "tool_timeout_sec",
        "enabled_tools",
        "default_tools_approval_mode",
    ):
        assert codex[key] == expected[key]
    assert codex["tools"]["search"]["approval_mode"] == expected["search_approval_mode"]


def test_python_error_classes_match_the_shared_category_golden() -> None:
    fixture = _json("error-categories-v1.json")
    assert isinstance(fixture, dict)
    categories = fixture["categories"]
    classes = {
        "invalid_descriptor": DescriptorError,
        "missing_binary": MissingBinaryError,
        "child_crash": ChildProcessError,
        "manager_command": ManagerCommandError,
        "deadline_exceeded": DeadlineExceededError,
        "output_limit": OutputLimitError,
        "protocol_contract": ProtocolError,
        "native_refusal": NativeRefusalError,
        "duplicate_search": DuplicateSearchError,
        "tool_refusal": ToolRefusalError,
        "entitlement": EntitlementError,
    }
    for code, cls in classes.items():
        assert cls.__name__ == categories[code]["python"]
        assert cls.code == code
    assert categories["cancelled"]["python"] == f"asyncio.{asyncio.CancelledError.__name__}"
    # Without this equality the golden and the implementation are only checked
    # in one direction: adding a category to error-categories-v1.json and
    # implementing it in TypeScript alone failed no test at all. `cancelled` is
    # the one category with no class of its own on this side.
    assert set(categories) - {"cancelled"} == set(classes)


def test_python_selects_only_index_aligned_refused_batch_items() -> None:
    fixture = _json("partial-batch-golden.json")
    assert isinstance(fixture, dict)
    request = fixture["request"]
    response = fixture["response"]
    assert isinstance(request, dict)
    assert isinstance(response, dict)
    selected = refused_batch_items(request, response)
    assert selected == [request["items"][index] for index in fixture["refused_indexes"]]


def test_python_refuses_misaligned_batch_results() -> None:
    with pytest.raises(ProtocolError, match="align"):
        refused_batch_items({"items": [{}, {}]}, {"results": [{"status": "created"}]})
