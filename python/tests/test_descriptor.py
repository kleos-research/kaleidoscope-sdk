from __future__ import annotations

import json
from pathlib import Path

import pytest

from kaleidoscope_memory.descriptor import (
    LaunchDescriptor,
    executable_sha256,
    load_launch_descriptor,
)
from kaleidoscope_memory.errors import DescriptorError, MissingBinaryError


def valid_mapping(command: Path) -> dict[str, object]:
    return {
        "version": 1,
        "transport": "stdio",
        "command": str(command),
        "args": ["mcp", "--profile", "test"],
        "tools": ["search", "remember"],
        "environment": {},
    }


def test_accepts_only_the_closed_v1_shape(fake_binary: Path) -> None:
    descriptor = LaunchDescriptor.from_mapping(valid_mapping(fake_binary))
    assert descriptor.profile == "test"
    assert descriptor.stdio_parameters() == {
        "command": str(fake_binary),
        "args": ["mcp", "--profile", "test"],
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("version", 2),
        ("transport", "http"),
        ("args", ["mcp", "ROOT", "WORKSPACE", "PRINCIPAL", "JOURNAL"]),
        ("tools", ["search", "remember", "feedback"]),
        ("environment", {"API_TOKEN": "must-not-pass"}),
    ],
)
def test_rejects_shape_drift(fake_binary: Path, field: str, value: object) -> None:
    mapping = valid_mapping(fake_binary)
    mapping[field] = value
    with pytest.raises(DescriptorError):
        LaunchDescriptor.from_mapping(mapping)


def test_rejects_extra_coordinate_field(fake_binary: Path) -> None:
    mapping = valid_mapping(fake_binary)
    mapping["workspace_id"] = "wsp_forbidden"
    with pytest.raises(DescriptorError):
        LaunchDescriptor.from_mapping(mapping)


def test_loads_profile_with_digest_pin_and_no_secret_inheritance(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KALEIDOSCOPE_TEST_SECRET", "must-not-reach-child")
    descriptor = load_launch_descriptor(
        fake_binary,
        "test",
        expected_sha256=executable_sha256(fake_binary),
    )
    assert descriptor.command == str(fake_binary)
    assert descriptor.environment == {}


def test_rejects_wrong_binary_digest(fake_binary: Path) -> None:
    with pytest.raises(DescriptorError, match="SHA-256"):
        load_launch_descriptor(fake_binary, "test", expected_sha256="0" * 64)


def test_json_rejects_non_object(fake_binary: Path) -> None:
    del fake_binary
    with pytest.raises(DescriptorError, match="must be an object"):
        LaunchDescriptor.from_json(json.dumps([]))


def test_missing_binary_has_a_stable_error_category(tmp_path: Path) -> None:
    with pytest.raises(MissingBinaryError) as missing:
        load_launch_descriptor(tmp_path / "absent-kscope", "test")
    assert missing.value.code == "missing_binary"
