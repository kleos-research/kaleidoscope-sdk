from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

CONFORMANCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CONFORMANCE))

import run_dx10b_hosts as lane  # noqa: E402


class HostConformanceUnitTests(unittest.TestCase):
    def test_exact_tools_accepts_order_independent_pair(self) -> None:
        result = lane.extract_exact_tool_names(
            {"result": {"tools": [{"name": "remember"}, {"name": "search"}]}}
        )
        self.assertEqual(result, ["search", "remember"])

    def test_exact_tools_rejects_extra_tool(self) -> None:
        with self.assertRaisesRegex(AssertionError, "exactly"):
            lane.extract_exact_tool_names(
                {
                    "result": {
                        "tools": [
                            {"name": "remember"},
                            {"name": "search"},
                            {"name": "feedback"},
                        ]
                    }
                }
            )

    def test_codex_server_accepts_closed_stdio_descriptor(self) -> None:
        engine = Path("/opt/kaleidoscope/kscope")
        lane.validate_codex_server(
            {
                "name": "kaleidoscope",
                "enabled": True,
                "transport": {
                    "type": "stdio",
                    "command": str(engine),
                    "args": ["mcp", "--profile", "test"],
                    "env": None,
                    "env_vars": [],
                    "cwd": None,
                },
                "enabled_tools": None,
                "disabled_tools": None,
            },
            engine=engine,
            profile="test",
            includes_tools=True,
        )

    def test_codex_server_rejects_environment(self) -> None:
        engine = Path("/opt/kaleidoscope/kscope")
        with self.assertRaisesRegex(AssertionError, "divergent"):
            lane.validate_codex_server(
                {
                    "name": "kaleidoscope",
                    "enabled": True,
                    "transport": {
                        "type": "stdio",
                        "command": str(engine),
                        "args": ["mcp", "--profile", "test"],
                        "env": {"KSCOPE_ROOT": "forbidden"},
                        "env_vars": [],
                        "cwd": None,
                    },
                },
                engine=engine,
                profile="test",
                includes_tools=False,
            )

    def test_private_coordinate_is_rejected(self) -> None:
        with self.assertRaisesRegex(AssertionError, "raw vault identity"):
            lane.assert_private_values_absent(
                ["usr_" + "12345678-1234-1234-1234-123456789abc"],
                private_values=[],
            )

    def test_provenance_binds_manager_and_engine(self) -> None:
        manager_hash = "a" * 64
        engine_hash = "b" * 64
        value = {
            "predicate": {
                "buildDefinition": {
                    "resolvedDependencies": [
                        {
                            "uri": "urn:kaleidoscope:public-manager-source",
                            "digest": {"gitCommit": lane.SDK_SOURCE_COMMIT},
                        }
                    ]
                }
            },
            "subject": [
                {"name": "bin/kaleidoscope", "digest": {"sha256": manager_hash}},
                {
                    "name": "libexec/kaleidoscope/kscope",
                    "digest": {"sha256": engine_hash},
                },
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "provenance.json"
            path.write_text(json.dumps(value))
            digest = lane.validate_manager_provenance(
                path, manager_sha256=manager_hash, engine_sha256=engine_hash
            )
        self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_schema_pins_lane_and_promotion_hold(self) -> None:
        schema = json.loads((CONFORMANCE / "host-evidence.schema.json").read_text())
        self.assertEqual(
            schema["properties"]["schema_version"]["const"], lane.SCHEMA_VERSION
        )
        promotion = schema["properties"]["promotion"]["properties"]
        self.assertFalse(promotion["authorized"]["const"])
        self.assertFalse(promotion["release_readiness_claimed"]["const"])


if __name__ == "__main__":
    unittest.main()
