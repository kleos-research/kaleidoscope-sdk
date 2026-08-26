#!/usr/bin/env python3
"""Exercise real persistent Python MCP sessions against one temporary profile."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from kaleidoscope_memory import (
    PersistentKaleidoscopeSession,
    load_launch_descriptor,
    load_profile,
    safe_bootstrap_environment,
)

FORBIDDEN_CHILD_KEYS = (
    "ANTHROPIC_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "KALEIDOSCOPE_TOKEN",
    "KSCOPE_JOURNAL",
    "KSCOPE_PRINCIPAL",
    "KSCOPE_PROFILE_HOME",
    "KSCOPE_ROOT",
    "KSCOPE_WORKSPACE",
    "OPENAI_API_KEY",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--profile", required=True)
    return parser.parse_args()


def matching_pids(engine: Path, profile: str) -> set[int]:
    completed = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,command="],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    marker = f"mcp --profile {profile}"
    matches: set[int] = set()
    for line in completed.stdout.splitlines():
        fields = line.strip().split(maxsplit=2)
        if len(fields) != 3:
            continue
        pid, _parent, command = fields
        if str(engine) in command and marker in command:
            matches.add(int(pid))
    return matches


def wait_for_pids(engine: Path, profile: str, expected: int) -> set[int]:
    deadline = time.monotonic() + 5
    observed: set[int] = set()
    while time.monotonic() < deadline:
        observed = matching_pids(engine, profile)
        if len(observed) == expected:
            return observed
        time.sleep(0.05)
    raise AssertionError(
        f"expected {expected} engine process(es) for the profile, observed {len(observed)}"
    )


async def run() -> dict[str, Any]:
    args = parse_args()
    engine = args.engine.resolve(strict=True)
    safe_environment = safe_bootstrap_environment()
    for key in FORBIDDEN_CHILD_KEYS:
        if key in safe_environment:
            raise AssertionError(f"safe child environment retained {key}")

    descriptor = load_launch_descriptor(
        engine,
        args.profile,
        expected_sha256=args.expected_sha256,
    )
    profile = load_profile(engine, args.profile)
    if profile.name != args.profile:
        raise AssertionError("profile lookup changed the requested profile")

    memory_id: str
    async with PersistentKaleidoscopeSession(descriptor) as session:
        first_pids = wait_for_pids(engine, args.profile, 1)
        remembered = await session.remember_text(
            {
                    "mode": "create",
                    "content_md": (
                        "# DX-10B persistent MCP probe\n\n"
                        "The local non-auth conformance probe retained one MCP process "
                        "for a complete controller run."
                    ),
                    "semantic_delta": {
                        "memory_type": "outcome",
                        "title": "DX-10B persistent MCP probe",
                        "entities": [
                            {
                                "n": "DX-10B conformance probe",
                                "kind": "artifact",
                                "is": "the local non-auth SDK conformance probe",
                            },
                            {
                                "n": "persistent MCP session",
                                "kind": "capability",
                                "is": "one initialized stdio MCP process retained across calls",
                            },
                        ],
                        "facts": [
                            {
                                "subject": "DX-10B conformance probe",
                                "predicate": "uses",
                                "object": "persistent MCP session",
                                "mode": "fact",
                                "basis": "stated",
                                "confidence": 0.99,
                            }
                        ],
                        "evidence": [
                            {
                                "kind": "test",
                                "reference": "local DX-10B non-auth conformance runner",
                            }
                        ],
                        "scope": {
                            "project": "kaleidoscope-sdk",
                            "artifact": "dx10b-local-conformance",
                        },
                    },
            }
        )
        first_line = remembered.splitlines()[0] if remembered.splitlines() else ""
        memory_id_value = first_line.removeprefix("Created | ")
        if not memory_id_value.startswith("mem_"):
            raise AssertionError("remember response omitted its stable memory_id")
        memory_id = memory_id_value
        ranked = await session.search_text(
            {
                "query": "DX-10B persistent MCP session",
                "top_k": 5,
                "maximum_context_bytes": 8192,
                "ledger": True,
            }
        )
        if (
            f"Memory 1 | {memory_id} |" not in ranked
            or "# DX-10B persistent MCP probe" not in ranked
        ):
            raise AssertionError("ranked search did not select the created memory")
        addressed = await session.search_text({"memory_id": memory_id})
        if not addressed.startswith(f"Memory | {memory_id}\n"):
            raise AssertionError("addressed search did not return the created memory")
    wait_for_pids(engine, args.profile, 0)

    async with PersistentKaleidoscopeSession(descriptor) as session:
        second_pids = wait_for_pids(engine, args.profile, 1)
        if first_pids == second_pids:
            raise AssertionError("MCP restart reused the terminated process identity")
        addressed = await session.search_text({"memory_id": memory_id})
        if not addressed.startswith(f"Memory | {memory_id}\n"):
            raise AssertionError("memory did not survive the MCP host restart")
        await session.search_text(
            {
                "query": "DX-10B controller restart persistence",
                "top_k": 5,
                "maximum_context_bytes": 8192,
                "ledger": True,
            }
        )
    wait_for_pids(engine, args.profile, 0)

    return {
        "calls": 5,
        "memory_id": memory_id,
        "processes_distinct": True,
        "restart_persisted": True,
        "sessions": 2,
        "teardown": True,
        "tools": ["search", "remember"],
    }


def main() -> int:
    result = asyncio.run(run())
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
