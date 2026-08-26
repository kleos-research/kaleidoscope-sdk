"""Run several public calls through one stdio child and MCP session."""

from __future__ import annotations

import argparse
import asyncio

from kaleidoscope_memory.descriptor import load_launch_descriptor
from kaleidoscope_memory.session import PersistentKaleidoscopeSession


async def main(binary: str, profile: str, query: str, sha256: str | None) -> None:
    descriptor = load_launch_descriptor(binary, profile, expected_sha256=sha256)
    async with PersistentKaleidoscopeSession(descriptor) as memory:
        first = await memory.search_text({"query": query, "top_k": 8})
        second = await memory.search_text({"query": f"follow-up: {query}", "top_k": 8})
    print(first)
    print(second)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--profile", default="default")
    parser.add_argument("--query", required=True)
    parser.add_argument("--sha256")
    args = parser.parse_args()
    asyncio.run(main(args.binary, args.profile, args.query, args.sha256))
