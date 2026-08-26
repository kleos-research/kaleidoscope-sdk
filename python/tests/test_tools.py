"""`KaleidoscopeMemory`: lifecycle, refusals, and the schema rule.

The framework bindings themselves are exercised in `test_tool_bindings.py`.
This module covers the object: when it opens, what it refuses, and the one
property the whole design rests on -- that a tool schema comes from live MCP
discovery and never from a copy in this package.
"""

from __future__ import annotations

import asyncio
import json
import re
import tempfile
import threading
import uuid
from pathlib import Path

import pytest

from kaleidoscope_memory import KaleidoscopeMemory, ToolDefinition
from kaleidoscope_memory.errors import IntegrationError
from kaleidoscope_memory.tools import _MCP_GOVERNORS, _assert_mcp_pin

PACKAGE = Path(__file__).parents[1] / "src" / "kaleidoscope_memory"
VALID_KEY = "ksk_alpha." + "A" * 43


def _nonce() -> str:
    return uuid.uuid4().hex[:8]


def _starts(profile: str) -> Path:
    return Path(tempfile.gettempdir()) / f"{profile}.starts"


# ---------------------------------------------------------------------------
# The schema rule -- the only property that can catch a hand-written copy
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tool_schemas_come_from_discovery_not_from_source(
    fake_binary: Path, tmp_path: Path
) -> None:
    """Change the ENGINE's published schema; the built tools must change too.

    This is the only test in the suite that can see the schema rule being
    broken. A table written into `tools.py` would satisfy every other assertion
    here -- the names would be right, the tools would build, the calls would
    work -- and it could not follow the engine. So the fixture is edited to
    publish a renamed field and an altered description, and all three bindings
    are required to carry the change through.

    The edit is made to a COPY of the fixture in tmp_path, so the shared one is
    untouched for every other test.
    """

    source = fake_binary.read_text(encoding="utf-8")
    mutated = source.replace(
        "            query: str | None = None,\n"
        "            memory_id: str | None = None,\n"
        "            top_k: int | None = None,\n"
        "        ) -> str:\n"
        "            del memory_id, top_k\n",
        "            query: str | None = None,\n"
        "            mutated_field: str | None = None,\n"
        "        ) -> str:\n"
        '            """A DESCRIPTION ONLY THIS TEST WRITES."""\n'
        "            del mutated_field\n",
    )
    assert mutated != source, "the fixture moved; this test edits nothing"
    binary = tmp_path / "mutated_kscope.py"
    binary.write_text(mutated, encoding="utf-8")
    binary.chmod(0o755)

    async with KaleidoscopeMemory(binary=binary, profile=f"schema{_nonce()}") as memory:
        definitions = {d.name: d for d in memory.tool_definitions()}
        assert "mutated_field" in definitions["search"].input_schema["properties"]
        assert "A DESCRIPTION ONLY THIS TEST WRITES." in definitions["search"].description

        openai_tools = {t.name: t for t in memory.as_openai_tools()}
        assert "mutated_field" in openai_tools["search"].params_json_schema["properties"]
        assert "A DESCRIPTION ONLY THIS TEST WRITES." in openai_tools["search"].description

        langchain_tools = {t.name: t for t in memory.as_langchain_tools()}
        assert "mutated_field" in langchain_tools["search"].args_schema["properties"]
        assert "A DESCRIPTION ONLY THIS TEST WRITES." in langchain_tools["search"].description

    with KaleidoscopeMemory(binary=binary, profile=f"schemasync{_nonce()}") as memory:
        crew_tools = {t.name: t for t in memory.as_crewai_tools()}
        assert "mutated_field" in crew_tools["search"].args_schema.model_fields
        assert "A DESCRIPTION ONLY THIS TEST WRITES." in crew_tools["search"].description


def test_no_json_schema_literal_exists_in_the_package() -> None:
    """A static tripwire beside the dynamic one above.

    Not a substitute for it: this catches the OBVIOUS copy, the one written as a
    dict literal in this package. The discovery test catches the clever one.
    Both, because a hand-written schema does not know it has drifted, and one
    hand-written vocabulary line in this project's history produced 13,060
    proposals that were then analysed as evidence about agent behaviour.
    """

    forbidden = (
        '"properties"',
        '"inputSchema"',
        '"top_k"',
        '"semantic_delta"',
        '"content_md"',
        '"memory_type"',
        "'properties'",
        "'top_k'",
        "'semantic_delta'",
        "'content_md'",
    )
    offenders: list[str] = []
    for path in sorted(PACKAGE.glob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("*"):
                continue
            if "inputSchema" in line and "getattr(" in line:
                # READING the protocol's field name off a discovered tool is the
                # opposite of writing a schema: it is how the engine's own bytes
                # are picked up. Exempted by SHAPE rather than by file, so a dict
                # literal spelling `"inputSchema": {...}` anywhere -- including
                # in session.py -- still fires.
                continue
            if re.search(r'(?:\.get\(|\[)\s*"properties"\s*[,)\]]', line):
                # Same exemption, same shape rule: `schema.get("properties")` and
                # `schema["properties"]` READ a keyword off a schema the engine
                # published. `_without_synthesised_nulls` in tools.py does exactly
                # that so the CrewAI binding can ask the ENGINE which fields
                # accept null instead of carrying a list of its own.
                #
                # Narrow on purpose: the needle must sit in a read position. A
                # literal `{"properties": {...}}` writes `"properties":` and is
                # still an offender -- the falsifier at the bottom of this test
                # is exactly that string and still matches.
                continue
            for needle in forbidden:
                if needle in line:
                    offenders.append(f"{path.name}:{number}: {stripped[:70]}")

    assert offenders == [], offenders

    # The falsifier: the needles really do match a schema literal, so an empty
    # result is a finding rather than an empty search.
    planted = '{"properties": {"query": {"type": "string"}}}'
    assert any(needle in planted for needle in forbidden), "the needles match nothing"


# ---------------------------------------------------------------------------
# Refusals -- each asserted on the message, never on "something was raised"
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "builder",
    ["as_openai_tools", "as_langchain_tools", "as_langgraph_tools", "as_crewai_tools",
     "tool_definitions"],
)
def test_as_tools_outside_the_context_refuses(builder: str, fake_binary: Path) -> None:
    """Not an empty list. An agent built from `[]` has no memory and no error."""

    memory = KaleidoscopeMemory(binary=fake_binary)

    with pytest.raises(RuntimeError, match=re.escape("built from live MCP discovery")):
        getattr(memory, builder)()


@pytest.mark.asyncio
async def test_mcp_server_config_inside_the_context_refuses(fake_binary: Path) -> None:
    """The escape hatch is the ALTERNATIVE to opening, not an addition to it."""

    async with KaleidoscopeMemory(binary=fake_binary, profile=f"cfg{_nonce()}") as memory:
        with pytest.raises(RuntimeError, match="alternative to opening"):
            memory.mcp_server_config()


def test_mcp_server_config_outside_the_context_returns_the_narrow_door(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It spawns nothing, and the key rides the same allowlist."""

    from kaleidoscope_memory.descriptor import _SAFE_ENV_KEYS

    monkeypatch.setenv("OPENAI_API_KEY", "decoy")
    memory = KaleidoscopeMemory(binary=fake_binary, profile="cfg", api_key=VALID_KEY)

    config = memory.mcp_server_config()

    assert config["command"] == str(fake_binary)
    assert config["args"] == ["mcp", "--profile", "cfg"]
    assert config["env"]["KALEIDOSCOPE_API_KEY"] == VALID_KEY
    assert set(config["env"]) <= set(_SAFE_ENV_KEYS)
    assert "OPENAI_API_KEY" not in config["env"]


@pytest.mark.asyncio
async def test_sync_calls_under_async_with_refuse(fake_binary: Path) -> None:
    """Named refusals, and the async twins still work in the same block."""

    async with KaleidoscopeMemory(binary=fake_binary, profile=f"mode{_nonce()}") as memory:
        for call in (
            lambda: memory.search("x"),
            lambda: memory.remember(mode="create"),
            memory.as_crewai_tools,
        ):
            with pytest.raises(RuntimeError, match=re.escape("opened with `async with`")):
                call()
        # The positive control: the async half of the same object works, so the
        # refusals above are about the MODE and not about a broken session.
        assert json.loads(await memory.asearch("still fine"))["query"] == "still fine"


def test_async_helpers_work_under_plain_with(fake_binary: Path) -> None:
    """`asearch` is legal in both modes and must not touch the owned loop directly.

    The first draft awaited the session from the caller's loop here. It drove
    the stdio transport from two event loops at once and killed a working child
    with `anyio.BrokenResourceError`, several frames from anything that named
    the cause.
    """

    with KaleidoscopeMemory(binary=fake_binary, profile=f"bothmode{_nonce()}") as memory:
        first = json.loads(memory.search("sync"))
        second = json.loads(asyncio.run(memory.asearch("async")))

    assert first["pid"] == second["pid"], "the two routes reached different children"


@pytest.mark.asyncio
async def test_reentry_refuses(fake_binary: Path) -> None:
    memory = KaleidoscopeMemory(binary=fake_binary, profile=f"reentry{_nonce()}")
    async with memory:
        pass
    with pytest.raises(RuntimeError, match="not re-entrant"):
        async with memory:
            pass


def test_reentry_refuses_in_sync_mode_too(fake_binary: Path) -> None:
    memory = KaleidoscopeMemory(binary=fake_binary, profile=f"reentrys{_nonce()}")
    with memory:
        pass
    with pytest.raises(RuntimeError, match="not re-entrant"):
        with memory:
            pass


# ---------------------------------------------------------------------------
# The synchronous bridge
# ---------------------------------------------------------------------------


def test_the_sync_bridge_joins_its_thread(fake_binary: Path) -> None:
    """Thread SETS compared, not absence-of-exception.

    A daemon thread left running would pass a "no error" test while still owning
    the engine child, and an interpreter shutting down would kill it without
    closing the child cleanly. That is why the thread is non-daemon and why this
    compares the set before and after.
    """

    before = set(threading.enumerate())

    with KaleidoscopeMemory(binary=fake_binary, profile=f"thread{_nonce()}") as memory:
        during = set(threading.enumerate()) - before
        assert any(t.name == "kaleidoscope-memory" for t in during), "no owner thread"
        assert all(not t.daemon for t in during if t.name == "kaleidoscope-memory")
        memory.search("keep it busy")

    for _ in range(50):
        if set(threading.enumerate()) - before == set():
            break
        threading.Event().wait(0.05)
    assert set(threading.enumerate()) - before == set()


def test_the_sync_bridge_keeps_exactly_one_child_across_many_calls(
    fake_binary: Path,
) -> None:
    """Counted from INSIDE the children, not inferred from a pid comparison.

    `asyncio.run` per call would tear down and respawn the stdio child on every
    tool invocation. The fixture appends its pid to a file on every `mcp` start,
    so the line count is the number of engine processes this run created.
    """

    profile = f"spawn-count-{_nonce()}"
    marker = _starts(profile)
    marker.unlink(missing_ok=True)

    with KaleidoscopeMemory(binary=fake_binary, profile=profile) as memory:
        pids = {json.loads(memory.search(f"call {index}"))["pid"] for index in range(5)}

    assert len(marker.read_text(encoding="utf-8").splitlines()) == 1
    assert len(pids) == 1
    marker.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# The mcp pin guard
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("binding", sorted(_MCP_GOVERNORS))
def test_the_mcp_pin_guard_does_not_fire_on_the_real_installed_pair(binding: str) -> None:
    """The negative half. A guard that always fired would pass the other test."""

    _assert_mcp_pin(binding)


@pytest.mark.parametrize("binding", sorted(_MCP_GOVERNORS))
def test_an_mcp_version_mismatch_refuses_by_name(
    binding: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refusal naming both versions and the extra, not a warning.

    The alternative is what this replaces: the framework fails several frames
    later with a message that does not mention `mcp` at all.
    """

    monkeypatch.setattr(
        "kaleidoscope_memory.tools._installed_mcp_version", lambda: "0.1.0"
    )
    _, extra = _MCP_GOVERNORS[binding]

    with pytest.raises(IntegrationError) as caught:
        _assert_mcp_pin(binding)

    message = str(caught.value)
    assert "0.1.0" in message
    assert f"[{extra}]" in message
    assert "mcp" in message


def test_the_pin_guard_reads_the_frameworks_own_requirement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The falsifier for a table of versions written into this package.

    A hard-coded range would answer the same for any declared requirement. This
    replaces what the framework declares and requires the guard to follow it.
    """

    monkeypatch.setattr(
        "kaleidoscope_memory.tools._installed_mcp_version", lambda: "1.28.1"
    )
    monkeypatch.setattr(
        "importlib.metadata.requires",
        lambda name: ["mcp<1.0,>=0.9"] if name == "openai-agents" else [],
    )

    with pytest.raises(IntegrationError, match=re.escape("mcp<1.0,>=0.9")):
        _assert_mcp_pin("openai")


# ---------------------------------------------------------------------------
# Shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tool_definitions_are_the_engine_s_two_verbs_in_order(
    fake_binary: Path,
) -> None:
    async with KaleidoscopeMemory(binary=fake_binary, profile=f"defs{_nonce()}") as memory:
        definitions = memory.tool_definitions()

    assert [d.name for d in definitions] == ["search", "remember"]
    assert all(isinstance(d, ToolDefinition) for d in definitions)
    assert all(d.input_schema["type"] == "object" for d in definitions)


def test_as_langgraph_tools_is_the_same_object_as_as_langchain_tools() -> None:
    """Identity, not equality. A copied body would pass an equality test."""

    assert KaleidoscopeMemory.as_langgraph_tools is KaleidoscopeMemory.as_langchain_tools


@pytest.mark.asyncio
async def test_the_descriptor_loads_without_a_key_and_without_opening(
    fake_binary: Path,
) -> None:
    """`profile launch` is ungated, so this works with nothing configured."""

    memory = KaleidoscopeMemory(binary=fake_binary, profile="descr")

    descriptor = memory.descriptor

    assert descriptor.profile == "descr"
    assert descriptor.environment == {}
    assert memory.profile == "descr"
    assert memory.descriptor is descriptor, "the descriptor was not cached"
