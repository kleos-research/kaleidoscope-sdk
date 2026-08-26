"""The four framework bindings, driven by the real frameworks.

Every test here counts engine processes from INSIDE the children rather than
inferring one from a pid comparison, and every one drives the tools through the
framework's own machinery -- `Runner`/`FunctionTool.on_invoke_tool`,
`StructuredTool.ainvoke`, a compiled `StateGraph` with a `ToolNode`, and
CrewAI's `BaseTool.run` -- rather than calling our own invoker and asserting the
framework would have liked it.

**None of these tests may `importorskip`.** All four frameworks are installed in
the environment this suite runs in, and a skip here is the exact defect class
the spec exists to avoid: a framework test that passes vacuously because the
framework is absent. If one of these errors on import, that is the finding.
"""

from __future__ import annotations

import json
import tempfile
import uuid
from pathlib import Path

import pytest

from kaleidoscope_memory import KaleidoscopeMemory

VALID_KEY = "ksk_alpha." + "A" * 43
_KALEIDOSCOPE_LIKE = ("KALEIDOSCOPE_", "KSCOPE_")


def _nonce() -> str:
    return uuid.uuid4().hex[:8]


def _spawn_profile() -> tuple[str, Path]:
    """A profile the fixture appends its pid to on every `mcp` start."""

    profile = f"spawn-count-{_nonce()}"
    marker = Path(tempfile.gettempdir()) / f"{profile}.starts"
    marker.unlink(missing_ok=True)
    return profile, marker


def _children(marker: Path) -> int:
    return len(marker.read_text(encoding="utf-8").splitlines())


def _delta(title: str) -> dict:
    return {
        "memory_type": "architecture",
        "title": title,
        "facts": [{"subject": title, "predicate": "uses", "object": "Kaleidoscope"}],
    }


def _text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(
        isinstance(block, dict) and block.get("type") == "text" for block in value
    ):
        return "\n".join(block["text"] for block in value)
    raise AssertionError(f"unexpected tool content: {value!r}")


def _entitlement_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    from kaleidoscope_memory.entitlement import clear_gate_status_cache

    for name in list(__import__("os").environ):
        if name.startswith(_KALEIDOSCOPE_LIKE):
            monkeypatch.delenv(name, raising=False)
    directory = tmp_path / "entitlement"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "fixture-gate.json").write_text(
        json.dumps({"entitlement_build": True}), encoding="utf-8"
    )
    monkeypatch.setenv("KSCOPE_ENTITLEMENT_HOME", str(directory))
    clear_gate_status_cache()
    return directory


# ---------------------------------------------------------------------------
# OpenAI Agents SDK
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_openai_function_tools_reuse_one_session(fake_binary: Path) -> None:
    """Driven through the SDK's own `Runner` with a scripted model.

    The scripted model issues two tool calls and one message, so the assertion
    on `model.calls` proves the agent really used the tools rather than
    answering from nothing -- and the spawn count proves both calls landed in
    one engine process.
    """

    from agents import Agent, Runner, set_tracing_disabled
    from agents.testing import ScriptedModel, assistant_message, function_call

    set_tracing_disabled(True)
    profile, marker = _spawn_profile()
    model = ScriptedModel(
        [
            [
                function_call(
                    "remember",
                    {
                        "mode": "create",
                        "content_md": "# Agents binding\n\nStored through as_openai_tools.",
                        "semantic_delta": _delta("Agents binding"),
                    },
                    call_id="remember-1",
                )
            ],
            [function_call("search", {"query": "Agents binding"}, call_id="search-1")],
            [assistant_message("done")],
        ]
    )

    async with KaleidoscopeMemory(binary=fake_binary, profile=profile) as memory:
        tools = memory.as_openai_tools()
        assert [tool.name for tool in tools] == ["search", "remember"]
        assert all(tool.strict_json_schema is False for tool in tools), (
            "strict mode would force this SDK to edit the engine's schema"
        )
        agent = Agent(
            name="Memory-aware assistant",
            instructions="Use Kaleidoscope as the only durable memory owner.",
            model=model,
            tools=tools,
        )
        result = await Runner.run(agent, "exercise memory")

    model.assert_complete()
    assert result.final_output == "done"
    assert len(model.calls) == 3
    assert _children(marker) == 1
    marker.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_openai_tool_arguments_arrive_as_the_engine_sees_them(
    fake_binary: Path,
) -> None:
    """The Agents SDK hands arguments over as a JSON string; decode, do not guess."""

    async with KaleidoscopeMemory(binary=fake_binary, profile=f"oa{_nonce()}") as memory:
        search = {tool.name: tool for tool in memory.as_openai_tools()}["search"]
        answer = json.loads(await search.on_invoke_tool(None, json.dumps({"query": "hello"})))
    assert answer["query"] == "hello"


# ---------------------------------------------------------------------------
# LangChain
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_langchain_tools_keep_one_session(fake_binary: Path) -> None:
    from langchain_core.tools import StructuredTool

    profile, marker = _spawn_profile()

    async with KaleidoscopeMemory(binary=fake_binary, profile=profile) as memory:
        tools = memory.as_langchain_tools()
        assert all(isinstance(tool, StructuredTool) for tool in tools)
        by_name = {tool.name: tool for tool in tools}
        wrote = json.loads(
            _text(
                await by_name["remember"].ainvoke(
                    {
                        "mode": "create",
                        "content_md": "# LangChain binding\n\nStored through as_langchain_tools.",
                        "semantic_delta": _delta("LangChain binding"),
                    }
                )
            )
        )
        found = json.loads(_text(await by_name["search"].ainvoke({"query": "LangChain binding"})))

    assert wrote["pid"] == found["pid"]
    assert found["records"] == ["# LangChain binding\n\nStored through as_langchain_tools."]
    assert _children(marker) == 1
    marker.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_langchain_never_synthesises_a_schema_from_our_invoker(
    fake_binary: Path,
) -> None:
    """`infer_schema=False` is mandatory, and this is what it buys.

    Left True, LangChain introspects the `**kwargs` invoker and SYNTHESISES an
    args schema from it -- a hand-written second copy arrived at by accident.
    The falsifier is the assertion that the schema still carries the engine's
    own field names, which a synthesised one would spell `kwargs`.
    """

    async with KaleidoscopeMemory(binary=fake_binary, profile=f"lc{_nonce()}") as memory:
        definitions = {d.name: d for d in memory.tool_definitions()}
        tools = {tool.name: tool for tool in memory.as_langchain_tools()}

        for name, tool in tools.items():
            assert tool.args_schema is definitions[name].input_schema
            assert "kwargs" not in json.dumps(tool.args_schema)
        assert set(tools["search"].args_schema["properties"]) == set(
            definitions["search"].input_schema["properties"]
        )


# ---------------------------------------------------------------------------
# LangGraph
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_langgraph_tool_node_reuses_the_same_session(fake_binary: Path) -> None:
    """Through a compiled graph, because a bare `ToolNode.ainvoke` has no config.

    The graph is built and run INSIDE the context. `get_tools()`-style stateless
    clients respawn stdio per call; the context is the lifecycle boundary that
    keeps exactly one engine process alive across turns.
    """

    from langchain_core.messages import AIMessage
    from langgraph.graph import END, START, MessagesState, StateGraph
    from langgraph.prebuilt import ToolNode

    profile, marker = _spawn_profile()

    async with KaleidoscopeMemory(binary=fake_binary, profile=profile) as memory:
        tools = memory.as_langgraph_tools()
        builder = StateGraph(MessagesState)
        builder.add_node("tools", ToolNode(tools))
        builder.add_edge(START, "tools")
        builder.add_edge("tools", END)
        graph = builder.compile()

        outputs = []
        for index, (name, arguments) in enumerate(
            [
                (
                    "remember",
                    {
                        "mode": "create",
                        "content_md": "# LangGraph binding\n\nToolNode used our tools.",
                        "semantic_delta": _delta("LangGraph binding"),
                    },
                ),
                ("search", {"query": "LangGraph binding"}),
            ]
        ):
            state = await graph.ainvoke(
                {
                    "messages": [
                        AIMessage(
                            content="",
                            tool_calls=[
                                {
                                    "name": name,
                                    "args": dict(arguments),
                                    "id": f"call-{index}",
                                    "type": "tool_call",
                                }
                            ],
                        )
                    ]
                }
            )
            outputs.append(json.loads(_text(state["messages"][-1].content)))

    wrote, found = outputs
    assert wrote["pid"] == found["pid"]
    assert found["records"] == ["# LangGraph binding\n\nToolNode used our tools."]
    assert _children(marker) == 1
    marker.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# CrewAI
# ---------------------------------------------------------------------------


def test_crewai_reuses_one_stdio_process(fake_binary: Path) -> None:
    """CrewAI's own `BaseTool.run`, over the synchronous bridge."""

    from crewai.tools import BaseTool

    profile, marker = _spawn_profile()

    with KaleidoscopeMemory(binary=fake_binary, profile=profile) as memory:
        tools = memory.as_crewai_tools()
        assert all(isinstance(tool, BaseTool) for tool in tools)
        by_name = {tool.name: tool for tool in tools}
        assert set(by_name) == {"search", "remember"}
        wrote = json.loads(
            _text(
                by_name["remember"].run(
                    mode="create",
                    content_md="# CrewAI binding\n\nStored through as_crewai_tools.",
                    semantic_delta=_delta("CrewAI binding"),
                )
            )
        )
        found = json.loads(_text(by_name["search"].run(query="CrewAI binding")))

    assert wrote["pid"] == found["pid"]
    assert found["records"] == ["# CrewAI binding\n\nStored through as_crewai_tools."]
    assert _children(marker) == 1
    marker.unlink(missing_ok=True)


def test_crewai_survives_a_schema_whose_optional_fields_are_not_nullable(
    fake_binary: Path,
) -> None:
    """The engine's shape, not the fixture's, and this test is why the fixture grew one.

    `test_crewai_reuses_one_stdio_process` above DOES invoke, and it was green
    while every CrewAI `search` against the real engine was refused. It could
    not have caught it: the default fixture profile declares every optional
    field as `X | None = None`, so the nulls CrewAI's `_validate_kwargs`
    synthesises -- `model_validate(kwargs).model_dump()` renders EVERY field --
    were legal against it. The real engine declares
    `ledger: {"enum":[true],"type":"boolean"}` and answered

        {"code":"invalid_arguments",
         "message":"invalid type: null, expected a boolean at line 1 column 179"}

    on every call. The `strictopt` profile publishes that shape so this seam has
    a fixture that can fail.
    """

    profile = f"strictopt.{_nonce()}"
    with KaleidoscopeMemory(binary=fake_binary, profile=profile) as memory:
        schema = {d.name: d.input_schema for d in memory.tool_definitions()}["search"]
        # The control: the fixture really is publishing a NON-nullable optional,
        # so a binding that sends `ledger: null` is refused by it.
        assert schema["properties"]["ledger"]["type"] == "boolean"
        assert "null" not in json.dumps(schema["properties"]["ledger"])
        assert "ledger" not in schema.get("required", [])

        # And the same shape one level down, behind a `$ref` -- which is how
        # the engine publishes `semantic_delta`. A binding that pruned only
        # top-level nulls passed the `search` half above and was still refused
        # by the engine with `invalid type: null, expected a sequence`.
        delta_schema = {d.name: d.input_schema for d in memory.tool_definitions()}[
            "remember"
        ]
        reference = delta_schema["properties"]["semantic_delta"]["$ref"]
        assert reference.startswith("#/$defs/"), reference
        nested = delta_schema["$defs"][reference.rsplit("/", 1)[1]]
        assert nested["properties"]["facts"]["type"] == "array"
        assert "default" not in nested["properties"]["facts"]
        assert "facts" not in nested.get("required", [])

        tools = {tool.name: tool for tool in memory.as_crewai_tools()}
        answer = json.loads(_text(tools["search"].run(query="strict optionals")))
        nested_answer = json.loads(
            _text(tools["remember"].run(mode="create", semantic_delta={"memory_type": "note"}))
        )

    # Both went through, and each field the caller omitted took the ENGINE's
    # default rather than the null CrewAI invented -- at both depths.
    assert answer["query"] == "strict optionals"
    assert answer["ledger"] is True
    assert nested_answer["memory_type"] == "note"
    assert nested_answer["facts"] == []


def test_crewai_args_schema_is_built_from_the_engines_schema(fake_binary: Path) -> None:
    """CrewAI needs a pydantic model, so this is the one binding that converts.

    It converts with CREWAI'S OWN converter, fed the engine's schema unedited --
    not with one written here. CrewAI's comment says that function exists
    because mcpadapt's model creation adds invalid null values to field schemas,
    and a converter written here would rediscover that bug.
    """

    with KaleidoscopeMemory(binary=fake_binary, profile=f"crew{_nonce()}") as memory:
        definitions = {d.name: d for d in memory.tool_definitions()}
        tools = {tool.name: tool for tool in memory.as_crewai_tools()}

        for name, tool in tools.items():
            assert set(tool.args_schema.model_fields) == set(
                definitions[name].input_schema["properties"]
            )
            assert tool.description == definitions[name].description


# ---------------------------------------------------------------------------
# The key, through every binding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("binding", ["as_openai_tools", "as_langchain_tools", "as_langgraph_tools"])
async def test_a_code_key_reaches_the_child_through_every_async_binding(
    binding: str, fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The test that would have caught a half-wired key.

    If `api_key=` threads through the session but a binding still builds its
    tools against a nullary environment, the parameter works for a direct
    session and silently does nothing for the framework -- one API wearing two
    behaviours, with nothing that looks wrong from either side. So the probe
    runs THROUGH the binding rather than beside it.
    """

    _entitlement_home(monkeypatch, tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "decoy-openai")

    async with KaleidoscopeMemory(
        binary=fake_binary, profile=f"gated.{_nonce()}", api_key=VALID_KEY
    ) as memory:
        search = {tool.name: tool for tool in getattr(memory, binding)()}["search"]
        if binding == "as_openai_tools":
            raw = await search.on_invoke_tool(None, json.dumps({"query": "__environment__"}))
        else:
            raw = _text(await search.ainvoke({"query": "__environment__"}))
        report = json.loads(raw)

    assert report["api_key_matches"] is True, binding
    assert report["secret"] == "absent", binding
    assert "OPENAI_API_KEY" not in report["environment_names"], binding


def test_a_code_key_reaches_the_child_through_the_crewai_binding(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The synchronous half of the test above."""

    _entitlement_home(monkeypatch, tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "decoy-openai")

    with KaleidoscopeMemory(
        binary=fake_binary, profile=f"gated.{_nonce()}", api_key=VALID_KEY
    ) as memory:
        search = {tool.name: tool for tool in memory.as_crewai_tools()}["search"]
        report = json.loads(_text(search.run(query="__environment__")))

    assert report["api_key_matches"] is True
    assert report["secret"] == "absent"
    assert "OPENAI_API_KEY" not in report["environment_names"]


@pytest.mark.asyncio
async def test_a_binding_built_without_a_key_reaches_a_child_without_one(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The falsifier for the four tests above.

    A fixture that reported `api_key_matches: true` unconditionally would pass
    all of them. This one supplies no key at all and requires the opposite
    answer from the same probe, through the same binding.
    """

    _entitlement_home(monkeypatch, tmp_path)
    (tmp_path / "entitlement" / "fixture-gate.json").write_text("{}", encoding="utf-8")
    from kaleidoscope_memory.entitlement import clear_gate_status_cache

    clear_gate_status_cache()

    async with KaleidoscopeMemory(binary=fake_binary, profile=f"nokey{_nonce()}") as memory:
        search = {tool.name: tool for tool in memory.as_langchain_tools()}["search"]
        report = json.loads(_text(await search.ainvoke({"query": "__environment__"})))

    assert report["api_key_seen"] is False
    assert report["api_key_matches"] is False
