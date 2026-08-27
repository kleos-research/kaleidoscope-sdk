"""Hand Kaleidoscope to an agent framework as tools.

    async with KaleidoscopeMemory(profile="default", api_key="ksk_alpha....") as memory:
        agent = Agent(..., tools=memory.as_openai_tools())

WHAT THIS MATCHES, AND WHAT IT DOES NOT
---------------------------------------
mem0 publishes four framework pages and only one of them -- the OpenAI Agents
SDK page -- is tool-shaped. Its LangChain, LangGraph and CrewAI pages all call
`mem0.search(...)` / `mem0.add(...)` directly and paste the result into a
prompt. So mem0's ergonomic advantage is not an adapter. It is three things:

 1. a zero-argument constructor that reads a key from the environment;
 2. two verbs;
 3. a four-line `@function_tool` wrapper the user writes by hand.

Kaleidoscope already had (2) -- the engine publishes exactly `search` and
`remember` and nothing else. This module supplies (1) and ships (3) for all four
frameworks so that nobody hand-writes it.

`remember` is NOT `mem0.add(text)`, and this module does not pretend otherwise.
`mem0.add([{"role": "user", "content": "..."}])` takes prose and runs its own
extraction. `remember` takes a structured write with a title, a mode, and a
semantic delta whose entities each carry a mandatory gloss. A `remember(text)`
convenience here would have to INVENT that structure, which is the SDK making up
vocabulary on the model's behalf -- and one hand-written relation name in one
prompt is what produced 13,060 identical proposals across 5,498 memories in this
project's own history. They were evidence about a line in a prompt, and were
analysed as evidence about how agents choose relations. So `remember(**fields)`
passes through verbatim and the engine validates. What teaches a model to fill
the structure in is the engine's own field descriptions, which arrive with the
schema. This is a real ergonomic gap against mem0 and it is the honest one.

THE SCHEMA RULE
---------------
**Tool schemas come from live MCP discovery. Nothing in this package writes a
JSON schema, a field name, a field description or an enum value for `search` or
`remember`.** That is why `as_*_tools()` only works inside the context manager:
discovery has not happened before that, and there is no second copy to fall back
on. The refusal is the mechanism, not an inconvenience around it -- it is also
what forces the one-child-per-run lifecycle the framework examples exist to
protect.

WHERE `api_key=` REACHES AND WHERE IT DOES NOT
-----------------------------------------------
`api_key=` configures the children THIS SDK spawns. A harness that launches the
engine itself -- Claude Code, Cursor, Codex, OpenCode reading an MCP server entry
-- never passes through this code, and every renderer of those entries emits an
empty `env` block deliberately. Such a harness takes its key from the
environment or from the engine's key file. A user who wires a harness up and then
sets a key only in Python has a working Python client and a harness that refuses.
The two routes do not overlap, and this docstring says so because the request
that produced this module read as though they did.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Callable

# Module level, not inside `as_crewai_tools`, and that is load-bearing rather
# than tidy. Pydantic resolves a model's annotations against the MODULE globals
# of the class's `__module__`, so a `BaseModel` imported into a function scope
# leaves the CrewAI tool subclass built below "not fully defined" and every
# instantiation raises PydanticUserError. `pydantic` is a hard dependency of
# `mcp`, which is a hard dependency of this package, so this import is always
# satisfiable -- it is not an optional framework import like the ones inside the
# binding methods.
from pydantic import BaseModel

from .descriptor import (
    LaunchDescriptor,
    RedactedEnvironment,
    _Secret,
    hold_api_key,
    load_launch_descriptor,
    reveal_api_key,
    safe_bootstrap_environment,
)
from .entitlement import entitlement_preflight
from .errors import ChildProcessError, IntegrationError
from .native import resolve_binary
from .session import PersistentKaleidoscopeSession
from .tool_definition import ToolDefinition

if TYPE_CHECKING:  # pragma: no cover - typing only
    pass

__all__ = ["KaleidoscopeMemory", "ToolDefinition"]

_MODE_CLOSED = "closed"
_MODE_SYNC = "sync"
_MODE_ASYNC = "async"

_NOT_OPEN = (
    "KaleidoscopeMemory tools are built from live MCP discovery; open the object "
    "first (async with / with)"
)
_ALREADY_OPEN = (
    "mcp_server_config() hands the child to the framework; it is the alternative "
    "to opening this object, not an addition to it"
)
_WRONG_MODE = (
    "this object was opened with `async with`; use asearch/aremember, or open it "
    "with `with` for the synchronous frameworks"
)
_REENTRANT = "KaleidoscopeMemory is not re-entrant; construct one per run"

#: Which installed distributions govern the `mcp` pin for each binding, and
#: which extra a user should install to fix a disagreement.
#:
#: The three MCP-consuming extras pin `mcp` to three mutually exclusive versions
#: (`crewai` forces 1.28.1, `langgraph`/`openai` want 1.29.0, `generic-mcp-v2`
#: wants 2.0.0), so one environment can satisfy at most one of them. That is a
#: resolver fact, not a code gap -- `session.py` handles the 1.x/2.x split at
#: runtime -- and the decision is not to paper over it but to say so loudly at
#: the point of use, instead of letting the framework fail later with an
#: unrelated message.
_MCP_GOVERNORS: dict[str, tuple[tuple[str, ...], str]] = {
    "openai": (("openai-agents",), "openai"),
    "langchain": (("langchain-mcp-adapters", "langchain-core", "langchain"), "langgraph"),
    "crewai": (("crewai-tools", "crewai"), "crewai"),
}


def _installed_mcp_version() -> str | None:
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("mcp")
    except PackageNotFoundError:  # pragma: no cover - mcp is a hard dependency
        return None


def _assert_mcp_pin(binding: str) -> None:
    """Refuse when the installed `mcp` violates the framework's own requirement.

    A refusal, never a warning and never a best-effort build: the failure this
    prevents surfaces inside the framework, several frames away, as something
    that does not mention `mcp` at all.

    It compares the framework's OWN declared requirement against the installed
    distribution, rather than a table of versions written here. A table would be
    a second source of truth about a pin this package does not own, and would go
    stale the first time a framework widened its range.
    """

    from importlib.metadata import PackageNotFoundError, requires

    from packaging.requirements import Requirement
    from packaging.version import InvalidVersion, Version

    governors, extra = _MCP_GOVERNORS[binding]
    installed = _installed_mcp_version()
    if installed is None:
        return
    try:
        parsed = Version(installed)
    except InvalidVersion:  # pragma: no cover - a local build of mcp
        return
    for distribution in governors:
        try:
            declared = requires(distribution) or []
        except PackageNotFoundError:
            # Not installed, so it declares nothing and there is nothing to
            # disagree with. Not a refusal: the binding may not need it.
            continue
        for line in declared:
            try:
                requirement = Requirement(line)
            except Exception:  # pragma: no cover - malformed third-party metadata
                continue
            if requirement.name != "mcp" or not requirement.specifier:
                continue
            if parsed in requirement.specifier:
                continue
            raise IntegrationError(
                f"{distribution} requires mcp{requirement.specifier} and mcp "
                f"{installed} is installed, so the {binding} tool binding would "
                f"fail inside the framework rather than here. Install exactly one "
                f"framework extra per environment: "
                f"pip install 'kscope-memory[{extra}]'"
            )


class KaleidoscopeMemory:
    """One Kaleidoscope engine process, exposed to a framework as two tools.

    Opened with `async with` (asynchronous frameworks: OpenAI Agents SDK,
    LangChain, LangGraph) or with `with` (CrewAI, whose `kickoff()` is
    synchronous). Exactly one of the two, never both -- the mode decides which
    calls are legal and every wrong-mode call refuses by name.

    `api_key=` configures THIS OBJECT'S CHILDREN only. See the module docstring:
    a harness that spawns the engine itself does not pass through here.
    """

    def __init__(
        self,
        *,
        profile: str = "default",
        binary: str | os.PathLike[str] | None = None,
        api_key: str | None = None,
        timeout_seconds: float = 30.0,
        expected_sha256: str | None = None,
    ) -> None:
        self._profile = profile
        self._binary = binary
        # Validated HERE, at construction, rather than at spawn: an error about
        # the caller's own argument belongs where the caller wrote it. Held in a
        # _Secret so no repr, f-string or traceback frame can render it.
        self._api_key: _Secret | None = hold_api_key(api_key)
        self._timeout_seconds = timeout_seconds
        self._expected_sha256 = expected_sha256

        self._descriptor: LaunchDescriptor | None = None
        self._session: PersistentKaleidoscopeSession | None = None
        self._definitions: tuple[ToolDefinition, ...] = ()
        self._mode = _MODE_CLOSED
        self._entered_once = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._shutdown: asyncio.Event | None = None
        self._owner: Any = None

    # -- introspection ------------------------------------------------------

    @property
    def profile(self) -> str:
        return self._profile

    @property
    def descriptor(self) -> LaunchDescriptor:
        """The engine's own launch descriptor, loaded once and cached.

        Loading it runs `kscope profile launch`, which is not a gated command,
        so this works with or without a key and spawns nothing gated.
        """

        if self._descriptor is None:
            command = resolve_binary(self._binary, expected_sha256=self._expected_sha256)
            self._descriptor = load_launch_descriptor(
                command,
                self._profile,
                expected_sha256=self._expected_sha256,
            )
        return self._descriptor

    def tool_definitions(self) -> tuple[ToolDefinition, ...]:
        """The engine's own tool definitions, verbatim. Inside the context only."""

        self._require_open()
        return self._definitions

    # -- lifecycle ----------------------------------------------------------

    async def __aenter__(self) -> "KaleidoscopeMemory":
        self._claim_entry()
        session = PersistentKaleidoscopeSession(
            self.descriptor,
            timeout_seconds=self._timeout_seconds,
            api_key=reveal_api_key(self._api_key),
        )
        await session.__aenter__()
        self._session = session
        self._definitions = session.tool_definitions()
        self._mode = _MODE_ASYNC
        return self

    async def __aexit__(self, *_exc: object) -> None:
        session, self._session = self._session, None
        self._mode = _MODE_CLOSED
        self._definitions = ()
        if session is not None:
            await session.__aexit__()

    def __enter__(self) -> "KaleidoscopeMemory":
        """Open synchronously, on a private event loop in a private thread.

        Why a thread rather than `asyncio.run` per call: `asyncio.run` per call
        would tear down and respawn the stdio child on every tool invocation.
        That is the failure the LangChain example was written to document --
        a stateless `get_tools()` reopens stdio per call -- and it is the
        difference between "one engine process per crew run" and one per tool
        call. The thread is what makes the first sentence true for a framework
        with no event loop of its own.

        The thread is NON-daemon on purpose. A daemon thread would let an
        interpreter shutting down leave the engine child behind, and nothing
        about that looks wrong from the outside.
        """

        self._claim_entry()
        ready = threading.Event()
        loop = asyncio.new_event_loop()

        def run() -> None:
            asyncio.set_event_loop(loop)
            loop.call_soon(ready.set)
            loop.run_forever()

        thread = threading.Thread(target=run, name="kscope-memory", daemon=False)
        thread.start()
        if not ready.wait(timeout=10.0):  # pragma: no cover - a wedged interpreter
            loop.call_soon_threadsafe(loop.stop)
            thread.join(timeout=10.0)
            raise ChildProcessError("the Kaleidoscope session loop did not start")
        self._loop = loop
        self._thread = thread

        # ONE task owns the session from open to close, and that is a
        # correctness requirement rather than a style choice. `stdio_client` is
        # an anyio task group; anyio refuses to exit a cancel scope in a
        # different task from the one that entered it, and
        # `asyncio.run_coroutine_threadsafe` makes a NEW task per call. Entering
        # in one submitted task and exiting in another raises "Attempted to exit
        # cancel scope in a different task than it was entered in" -- at
        # __exit__, after the run has already succeeded, which is the worst
        # possible moment to learn it. So the owner task parks on an event and
        # __exit__ sets that event instead of submitting a second coroutine.
        opened = threading.Event()
        failure: list[BaseException] = []
        owner = asyncio.run_coroutine_threadsafe(self._own_session(opened, failure), loop)
        self._owner = owner
        if not opened.wait(timeout=self._timeout_seconds + 5.0):  # pragma: no cover
            self._stop_loop()
            raise ChildProcessError("the Kaleidoscope session did not open in time")
        if failure:
            self._stop_loop()
            raise failure[0]
        self._mode = _MODE_SYNC
        return self

    async def _own_session(
        self, opened: threading.Event, failure: list[BaseException]
    ) -> None:
        session = PersistentKaleidoscopeSession(
            self.descriptor,
            timeout_seconds=self._timeout_seconds,
            api_key=reveal_api_key(self._api_key),
        )
        try:
            await session.__aenter__()
        except BaseException as exc:
            failure.append(exc)
            opened.set()
            return
        self._session = session
        self._definitions = session.tool_definitions()
        self._shutdown = asyncio.Event()
        opened.set()
        try:
            await self._shutdown.wait()
        finally:
            await session.__aexit__()

    def __exit__(self, *_exc: object) -> None:
        self._session = None
        self._mode = _MODE_CLOSED
        self._definitions = ()
        shutdown, self._shutdown = self._shutdown, None
        owner, self._owner = self._owner, None
        try:
            if shutdown is not None and self._loop is not None:
                self._loop.call_soon_threadsafe(shutdown.set)
            if owner is not None:
                # Wait for the OWNER task, not for a fresh submission: the close
                # happens inside it, in the task that opened the child.
                owner.result(timeout=self._timeout_seconds + 5.0)
        finally:
            self._stop_loop()

    def _claim_entry(self) -> None:
        if self._entered_once:
            raise RuntimeError(_REENTRANT)
        self._entered_once = True

    def _stop_loop(self) -> None:
        loop, self._loop = self._loop, None
        thread, self._thread = self._thread, None
        if loop is not None:
            loop.call_soon_threadsafe(loop.stop)
        if thread is not None:
            thread.join(timeout=10.0)
            if thread.is_alive():
                # Refuse rather than return. A thread left behind still owns the
                # engine child, and reporting success would make a leaked
                # process indistinguishable from a clean exit.
                raise ChildProcessError(
                    "the Kaleidoscope session thread did not stop; the engine "
                    "child may still be running"
                )
        if loop is not None:
            loop.close()

    def _await_on_loop(self, coroutine: Any) -> Any:
        loop = self._loop
        if loop is None:  # pragma: no cover - guarded by every caller
            raise RuntimeError(_NOT_OPEN)
        future = asyncio.run_coroutine_threadsafe(coroutine, loop)
        return future.result(timeout=self._timeout_seconds + 5.0)

    # -- guards -------------------------------------------------------------

    def _require_open(self) -> PersistentKaleidoscopeSession:
        if self._session is None:
            raise RuntimeError(_NOT_OPEN)
        return self._session

    def _require_sync(self) -> PersistentKaleidoscopeSession:
        session = self._require_open()
        if self._mode != _MODE_SYNC:
            raise RuntimeError(_WRONG_MODE)
        return session

    # -- direct verbs -------------------------------------------------------

    async def asearch(self, query: str, **options: Any) -> str:
        """`search`, awaited. The engine's concise model-visible projection.

        Legal in both modes, and it goes through `_call_async` in both rather
        than touching the session directly. Awaiting the session from a second
        event loop -- which is what a caller in sync mode has -- drives the
        stdio transport from two loops at once, and the child dies with an
        `anyio.BrokenResourceError` several frames from anything that names the
        cause. Measured while writing this: the first draft called the session
        directly here and killed a working child on the way out.
        """

        return await self._call_async("search", {"query": query, **options})

    async def aremember(self, **fields: Any) -> str:
        """`remember`, awaited. Fields pass through VERBATIM; the engine validates.

        No field is defaulted, renamed or synthesised here. See the module
        docstring for why a prose-only convenience is not offered.
        """

        return await self._call_async("remember", dict(fields))

    def search(self, query: str, **options: Any) -> str:
        self._require_sync()
        return self._call_sync("search", {"query": query, **options})

    def remember(self, **fields: Any) -> str:
        self._require_sync()
        return self._call_sync("remember", dict(fields))

    def _call_sync(self, tool: str, arguments: "Mapping[str, Any]") -> str:
        session = self._require_sync()
        return self._await_on_loop(session.call_text(tool, dict(arguments)))

    async def _call_async(self, tool: str, arguments: "Mapping[str, Any]") -> str:
        session = self._require_open()
        if self._mode == _MODE_ASYNC:
            return await session.call_text(tool, dict(arguments))
        # Opened with `with`, awaited from somebody else's loop: marshal onto the
        # loop that owns the child rather than touching it from two loops.
        return await asyncio.to_thread(self._call_sync, tool, arguments)

    def _async_invoker(self, name: str) -> Callable[..., Any]:
        async def invoke(**arguments: Any) -> str:
            return await self._call_async(name, arguments)

        invoke.__name__ = name
        return invoke

    def _sync_invoker(self, name: str) -> Callable[..., Any]:
        def invoke(**arguments: Any) -> str:
            self._require_sync()
            return self._call_sync(name, arguments)

        invoke.__name__ = name
        return invoke

    # -- framework bindings -------------------------------------------------

    def as_openai_tools(self) -> list[Any]:
        """`tools=[...]` for the OpenAI Agents SDK."""

        self._require_open()
        _assert_mcp_pin("openai")
        from agents import FunctionTool

        def build(definition: ToolDefinition) -> Any:
            async def on_invoke(_context: Any, arguments: str) -> str:
                return await self._call_async(name, _decode_arguments(arguments))

            name = definition.name
            return FunctionTool(
                name=definition.name,
                description=definition.description,
                params_json_schema=definition.input_schema,
                on_invoke_tool=on_invoke,
                # REQUIRED, and not a preference. The engine's schemas are
                # `additionalProperties: false` flat objects with optional
                # fields; OpenAI's strict mode demands every property be
                # `required`. Setting True would force this SDK to EDIT the
                # engine's schema, which is the one thing this module may not do.
                strict_json_schema=False,
            )

        return [build(definition) for definition in self._definitions]

    def as_langchain_tools(self) -> list[Any]:
        """`tools=[...]` for LangChain, and for LangGraph's `ToolNode`."""

        self._require_open()
        _assert_mcp_pin("langchain")
        from langchain_core.tools import StructuredTool

        return [
            StructuredTool.from_function(
                func=self._sync_invoker(definition.name),
                coroutine=self._async_invoker(definition.name),
                name=definition.name,
                description=definition.description,
                # A dict is an accepted `ArgsSchema` in langchain-core 1.x, and
                # that branch is the whole reason the engine's schema can be
                # passed unedited.
                args_schema=definition.input_schema,
                # MANDATORY. Left True, LangChain introspects the `**kwargs`
                # invoker above and SYNTHESISES a schema from it -- which is
                # precisely the hand-written second copy this module forbids,
                # arrived at by accident.
                infer_schema=False,
                return_direct=False,
            )
            for definition in self._definitions
        ]

    #: A literal alias, not a copy.
    #:
    #: LangGraph's `ToolNode` and `bind_tools()` consume LangChain tools
    #: unchanged; there is no LangGraph tool type to build. The alias exists
    #: because users look for it by name, and it is an alias rather than a
    #: forwarding method so that the two cannot drift --
    #: `test_as_langgraph_tools_is_the_same_object_as_as_langchain_tools`
    #: asserts identity, which a copied body would fail.
    as_langgraph_tools = as_langchain_tools

    def as_crewai_tools(self) -> list[Any]:
        """`tools=[...]` for CrewAI. Synchronous form only."""

        self._require_sync()
        _assert_mcp_pin("crewai")
        from crewai.tools import BaseTool
        from crewai.utilities.pydantic_schema_utils import create_model_from_schema
        from crewai.utilities.string_utils import sanitize_tool_name

        owner = self

        def build(definition: ToolDefinition) -> Any:
            # CrewAI's OWN JSON-schema-to-pydantic converter, fed the engine's
            # schema unedited. Reused deliberately rather than written here:
            # CrewAI's own comment says this function exists because mcpadapt's
            # model creation adds invalid null values to field schemas, and a
            # converter written here would rediscover that bug.
            args_model = create_model_from_schema(definition.input_schema)
            invoke = owner._sync_invoker(definition.name)
            schema = definition.input_schema

            class _KaleidoscopeCrewTool(BaseTool):
                name: str = sanitize_tool_name(definition.name)
                description: str = definition.description
                args_schema: type[BaseModel] = args_model

                def _run(self, **arguments: Any) -> str:
                    return invoke(**_without_synthesised_nulls(arguments, schema, schema))

            return _KaleidoscopeCrewTool()

        return [build(definition) for definition in self._definitions]

    # -- the native-MCP escape hatch ---------------------------------------

    def mcp_server_config(self) -> dict[str, Any]:
        """The stdio server entry, for a framework that wants to own the child.

        The framework owns the child from here. Two properties this SDK
        maintains do not survive the handover:

        1. **The child's stderr is not bounded.** The MCP SDK's default inherits
           it into the parent, which for the OpenAI Agents SDK means
           model-visible output. `MCPServerStdioParams` has no `errlog` field, so
           passing one is silently dropped by pydantic -- see
           `examples/openai_agents.py`, which overrides `create_streams` because
           that is the only wiring that actually fires.
        2. **An entitlement refusal reaches you as the framework's transport
           error**, not as `EntitlementError`.

        The allowlist and the API key still reach the child, because they are in
        the dict this returns. What is lost is the two properties above, and the
        recommended path in the README never produces this dict at all.

        The returned `env` is a `RedactedEnvironment`: a `dict` in every respect
        the framework needs -- `[]`, `**`, `dict(...)`, `json.dumps` all see the
        real key -- whose `repr`/`str` masks the credential. `print(config)` is
        the next line most callers write, and on a plain dict that prints the
        key into their terminal and their logs.
        """

        if self._session is not None:
            raise RuntimeError(_ALREADY_OPEN)
        descriptor = self.descriptor
        # Inline, never a named local: see session.__aenter__ for the frame-locals
        # accident this avoids.
        entitlement_preflight(
            descriptor.command, api_key=reveal_api_key(self._api_key)
        )
        return {
            "command": descriptor.command,
            "args": list(descriptor.args),
            "env": RedactedEnvironment(
                safe_bootstrap_environment(api_key=reveal_api_key(self._api_key))
            ),
        }

    def __repr__(self) -> str:
        # Explicit, so that adding a field can never start rendering a secret
        # through a generated repr. `_Secret` is the belt; this is the braces.
        return (
            f"KaleidoscopeMemory(profile={self._profile!r}, mode={self._mode!r}, "
            f"tools={[d.name for d in self._definitions]!r})"
        )


def _resolved(schema: Any, root: Mapping[str, Any]) -> Any:
    """Follow a local `$ref` so the walk below sees the real subschema.

    The engine publishes `remember`'s `semantic_delta` as `{"$ref":
    "#/$defs/d"}`, so a walk that does not resolve refs sees a schema with no
    `properties`, treats every nested field as unconstrained, and keeps the
    nulls it was supposed to drop. Local refs only; a remote `$ref` is left
    alone and the subschema then reads as unconstrained, which is the
    conservative direction -- an unresolved field keeps its null and the engine
    decides, exactly as it does today.
    """

    seen = 0
    while isinstance(schema, Mapping) and isinstance(schema.get("$ref"), str):
        reference = schema["$ref"]
        if not reference.startswith("#/") or seen > 32:
            return schema
        seen += 1
        target: Any = root
        for token in reference[2:].split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            if not isinstance(target, Mapping) or token not in target:
                return schema
            target = target[token]
        schema = target
    return schema


def _schema_admits_null(schema: Any, root: Mapping[str, Any]) -> bool:
    """Does the ENGINE's schema for one property accept an explicit null?

    Read off the engine's schema, never guessed and never hardcoded. An absent
    or non-object schema is unconstrained, so it admits null; a `type` of
    "null", a `type` list containing "null", a nullable composite, or an `enum`
    carrying null all admit it; anything else does not.
    """

    schema = _resolved(schema, root)
    if not isinstance(schema, Mapping):
        return True
    declared = schema.get("type")
    if declared == "null" or (
        isinstance(declared, (list, tuple)) and "null" in declared
    ):
        return True
    for keyword in ("anyOf", "oneOf", "allOf"):
        branches = schema.get(keyword)
        if isinstance(branches, (list, tuple)) and any(
            _schema_admits_null(branch, root) for branch in branches
        ):
            return True
    enumerated = schema.get("enum")
    if isinstance(enumerated, (list, tuple)) and None in enumerated:
        return True
    return declared is None and not schema.get("properties")


def _without_synthesised_nulls(
    arguments: Mapping[str, Any],
    schema: Any,
    root: Mapping[str, Any],
) -> dict[str, Any]:
    """Drop the nulls CrewAI invents for fields the caller never supplied.

    CrewAI's `BaseTool._validate_kwargs` does
    `self.args_schema.model_validate(kwargs).model_dump()`, and `model_dump()`
    renders EVERY field at EVERY level -- so a caller who passed only `query`
    reaches `_run` with all eleven of `search`'s properties present and ten of
    them `None`, and a caller who passed a `semantic_delta` reaches it with all
    eleven of the delta's fields present too. The engine's schema is
    `additionalProperties: false` with non-nullable optional fields, so it
    refuses the whole call:

        search   -> {"code":"invalid_arguments",
                     "message":"invalid type: null, expected a boolean at line 1 column 179"}
        remember -> {"code":"invalid_arguments",
                     "message":"invalid type: null, expected a sequence at line 1 column 249"}

    -- `ledger` is `{"enum":[true],"type":"boolean"}`, and the second one is
    inside `semantic_delta`, which the engine publishes as `{"$ref":
    "#/$defs/d"}`. That is EVERY CrewAI call, not an edge case. Both measured
    against the real engine.

    The validated pydantic model is discarded by `_validate_kwargs` before
    `_run` is reached, so `model_fields_set` -- the one thing that could
    distinguish "the caller passed None" from "pydantic defaulted it" -- is not
    available at this seam. The engine's own schema is used instead, walked
    recursively and through its `$ref`s: a null is dropped only for a property
    the engine says cannot be null, and kept for every property the engine says
    can, at every depth. Nothing is renamed, defaulted or invented, and no
    schema is written here.

    The residual, stated rather than hidden: a caller who explicitly passes
    `ledger=None` through CrewAI gets the engine's default instead of a refusal.
    There is no information at this seam that could tell the two apart, and the
    alternative -- the behaviour before this existed -- is that every CrewAI
    call fails.
    """

    resolved = _resolved(schema, root)
    properties = resolved.get("properties") if isinstance(resolved, Mapping) else None
    kept: dict[str, Any] = {}
    for name, value in arguments.items():
        sub = properties.get(name) if isinstance(properties, Mapping) else None
        if value is None and not _schema_admits_null(sub, root):
            continue
        kept[name] = _pruned(value, sub, root)
    return kept


def _pruned(value: Any, schema: Any, root: Mapping[str, Any]) -> Any:
    """The same rule, applied inside objects and arrays."""

    if isinstance(value, Mapping):
        return _without_synthesised_nulls(value, schema, root)
    if isinstance(value, list):
        resolved = _resolved(schema, root)
        item = resolved.get("items") if isinstance(resolved, Mapping) else None
        return [_pruned(element, item, root) for element in value]
    return value


def _decode_arguments(payload: str) -> dict[str, Any]:
    """The OpenAI Agents SDK hands tool arguments over as a JSON string."""

    if not payload:
        return {}
    try:
        decoded = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise IntegrationError("tool arguments were not valid JSON") from exc
    if not isinstance(decoded, dict):
        raise IntegrationError("tool arguments must decode to an object")
    return decoded
