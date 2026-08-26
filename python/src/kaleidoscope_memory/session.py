"""One-process, one-session MCP lifecycle for Kaleidoscope."""

from __future__ import annotations

import os
import tempfile
from contextlib import AsyncExitStack
from datetime import timedelta
from functools import lru_cache
from typing import IO, Any, Mapping, Self

from .descriptor import (
    EXPECTED_TOOLS,
    _MAX_DIAGNOSTIC_BYTES,
    LaunchDescriptor,
    _Secret,
    _bounded_diagnostic,
    hold_api_key,
    redacted_environment_items,
    reveal_api_key,
    safe_bootstrap_environment,
)
from .entitlement import classify_refusal, entitlement_preflight
from .errors import ChildProcessError, EntitlementError, ProtocolError, ToolRefusalError
from .tool_definition import ToolDefinition


@lru_cache(maxsize=4)
def _redacting_parameters(base: type) -> type:
    """Subclass the MCP SDK's `StdioServerParameters` so its repr is safe.

    `stdio_client(server, ...)` binds the parameters object as a local named
    `server` in an async-generator frame that stays alive for the whole session,
    and pydantic's generated repr renders `env` -- the credential included --
    whenever anything captures frame locals. The MCP SDK's local is not ours to
    delete, so the repr is what changes.

    `__repr_args__` is pydantic v2's single source for both `repr()` and
    `str()`, so overriding it covers every rendering. The stored value is
    untouched: `server.env[API_KEY_VARIABLE]` still holds the real key, which is
    the whole point -- redaction must not become a second way to lose a key that
    was supplied.

    Cached because the class is built once per MCP SDK class, not per connect.
    """

    class _RedactedStdioServerParameters(base):  # type: ignore[misc,valid-type]
        def __repr_args__(self) -> Any:
            for name, value in super().__repr_args__():
                if name == "env" and isinstance(value, Mapping):
                    yield name, redacted_environment_items(value)
                else:
                    yield name, value

    _RedactedStdioServerParameters.__name__ = base.__name__
    _RedactedStdioServerParameters.__qualname__ = base.__qualname__
    return _RedactedStdioServerParameters


def _definition_of(tool: Any) -> ToolDefinition:
    """Copy one discovered tool through unedited.

    `inputSchema` is MCP 1.x's spelling and `input_schema` a plausible future
    one; neither is normalised, re-keyed or defaulted. A tool that publishes no
    schema is a protocol violation here rather than an empty dict, because an
    empty schema silently makes every field optional to the model.
    """

    schema = getattr(tool, "inputSchema", None)
    if schema is None:
        schema = getattr(tool, "input_schema", None)
    if not isinstance(schema, dict):
        raise ProtocolError(
            f"MCP tool {getattr(tool, 'name', '?')!r} published no input schema"
        )
    return ToolDefinition(
        name=tool.name,
        description=getattr(tool, "description", None) or "",
        input_schema=schema,
    )


class PersistentKaleidoscopeSession:
    """Keep one stdio child alive for a complete agent or graph run.

    MCP SDK 2 deliberately selects `mode="legacy"` for Kaleidoscope's
    initialize-based 2025-11-25 protocol, avoiding an automatic probe process.
    MCP SDK 1.29 (required by the current LangChain adapter) uses its explicit
    initialize session. Both paths keep one application session alive.
    """

    def __init__(
        self,
        descriptor: LaunchDescriptor,
        *,
        timeout_seconds: float = 30.0,
        api_key: str | None = None,
    ) -> None:
        self._descriptor = descriptor
        self._timeout_seconds = timeout_seconds
        # Validated at CONSTRUCTION, not at spawn: an error about the caller's
        # own argument belongs where the caller wrote it. Held in a _Secret so
        # no repr, traceback frame or pydantic error can render it.
        self._api_key: _Secret | None = hold_api_key(api_key)
        self._stack: AsyncExitStack | None = None
        self._client: Any = None
        self._sdk_major: int | None = None
        self._errlog: IO[bytes] | None = None
        self._diagnostic: str = ""
        self._tool_definitions: tuple[ToolDefinition, ...] = ()

    async def __aenter__(self) -> Self:
        try:
            from mcp.client.stdio import StdioServerParameters, stdio_client
        except ImportError as exc:  # pragma: no cover - dependency installation failure
            raise ChildProcessError("mcp 1.29.0 or 2.0.0 is required") from exc

        # Refuse before spawning when the engine enforces the gate and the user
        # has configured no key at all. Fails open on any engine whose gate
        # status cannot be read; the engine is still the authority.
        #
        # The returned status is quoted for the rest of this connect rather than
        # re-probed on the error path. Asking twice let the two answers differ,
        # and a refusal naming a key file the user never configured is a refusal
        # spelled as the wrong answer.
        #
        # `reveal_api_key(...)` is called INLINE and its result is never bound
        # to a name. A named local in this frame outlives the whole connect --
        # every await below is a suspension point at which an exception can be
        # raised with this frame still on the stack -- and any instrument that
        # captures frame locals (`pytest --showlocals`, Sentry's default
        # `with_locals=True`, `cgitb`, IPython's verbose traceback,
        # `TracebackException(capture_locals=True)`) then prints the credential.
        # That is the exact accident `_Secret` exists to prevent, and holding it
        # in `_Secret` up to this line does not prevent it. Measured: with
        # `key = reveal_api_key(...)` here, `--showlocals` rendered the key.
        gate = entitlement_preflight(
            self._descriptor.command, api_key=reveal_api_key(self._api_key)
        )

        stack = AsyncExitStack()
        await stack.__aenter__()
        try:
            # Same rule, and one more mechanism on top of it. Even unnamed, the
            # parameters object is a local named `server` inside `stdio_client`'s
            # own frame, which stays alive for the entire session, and
            # `StdioServerParameters` is a pydantic model whose repr renders
            # `env` in full. We cannot delete a third party's local, so the repr
            # is what gets fixed: `_redacting_parameters(cls)` subclasses their
            # model and masks the credential in `__repr_args__`, which pydantic
            # uses for both `repr()` and `str()`. The VALUE is untouched --
            # `server.env` still carries the real key to the spawn -- so this
            # changes what is printed and nothing about what is passed.
            parameters = _redacting_parameters(StdioServerParameters)(
                command=self._descriptor.command,
                args=list(self._descriptor.args),
                env=safe_bootstrap_environment(
                    api_key=reveal_api_key(self._api_key)
                ),
            )
            # Descriptor environment:{} means no added authority. The explicit
            # bootstrap allowlist still supplies HOME/PATH/etc. plus the three
            # entitlement variables, so the native process can resolve its
            # non-secret profile store and read the gate's key.
            #
            # Still not model-visible and still not an unbounded application
            # buffer: the child's stderr goes to a temporary file this session
            # owns and closes, and it is read back bounded to the last
            # _MAX_DIAGNOSTIC_BYTES. Nothing is streamed anywhere. Previously
            # this was DEVNULL, which kept both properties and threw away the
            # engine's entitlement refusal, leaving the caller with
            # `McpError: Connection closed` and no way to learn why.
            #
            # The one residual: the file grows on disk while the session lives.
            # The engine writes at most one refusal (~600 B) or one grace line to
            # this stream, so the *expected* size is under a kilobyte -- but the
            # READ is bounded independently of that expectation, because a child
            # that floods stderr is exactly the case where an expectation is the
            # wrong instrument. See `_drain_errlog_and_classify`.
            # TypeScript's ring buffer is bounded in memory; the observable
            # behaviour -- which error, which message -- is identical, which is
            # what parity means here.
            self._errlog = tempfile.TemporaryFile(mode="w+b")
            transport = stdio_client(parameters, errlog=self._errlog)
            try:
                from mcp import Client  # MCP SDK 2
            except ImportError:
                from mcp import ClientSession  # MCP SDK 1.29 (LangChain adapter constraint)

                read_stream, write_stream = await stack.enter_async_context(transport)
                self._client = await stack.enter_async_context(
                    ClientSession(
                        read_stream,
                        write_stream,
                        read_timeout_seconds=timedelta(seconds=self._timeout_seconds),
                    )
                )
                await self._client.initialize()
                self._sdk_major = 1
            else:
                self._client = await stack.enter_async_context(
                    Client(
                        transport,
                        mode="legacy",
                        read_timeout_seconds=self._timeout_seconds,
                    )
                )
                self._sdk_major = 2
            await self._assert_exact_tools()
        except BaseException as exc:
            await stack.aclose()
            self._client = None
            self._sdk_major = None
            reason = self._drain_errlog_and_classify()
            self._close_errlog()
            if reason is not None:
                raise EntitlementError(
                    reason,
                    diagnostic=self._diagnostic,
                    key_file=gate.key_file,
                ) from exc
            # Every non-entitlement failure reaches the caller exactly as it did
            # before this change: same type, same message, same cause chain.
            raise
        self._stack = stack
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        stack, self._stack = self._stack, None
        self._client = None
        self._sdk_major = None
        if stack is not None:
            await stack.aclose()
        self._close_errlog()

    def _drain_errlog_and_classify(self) -> str | None:
        """Read the child's stderr back, bounded, and say which refusal it was.

        Classification runs on the raw undecorated bytes; only the copy kept for
        the caller is redacted. A redaction pattern must never be able to eat the
        discriminator -- see test_the_marker_survives_redaction_and_truncation.

        **The read is bounded to the last `_MAX_DIAGNOSTIC_BYTES`, not merely
        the diagnostic built from it.** `errlog.read()` pulled the whole file
        into memory and then `_bounded_diagnostic` decoded a second full copy,
        so the parent's peak RSS tracked the child's stderr at roughly 2x: a
        400 MB flood cost 858 MB here against TypeScript's flat 229 MB, and the
        correct `E_REVOKED` still came back, so nothing looked wrong. Seeking to
        the tail is sound for the same reason keeping the tail is: the marker is
        the LAST line of a refusal by contract, so a bounded tail read cannot
        lose the discriminator.
        """

        errlog, self._errlog = self._errlog, None
        if errlog is None:
            return None
        try:
            size = errlog.seek(0, os.SEEK_END)
            errlog.seek(max(0, size - _MAX_DIAGNOSTIC_BYTES))
            captured = errlog.read()
        except (OSError, ValueError):
            return None
        finally:
            try:
                errlog.close()
            except OSError:  # pragma: no cover - close of a temp file
                pass
        self._diagnostic = _bounded_diagnostic(captured)
        return classify_refusal(captured, None)

    def _close_errlog(self) -> None:
        errlog, self._errlog = self._errlog, None
        if errlog is not None:
            try:
                errlog.close()
            except OSError:  # pragma: no cover - close of a temp file
                pass

    def _connected_client(self) -> Any:
        if self._client is None:
            raise RuntimeError("PersistentKaleidoscopeSession is not connected")
        return self._client

    async def _assert_exact_tools(self) -> None:
        client = self._connected_client()
        names: list[str] = []
        discovered: list[ToolDefinition] = []
        cursor: str | None = None
        while True:
            if self._sdk_major == 2:
                result = await client.list_tools(cursor=cursor, cache_mode="reload")
            else:
                result = await client.list_tools(cursor=cursor)
            for tool in result.tools:
                names.append(tool.name)
                discovered.append(_definition_of(tool))
            cursor = getattr(result, "next_cursor", None) or getattr(result, "nextCursor", None)
            if not cursor:
                break
        if len(names) != len(set(names)) or set(names) != set(EXPECTED_TOOLS):
            raise ProtocolError(
                f"MCP discovery must publish exactly {list(EXPECTED_TOOLS)!r}; got {names!r}"
            )
        by_name = {definition.name: definition for definition in discovered}
        # Ordered by the engine's own tool list, not by discovery order, so the
        # tools a framework is handed appear in one stable order.
        self._tool_definitions = tuple(by_name[name] for name in EXPECTED_TOOLS)

    def tool_definitions(self) -> tuple[ToolDefinition, ...]:
        """The engine's own tool definitions, verbatim, for this live session.

        Only meaningful once connected, and it says so rather than returning an
        empty tuple: a builder handed `()` would produce an agent with no memory
        tools and no error, which is a refusal spelled as an answer.
        """

        if self._client is None:
            raise RuntimeError("PersistentKaleidoscopeSession is not connected")
        return self._tool_definitions

    async def call_text(self, tool: str, arguments: Mapping[str, Any]) -> str:
        if tool not in EXPECTED_TOOLS:
            raise ProtocolError(f"controller refuses non-agent tool {tool!r}")
        if self._sdk_major == 2:
            result = await self._connected_client().call_tool(
                tool,
                arguments=dict(arguments),
                read_timeout_seconds=self._timeout_seconds,
            )
            structured_content = result.structured_content
            is_error = result.is_error
        else:
            result = await self._connected_client().call_tool(
                tool,
                arguments=dict(arguments),
                read_timeout_seconds=timedelta(seconds=self._timeout_seconds),
            )
            structured_content = result.structuredContent
            is_error = result.isError
        if structured_content is not None:
            raise ProtocolError("Kaleidoscope tool result carried forbidden structuredContent")

        try:
            if self._sdk_major == 2:
                from mcp_types import TextContent
            else:
                from mcp.types import TextContent
        except ImportError as exc:  # pragma: no cover
            raise ProtocolError("the selected MCP SDK content types are unavailable") from exc
        if not result.content or any(not isinstance(block, TextContent) for block in result.content):
            raise ProtocolError("Kaleidoscope tool result must contain text blocks only")
        text = "\n".join(block.text for block in result.content)
        if is_error:
            raise ToolRefusalError(tool, text)
        return text

    async def search_text(self, arguments: Mapping[str, Any]) -> str:
        """Return the engine's concise model-visible search projection."""

        return await self.call_text("search", arguments)

    async def remember_text(self, arguments: Mapping[str, Any]) -> str:
        """Return the engine's concise model-visible remember receipt."""

        return await self.call_text("remember", arguments)

    async def search_raw(self, arguments: Mapping[str, Any]) -> str:
        """Compatibility spelling for the raw MCP text result."""

        return await self.search_text(arguments)

    async def remember_raw(self, arguments: Mapping[str, Any]) -> str:
        """Compatibility spelling for the raw MCP text result."""

        return await self.remember_text(arguments)
