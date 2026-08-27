"""Direct native controller and explicit operator namespace.

These objects are application/controller APIs. They are never exposed to a
model as tools; model-facing use stays on the two-tool MCP surface.
"""

from __future__ import annotations

import asyncio
import json
import math
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .descriptor import (
    LaunchDescriptor,
    _bounded_diagnostic,
    _canonical_executable,
    _Secret,
    _safe_process_environment,
    _ungated_environment,
    executable_sha256,
    hold_api_key,
    reveal_api_key,
    validate_profile_name,
)
from .entitlement import classify_refusal, entitlement_preflight
from .errors import (
    ChildProcessError,
    DeadlineExceededError,
    DescriptorError,
    EntitlementError,
    NativeRefusalError,
    OutputLimitError,
    ProtocolError,
)

_AGENT_OPERATIONS = frozenset({"search", "remember"})
_OPERATOR_OPERATIONS = frozenset(
    {
        "feedback",
        "memory_lifecycle",
        "memory_import",
        "address_maintenance",
        "maintenance",
        "ontology",
        "doctor",
    }
)
_PROFILE_KEYS = frozenset(
    {
        "version",
        "name",
        "root",
        "workspace_id",
        "principal_id",
        "journal",
        "durability",
    }
)


@dataclass(frozen=True, slots=True)
class Profile:
    version: int
    name: str
    root: str
    workspace_id: str
    principal_id: str
    journal: str
    durability: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "Profile":
        if set(value) != _PROFILE_KEYS or type(value.get("version")) is not int or value["version"] != 1:
            raise DescriptorError("profile differs from the closed v1 shape")
        name = validate_profile_name(value["name"])
        strings = ("root", "workspace_id", "principal_id", "journal", "durability")
        if any(not isinstance(value.get(key), str) or not value[key] for key in strings):
            raise DescriptorError("profile contains an invalid identity field")
        root = Path(value["root"])
        if not root.is_absolute():
            raise DescriptorError("profile root must be absolute")
        return cls(
            version=1,
            name=name,
            root=str(root),
            workspace_id=value["workspace_id"],
            principal_id=value["principal_id"],
            journal=value["journal"],
            durability=value["durability"],
        )


def resolve_binary(candidate: str | Path | None = None, *, expected_sha256: str | None = None) -> str:
    if candidate is None:
        from .distribution import locate_engine

        candidate = locate_engine().path
    command = _canonical_executable(str(candidate))
    if expected_sha256 is not None and executable_sha256(command) != expected_sha256.lower():
        raise DescriptorError("Kaleidoscope executable SHA-256 does not match the caller's pin")
    return command


def resolve_manager(candidate: str | Path | None = None, *, expected_sha256: str | None = None) -> str:
    if candidate is None:
        from .distribution import locate_manager

        candidate = locate_manager().path
    command = _canonical_executable(str(candidate))
    if expected_sha256 is not None and executable_sha256(command) != expected_sha256.lower():
        raise DescriptorError("Kaleidoscope manager SHA-256 does not match the caller's pin")
    return command


def mcp_stdio_config(descriptor: LaunchDescriptor) -> dict[str, object]:
    """SDK-neutral config; omitted env means the SDK's safe bootstrap allowlist."""

    return {"command": descriptor.command, "args": list(descriptor.args)}


def load_profile(binary: str | Path, name: str, *, timeout_seconds: float = 10.0) -> Profile:
    command = resolve_binary(binary)
    validate_profile_name(name)
    value = _run_manager_json(command, ["profile", "show", name], timeout_seconds)
    if not isinstance(value, dict):
        raise ProtocolError("profile show must return one JSON object")
    profile = Profile.from_mapping(value)
    if profile.name != name:
        raise ProtocolError("profile show changed the requested name")
    return profile


def schema(binary: str | Path, operation: str | None = None, *, timeout_seconds: float = 10.0) -> str:
    command = resolve_binary(binary)
    if operation is not None and operation not in _AGENT_OPERATIONS | _OPERATOR_OPERATIONS:
        raise ValueError(f"unknown public operation {operation!r}")
    argv = [command, "schema", *([operation] if operation is not None else [])]
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            # `schema` is not in the engine's gated command list.
            env=_ungated_environment(),
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise DeadlineExceededError("schema deadline elapsed") from exc
    except OSError as exc:
        raise ChildProcessError("schema process could not start") from exc
    if completed.returncode != 0:
        raise ChildProcessError(f"schema exited {completed.returncode}")
    try:
        return completed.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError("schema output was not UTF-8") from exc


def _run_manager_json(command: str, args: list[str], timeout_seconds: float) -> Any:
    try:
        completed = subprocess.run(
            [command, *args],
            check=False,
            capture_output=True,
            # `profile show`/`profile list` are not gated commands.
            env=_ungated_environment(),
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise DeadlineExceededError("manager deadline elapsed") from exc
    except OSError as exc:
        raise ChildProcessError("manager process could not start") from exc
    if completed.returncode != 0:
        raise ChildProcessError(f"manager exited {completed.returncode}")
    try:
        return json.loads(completed.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProtocolError("manager output was not one JSON value") from exc


async def _read_bounded(stream: asyncio.StreamReader, limit: int, label: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while chunk := await stream.read(64 * 1024):
        total += len(chunk)
        if total > limit:
            raise OutputLimitError(f"native {label} exceeded {limit} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


async def _communicate_bounded(
    process: asyncio.subprocess.Process,
    payload: bytes,
    *,
    stdout_limit: int,
    stderr_limit: int,
) -> tuple[bytes, bytes]:
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None

    async def write() -> None:
        try:
            process.stdin.write(payload)
            await process.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            process.stdin.close()

    stdout_task = asyncio.create_task(_read_bounded(process.stdout, stdout_limit, "stdout"))
    stderr_task = asyncio.create_task(_read_bounded(process.stderr, stderr_limit, "stderr"))
    write_task = asyncio.create_task(write())
    try:
        stdout, stderr, _ = await asyncio.gather(stdout_task, stderr_task, write_task)
        await process.wait()
        return stdout, stderr
    except BaseException:
        for task in (stdout_task, stderr_task, write_task):
            task.cancel()
        raise


async def _terminate(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    process.terminate()
    try:
        await asyncio.wait_for(process.wait(), timeout=1.0)
    except TimeoutError:
        process.kill()
        await process.wait()


class _NativeCaller:
    def __init__(
        self,
        descriptor: LaunchDescriptor,
        *,
        timeout_seconds: float = 30.0,
        attempts: int,
        stdout_limit: int = 8 * 1024 * 1024,
        stderr_limit: int = 64 * 1024,
        api_key: str | None = None,
    ) -> None:
        self._descriptor = descriptor
        self._timeout_seconds = timeout_seconds
        self._attempts = attempts
        self._stdout_limit = stdout_limit
        self._stderr_limit = stderr_limit
        # Validated where the caller wrote it; held so no repr can render it.
        self._api_key: _Secret | None = hold_api_key(api_key)

    async def _call(self, operation: str, arguments: Mapping[str, Any]) -> Any:
        # `call` is a gated command. Refuse once, before the attempt loop, when
        # the engine enforces the gate and nothing is configured. Fails open.
        #
        # The returned status is quoted for the rest of this call rather than
        # re-probed on the error path. Asking twice let the two answers differ,
        # and a refusal naming a key file the user never configured is a refusal
        # spelled as the wrong answer.
        #
        # Revealed INLINE and never bound to a name: a `key = reveal_api_key(...)`
        # local here survives the whole retry loop, and every `await` in it is a
        # point at which an exception can be raised with this frame still on the
        # stack. Any instrument that captures frame locals then prints the
        # credential. Measured before this change with
        # `TracebackException(capture_locals=True)` against the real engine.
        gate = entitlement_preflight(
            self._descriptor.command, api_key=reveal_api_key(self._api_key)
        )
        try:
            _validate_json_value(arguments)
            payload = json.dumps(
                arguments,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise ProtocolError("native arguments are not a closed JSON value") from exc
        deadline = time.monotonic() + self._timeout_seconds
        last_failure: BaseException | None = None
        for attempt in range(self._attempts):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            attempts_left = self._attempts - attempt
            attempt_budget = remaining / attempts_left
            try:
                process = await asyncio.create_subprocess_exec(
                    self._descriptor.command,
                    "call",
                    "--profile",
                    self._descriptor.profile,
                    operation,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    # `call` IS gated, so this is the one native spawn that gets
                    # the credential. Built inline for the same reason it is
                    # revealed inline above: the dict is a temporary on this
                    # frame's value stack, not a local anything can capture.
                    env=_safe_process_environment(
                        api_key=reveal_api_key(self._api_key)
                    ),
                )
            except OSError as exc:
                last_failure = ChildProcessError("native child could not start")
                last_failure.__cause__ = exc
                continue
            try:
                stdout, stderr = await asyncio.wait_for(
                    _communicate_bounded(
                        process,
                        payload,
                        stdout_limit=self._stdout_limit,
                        stderr_limit=self._stderr_limit,
                    ),
                    timeout=attempt_budget,
                )
            except asyncio.CancelledError:
                await _terminate(process)
                raise
            except TimeoutError as exc:
                await _terminate(process)
                last_failure = DeadlineExceededError(
                    "native call timed out after send; final outcome may be uncertain"
                )
                last_failure.__cause__ = exc
                continue
            except OutputLimitError:
                await _terminate(process)
                raise

            parsed: Any | None = None
            try:
                parsed = json.loads(stdout)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
            if process.returncode != 0:
                reason = classify_refusal(stderr, process.returncode)
                if reason is not None:
                    # Deterministic: the second spawn refuses identically, so
                    # this raises rather than `continue`, joining
                    # NativeRefusalError and OutputLimitError in the
                    # non-retryable set. It is also a deliberate refusal, not a
                    # crash, so it is not a ChildProcessError.
                    raise EntitlementError(
                        reason,
                        diagnostic=_bounded_diagnostic(stderr),
                        key_file=gate.key_file,
                    )
                if parsed is not None:
                    raise NativeRefusalError(operation, parsed)
                last_failure = ChildProcessError(
                    f"native child exited {process.returncode} before a JSON response"
                )
                continue
            if parsed is None:
                raise ProtocolError("native child returned non-JSON on a successful exit")
            return parsed

        if isinstance(last_failure, DeadlineExceededError):
            raise DeadlineExceededError(
                "native call exhausted its original deadline after one bounded retry"
            ) from last_failure
        if last_failure is not None:
            raise ChildProcessError("native call crashed before a response after one bounded retry") from last_failure
        raise DeadlineExceededError("native call deadline elapsed before launch")


def _validate_json_value(value: Any, active: set[int] | None = None) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JSON numbers must be finite")
        return
    if active is None:
        active = set()
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("JSON object keys must be strings")
        identity = id(value)
        if identity in active:
            raise ValueError("JSON values cannot contain cycles")
        active.add(identity)
        try:
            for item in value.values():
                _validate_json_value(item, active)
        finally:
            active.remove(identity)
        return
    if isinstance(value, list):
        identity = id(value)
        if identity in active:
            raise ValueError("JSON values cannot contain cycles")
        active.add(identity)
        try:
            for item in value:
                _validate_json_value(item, active)
        finally:
            active.remove(identity)
        return
    raise TypeError(f"unsupported JSON value {type(value).__name__}")


class Controller(_NativeCaller):
    """Private native JSON access for application-owned acquisition/write paths."""

    def __init__(
        self,
        descriptor: LaunchDescriptor,
        *,
        timeout_seconds: float = 30.0,
        stdout_limit: int = 8 * 1024 * 1024,
        stderr_limit: int = 64 * 1024,
        api_key: str | None = None,
    ) -> None:
        super().__init__(
            descriptor,
            timeout_seconds=timeout_seconds,
            attempts=2,
            stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
            api_key=api_key,
        )

    async def search_raw(self, arguments: Mapping[str, Any]) -> Any:
        return await self._call("search", arguments)

    async def remember_raw(self, arguments: Mapping[str, Any]) -> Any:
        return await self._call("remember", arguments)


class Operator(_NativeCaller):
    """Explicit non-model namespace; operator calls are never advertised over MCP."""

    def __init__(
        self,
        descriptor: LaunchDescriptor,
        *,
        timeout_seconds: float = 30.0,
        api_key: str | None = None,
    ) -> None:
        # Operator semantics differ by verb, so staging does not auto-retry them.
        super().__init__(
            descriptor,
            timeout_seconds=timeout_seconds,
            attempts=1,
            api_key=api_key,
        )

    async def call(self, operation: str, arguments: Mapping[str, Any]) -> Any:
        if operation not in _OPERATOR_OPERATIONS:
            raise ValueError(f"operation {operation!r} is not in the operator namespace")
        return await self._call(operation, arguments)
