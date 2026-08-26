#!/usr/bin/env python3
"""Test-only process fixture; it is not a memory implementation or shim."""

from __future__ import annotations

import json
import os
import hashlib
import stat
import sys
import tempfile
import time
import warnings
from pathlib import Path
from typing import Annotated, Any

from pydantic import BaseModel, Field


def _engine_shaped_ledger(schema: dict[str, Any]) -> None:
    """Publish `{"enum":[true],"type":"boolean"}` and NO `default`.

    The missing `default` is the whole point of the `strictopt` profile. A
    signature default (`ledger: bool = True`) puts `"default": true` in the
    published schema; CrewAI's converter then fills it, no null is ever
    synthesised, and the fixture stops reproducing the engine. The engine
    publishes this property with no default at all.

    Module level because `from __future__ import annotations` makes the
    annotation a STRING that FastMCP evaluates against module globals -- a
    function-scope definition raises InvalidSignature at tool registration.
    """

    schema.pop("default", None)
    schema["enum"] = [True]


#: The engine's `ledger` shape, reproduced exactly. See above.
EngineShapedLedger = Annotated[bool, Field(json_schema_extra=_engine_shaped_ledger)]


def _engine_shaped_facts(schema: dict[str, Any]) -> None:
    """A non-nullable optional NESTED one level down, with no default."""

    schema.pop("default", None)


#: The engine's `semantic_delta` shape: a nested object that pydantic publishes
#: behind a `$ref` into `$defs`, carrying its own non-nullable optional. The
#: real engine publishes `semantic_delta` as `{"$ref": "#/$defs/d"}`, and a
#: binding that pruned only TOP-LEVEL nulls passed against a flat fixture and
#: was still refused by the engine with `invalid type: null, expected a sequence
#: at line 1 column 249`. Both levels, and the `$ref`, are needed here or the
#: fixture cannot see the bug.
class StrictDelta(BaseModel):
    memory_type: str
    facts: Annotated[list[str], Field(json_schema_extra=_engine_shaped_facts)] = []


# --------------------------------------------------------------------------
# Alpha entitlement stand-in.
#
# This fixture is the engine both SDKs drive in test. It reproduces the parts of
# the real gate the SDK boundary can observe -- the `gate` report, the key-file
# route, the marker line and exit code 4 -- and nothing else. It is not an
# entitlement implementation: it never contacts anything and it never decides
# that a key is GOOD, only that one is shaped like a key.
# --------------------------------------------------------------------------

ENTITLEMENT_HOME_VARIABLE = "KSCOPE_ENTITLEMENT_HOME"
API_KEY_VARIABLE = "KALEIDOSCOPE_API_KEY"
KEY_FILE_NAME = "api-key"
MAX_KEY_FILE_BYTES = 256
GATE_MARKER_PRESENT = "kaleidoscope.alpha-entitlement-gate.v1:present"
GATE_MARKER_ABSENT = "kaleidoscope.alpha-entitlement-gate.v1:absent"
GATED_COMMANDS = ["mcp", "context", "call", "serve"]
REFUSAL_MARKER_PREFIX = "kscope-entitlement-refusal: "
#: Optional control file inside the entitlement directory.
#:
#: Absent means the DEFAULT BUILD, which is ungated -- faithfully, because the
#: engine's `entitlement` cargo feature defaults off and a plain build really
#: does answer `"status":"absent"`. A test that wants the enforcing build writes
#: {"entitlement_build": true} here; {"gate_exit": 2} impersonates an engine so
#: old it has no `gate` command at all.
GATE_CONTROL_FILE = "fixture-gate.json"


def entitlement_directory() -> Path | None:
    """Mirror the engine's resolution so no test has to reimplement it."""

    override = os.environ.get(ENTITLEMENT_HOME_VARIABLE)
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = os.environ.get("APPDATA")
        return Path(base) / "kaleidoscope" / "entitlement" if base else None
    home = os.environ.get("HOME")
    if not home:
        return None
    if sys.platform == "darwin":
        return Path(home) / "Library" / "Application Support" / "kaleidoscope" / "entitlement"
    config = os.environ.get("XDG_CONFIG_HOME") or str(Path(home) / ".config")
    return Path(config) / "kaleidoscope" / "entitlement"


def gate_control() -> dict[str, Any]:
    directory = entitlement_directory()
    if directory is None:
        return {}
    try:
        return json.loads((directory / GATE_CONTROL_FILE).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


#: Where an ungated child writes what it was given.
#:
#: Recorded from INSIDE the child, not inferred by the parent. "The SDK did not
#: put the key in that call" is a claim about the parent; "the child did not
#: receive it" is the property, and only the child can report it.
#:
#: The location is derived from KSCOPE_ENTITLEMENT_HOME rather than from a
#: variable of its own, and that is not a convenience -- a dedicated
#: `KALEIDOSCOPE_FIXTURE_RECORD` variable was tried first and never arrived,
#: because the allowlist does not name it. The instrument could not be plumbed
#: in by the route the thing it measures is blocked on, which is the neatest
#: possible demonstration that the allowlist is closed.
ENVIRONMENT_RECORD_NAME = "fixture-environment.jsonl"


def record_environment(command: str) -> None:
    directory = entitlement_directory()
    if directory is None or not directory.is_dir():
        return
    path = directory / ENVIRONMENT_RECORD_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as output:
        output.write(
            json.dumps(
                {
                    "command": command,
                    "pid": os.getpid(),
                    "argv": sys.argv,
                    # Compared by the test, never echoed: this fixture is
                    # scanned by scripts/poison_scan.py like every other file.
                    "api_key_seen": bool(os.environ.get(API_KEY_VARIABLE)),
                    "environment_names": sorted(os.environ),
                },
                separators=(",", ":"),
            )
            + "\n"
        )


def gate_report() -> None:
    """`kscope gate`: build status only, never a key decision. Ungated command."""

    record_environment("gate")
    control = gate_control()
    exit_code = int(control.get("gate_exit", 0))
    if exit_code != 0:
        # An older engine that has no `gate` command at all.
        sys.stderr.write("fixture: unsupported fake invocation\n")
        raise SystemExit(exit_code)
    build = bool(control.get("entitlement_build", False))
    directory = entitlement_directory() if build else None
    print(
        json.dumps(
            {
                "status": "enforcing" if build else "absent",
                "entitlement_build": build,
                "gated_commands": GATED_COMMANDS if build else [],
                "entitlement_home": str(directory) if directory is not None else None,
                "key_file": str(directory / KEY_FILE_NAME) if directory is not None else None,
                "build_features": "bundled-model,entitlement" if build else "bundled-model",
                "marker": GATE_MARKER_PRESENT if build else GATE_MARKER_ABSENT,
            },
            separators=(",", ":"),
        )
    )


def key_file_state() -> tuple[str | None, str | None]:
    """(key, refusal_code). Both None means: no key file, nothing to say."""

    directory = entitlement_directory()
    if directory is None:
        return None, None
    path = directory / KEY_FILE_NAME
    try:
        info = path.lstat()
    except OSError:
        return None, None
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_KEY_FILE_BYTES:
        return None, "E_KEY_FILE_UNUSABLE"
    if sys.platform != "win32" and stat.S_IMODE(info.st_mode) != 0o600:
        return None, "E_KEY_FILE_UNUSABLE"
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None, "E_KEY_FILE_UNUSABLE"
    return (value, None) if value else (None, None)


def resolved_key() -> tuple[str | None, str | None]:
    """The engine's step 1: environment first, then the file. Explicit beats implicit."""

    value = os.environ.get(API_KEY_VARIABLE, "").strip()
    if value:
        return value, None
    return key_file_state()


def well_formed(key: str) -> bool:
    body = key.removeprefix("ksk_alpha.")
    return key.startswith("ksk_alpha.") and len(body) == 43


def refuse(code: str) -> None:
    """Engine-shaped refusal: prose to stderr, marker LAST, exit 4, empty stdout."""

    sys.stderr.write(
        f"kscope: this build requires an alpha entitlement and the command was\n"
        f"refused ({code}). Set {API_KEY_VARIABLE}=ksk_alpha.... or write the key to\n"
        f"the entitlement key file.\n"
        f"Your local vault data is intact and unchanged: this refusal read nothing.\n"
        f"{REFUSAL_MARKER_PREFIX}{code}\n"
    )
    sys.stderr.flush()
    raise SystemExit(4)


def gate_check() -> None:
    """The refusal the real engine would reach on a `gated.` profile."""

    key, problem = resolved_key()
    if problem is not None:
        refuse(problem)
    if key is None:
        refuse("E_NO_KEY")
    if not well_formed(key):
        refuse("E_MALFORMED_KEY")


def record_spawn(profile: str) -> None:
    marker = Path(tempfile.gettempdir()) / f"kscope-fixture-{profile}.starts"
    with marker.open("a", encoding="utf-8") as output:
        output.write(f"{os.getpid()}\n")


def profile_launch() -> None:
    record_environment("profile_launch")
    if os.environ.get("KALEIDOSCOPE_TEST_SECRET"):
        raise SystemExit("unsafe environment inheritance")
    profile = sys.argv[3]
    print(
        json.dumps(
            {
                "version": 1,
                "transport": "stdio",
                "command": str(Path(__file__).resolve()),
                "args": ["mcp", "--profile", profile],
                "tools": ["search", "remember"],
                "environment": {},
            },
            separators=(",", ":"),
        )
    )


def profile_show() -> None:
    record_environment("profile_show")
    if os.environ.get("KALEIDOSCOPE_TEST_SECRET"):
        raise SystemExit("unsafe environment inheritance")
    profile = sys.argv[3]
    print(
        json.dumps(
            {
                "version": 1,
                "name": profile,
                "root": "/tmp/fake-kaleidoscope-vault",
                "workspace_id": "wsp_fixture",
                "principal_id": "usr_fixture",
                "journal": "journal:fixture",
                "durability": "process-local",
            },
            separators=(",", ":"),
        )
    )


def operation_schema() -> None:
    if os.environ.get("KALEIDOSCOPE_TEST_SECRET"):
        raise SystemExit("unsafe environment inheritance")
    operation = sys.argv[2] if len(sys.argv) == 3 else "all"
    print(f"fixture schema {operation}")


def native_call() -> None:
    raw = sys.stdin.buffer.read()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        raise SystemExit("invalid fixture JSON")
    mode = payload.get("_fixture_mode")
    marker_value = payload.get("marker")
    marker = Path(marker_value) if isinstance(marker_value, str) else None
    invocation = 1
    if marker is not None:
        if marker.exists():
            invocation = int(marker.read_text(encoding="utf-8")) + 1
        marker.write_text(str(invocation), encoding="utf-8")

    if mode == "crash_once" and invocation == 1:
        raise SystemExit(19)
    if mode == "timeout_once" and invocation == 1:
        time.sleep(2)
    if mode == "sleep":
        time.sleep(30)
    if mode == "stderr_flood":
        sys.stderr.write("x" * (128 * 1024))
        sys.stderr.flush()
    if mode == "invalid_json":
        print("not-json")
        return
    if mode == "refuse":
        print('{"status":"refused","code":"invalid_schema"}')
        raise SystemExit(2)
    if mode == "entitlement_refusal":
        refuse(str(payload.get("_entitlement_code", "E_UNVERIFIED")))
    if mode == "opaque_failure":
        # Nonzero, no marker, non-JSON stdout: the shape a non-entitlement crash
        # has. This is A5's falsifier for the classifier.
        sys.stderr.write("kscope: the vault root is not a Kaleidoscope vault\n")
        sys.stderr.flush()
        raise SystemExit(2)
    if mode == "gate_check":
        gate_check()

    print(
        json.dumps(
            {
                "status": "accepted",
                "operation": sys.argv[4],
                "invocation": invocation,
                "payload_sha256": hashlib.sha256(raw).hexdigest(),
                "payload": payload,
            },
            separators=(",", ":"),
        )
    )


def run_mcp() -> None:
    warnings.filterwarnings("ignore")
    try:
        from mcp.server import MCPServer
        from mcp.server.mcpserver.exceptions import ToolError
    except ImportError:  # MCP Python SDK 1.29, required by LangChain's adapter
        from mcp.server.fastmcp import FastMCP as MCPServer
        from mcp.server.fastmcp.exceptions import ToolError

    profile = sys.argv[3]
    if profile.startswith("spawn-count-"):
        marker = Path(tempfile.gettempdir()) / f"{profile}.starts"
        with marker.open("a", encoding="utf-8") as output:
            output.write(f"{os.getpid()}\n")

    # `refusal.<CODE>.<nonce>`, `gated.<nonce>` and `startupfail.<nonce>` all
    # record that the process really started before they refuse. That marker is
    # what lets a test distinguish "refused THERE" from "refused in the SDK".
    kind = profile.split(".", 1)[0]
    if kind in ("refusal", "gated", "startupfail"):
        record_spawn(profile)
    if kind == "refusal":
        refuse(profile.split(".")[1])
    if kind == "gated":
        gate_check()
    if kind == "startupfail":
        sys.stderr.write(
            "kscope: profile 'x' does not name a vault this build can open.\n"
            "No entitlement marker line follows, because this is not an\n"
            "entitlement refusal.\n"
        )
        sys.stderr.flush()
        raise SystemExit(2)
    records: list[str] = []
    server = MCPServer("fake-kaleidoscope", log_level="CRITICAL")

    # The `strictopt` profile publishes a `search` whose optional fields are NOT
    # nullable -- `ledger: bool = True`, `scope: str = "all"` -- which is the
    # shape the real engine publishes (`ledger` is
    # `{"enum":[true],"type":"boolean"}`) and which the default profile below
    # does not have. That difference is not cosmetic: every optional field here
    # was `X | None = None`, so a binding that hands the engine an explicit null
    # for a field the caller never supplied passed against this fixture and
    # failed against the engine. `search AS SHIPPED -> REFUSED: invalid type:
    # null, expected a boolean` was live in the CrewAI binding for exactly as
    # long as this fixture could not express a non-nullable optional.
    strict_optionals = kind == "strictopt"

    if strict_optionals:

        @server.tool(name="search", structured_output=False)
        def search(  # type: ignore[misc]
            query: str,
            ledger: EngineShapedLedger = True,
        ) -> str:
            return json.dumps(
                {"pid": os.getpid(), "query": query, "ledger": ledger, "records": records}
            )

    else:

        @server.tool(name="search", structured_output=False)
        def search(
            query: str | None = None,
            memory_id: str | None = None,
            top_k: int | None = None,
        ) -> str:
            del memory_id, top_k
            if query == "__environment__":
                api_key = os.environ.get(API_KEY_VARIABLE, "")
                expected = "ksk_alpha." + "A" * 43
                file_key, _ = key_file_state()
                return json.dumps(
                    {
                        "pid": os.getpid(),
                        # The child's own argv, so a test can assert the key never
                        # rode on the command line rather than assuming it did not.
                        "argv": sys.argv,
                        # Reported as a LENGTH and a boolean. Enough for a test to
                        # tell "arrived intact" from "arrived truncated" without the
                        # value ever being written anywhere.
                        "api_key_length": len(api_key),
                        "secret": os.environ.get("KALEIDOSCOPE_TEST_SECRET", "absent"),
                        # Compared, never echoed: this fixture is scanned by
                        # scripts/poison_scan.py like every other file here.
                        "api_key_seen": bool(api_key),
                        "api_key_matches": api_key == expected,
                        "key_file_seen": file_key is not None,
                        "environment_names": sorted(os.environ),
                    }
                )
            return json.dumps({"pid": os.getpid(), "query": query, "records": records})

    if strict_optionals:

        @server.tool(name="remember", structured_output=False)
        def remember(mode: str, semantic_delta: StrictDelta) -> str:  # type: ignore[misc]
            return json.dumps(
                {
                    "pid": os.getpid(),
                    "mode": mode,
                    "memory_type": semantic_delta.memory_type,
                    "facts": semantic_delta.facts,
                }
            )

    elif profile == "structured":

        @server.tool(name="remember", structured_output=True)
        def remember(mode: str, content_md: str | None = None) -> dict[str, Any]:
            return {"mode": mode, "content": content_md}

    elif profile == "refuse":

        @server.tool(name="remember", structured_output=False)
        def remember(mode: str, content_md: str | None = None) -> str:
            del mode, content_md
            raise ToolError('{"status":"refused","code":"invalid_schema"}')

    else:

        @server.tool(name="remember", structured_output=False)
        def remember(
            mode: str,
            content_md: str | None = None,
            semantic_delta: dict[str, Any] | None = None,
        ) -> str:
            del semantic_delta
            if mode == "create" and content_md:
                records.append(content_md)
            return json.dumps({"pid": os.getpid(), "status": "accepted", "count": len(records)})

    if profile == "extra":

        @server.tool(name="feedback", structured_output=False)
        def feedback() -> str:
            return "operator-only"

    server.run("stdio")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1:3] == ["profile", "launch"]:
        profile_launch()
    elif len(sys.argv) == 4 and sys.argv[1:3] == ["profile", "show"]:
        profile_show()
    elif len(sys.argv) == 5 and sys.argv[1:3] == ["call", "--profile"]:
        native_call()
    elif len(sys.argv) == 2 and sys.argv[1] == "gate":
        gate_report()
    elif len(sys.argv) in (2, 3) and sys.argv[1] == "schema":
        operation_schema()
    elif len(sys.argv) == 4 and sys.argv[1:3] == ["mcp", "--profile"]:
        run_mcp()
    else:
        raise SystemExit("unsupported fake invocation")
