from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("agents")

from agents import set_tracing_disabled
from agents.testing import ScriptedModel, assistant_message, function_call

from examples.openai_agents import run_agent_turns
from kaleidoscope_memory.descriptor import load_launch_descriptor


@pytest.mark.asyncio
async def test_openai_agents_owns_one_persistent_mcp_lifecycle(fake_binary: Path) -> None:
    set_tracing_disabled(True)
    model = ScriptedModel(
        [
            [
                function_call(
                    "remember",
                    {
                        "mode": "create",
                        "content_md": "# Python Agents fixture\n\nStored by the scripted model.",
                        "semantic_delta": {
                            "memory_type": "architecture",
                            "title": "Python Agents fixture",
                            "facts": [
                                {
                                    "subject": "Python Agents fixture",
                                    "predicate": "uses",
                                    "object": "Kaleidoscope MCP",
                                }
                            ],
                        },
                    },
                    call_id="remember-1",
                )
            ],
            [function_call("search", {"query": "Python Agents fixture"}, call_id="search-1")],
            [assistant_message("done")],
        ]
    )
    descriptor = load_launch_descriptor(fake_binary, "openai-python")
    outputs = await run_agent_turns(descriptor, model, ["exercise memory"])
    model.assert_complete()
    assert len(model.calls) == 3
    assert len(outputs) == 1
    assert outputs[0].final_output == "done"


@pytest.mark.asyncio
async def test_openai_agents_bounds_child_stderr(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The stderr redirect fires, rather than being silently dropped.

    `MCPServerStdioParams` has no errlog field, so the obvious wiring -- an
    "errlog" key in params -- is discarded by pydantic and the child's stderr
    keeps inheriting to the parent. Nothing about that looks wrong, which is why
    this test reads the file back instead of trusting the call site.
    """

    from examples.openai_agents import _BoundedStderrServer
    from kaleidoscope_memory.descriptor import safe_bootstrap_environment

    descriptor = load_launch_descriptor(fake_binary, f"startupfail.{'e' * 4}stderr")
    with tempfile.TemporaryFile(mode="w+b") as errlog:
        server = _BoundedStderrServer(
            errlog=errlog,
            name="kaleidoscope",
            params={
                "command": descriptor.command,
                "args": list(descriptor.args),
                "env": safe_bootstrap_environment(),
            },
            client_session_timeout_seconds=10,
        )
        with pytest.raises(BaseException):
            async with server:
                pass
        errlog.seek(0)
        captured = errlog.read()

    # The engine's refusal landed in the file this call owns. If create_streams
    # were not overridden this would be empty and the bytes would have gone to
    # the parent's stderr instead.
    assert b"does not name a vault this build can open" in captured
