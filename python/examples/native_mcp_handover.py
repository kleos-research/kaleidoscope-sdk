"""The escape hatch: let the framework own the child.

`mcp_server_config()` returns the stdio entry and spawns nothing. It is the
ALTERNATIVE to opening `KaleidoscopeMemory`, not an addition -- calling it
inside the context refuses.

Two properties this SDK maintains do not survive the handover, and they are the
reason the four `*_tools.py` examples beside this one never produce this dict:

1. The child's stderr is not bounded. The MCP SDK's default inherits it into the
   parent, which for the OpenAI Agents SDK means model-visible output.
   `MCPServerStdioParams` has no `errlog` field, so passing one is silently
   dropped by pydantic; `openai_agents.py` overrides `create_streams` because
   that is the only wiring that actually fires.
2. An entitlement refusal reaches you as the framework's transport error rather
   than as `EntitlementError` with this SDK's own instruction text.

The allowlist and the API key still reach the child, because they are in the
dict below.
"""

from __future__ import annotations

from kaleidoscope_memory import KaleidoscopeMemory


def main() -> None:
    memory = KaleidoscopeMemory(profile="default", api_key="ksk_alpha....")
    config = memory.mcp_server_config()
    print(config["command"], config["args"])
    print(sorted(config["env"]))


if __name__ == "__main__":
    main()
