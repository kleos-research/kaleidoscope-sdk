"""One discovered MCP tool, exactly as the engine published it.

Its own module because `session` produces these and `tools` consumes them, and
a definition in either would make the other's import a cycle.

**Nothing in this package ever writes one of these by hand.** `description` and
`input_schema` are the engine's own bytes, carried through unedited. The engine
publishes one semantic contract with bounded renderings precisely so that no
consumer maintains a copy; a schema literal in this package would be one more
copy, and a copy cannot know it has drifted. `test_tool_schemas_come_from_
discovery_not_from_source` is the assertion that this stayed true -- it changes
the fixture's description and schema and requires the built tools to change with
it, which a hand-written table cannot do.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """`search` or `remember`, with the engine's verbatim description and schema."""

    name: str
    description: str
    input_schema: dict[str, Any]
