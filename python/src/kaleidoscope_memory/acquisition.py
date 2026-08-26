"""Controller-owned turn guard: native acquisition replaces the MCP search."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Mapping, Protocol

from .errors import DuplicateSearchError, ProtocolError


class SearchController(Protocol):
    async def search_raw(self, arguments: Mapping[str, Any]) -> Any: ...


class ControllerTurn:
    """Allow exactly one private search and remove search from model tools."""

    model_mcp_tools = ("remember",)

    def __init__(self, controller: SearchController) -> None:
        self._controller = controller
        self._searched = False

    async def search_raw_once(self, arguments: Mapping[str, Any]) -> Any:
        if self._searched:
            raise DuplicateSearchError("controller acquisition already replaced MCP search for this turn")
        self._searched = True
        return await self._controller.search_raw(arguments)


def refused_batch_items(
    arguments: Mapping[str, Any], response: Mapping[str, Any]
) -> list[Mapping[str, Any]]:
    """Return the original items refused by an index-aligned batch response.

    This is intentionally a pure selector, not an automatic retry. The caller
    must repair the returned items and explicitly choose whether to resubmit
    them; accepted items are never returned or duplicated.
    """

    items = arguments.get("items")
    results = response.get("results")
    if (
        not isinstance(items, Sequence)
        or isinstance(items, (str, bytes, bytearray))
        or not isinstance(results, Sequence)
        or isinstance(results, (str, bytes, bytearray))
        or len(items) != len(results)
    ):
        raise ProtocolError("remember batch response must align one result with each item")

    refused: list[Mapping[str, Any]] = []
    for item, result in zip(items, results, strict=True):
        if not isinstance(item, Mapping) or not isinstance(result, Mapping):
            raise ProtocolError("remember batch items and results must be JSON objects")
        status = result.get("status")
        if not isinstance(status, str):
            raise ProtocolError("remember batch result status must be a string")
        if status == "refused":
            refused.append(item)
    return refused
