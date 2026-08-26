import { DuplicateSearchError, ProtocolContractError } from "./errors.js";

export interface SearchController {
  searchRaw(arguments_: Record<string, unknown>): Promise<unknown>;
}

/** One private controller search replaces, rather than duplicates, MCP search. */
export class ControllerTurn {
  readonly modelMcpTools = ["remember"] as const;
  readonly #controller: SearchController;
  #searched = false;

  constructor(controller: SearchController) {
    this.#controller = controller;
  }

  async searchRawOnce(arguments_: Record<string, unknown>): Promise<unknown> {
    if (this.#searched) {
      throw new DuplicateSearchError(
        "controller acquisition already replaced MCP search for this turn",
      );
    }
    this.#searched = true;
    return this.#controller.searchRaw(arguments_);
  }
}

/**
 * Select original, index-aligned refused items without retrying or returning
 * accepted writes. The caller repairs and explicitly resubmits these items.
 */
export function refusedBatchItems(
  arguments_: Readonly<Record<string, unknown>>,
  response: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>>[] {
  const items = arguments_.items;
  const results = response.results;
  if (!Array.isArray(items) || !Array.isArray(results) || items.length !== results.length) {
    throw new ProtocolContractError(
      "remember batch response must align one result with each item",
    );
  }
  const refused: Readonly<Record<string, unknown>>[] = [];
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index];
    const result = results[index];
    if (!isRecord(item) || !isRecord(result)) {
      throw new ProtocolContractError("remember batch items and results must be JSON objects");
    }
    if (typeof result.status !== "string") {
      throw new ProtocolContractError("remember batch result status must be a string");
    }
    if (result.status === "refused") refused.push(item);
  }
  return refused;
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
