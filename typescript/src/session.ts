import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

import {
  boundedDiagnostic,
  EXPECTED_TOOLS,
  mcpStdioConfig,
  safeBootstrapEnvironment,
  validatedApiKey,
  type LaunchDescriptor,
} from "./descriptor.js";
import { classifyRefusal, entitlementPreflight } from "./entitlement.js";
import {
  ChildProcessError,
  EntitlementError,
  ProtocolContractError,
  ToolRefusalError,
} from "./errors.js";

const STDERR_LIMIT = 4096;
export class PersistentKaleidoscopeSession {
  readonly #descriptor: LaunchDescriptor;
  readonly #timeoutMs: number;
  #client: Client | undefined;
  #transport: StdioClientTransport | undefined;
  #stderr = Buffer.alloc(0);

  readonly #apiKey: string | undefined;

  constructor(
    descriptor: LaunchDescriptor,
    options: { timeoutMs?: number; apiKey?: string } = {},
  ) {
    this.#descriptor = descriptor;
    this.#timeoutMs = options.timeoutMs ?? 30_000;
    // Validated at CONSTRUCTION, not at spawn: an error about the caller's own
    // argument belongs where the caller wrote it. Held in a private field so no
    // structured clone, JSON.stringify or console.log of the session shows it.
    this.#apiKey = validatedApiKey(options.apiKey);
  }

  async connect(): Promise<this> {
    if (this.#client) throw new Error("PersistentKaleidoscopeSession is already connected");
    // Fail fast when nothing is configured at all, so the caller gets this
    // SDK's own instruction instead of an opaque MCP connection failure. It
    // fails OPEN on any engine that does not answer `gate`.
    const key = this.#apiKey === undefined ? {} : { apiKey: this.#apiKey };
    const gate = entitlementPreflight(this.#descriptor.command, key);
    const transport = new StdioClientTransport({
      ...mcpStdioConfig(this.#descriptor),
      env: safeBootstrapEnvironment(key),
      stderr: "pipe",
      maxBufferSize: 1024 * 1024,
    });
    transport.stderr?.on("data", (chunk: Buffer | string) => {
      const next = Buffer.concat([this.#stderr, Buffer.from(chunk)]);
      this.#stderr = next.subarray(Math.max(0, next.length - STDERR_LIMIT));
    });
    const client = new Client(
      { name: "kaleidoscope", version: "0.1.0-rc.1" },
      {
        versionNegotiation: { mode: "legacy" },
        listMaxPages: 4,
      },
    );
    this.#transport = transport;
    this.#client = client;
    try {
      await client.connect(transport, { timeout: this.#timeoutMs });
      const { tools } = await client.listTools(undefined, {
        timeout: this.#timeoutMs,
        cacheMode: "refresh",
      });
      const names = tools.map((tool) => tool.name);
      if (new Set(names).size !== names.length || !sameSet(names, EXPECTED_TOOLS)) {
        throw new ProtocolContractError(
          `MCP discovery must publish exactly ${JSON.stringify(EXPECTED_TOOLS)}; got ${JSON.stringify(names)}`,
        );
      }
    } catch (error) {
      // close() first, deliberately: it reaps the child, and the child's stderr
      // has therefore been delivered by the time this buffer is read. A timer-
      // based drain was tried here and removed -- it could not be made to
      // change any outcome in repeated runs, and it charged every NON-
      // entitlement connect failure the full timeout, measured as 271 ms to
      // 790 ms at 500 ms and 545 ms at 250 ms. An unprovable mitigation that
      // costs a measurable amount on the path it does not serve is worse than
      // no mitigation, because it reads as a hazard already handled.
      await this.close().catch(() => undefined);
      // The child's stderr has been accumulating in #stderr all along and was
      // read nowhere. On the MCP path no exit code is observable -- the stdio
      // client awaits the process in its own finally and discards the return
      // code -- so the marker line in this buffer is the only discriminator
      // there is, and without it the caller sees "Connection closed".
      const reason = classifyRefusal(this.#stderr, null);
      if (reason !== null) {
        const keyFile = gate.keyFile;
        throw new EntitlementError(reason, {
          diagnostic: boundedDiagnostic(this.#stderr),
          ...(keyFile === undefined ? {} : { keyFile }),
          // Matches Python's `raise EntitlementError(...) from exc` on this
          // path, so a caller walking the cause chain sees the same thing in
          // both languages.
          cause: error,
        });
      }
      throw error;
    }
    return this;
  }

  async close(): Promise<void> {
    const client = this.#client;
    const transport = this.#transport;
    this.#client = undefined;
    this.#transport = undefined;
    if (client) {
      await client.close();
    } else if (transport) {
      await transport.close();
    }
  }

  async callText(tool: string, arguments_: Record<string, unknown>): Promise<string> {
    if (!EXPECTED_TOOLS.includes(tool as (typeof EXPECTED_TOOLS)[number])) {
      throw new ProtocolContractError(`controller refuses non-agent tool ${JSON.stringify(tool)}`);
    }
    if (!this.#client) throw new ChildProcessError("PersistentKaleidoscopeSession is not connected");
    const result = await this.#client.callTool(
      { name: tool, arguments: arguments_ },
      { timeout: this.#timeoutMs },
    );
    if (result.structuredContent !== undefined) {
      throw new ProtocolContractError("Kaleidoscope tool result carried forbidden structuredContent");
    }
    if (
      result.content.length === 0 ||
      result.content.some((block) => block.type !== "text" || typeof block.text !== "string")
    ) {
      throw new ProtocolContractError("Kaleidoscope tool result must contain text blocks only");
    }
    const text = result.content.map((block) => (block.type === "text" ? block.text : "")).join("\n");
    if (result.isError) throw new ToolRefusalError(tool, text);
    return text;
  }

  searchText(arguments_: Record<string, unknown>): Promise<string> {
    return this.callText("search", arguments_);
  }

  rememberText(arguments_: Record<string, unknown>): Promise<string> {
    return this.callText("remember", arguments_);
  }

  searchRaw(arguments_: Record<string, unknown>): Promise<string> {
    return this.searchText(arguments_);
  }

  rememberRaw(arguments_: Record<string, unknown>): Promise<string> {
    return this.rememberText(arguments_);
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }
}

function sameSet(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((item) => right.includes(item as never));
}
