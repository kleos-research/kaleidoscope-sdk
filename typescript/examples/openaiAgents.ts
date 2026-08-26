import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import {
  Agent,
  run,
  type CallToolResultContent,
  type MCPCallToolOptions,
  type MCPServer,
  type Model,
} from "@openai/agents";

import {
  boundedDiagnostic,
  EXPECTED_TOOLS,
  mcpStdioConfig,
  safeBootstrapEnvironment,
  type LaunchDescriptor,
} from "../src/descriptor.js";
import { classifyRefusal, entitlementPreflight } from "../src/entitlement.js";
import { EntitlementError, ProtocolContractError, ToolRefusalError } from "../src/errors.js";

const STDERR_LIMIT = 4096;

type ListedTool = Awaited<ReturnType<Client["listTools"]>>["tools"][number];
type AgentsTool = Awaited<ReturnType<MCPServer["listTools"]>>[number];

/**
 * Agents-compatible MCP server backed by one explicit legacy MCP client.
 *
 * The pinned Agents SDK's built-in TypeScript stdio wrapper selects automatic
 * negotiation, which launches a disposable probe before its real child. This
 * adapter keeps the official MCPServer interface while selecting the pinned
 * initialize-era protocol directly, so a complete agent run owns one process.
 */
export class LegacyKaleidoscopeMCPServer implements MCPServer {
  readonly name = "kaleidoscope";
  readonly cacheToolsList = true;
  readonly useStructuredContent = false;
  readonly errorFunction = null;
  readonly #descriptor: LaunchDescriptor;
  readonly #timeoutMs: number;
  #client: Client | undefined;
  #transport: StdioClientTransport | undefined;
  #tools: ListedTool[] = [];
  #stderr = Buffer.alloc(0);

  constructor(descriptor: LaunchDescriptor, timeoutMs = 30_000) {
    this.#descriptor = descriptor;
    this.#timeoutMs = timeoutMs;
  }

  async connect(): Promise<void> {
    if (this.#client) throw new Error("Kaleidoscope MCP server is already connected");
    const gate = entitlementPreflight(this.#descriptor.command);
    const transport = new StdioClientTransport({
      ...mcpStdioConfig(this.#descriptor),
      env: safeBootstrapEnvironment(),
      // Was "ignore", which sent the engine's entitlement refusal to nowhere.
      // Still not model-visible and still not an unbounded buffer: a bounded
      // tail ring the same size session.ts uses, read only on failure.
      stderr: "pipe",
      maxBufferSize: 1024 * 1024,
    });
    transport.stderr?.on("data", (chunk: Buffer | string) => {
      const next = Buffer.concat([this.#stderr, Buffer.from(chunk)]);
      this.#stderr = next.subarray(Math.max(0, next.length - STDERR_LIMIT));
    });
    const client = new Client(
      { name: "openai-agents-kaleidoscope", version: "0.0.0" },
      { versionNegotiation: { mode: "legacy" }, listMaxPages: 4 },
    );
    this.#transport = transport;
    this.#client = client;
    try {
      await client.connect(transport, { timeout: this.#timeoutMs });
      await this.#reloadTools();
    } catch (error) {
      // close() first, reaping the child, for the reason session.ts documents.
      await this.close().catch(() => undefined);
      const reason = classifyRefusal(this.#stderr, null);
      if (reason !== null) {
        const keyFile = gate.keyFile;
        throw new EntitlementError(reason, {
          diagnostic: boundedDiagnostic(this.#stderr),
          ...(keyFile === undefined ? {} : { keyFile }),
        });
      }
      throw error;
    }
  }

  async close(): Promise<void> {
    const client = this.#client;
    const transport = this.#transport;
    this.#client = undefined;
    this.#transport = undefined;
    this.#tools = [];
    if (client) await client.close();
    else if (transport) await transport.close();
  }

  async listTools(): Promise<AgentsTool[]> {
    this.#connectedClient();
    return this.#tools.map((tool) => ({ ...tool })) as AgentsTool[];
  }

  async callTool(
    toolName: string,
    args: Record<string, unknown> | null,
    meta?: Record<string, unknown> | null,
    options: MCPCallToolOptions = {},
  ): Promise<CallToolResultContent> {
    if (!EXPECTED_TOOLS.includes(toolName as (typeof EXPECTED_TOOLS)[number])) {
      throw new ProtocolContractError(`controller refuses non-agent tool ${JSON.stringify(toolName)}`);
    }
    const definition = this.#tools.find((tool) => tool.name === toolName);
    if (!definition) {
      throw new ProtocolContractError(`tool ${JSON.stringify(toolName)} was not listed`);
    }
    const result = await this.#connectedClient().callTool(
      {
        name: toolName,
        arguments: args ?? {},
        ...(meta == null ? {} : { _meta: meta }),
      },
      {
        timeout: this.#timeoutMs,
        ...(options.signal === undefined ? {} : { signal: options.signal }),
        toolDefinition: definition,
      },
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
    const text = result.content
      .map((block) => (block.type === "text" ? block.text : ""))
      .join("\n");
    if (result.isError) throw new ToolRefusalError(toolName, text);
    return result.content as CallToolResultContent;
  }

  async invalidateToolsCache(): Promise<void> {
    await this.#reloadTools();
  }

  #connectedClient(): Client {
    if (!this.#client) throw new Error("Kaleidoscope MCP server is not connected");
    return this.#client;
  }

  async #reloadTools(): Promise<void> {
    const result = await this.#connectedClient().listTools(undefined, {
      timeout: this.#timeoutMs,
      cacheMode: "refresh",
    });
    const names = result.tools.map((tool) => tool.name);
    if (new Set(names).size !== 2 || !names.includes("search") || !names.includes("remember")) {
      throw new ProtocolContractError(
        `Kaleidoscope published an incompatible tool set: ${JSON.stringify(names)}`,
      );
    }
    this.#tools = [...result.tools];
  }
}

export async function runAgentTurns(
  descriptor: LaunchDescriptor,
  model: Model,
  prompts: readonly string[],
): Promise<unknown[]> {
  const server = new LegacyKaleidoscopeMCPServer(descriptor);
  await server.connect();
  try {
    const names = (await server.listTools()).map((tool) => tool.name);
    if (new Set(names).size !== 2 || !names.includes("search") || !names.includes("remember")) {
      throw new Error(`Kaleidoscope published an incompatible tool set: ${JSON.stringify(names)}`);
    }
    const agent = new Agent({
      name: "Memory-aware assistant",
      instructions: "Use Kaleidoscope as the only durable memory owner.",
      model,
      mcpServers: [server],
    });
    const outputs: unknown[] = [];
    for (const prompt of prompts) outputs.push(await run(agent, prompt));
    return outputs;
  } finally {
    await server.close();
  }
}
