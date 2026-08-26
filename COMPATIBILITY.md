# DX-07 compatibility matrix

Verified against official primary documentation on 2026-08-22. Dependency
versions below are exact package pins in `python/pyproject.toml` or
`typescript/package-lock.json`. All stdio sessions negotiate MCP revision
`2025-11-25`; MCP SDK 2 clients explicitly select legacy/initialize negotiation
to avoid a disposable probe process.

The engine build these results were produced against — its source commit and its
executable digest — is recorded in `reference/binary-pin.json`, which is the one
place those values are authored. The primary `sha256` there is the isolated
distribution/live candidate and is the executable used by real profile tests.
The shared-vault runtime hash is recorded separately only for authenticated
local-memory operations; it is not the DX-07 release-candidate pin.

| Integration target | Exact target/pin | Language | Staged verification | Status |
| --- | --- | --- | --- | --- |
| Generic MCP SDK | `mcp==1.29.0` | Python | Exact tools, persistent PID/state, model-visible text projection, refusal, no secret inheritance | Passing |
| Generic MCP SDK | `mcp==2.0.0` | Python | Explicit legacy negotiation, same lifecycle/contract suite, real profile lane | Passing |
| Generic MCP client | `@modelcontextprotocol/client==2.0.0` | TypeScript | Explicit legacy negotiation, same shared contract/error goldens, real profile lane | Passing |
| Standalone LangChain | `langchain==1.3.16`, `langchain-mcp-adapters==0.3.2`, `mcp==1.29.0` | Python | `client.session()` held around provider calls; remember/search share one PID | Passing |
| LangGraph | `langgraph==1.2.11` with the LangChain pins above | Python | `StateGraph` + `ToolNode`; no graph store/checkpointer; calls share one PID | Passing |
| OpenAI Agents SDK | `openai-agents==0.22.0`, `mcp==1.29.0` | Python | Context-managed `MCPServerStdio`, exact filter, fake `ScriptedModel` | Passing |
| OpenAI Agents SDK | `@openai/agents==0.17.0`, MCP client `2.0.0` | TypeScript | Public `MCPServer` adapter, explicit legacy client, fake `ScriptedModel`, exactly one child | Passing with adapter caveat |
| Claude Agent SDK | `claude-agent-sdk==0.2.143` | Python | One `ClaudeSDKClient`, strict MCP config, exact allow/approval names, fake lifecycle | Passing without live provider |
| CrewAI | `crewai==1.15.17`, `crewai-tools[mcp]==1.15.17`, `mcp==1.28.1` | Python | One `MCPServerAdapter` context, exact tool filter, real adapter/fake server | Passing |
| Codex host config | Current stable config schema as checked 2026-08-22 | Host renderer | `required=false`, `tool_timeout_sec=30`, exact `enabled_tools`, empty override env; shared golden | Render-only, release gated |
| Codex MCP CLI | `codex-cli 0.149.0-alpha.4` local binary | macOS arm64 host | Isolated `CODEX_HOME`; real add/list/get/remove; no env/vault coordinates; exact rollback; separate real stdio discovery | Passing at CLI-configuration level; model/TUI/IDE held |
| Claude Code host config | Current stable MCP schema as checked 2026-08-22 | Host renderer | Profile-first stdio JSON and empty override env; shared golden | Render-only, release gated |
| Cursor host config | Current stable MCP schema as checked 2026-08-22 | Host renderer | Profile-first stdio JSON and empty override env; shared golden | Render-only, release gated |
| OpenCode stable | Stable v1 config schema | Host renderer | Direct `mcp.kaleidoscope`, `enabled: true`; explicit renderer/golden | Default OpenCode target |
| OpenCode beta | Opt-in v2 beta config schema | Host renderer | `mcp.servers.kaleidoscope`, `codemode: false`; explicit renderer/golden | Beta only; never auto-selected |
| Manager account CLI | DX-05B closed JSON commands | Python | Manager-only command builders, signed-out status parser, provider-not-configured redaction, no MCP/vault payload | Passing offline; live OIDC held |
| Manager account CLI | DX-05B closed JSON commands | TypeScript | Same shared command/status golden and credential-free fake-manager lane | Passing offline; live OIDC held |

The "empty override env" in every host-renderer row above is unchanged by the
alpha entitlement allowlist, and the two are easy to confuse. A rendered host
config declares `env: {}` / `environment: {}`, meaning *this server declaration
adds nothing*; the host itself spawns the engine and supplies its own inherited
environment. The twenty-one-name bootstrap allowlist governs the launches this
SDK performs directly -- the persistent MCP session, the native controller, and
the framework adapters -- and does not reach a host-launched engine at all.

There is no OpenCode version auto-detection. A caller must request either the
stable-v1 renderer or the beta-v2 renderer, and ambiguous input is refused by
the API shape rather than guessed.

## Official primary sources

- Codex MCP and configuration: <https://developers.openai.com/codex/mcp/> and <https://developers.openai.com/codex/config-reference/>
- Claude Code MCP: <https://code.claude.com/docs/en/mcp>
- Claude Agent SDK MCP, Python, and sessions: <https://code.claude.com/docs/en/agent-sdk/mcp>, <https://code.claude.com/docs/en/agent-sdk/python>, and <https://code.claude.com/docs/en/agent-sdk/sessions>
- Cursor MCP: <https://docs.cursor.com/context/model-context-protocol>
- OpenCode stable v1 and beta v2: <https://opencode.ai/docs/mcp-servers>, <https://opencode.ai/v2/docs>, and <https://opencode.ai/v2/docs/mcp-servers>
- LangChain MCP: <https://docs.langchain.com/oss/python/langchain/mcp>
- LangChain tools and LangGraph: <https://docs.langchain.com/oss/python/langchain/tools> and <https://docs.langchain.com/oss/python/langgraph/overview>
- OpenAI Agents quickstart and MCP lifecycle: <https://developers.openai.com/api/docs/guides/agents/quickstart>, <https://openai.github.io/openai-agents-python/mcp/>, and <https://openai.github.io/openai-agents-js/guides/mcp/>
- CrewAI MCP overview, stdio, and security: <https://docs.crewai.com/en/mcp/overview>, <https://docs.crewai.com/en/mcp/stdio>, and <https://docs.crewai.com/en/mcp/security>
- MCP client guide and revisioned transport/schema: <https://modelcontextprotocol.io/docs/develop/build-client>, <https://modelcontextprotocol.io/specification/2025-11-25/basic/transports>, and <https://modelcontextprotocol.io/specification/2025-11-25/schema>
- Official Python and TypeScript MCP SDK documentation: <https://py.sdk.modelcontextprotocol.io/client/>, <https://py.sdk.modelcontextprotocol.io/client/transports/>, <https://py.sdk.modelcontextprotocol.io/client/protocol-versions/>, <https://ts.sdk.modelcontextprotocol.io/v2/clients/connect.html>, and <https://ts.sdk.modelcontextprotocol.io/v2/protocol-versions.html>

## Dependency blockers

- Live OIDC login, remote logout/link/device calls, and native keychain
  acceptance require the staging issuer configuration and platform runners.
  Provider-not-configured and signed-out manager behavior are already covered
  without credentials; account commands remain separate from the engine's two
  MCP tools.
- Publication, installer/config writes, and live host acceptance remain gated
  on the release-manager dependencies. The generated contract explicitly says
  it is contract-only and does not claim release readiness.
- Live Claude/OpenAI/provider calls are excluded: they would require external
  credentials and network mutation. Fake-provider tests exercise lifecycle and
  tool routing without tokens.
- The pinned TypeScript OpenAI Agents built-in stdio wrapper hardcodes automatic
  MCP negotiation. DX-07 therefore uses its public `MCPServer` interface over
  the pinned explicit-legacy MCP client until the wrapper exposes a negotiation
  option; switching back without a one-child test is not compatible.

## Harness hook mechanisms

An absence claim needs an attempt to make it fire. Each row below records what
was actually tried, on what date, with the command used -- not a reading of
documentation. `tests/manager_cli.rs::the_installed_hook_actually_fires_and_makes_no_gated_engine_call`
executes the hook exactly as the settings file spells it, because a hook entry
written into a settings file that nothing executes is indistinguishable from no
hook at all: the counter reads zero and everyone concludes there is no problem.

| harness | hook in v1 | checked | how |
| --- | --- | --- | --- |
| claude-code | **yes**, `SessionStart` in `.claude/settings.json` | 2026-08-26 | Wrote the entry by hand into a scratch project's `.claude/settings.json`, ran `claude -p` in that directory, and the hook command executed: it appended to its sentinel file. The `hooks.SessionStart[].matcher` / `.hooks[].command` / `.timeout` shape is accepted, and the settings schema published by the installed Claude Code lists `SessionStart` among its hook events and `hookSpecificOutput.additionalContext` among the hook output fields. |
| codex | **no** | 2026-08-26 | `grep -rn hook` over this repository returns one hit and it is unrelated prose in `conformance/README.md`. Codex's injection point is `AGENTS.md`, which `init` installs. No hook mechanism was found to attempt. |
| cursor | **no** | 2026-08-26 | Cursor's equivalent is the always-on rule: `.cursor/rules/kaleidoscope.mdc` carries `alwaysApply: true`, which `init` installs. No hook mechanism was found to attempt. |
| opencode | **deferred** | 2026-08-26 | OpenCode has a plugin system. It was NOT verified here, and shipping an unverified hook is worse than shipping none: the mechanism reads as present while the hazard counter reads zero. `init --host opencode` reports the hook step as `skipped` with this reason rather than pretending. |

**What the claude-code check does NOT establish.** The sentinel proves the hook
command RAN. It does not prove `additionalContext` reached the model's context,
because the session that fired it then failed to authenticate
(`Failed to authenticate: OAuth session expired`) and produced no turn. The
output contract is taken from the installed Claude Code's own settings schema,
not from an observed injection.
