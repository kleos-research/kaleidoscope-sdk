# Kaleidoscope local manager

This repository is a clean public control-plane implementation for a separately supplied native `kscope` engine. It contains no memory engine, MCP proxy, account service, model, vault implementation, or private engine source. The release-candidate package names are `kaleidoscope-memory` (Python) and `@kleos-research/kaleidoscope` (TypeScript); this checkout remains local-only staging until the protected license, signing, registry, and publication gates are approved.

The Rust binary provides profile initialization and selection, closed validation of the native profile/launch contract, reversible host configuration, offline redacted diagnostics, owner-marked installation of agent instructions, and a manager-only account surface for OIDC login, status, logout, identity linking, and device revocation. The crate is intentionally `publish = false`; no package or repository publication is performed here.

## License boundary

Apache-2.0 covers everything in this repository: the manager, the Python and
TypeScript wrappers, the integration helpers, examples and snippets, the
conformance probes, the reference goldens and `skills/use-kaleidoscope`. See
[LICENSE](LICENSE) for the licence text and [NOTICE](NOTICE) for the copyright
line Section 4(d) requires downstream redistributors to carry forward, and for
the authoritative statement of scope.

That licence does not apply to a separately distributed native `kscope` engine,
model weights, or other proprietary object-code payloads. Those payloads are not
licensed by this repository: they require their own end-user terms, which do not
exist yet and are a precondition of first publication. The engine carries the
third-party attribution it has inside the executable — and states in that same
output which attribution is still missing — readable with `kscope licences`.

Third-party attribution for the code in this repository is in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), regenerated from the three
dependency manifests by `scripts/third_party_notices.py`. Its Rust table is the
union over the three shipped target triples of what actually links into the
manager binary; the crates that link on no target we ship, and the build-time
proc-macro closure, are excluded rather than swept in for safety.

The four manifests that claim a licence — `Cargo.toml`,
`python/pyproject.toml`, `typescript/package.json` and
`conformance/package.json` — are asserted by `python/tests/test_licensing.py`
to agree on `Apache-2.0`, to name `Kleos Research` as the holder, and to be
backed by files that actually exist. A licence claimed in metadata with no file
behind it, or terms stated with no party holding them, are the two specific
defects that test exists to prevent.

## Repository layout

| Path | Contents |
| --- | --- |
| `src/`, `tests/` | Rust local manager and its functional contract tests |
| `python/` | Python controller, persistent MCP client, harness adapters and examples |
| `typescript/` | TypeScript controller, persistent MCP client, host renderers and examples |
| `reference/` | Shared public-contract, launch, error, host and batch goldens |
| `skills/`, `snippets/` | Canonical skill and reversible harness instruction fragments |
| `conformance/` | Local non-auth/account-offline DX-10B runner, probes and evidence schema |
| `scripts/` | Source-boundary and poison checks |

The engine build this checkout is pinned to — its source commit, its executable
digest and the public-contract digest — is recorded in
[`reference/binary-pin.json`](reference/binary-pin.json), which is the one place
those values are authored. Restating them in prose gives a reader a second copy
to keep in step and no way to notice when it drifts. The isolated local
candidate and the separate shared-vault development runtime are labelled
independently there; the latter is never a release-candidate substitution.

## Getting started

```bash
cargo build --release

# One command: find the vault, wire the harness.
target/release/kaleidoscope --engine /absolute/path/to/kscope init \
  --profile default --host claude-code --scope project --project "$PWD"

target/release/kaleidoscope --engine /absolute/path/to/kscope doctor --project "$PWD"
```

The native version-1 launch descriptor must name the canonical engine executable, `stdio`, arguments `mcp --profile <name>`, tools `search` and `remember`, and an empty environment. Any unknown field or mismatch is refused before a host file is changed.

The manager stores only `{version, active_profile, account_bindings}` in its own `manager.json`. Vault root, workspace, principal, journal, and credentials are never written to manager state, owner receipts, doctor output, or host configuration.

## init

`init` **discovers an existing vault before it creates one.** Running it against a directory that already holds a vault used to return `rc=0`, report `"initialized"`, and silently **fork** the vault -- the engine adds a second workspace, every read and write on the resulting profile then reports corrupt state, and `kscope profile import` afterwards refuses because the vault has two workspaces, so the recovery path is gone too. That cannot happen now: `init-profile` is never called on a root that probes as a vault, and the refusal fires even under `--create`.

The search order, first rule that yields a decision wins:

1. `--root PATH` -- exactly that path, nothing else is searched.
2. A profile already named `--profile` -- that profile **is** the answer (`status: already_initialized`). If `--root` names a different vault, this refuses rather than repointing the profile.
3. The roots of every other registered profile.
4. The manager's default vault root for this profile.
5. `<project>/.kaleidoscope`.
6. Every immediate child of the user-level vault directory.

Three outcomes, and the third is a refusal:

| candidates found | action | `status` | exit |
| --- | --- | --- | --- |
| none | create at the default root | `initialized` | 0 |
| exactly one | adopt it via `kscope profile import` | `adopted` | 0 |
| several | **refuse**, listing every candidate with the rule that found it and its workspace count | `ambiguous` | 2 |

`--adopt` forces the single-candidate path; `--create` forces creation and refuses if `--root` is already a vault.

### What `--host` wires

With no `--host`, `init` does profile work only and prints the hosts it could have wired. With `--host` (repeatable) it chains four steps per harness:

| step | codex | claude-code | cursor | opencode |
| --- | --- | --- | --- | --- |
| config | `.codex/config.toml` | `.mcp.json` | `.cursor/mcp.json` | `opencode.json` |
| instructions | `AGENTS.md` | `CLAUDE.md` | `.cursor/rules/kaleidoscope.mdc` | `AGENTS.md` |
| skill | `.agents/skills/…` | `.claude/skills/…` | none -- the rule is the skill | `.agents/skills/…` |
| hook | none | `.claude/settings.json`, `SessionStart` | none | deferred |

The skill path is per harness and `instructions install skill` **requires `--host`**. Claude Code reads `.claude/skills/<name>/SKILL.md`; it does not read `.agents/skills/`, and a skill outside `.claude/skills/` is not loaded as a skill at all. Defaulting is what put the file in the wrong place, so there is no default. Codex and OpenCode share both `AGENTS.md` and `.agents/skills/`, so naming both hosts installs each once.

`init` is atomic **per step**, not overall. A step that fails leaves the earlier steps applied, reports `"issue"` with the reason, exits 2, and names the `teardown` that undoes what did land. A successful `connect` is never rolled back because a later hook failed.

### The hook

`kaleidoscope hook session-start --profile NAME` is invoked **by** Claude Code, not by users. It runs `kscope profile launch` -- which is ungated -- and emits a bounded reminder. It **never** calls `search` or `remember`: `search` writes an exposure row on every call, and a hook firing on every start, resume, clear and compact would write to the vault without the user asking for a read. It exits 0 always, reporting a broken configuration in the session rather than failing the session.

It earns its place over `CLAUDE.md` alone because `CLAUDE.md` is read once at session start, while the hook fires again on `resume`, `clear` and `compact` -- so the instruction survives compaction.

### teardown, and what reversible means here

```bash
kaleidoscope teardown --host claude-code --scope project --project "$PWD" --dry-run
kaleidoscope teardown --host claude-code --scope project --project "$PWD"
```

Every removal reports which of **two tiers** it achieved, and the tier is checked, not asserted:

- **`byte_identical`** -- the file is still exactly what the manager wrote, so the pre-install bytes go back verbatim (or a manager-created file is deleted, and the directory it created with it). Independent of key ordering, indentation and trailing newlines.
- **`structural`** -- the user edited the file after install, so byte-identity to the pre-install state would *destroy their edit*. The owned span is removed and the rest re-encoded; the report adds `formatting: "normalized"` and the backup is kept, because it is the user's only copy of the pre-edit state.

A reversibility claim that cannot say which tier it achieved is a claim nothing can check, which is why `restore` is in the JSON and why the round-trip tests assert it: a `structural` result where `byte_identical` was expected is a failure even if the bytes happen to match.

`teardown` **never touches the vault or the profile.** Data removal is `kaleidoscope profile remove NAME` and `kscope vault-delete ROOT`, deliberately separate verbs.

A manager-owned block that has been hand-edited refuses -- and the refusal now names `--force`, which removes it after printing the discarded bytes in full to stderr and reporting `discarded_user_edits: true`. Before `--force` existed, one changed character wedged the block into the user's file permanently: remove, re-install and receipt deletion all refused, honestly, and there was no way out.

## Connect a harness

Project scope is the default. Every mutation is previewed, requires confirmation unless `--yes` is supplied, takes an atomic snapshot check, writes a bounded sibling backup for an existing file, and records exact ownership in a sibling receipt.

```bash
# Effect-free preview
kaleidoscope connect codex --profile default --project "$PWD" --dry-run

# Apply after confirmation
kaleidoscope connect codex --profile default --project "$PWD"

# Reversible removal of only the manager-owned block or entry
kaleidoscope disconnect codex --project "$PWD"
```

Supported targets and paths:

| Host | Project | User |
| --- | --- | --- |
| Codex | `.codex/config.toml` | `~/.codex/config.toml` |
| Claude Code | `.mcp.json` | `~/.claude.json` |
| Cursor | `.cursor/mcp.json` | `~/.cursor/mcp.json` |
| OpenCode | `opencode.json` | `~/.config/opencode/opencode.json` |

Codex receives `enabled_tools = ["search", "remember"]`, `required = false`, and a 30-second tool timeout. No host receives environment coordinates.

### OpenCode stable and beta formats

Blank files default to the current stable direct entry at `mcp.kaleidoscope`, with `type: "local"`, a command array, and `enabled: true`. This follows the [stable OpenCode MCP documentation](https://dev.opencode.ai/docs/mcp-servers/).

OpenCode v2 is explicitly beta. An existing `mcp.servers` object selects the beta shape deterministically; a blank file selects it only with `--opencode-version beta-v2`. The beta entry is written at `mcp.servers.kaleidoscope`, uses a command array, and sets `codemode: false` so the two MCP tools remain directly available. See the [OpenCode v2 beta documentation](https://opencode.ai/v2/docs/).

A valid existing stable or beta Kaleidoscope entry is adopted in place with an owner receipt. The manager never auto-migrates stable v1 to beta v2. Divergent entries, conflicting requested versions, and ambiguous dual shapes are refused for manual review.

## Install agent instructions

The canonical skill is [skills/use-kaleidoscope/SKILL.md](skills/use-kaleidoscope/SKILL.md). `init --host` installs it for you; the commands below are the manual equivalents. `skill` takes `--host` because the directory differs per harness, and the installed file is byte-identical to the shipped one -- it carries no injected marker.

```bash
kaleidoscope instructions install skill --host claude-code --project "$PWD"
kaleidoscope instructions install skill --host codex --project "$PWD"
kaleidoscope instructions install agents --project "$PWD" --dry-run
kaleidoscope instructions install agents --project "$PWD"
kaleidoscope instructions install claude --project "$PWD"
kaleidoscope instructions install cursor --project "$PWD"

kaleidoscope instructions remove cursor --project "$PWD"
```

These operations use the same confirmation, backup, exact receipt, idempotence, tamper refusal, and concurrent-edit refusal as host configuration. The source snippets are under `snippets/`.

## Offline doctor

```bash
kaleidoscope --engine /absolute/path/to/kscope doctor --project "$PWD"
```

Doctor invokes only local native contract commands, validates profiles/descriptors and owned host state, and returns generic redacted details. Engine subprocesses start from an empty environment and receive only a closed, by-name allowlist: eighteen conventional non-secret bootstrap variables plus two named alpha-entitlement variables (`KALEIDOSCOPE_API_KEY`, `KSCOPE_ENTITLEMENT_HOME`) — each admitted because a reader in the engine consumes it. `KALEIDOSCOPE_CONTROL_PLANE_ORIGIN` was a third until an audit went looking for its reader and found none, and it now sits in the goldens' `never_admitted` list. Provider tokens, account tokens, cloud credentials and direct vault-coordinate variables are not inherited, because they are not named. `KSCOPE_PROFILE_HOME` is retained as the documented non-secret profile-registry override **of the Rust manager**; it has never been forwarded by the Python or TypeScript SDK allowlist and still is not, which is why it sits in the goldens' `never_admitted` list beside the provider keys.

## Python and TypeScript clients

The release-candidate package metadata is ready for offline packaging:

```bash
python -m build --wheel --no-isolation python
cd typescript && npm ci && npm run build && npm pack --dry-run
```

The Python distribution is `kaleidoscope-memory`; the TypeScript distribution
is `@kleos-research/kaleidoscope`. Both are thin process-ABI clients. They do
not contain engine source, a second memory implementation, or a network
installer. Publication remains disabled in this staging checkout.

Each facade now selects only a natively tested platform companion. On macOS
arm64 the companion is `@kleos-research/kaleidoscope-darwin-arm64` for npm and
`kaleidoscope-memory-native-darwin-arm64` for Python. The facade installs the
human-facing `kaleidoscope` command, the explicit native `kscope` command, and
the full language client under one canonical registry coordinate. Missing or
unsupported companions fail with typed installation errors; no postinstall or
runtime download is used. Explicit binary paths remain supported for pinned
controllers.

Every integration consumes the same closed version-1, profile-first launch
descriptor. It names an absolute engine command, `mcp --profile NAME`, exactly
`search` and `remember`, and an empty override environment. The persistent MCP
clients retain one engine process and one initialized session across a complete
agent run.

Controller-owned launches build the child environment from a closed, by-name
allowlist of twenty variables, pinned in
`reference/entitlement-contract-v1.json` and asserted by both SDKs. Eighteen are
conventional non-secret process variables. Two are the alpha-entitlement
variables, and one of those two -- `KALEIDOSCOPE_API_KEY` -- is a credential,
passed deliberately because the engine's entitlement gate reads it and no SDK
path works without it. The promise is therefore narrower than "no credentials",
and it is the one that is kept: **only those names are copied.** Everything else
in the operator's environment -- other providers' API keys, account tokens,
cloud credentials, a database service-role key, anything in a `.env` -- is not
copied, because it is not named. Widening the list is an edit to two literal
tuples and to the shared golden, never a prefix or a pattern.

A tester who prefers to export nothing can instead write the key to the
entitlement key file; the SDK reads the resolved path out of `kscope gate` and
never reimplements it. The SDK checks only that a key is *present*, never that
it is good: the engine and the control plane are the only authorities, and an
Apache-2.0, trivially editable client is the wrong place for a validity check.

Only `search` and `remember` are model tools. Operator commands remain in the
explicit native `Operator` namespace. The clients contain no memory algorithm,
secondary store, compatibility shim, or framework checkpoint backend.

The shared Python/TypeScript surface includes digest-pinned engine resolution,
closed descriptor and profile loading, safe child environments, persistent MCP
sessions, raw model-visible MCP text, parsed native controller calls, explicit operator calls, schema
reads, a one-search controller guard, and partial-batch refusal selection.
See [COMPATIBILITY.md](COMPATIBILITY.md) for the exact dependency and harness
matrix.

Account operations are exposed through `ManagerAccountClient` in Python and
TypeScript. That client invokes only the manager JSON CLI: `status --json`,
`login`, `logout`, `account link|identities|unlink|revoke-session`, and
`devices list|revoke`. `account identities` returns the opaque identity IDs
accepted by `account unlink`; `revoke-session` is deliberately named for its
actual scope and does not claim to deactivate an account.
It never resolves the engine, starts MCP, submits stdin, or inherits
`KSCOPE_*`, provider-token, or vault-coordinate variables. Status has a closed
version-1 parser; the remaining calls return the manager's versioned JSON
object. The command builder is public so interactive login/device flows can be
launched by a host with its preferred terminal UX.

Account provider origin, issuer, audience, and public client ID are the only
account configuration variables forwarded. Refresh credentials remain in the
native operating-system credential store and are not exposed to either SDK.
Credential-free tests cover provider-not-configured and signed-out behavior;
live OIDC and native keychain acceptance remain release-held.

The manager also supports explicit `profile account show|bind|unbind` commands.
They store only a local profile-name → account-UUID reference in
`manager.json`; that reference never changes the profile's vault/principal/
workspace identity and carries no token or credential. These commands neither
resolve the engine nor contact the account service.

Python examples cover generic MCP, Claude Agent SDK, LangChain, LangGraph,
OpenAI Agents SDK, and CrewAI. TypeScript examples cover generic MCP and the
OpenAI Agents SDK. Fake-provider tests exercise lifecycle and routing without
external credentials.

## Local non-auth and account-offline conformance

The DX-10B staging runner exercises a clean temporary user and vault, friendly
init/profile selection, all four reversible host transforms, all four
instruction targets, offline doctor, persistent Python and TypeScript MCP
sessions, generic-harness restart/teardown, runtime privacy checks, source
poison checks, and byte-exact config rollback. It refuses an engine whose hash
does not match the isolated candidate pin, or a public contract whose digest or
embedded executable hash does not bind to that same engine.

```sh
python3 conformance/run_dx10b_non_auth.py \
  --manager target/release/kaleidoscope \
  --engine /absolute/path/to/the/local-candidate \
  --python python/.venv/bin/python \
  --node node \
  --output conformance/evidence/dx10b-non-auth.local.json
```

This is native evidence only for the executing local platform. It covers
provider-not-configured failure, signed-out facade parsing, closed account
command shapes, and no profile/vault effect without live credentials or
keychain writes. Live OIDC/keychain acceptance, live
Codex/Claude/Cursor/OpenCode acceptance, signed installation/update, machine
restart, other platform targets, and production promotion remain
dependency-held.

The separate credential-free native Codex lane runs the real
`codex mcp add/list/get/remove` workflow inside an isolated `CODEX_HOME`, proves
byte-exact rollback and the absence of environment/vault coordinates, then
independently initializes the real stdio server and requires discovery to be
exactly `search` and `remember`. It follows the
[official Codex MCP workflow](https://developers.openai.com/codex/mcp) but does
not invoke a model, account, browser, TUI, IDE, or network-dependent command.

```sh
python3 conformance/run_dx10b_hosts.py \
  --manager /absolute/path/to/kaleidoscope \
  --engine /absolute/path/to/the-local-candidate \
  --manager-provenance /absolute/path/to/provenance.json \
  --codex /absolute/path/to/codex \
  --output conformance/evidence/dx10b-hosts.local.json
```

## Safety boundary

- Symlinked *configuration files* are refused. A symlinked **engine** on `PATH` is not: `npm i -g` installs every `bin` entry as a symlink, so the manager canonicalises the engine path first and then validates the file it will actually execute.
- Unbounded/non-regular files, traversal, malformed structured files, invalid receipts, unmanaged name collisions, and concurrent edits are refused.
- A marker that is duplicated, retyped or missing its closing half is refused too, and `--force` removes it and discloses exactly which bytes went. The one state nothing can repair is a block with no marker of any kind left; that refusal names the file and the receipt to delete by hand.
- Disconnect removes only bytes exactly matching the owner receipt. Unrelated content is preserved.
- Repeating a successful connect or instruction install is a no-op and does not create a second backup.
- Profile, host, instruction, and doctor commands remain local-only. Account commands use only the configured first-party HTTPS/OIDC endpoints; the SDK facade forwards no bearer token or vault authority.

Run the source-poison check from the repository root:

```sh
python3 scripts/poison_scan.py
```

This staging implementation is licensed (Apache-2.0, see [LICENSE](LICENSE) and
[NOTICE](NOTICE)) but not published. It does not provide distribution approval,
package publication, repository publication, a production account service, or
authenticated operator attribution. Those are separate release and product
decisions.

## Frameworks

Install the CLI, then hand Kaleidoscope to your agent framework as tools.
`KaleidoscopeMemory` opens one engine process for the whole run and builds the
tool definitions from live MCP discovery, so the schemas your model sees are the
engine's own — this SDK never writes one.

**Install exactly one framework extra per environment.** The three MCP-consuming
extras pin `mcp` to three mutually exclusive versions, so one virtualenv can
satisfy at most one of them. If the installed `mcp` violates the framework's own
requirement, `as_*_tools()` refuses and names both versions and the extra,
rather than letting the framework fail later with a message that does not
mention `mcp`.

### OpenAI Agents SDK

```python
import asyncio
from agents import Agent, Runner
from kaleidoscope_memory import KaleidoscopeMemory


async def main() -> None:
    async with KaleidoscopeMemory(profile="default", api_key="ksk_alpha....") as memory:
        agent = Agent(
            name="Memory-aware assistant",
            instructions=(
                "Use Kaleidoscope as the only durable memory owner. Search at the "
                "start of a nontrivial task; remember verified durable deltas."
            ),
            model="gpt-5-mini",
            tools=memory.as_openai_tools(),
        )
        result = await Runner.run(agent, "What did we decide about the retry policy?")
        print(result.final_output)


asyncio.run(main())
```

### LangChain

```python
import asyncio
from langchain.agents import create_agent
from kaleidoscope_memory import KaleidoscopeMemory


async def main() -> None:
    async with KaleidoscopeMemory(profile="default") as memory:   # key from KALEIDOSCOPE_API_KEY
        agent = create_agent(
            model="openai:gpt-5-mini",
            tools=memory.as_langchain_tools(),
            system_prompt="Use Kaleidoscope as the only durable memory owner.",
        )
        state = await agent.ainvoke(
            {"messages": [{"role": "user", "content": "What did we decide about retries?"}]}
        )
        print(state["messages"][-1].content)


asyncio.run(main())
```

### LangGraph

```python
import asyncio
from langchain.chat_models import init_chat_model
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from kaleidoscope_memory import KaleidoscopeMemory


async def main() -> None:
    async with KaleidoscopeMemory(profile="default") as memory:
        tools = memory.as_langgraph_tools()          # alias of as_langchain_tools
        model = init_chat_model("openai:gpt-5-mini").bind_tools(tools)

        async def call_model(state: MessagesState) -> dict:
            return {"messages": [await model.ainvoke(state["messages"])]}

        builder = StateGraph(MessagesState)
        builder.add_node("model", call_model)
        builder.add_node("tools", ToolNode(tools))
        builder.add_edge(START, "model")
        builder.add_conditional_edges("model", _needs_tools, {"tools": "tools", "end": END})
        builder.add_edge("tools", "model")
        graph = builder.compile()

        # The graph is built and run INSIDE the context. get_tools()-style
        # stateless clients respawn stdio per call; the context is the lifecycle
        # boundary that keeps exactly one engine process alive across turns.
        state = await graph.ainvoke(
            {"messages": [{"role": "user", "content": "What did we decide about retries?"}]}
        )
        print(state["messages"][-1].content)


def _needs_tools(state: MessagesState) -> str:
    return "tools" if getattr(state["messages"][-1], "tool_calls", None) else "end"


asyncio.run(main())
```

### CrewAI

CrewAI's `kickoff()` is synchronous, so this is the **sync** form. `with` starts
one private event loop in one non-daemon thread which owns exactly one engine
process for the whole crew run.

```python
from crewai import Agent, Crew, Task
from kaleidoscope_memory import KaleidoscopeMemory

with KaleidoscopeMemory(profile="default", api_key="ksk_alpha....") as memory:
    agent = Agent(
        role="Memory-aware assistant",
        goal="Complete the task using only the public Kaleidoscope memory boundary",
        backstory="Uses Kaleidoscope as the sole durable memory owner.",
        llm="gpt-5-mini",
        tools=memory.as_crewai_tools(),
    )
    task = Task(
        description="What did we decide about the retry policy?",
        expected_output="A concise answer citing the remembered decision.",
        agent=agent,
    )
    print(Crew(agents=[agent], tasks=[task]).kickoff())
```

### Letting the framework own the child

If you would rather the framework spawn the engine itself:

```python
from kaleidoscope_memory import KaleidoscopeMemory

memory = KaleidoscopeMemory(profile="default", api_key="ksk_alpha....")
config = memory.mcp_server_config()
# -> {"command": "/abs/path/kscope", "args": ["mcp", "--profile", "default"],
#     "env": {...the 20-name allowlist, with KALEIDOSCOPE_API_KEY set...}}
```

This spawns nothing and is the alternative to opening the object, not an
addition to it — calling it inside the context refuses. Two properties do not
survive the handover: the child's stderr is no longer bounded (the MCP SDK's
default inherits it into the parent, which for the OpenAI Agents SDK means
model-visible output), and an entitlement refusal arrives as the framework's
transport error rather than as `EntitlementError` with this SDK's instruction
text. The allowlist and the key still reach the child.

### `remember` is not `mem0.add(text)`

`mem0.add([{"role": "user", "content": "..."}])` takes prose and runs its own
extraction. Kaleidoscope's `remember` takes a structured write: a `mode`, a
`content_md` beginning with `# `, and a semantic delta whose entities each carry
a mandatory gloss. This SDK passes your fields through **verbatim** and lets the
engine validate them. A `remember(text)` convenience would have to invent that
structure on the model's behalf, which is the SDK making up vocabulary — and one
hand-written relation name in one prompt is what produced 13,060 identical
proposals in this project's own history, which were then analysed as evidence
about how agents choose relations. What teaches a model to fill the structure in
is the engine's own field descriptions, which arrive with the schema.

This is a real ergonomic gap against mem0 and it is stated here rather than
hidden behind a lossy wrapper.

## The API key

Two routes, and both work:

```python
# 1. in code
memory = KaleidoscopeMemory(profile="default", api_key="ksk_alpha....")

# 2. in the environment  (omit api_key entirely)
#    export KALEIDOSCOPE_API_KEY=ksk_alpha....
memory = KaleidoscopeMemory(profile="default")
```

**Code beats environment. Environment beats key file.** The SDK implements only
the first comparison: a code key is placed in `KALEIDOSCOPE_API_KEY` in the
child's environment, and the engine's own environment-before-file rule ranks it
against the key file correctly with no SDK involvement. `os.environ` is never
mutated, so the key reaches this SDK's children and no other subprocess your
process spawns. The allowlist does not grow to carry it: the key rides in a name
already on the twenty-name list.

**There is no `.env` file reader**, in either language, and none is planned.
"An env file works" means your shell or your tooling exported the variable, or
you wrote the key to the engine's key file. A `.env` reader would be a fourth
credential source needing its own precedence rank, and it would put this SDK in
the business of parsing files that also hold your *other* secrets — the exact
blast radius the allowlist exists to prevent.

### What this SDK will never do with your key

It **carries** the credential and **reports** the engine's verdict. It is never
an authority on whether a key is good:

- no signature, prefix, length, charset or checksum check;
- no expiry arithmetic — `E_KEY_EXPIRED` and `E_GRACE_EXPIRED` are identifiers
  the engine emits and this SDK renders;
- no caching of a verdict; the memoised `kscope gate` answer is about the
  engine's *build*, reads no key, and cannot take one as an argument.

This package is Apache-2.0 and trivially editable, so a validity rule here would
be theatre against an adversary and a second source of truth against everyone
else. When two copies of a rule disagree, the SDK either refuses a key that
works or admits one that does not, and in both cases the user is told something
false by the layer with no standing to say it. The permitted preflight is
exactly: is a key *present*, and can it be put in an environment variable at
all. That saves a spawn and produces a better message. It decides nothing.

The one place a key is looked at is redaction: a key-shaped string is masked
wherever it appears in a child's diagnostic. Redaction is not validation — a
string that matches is masked whether or not it is real, a string that does not
match is not treated as bad, and nothing branches on the result.

### `api_key=` does not reach a harness

`api_key=` configures the children **this SDK** spawns. A harness that launches
the engine itself — Claude Code, Cursor, Codex, OpenCode reading an MCP server
entry — never passes through Python, and every renderer of those entries emits
an empty `env` block deliberately. Such a harness takes its key from
`KALEIDOSCOPE_API_KEY` in the environment, or from the engine's key file.

So if you wire up a harness and then set a key only in Python, you will have a
working Python client and a harness that refuses. The two routes do not overlap.
