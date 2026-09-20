# Three artefacts, three channels, and one name two of them claim

Written down because it was reconstructed once from scratch, wrongly, and the
mistake cost an hour: a search of the *engine* repository for the host-wiring
code correctly found none, and concluded the mechanism did not exist. It exists.
It is here.

| Artefact | Lives in | Ships as | Contains |
| --- | --- | --- | --- |
| **Engine** | `kleos-research/kaleidoscope` | npm `@kleos-research/kaleidoscope` + six per-platform packages | `kscope`: the vault, the CLI, the MCP server. The two agent tools `search` and `remember`. |
| **Manager** | **here**, `src/` (Rust) | the `kaleidoscope` binary | Host wiring: MCP registration, instruction blocks, the skill, the session hook. Profiles, accounts, doctor. |
| **Python client** | **here**, `python/` | PyPI `kscope-memory`, module `kaleidoscope_memory` | Client + agent-framework integrations: claude, crewai, langgraph, openai. |
| **TypeScript client** | **here**, `typescript/` | npm `@kleos-research/kaleidoscope` | Client, and the `kaleidoscope` + `kscope` bins. |

**The engine is not a memory library you import. It is a binary you talk to.**
The clients here are *client surfaces* onto it; the manager is the thing that
tells an agent harness the binary exists. Neither contains a memory engine, a
vault implementation, a model, or an MCP proxy.

## The collision, stated so nobody rediscovers it

`typescript/package.json` and the engine's `scripts/npm_targets.py:135` both
name **`@kleos-research/kaleidoscope`**. Two repositories, one npm name; whichever
publishes last silently replaces the other. The engine's `check_npm_package.py`
cannot see it -- it validates one tarball against an allowlist, never against
another repository's claim.

It matters which way it resolves, because the two packages are not
interchangeable. The engine's entry package ships `bin: {kscope}` alone; this
one ships `bin: {kaleidoscope, kscope}` -- manager *and* engine. **Only the
second makes `npm install` followed by an init produce a working, discovered
setup**, which is the whole point of having a manager.

## Why an agent forgets Kaleidoscope exists

Measured in a real session with everything correctly installed. The concrete
WHEN-triggers -- *call `search` BEFORE a nontrivial task, call `remember`
unprompted* -- live in the MCP **tool descriptions**, about 2,539 bytes of the
best instruction text in the system. A client that defers tool definitions shows
those descriptions **name-only**, so that text never reaches the model.
`SERVER_INSTRUCTIONS` does load and had spare budget.

The lesson generalises past this bug: **put an instruction where the model will
be standing when it has to decide.** A refusal is read at the moment of failure
with full attention; a document is read once, early, competing with everything
else. Errors are a prompting surface, and an error addressed to a human at a
shell is wasted on an agent that can only relay, retry, or fall back.

<!-- >>> kaleidoscope-manager owner=kaleidoscope-manager-v1 instruction=claude -->
## Kaleidoscope memory

For nontrivial tasks, read and follow `.claude/skills/use-kaleidoscope/SKILL.md` before using Kaleidoscope. Use only the public `search` and `remember` tools for agent work. Retrieve at task start, persist only verified durable semantic deltas, never store secrets or transcripts, and leave the required exposure record. Curated repository evidence maps are durable deltas, unlike raw artifacts: save verified conclusions and evidence pointers, and batch independently correctable findings as atomic items when the live schema supports it. If the skill or authenticated tools are unavailable, continue without inventing memory operations.
<!-- <<< kaleidoscope-manager owner=kaleidoscope-manager-v1 instruction=claude -->
