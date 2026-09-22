# Notes for coding agents

This file is for AI coding agents working in this repository, and for the people who direct
them. [CONTRIBUTING.md](CONTRIBUTING.md) explains how to build and test. The rules below are the
ones a change here most often breaks.

1. **This repository is public; the engine is not.** Never add engine source, names of engine
   internals, real vault contents or identifiers, paths from a developer's machine, commit ids,
   or API keys. Run `python3 scripts/poison_scan.py` before every commit.

2. **Do not hand-edit generated files.** `reference/binary-pin.json`, the vendored engine
   contract in `reference/` and the platform package pins are written by
   `scripts/sync_from_release.py --apply` from an engine release. Never restate the versions,
   commits or digests they hold in prose: the pin file is the one place they live.

3. **Tool schemas come from the engine.** Nothing in this repository writes a JSON schema, a
   field name, a field description or an enum value for `search` or `remember`. The clients
   build their tools from live MCP discovery, which is why the framework tools only exist
   inside an open `KaleidoscopeMemory`.

4. **`remember` fields pass through unchanged.** Do not add a `remember(text)` convenience, or
   anything else that invents the structured write on the model's behalf. The engine validates
   the fields; its schema teaches the model how to fill them in.

5. **The clients only check that a key is present.** Never add key validation (prefix, length,
   characters, checksum, expiry arithmetic) and never cache the engine's verdict. The engine
   and the key service are the only authorities. A second copy of a validity rule either
   refuses a key that works or admits one that does not.

6. **There is no `.env` reader, and none is planned.** It would be a fourth source of
   credentials with its own precedence, and it would parse files that hold other secrets.

7. **The engine's environment is an allowlist of names.** To pass another variable to the
   engine, change the literal lists in `python/src/kaleidoscope_memory/descriptor.py` and
   `typescript/src/descriptor.ts` and the file `reference/entitlement-contract-v1.json`
   together (the manager keeps its own list in `src/engine.rs`). Never add a prefix or a
   pattern. See [docs/api-keys-and-environment.md](docs/api-keys-and-environment.md).

8. **Instruction assets ship to users.** Files under `skills/` and `snippets/` are compiled
   into the manager binary and written into users' projects, where their agents read them.
   Treat an edit there as a change to what every user's agent is told.

9. **Run the manager in a scratch project.** It writes `.mcp.json`, `CLAUDE.md`, `.claude/`
   and small `*.kaleidoscope-owner.json` receipts into whatever project it runs in. Those files
   are ignored here and must never be committed.
