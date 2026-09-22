# The `kaleidoscope` manager

`kaleidoscope` connects a Kaleidoscope vault to the coding agents on your machine (Claude
Code, Codex, Cursor and OpenCode) and removes that connection cleanly when you want it gone.
It also installs the agent skill and instruction files, checks your setup offline, and
provides a session-start hook for Claude Code.

**Most people do not need it.** `kscope init`, which comes with the npm package, creates a
vault and connects every agent it finds in one step. Reach for `kaleidoscope` when you want
more control: one editor at a time, wiring kept inside one project, a preview before any file
changes, or a clean teardown afterwards.

**It is not distributed yet.** No package registry carries `kaleidoscope`, and the npm package
does not include it. Build it from this repository.

## Build it

You need Rust 1.85 or newer.

```bash
git clone https://github.com/kleos-research/kaleidoscope-sdk.git
cd kaleidoscope-sdk
cargo build --release
```

The program is `target/release/kaleidoscope`. Put it on your `PATH`, or call it by its full
path.

## Point it at the engine

The manager drives the `kscope` engine, which you install separately (see the
[quickstart](../README.md#quickstart)). It looks for the engine in this order:

1. `--engine PATH` on the command line;
2. the `KALEIDOSCOPE_ENGINE` environment variable;
3. a `kscope` in the same folder as `kaleidoscope`;
4. each folder on your `PATH`.

If you installed `kscope` with npm, point the manager at the copy of the engine that
`kscope init` keeps. The `kscope` that npm puts on your `PATH` is a launcher script, and the
manager cannot run it:

```bash
export KALEIDOSCOPE_ENGINE="$HOME/.kaleidoscope/bin/kscope"
```

## Set up a project

```bash
cd your-project
kaleidoscope init --host claude-code --dry-run   # show what would change
kaleidoscope init --host claude-code             # do it, after asking you to confirm
```

`--host` can be repeated, and takes `claude-code`, `codex`, `cursor` or `opencode`. Add
`--yes` to skip the confirmation. Without `--host`, `init` only sets up the profile and lists the
editors it could have connected.

### Finding or creating the vault

`init` looks for an existing vault before it creates one, so running it again never creates a
second vault. It checks these places in order, and the first rule that reaches a decision wins:

1. `--root PATH`: exactly that path, and nothing else is searched.
2. A profile that already has the `--profile` name. That profile is the answer
   (`already_initialized`). If `--root` names a different vault, `init` refuses rather than
   repointing the profile.
3. The vaults of every other registered profile.
4. The manager's default vault location for this profile.
5. `<project>/.kaleidoscope`.
6. Every folder directly inside the user-level vault folder.

| Vaults found | What happens | `status` | Exit code |
| --- | --- | --- | --- |
| none | a new vault is created in the default location | `initialized` | 0 |
| exactly one | that vault is adopted | `adopted` | 0 |
| more than one | refused; every vault found is listed, with the rule that found it | `ambiguous` | 2 |

`--adopt` forces the single-vault path. `--create` forces a new vault, and refuses if `--root`
already holds one.

### What `--host` sets up

For each editor, `init --host` performs four steps:

| Step | Codex | Claude Code | Cursor | OpenCode |
| --- | --- | --- | --- | --- |
| MCP server entry | `.codex/config.toml` | `.mcp.json` | `.cursor/mcp.json` | `opencode.json` |
| Instructions | `AGENTS.md` | `CLAUDE.md` | `.cursor/rules/kaleidoscope.mdc` | `AGENTS.md` |
| Skill | `.agents/skills/…` | `.claude/skills/…` | none; the rule is the skill | `.agents/skills/…` |
| Hook | none | `SessionStart` in `.claude/settings.json` | none | not yet |

The table shows project paths. With the default user scope, the MCP entry and the hook go in
your home folder instead (see the next section).

Each step either completes or leaves its file untouched, but `init` as a whole is not all or
nothing. If a step fails, the steps before it stay applied. `init` reports `"issue"` with the
reason, exits 2, and names the `teardown` command that undoes what did land. A successful
connection is never rolled back because a later step failed.

## Where files go

**User scope is the default.** The MCP entry and the Claude Code hook go under your home
folder, so every directory sees them, including git worktrees and temporary clones. Agent tools
often run your work in exactly those places, and they do not read a project-scoped entry there.
`--scope project` puts the entry and the hook in the project instead. Every command says on
stderr which scope it used, and whether that came from the flag or the default.

**Instructions and the skill always go in the project**, whatever `--scope` says: `CLAUDE.md`,
`AGENTS.md`, the Cursor rule and `SKILL.md`. Git is what carries them into a worktree or a
clone, and a home-wide `CLAUDE.md` would bring Kaleidoscope into every unrelated project you
open. The JSON output reports this split as `scope_applies_to` and `instructions_scope`.

**Project files land at the project root**, not in your current folder. The engine finds the
root by walking up to a marker such as `CLAUDE.md`, `.claude/` or `.git`, and `--project PATH`
overrides it. Inside a linked git worktree, files go into the worktree, not the main checkout.

If you set up a project with an older version of the manager, which defaulted to project scope,
a plain `init` leaves those files where they are. It reports a `project_scope_carryover` warning
naming them, with the `teardown` command that removes them. Nothing is removed without you
asking.

## How changes are made

Every change is shown to you first and needs your confirmation unless you pass `--yes`.
`--dry-run` shows the plan and changes nothing. Before it edits an existing file, the manager
makes a bounded backup beside it. After each change it writes a small receipt file beside the
target (`*.kaleidoscope-owner.json`) recording exactly which bytes it owns. Doing the same thing
twice changes nothing and makes no second backup.

**If a file already contains exactly what the manager would write, it is adopted, not
refused.** This covers an MCP entry or a skill you placed by hand. The manager writes a receipt
beside your file and changes no bytes. If the content differs, the manager refuses, and the
message names the flag that skips that step (`--no-connect`, `--no-instructions`, `--no-skill`
or `--no-hooks`) or the exact key to delete by hand. Tearing down an adopted entry removes the
entry. Tearing down an adopted file leaves the file, because it is yours, and removes only the
receipt.

Before it writes any editor configuration, the manager asks the engine for the profile's launch
details and checks them. The command must be the engine itself, run over stdio with the
arguments `mcp --profile <name>`, offering exactly the tools `search` and `remember`, with no
extra environment. Anything else is refused before a file is touched.

## Connect or disconnect one editor

```bash
kaleidoscope connect codex --profile default --dry-run   # preview, changes nothing
kaleidoscope connect codex --profile default             # apply, after confirmation
kaleidoscope disconnect codex                            # remove only what the manager added
```

The files each editor reads:

| Editor | Project | User |
| --- | --- | --- |
| Codex | `.codex/config.toml` | `~/.codex/config.toml` |
| Claude Code | `.mcp.json` | `~/.claude.json` |
| Cursor | `.cursor/mcp.json` | `~/.cursor/mcp.json` |
| OpenCode | `opencode.json` | `~/.config/opencode/opencode.json` |

Codex gets `enabled_tools = ["search", "remember"]`, `required = false` and a 30-second tool
timeout. No editor configuration contains your vault's location or any environment values.

### OpenCode: stable and beta formats

A new or empty OpenCode file gets the current stable format: an entry at `mcp.kaleidoscope`
with `type: "local"`, a command array and `enabled: true`, following the
[stable OpenCode MCP documentation](https://dev.opencode.ai/docs/mcp-servers/).

OpenCode v2 is in beta. An existing `mcp.servers` object selects the beta format; for a new
file, pass `--opencode-version beta-v2`. The beta entry goes at `mcp.servers.kaleidoscope`, uses
a command array, and sets `codemode: false` so that the two tools stay directly available. See
the [OpenCode v2 beta documentation](https://opencode.ai/v2/docs/).

A valid existing Kaleidoscope entry in either format is adopted in place. The manager never
migrates a stable entry to the beta format by itself. Entries that differ, conflicting version
requests and files containing both formats are refused, for you to sort out by hand.

## Install the agent instructions yourself

`init --host` installs these for you. The commands below do the same one piece at a time. The
skill needs `--host` because each editor reads skills from a different folder: Claude Code reads
only `.claude/skills/<name>/SKILL.md`, while Codex and OpenCode share `.agents/skills/`.

```bash
kaleidoscope instructions install skill --host claude-code
kaleidoscope instructions install skill --host codex
kaleidoscope instructions install agents --dry-run
kaleidoscope instructions install agents
kaleidoscope instructions install claude
kaleidoscope instructions install cursor

kaleidoscope instructions remove cursor
```

The installed skill is byte-for-byte the file in
[`skills/use-kaleidoscope/SKILL.md`](../skills/use-kaleidoscope/SKILL.md). The instruction
blocks come from [`snippets/`](../snippets/). These commands use the same preview, backup,
receipt and refusal rules as editor configuration.

## Remove everything: `teardown`

```bash
kaleidoscope teardown --host claude-code --dry-run
kaleidoscope teardown --host claude-code
```

`teardown` reverses the four `init` steps in reverse order. For each file it reports which of
two kinds of restore it achieved:

- **`byte_identical`**: the file was exactly what the manager wrote, so the original bytes go
  back, or a file the manager created is deleted along with any folder it created.
- **`structural`**: you edited the file after the manager wrote it, so restoring the original
  bytes would destroy your edit. Only the manager's part is removed and the rest is written
  back; the report adds `formatting: "normalized"`, and the backup is kept.

If you hand-edited a block that the manager owns, removing it refuses and names `--force`. With
`--force`, the manager prints the bytes it is about to discard in full on stderr, removes the
block, and reports `discarded_user_edits: true`. A block whose markers are duplicated, retyped
or half missing is handled the same way. The one state nothing can repair is a block with no
marker left at all; that refusal names the file and the receipt to delete by hand.

`teardown` never touches your vault or your profile. To remove data, use
`kaleidoscope profile remove NAME` and `kscope vault-delete ROOT`.

## Check your setup: `doctor`

```bash
kaleidoscope doctor
```

`doctor` works offline. It runs only local engine commands, checks your profiles, launch
details, editor entries, instructions, skills and hooks, and prints a JSON report. The report
never includes your vault's location or identifiers, or any credentials. It exits 0 when
everything is in order and 3 when at least one check reports an issue.

## The Claude Code session-start hook

`kaleidoscope hook session-start [--profile NAME] [--no-memories]` is run by Claude Code, not by
you. `init --host claude-code` registers it. It exits 0 in every case, because a hook that
fails is a hook people switch off.

Each time a session starts, it:

- speaks MCP to the exact server Claude Code will start for this project, to confirm the two
  tools are really visible;
- asks the engine for the profile's launch details, to tell "your memory setup is broken" apart
  from "the setup is fine but the editor rejected the tool list";
- finds the project root, following a linked worktree back to its main checkout;
- retrieves a few memories for the project and adds them to the session's context.

The first line of what it adds is a one-line JSON summary, including `tools_visible` and each
check behind it, so a later session can see exactly what happened. When the tools are not
reachable it says so plainly and names the `kscope` command-line fallback, which still works.

It searches but never writes: no call to `remember`. Every search is recorded in the vault, so
each session start adds one such record. It asks for 4 results and caps the output: the whole
line at 4 KiB, the added context at 2,600 bytes, and the memories within it at 1,500 bytes. Text
over the limit is shortened, never replaced with a generic sentence. Every step has a time limit
and all of them share a 6-second deadline, inside the 10 seconds the settings entry allows.
Against a real vault of 179 memories it took about 100 ms from start to finish. Pass
`--no-memories`, or set `KALEIDOSCOPE_HOOK_MEMORIES=0`, to keep the checks and skip the search.

Why a hook as well as `CLAUDE.md`: Claude Code reads `CLAUDE.md` once at session start, but it
runs the hook again on resume, on clear and after compaction, so the context survives
compaction.

## Safety rules

- Configuration files that are symbolic links are refused. An engine reached through a symbolic
  link is fine: npm installs commands as links, so the manager resolves the link and checks the
  real file it will run.
- Files that are too large or not regular files, paths that escape the project, malformed
  configuration, invalid receipts, name collisions with entries the manager does not own, and
  files changed by someone else during an edit are all refused.
- `disconnect` removes only bytes that exactly match the receipt. Everything else in the file is
  kept.
- Profile, editor, instruction and `doctor` commands never use the network.

## What the manager stores

The manager's own state file, `manager.json`, holds only a version, the active profile, and
any account bindings. Your vault's location and identifiers, and any credentials, are never
written to it, to receipts, to `doctor` output or to editor configuration.

## Account commands

The manager also has account commands: `login`, `status`, `logout`, `account` and `devices`,
plus `profile account show|bind|unbind`. There is no Kaleidoscope account service to sign in to
yet, so they are not usable: `status` reports that no account provider is configured.
`profile account bind` stores only a local link from a profile name to an account id. It never
changes which vault the profile points at, and it holds no token.

The Python and TypeScript clients can drive these commands through `ManagerAccountClient`. It
runs only the manager's JSON commands: it never starts the engine, opens an MCP session or
passes on your vault's location, and sign-in tokens stay in your operating system's credential
store, out of reach of either client.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success, including every documented no-op |
| 2 | Refused |
| 3 | `doctor` finished and at least one check reported an issue |
