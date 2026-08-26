# DX-10B local non-auth and account-offline conformance

`run_dx10b_non_auth.py` is a fail-closed, local-only conformance runner for the
consolidated manager and Python/TypeScript SDK. It accepts an already built
manager plus the exact isolated engine candidate, creates a disposable user and
vault, verifies that the pinned public contract names that exact executable,
and writes a source-free evidence manifest.

It proves only the executing native platform. The Codex, Claude Code, Cursor
and OpenCode checks exercise the manager's configuration transforms; they are
not live-host acceptance claims. Generic Python and TypeScript MCP clients do
perform real persistent-process calls, restart the process, read the same
memory after restart, and verify teardown.

The runner also proves that the real manager fails closed when no account
provider is configured, and that the Python and TypeScript manager-only account
facades produce the closed CLI shapes and parse signed-out status through a
credential-free fake manager. These calls receive no engine, MCP operation,
vault coordinate, or stdin memory payload and leave the disposable profile and
vault byte-identical. Live OIDC, native credential-store acceptance, live-host,
machine-restart, signed installer/update/rollback, other-platform and
production-promotion cells remain dependency-held in the manifest.

The output contains hashes, pass/held states and bounded counts. It never
contains the temporary vault path, raw workspace/principal/journal identities,
memory IDs, process IDs, credentials, or host configuration bytes.

## Credential-free native host lane

`run_dx10b_hosts.py` binds the manager to SDK commit `05948a3...` through
DX-06 provenance, pins the exact `988192ac...` engine, and creates disposable
HOME, CODEX_HOME, XDG, project, profile, and vault roots. It uses the installed
Codex CLI for `mcp add/list/get/remove`, requires no environment or vault
coordinates in config, proves byte-exact rollback, and separately performs real
stdio discovery of exactly `search` and `remember`.

The [official Codex MCP documentation](https://developers.openai.com/codex/mcp)
documents local STDIO servers, `~/.codex/config.toml`, and these CLI workflows.
This lane invokes no model, account, browser, TUI, IDE, or network-dependent
command. Claude Code, Cursor, and OpenCode remain held when their CLIs are
absent; `--host-binary HOST=PATH` provides the bounded future inventory hook.

```sh
python3 conformance/run_dx10b_hosts.py \
  --manager /absolute/path/to/kaleidoscope \
  --engine /absolute/path/to/kscope \
  --manager-provenance /absolute/path/to/provenance.json \
  --codex /absolute/path/to/codex \
  --output conformance/evidence/dx10b-hosts.local.json
```
