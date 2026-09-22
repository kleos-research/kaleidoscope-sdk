# Kaleidoscope for TypeScript

A TypeScript client for [Kaleidoscope](https://memory.kleosresearch.xyz), local memory for AI
agents. It starts the `kscope` engine, keeps one MCP session open, and calls the two memory
tools, `search` and `remember`, from Node.js.

**It is not on npm yet.** The npm package named `@kleos-research/kaleidoscope` installs the
Kaleidoscope engine, not this client. To use this client, build it from the repository.

## Build it

You need Node.js 22 or newer, and the engine installed and activated. The
[quickstart](https://github.com/kleos-research/kaleidoscope-sdk#quickstart) covers the engine,
including how to get an API key.

```bash
git clone https://github.com/kleos-research/kaleidoscope-sdk.git
cd kaleidoscope-sdk/typescript
npm ci
npm run build
```

## Use it

Give the client the path to the engine. `kscope init` keeps a copy of the engine at
`~/.kaleidoscope/bin/kscope`, and creates the `default` profile used here:

```js
import { homedir } from "node:os";
import { join } from "node:path";
import { loadLaunchDescriptor, PersistentKaleidoscopeSession } from "./dist/src/index.js";

const engine = join(homedir(), ".kaleidoscope", "bin", "kscope");
const descriptor = loadLaunchDescriptor(engine, "default");

const memory = await new PersistentKaleidoscopeSession(descriptor).connect();
try {
  console.log(await memory.searchText({ query: "What did we decide about retries?" }));
} finally {
  await memory.close();
}
```

Save it as a `.mjs` file in this folder and run it with `node`. A session keeps one engine
process for its whole life, so open one per run, not one per call.

Pass the path explicitly. Without one, the client looks for a platform package that the
published npm packages do not provide.

More examples: [`examples/genericMcp.ts`](examples/genericMcp.ts), a plain MCP session, and
[`examples/openaiAgents.ts`](examples/openaiAgents.ts), the OpenAI Agents SDK.

## Your API key

The engine reads your key from `KALEIDOSCOPE_API_KEY` or from the key file that
`kscope activate` wrote. To pass it in code, use
`new PersistentKaleidoscopeSession(descriptor, { apiKey })`.

The client starts the engine with only a fixed list of environment variables, so other secrets
in your environment are not passed on. If the engine refuses for a key reason, you get an
`EntitlementError` with a readable `message`, the engine's own output in `diagnostic` (shortened,
with keys masked), and the refusal code, such as `E_NO_KEY`, in `reason`. See
[API keys and the engine's environment](https://github.com/kleos-research/kaleidoscope-sdk/blob/main/docs/api-keys-and-environment.md).

## Run the tests

```bash
npm run test:bootstrap
npm test
```

The tests talk to a small fake MCP server written in Python. `test:bootstrap` creates a Python
virtual environment at `../python/.venv` with one pinned dependency (`mcp==1.29.0`) and runs
`npm ci`. It installs no engine, creates no vault, and contacts no account service.

## Licence

Apache-2.0. See LICENSE for the terms and NOTICE for the copyright line, which Section 4(d) of
the licence requires anyone redistributing this package to carry forward.

The licence covers this package's own source. It does not cover the `kscope` memory engine or
any other proprietary object code delivered inside a platform package. Those are closed source,
are not part of this repository, and are not licensed by it at all: separate terms apply to
them. `kscope licences` prints the engine's own third-party notices, including which ones are
not embedded yet. Notices for this repository's dependencies are in `THIRD_PARTY_NOTICES.md` at
the repository root.
