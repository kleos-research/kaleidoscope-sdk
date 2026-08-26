# Kaleidoscope for TypeScript

`@kleos-research/kaleidoscope` is the public TypeScript client and command
package for Kaleidoscope. The package contains the typed process/MCP helpers
and two small command launchers; its platform companion contains the public
manager and proprietary `kscope` engine as object code.

The first release candidate supports only the natively exercised macOS arm64
coordinate. Installation remains protected and unpublished until the legal,
signing, registry, and promotion gates are approved.

```sh
npm install @kleos-research/kaleidoscope
kaleidoscope --version
kscope --version
```

```ts
import {
  installedPayloadPaths,
  loadLaunchDescriptor,
  mcpStdioConfig,
} from "@kleos-research/kaleidoscope";

const { engine } = installedPayloadPaths();
const descriptor = loadLaunchDescriptor(engine, "default");
const mcp = mcpStdioConfig(descriptor);
```

Explicit executable paths and SHA-256 pins remain available for controllers.
The wrapper implements no memory algorithm or secondary store, and models see
only the native MCP tools `search` and `remember`.

## The alpha entitlement and the child environment

An alpha `kscope` refuses `mcp`, `context`, `call` and `serve` without a valid
entitlement, so the key has to reach the engine this package spawns.

The child environment is built from a closed, **by-name** allowlist in
`src/descriptor.ts`: eighteen conventional process/bootstrap variables, plus
exactly two entitlement variables — `KALEIDOSCOPE_API_KEY` and
`KSCOPE_ENTITLEMENT_HOME`. The first is a credential and is passed
deliberately; the second is where the engine looks for the key file.

Everything else in your environment is not copied, because it is not named:
other providers' API keys, a Supabase service-role key, anything in a `.env`.
There is no prefix rule and no pattern — `KSCOPE_ENTITLEMENT_PROBE`, which names
an executable the engine would spawn and hand the key to, is deliberately not
admitted. Widening the list is an edit to two literal arrays and to
`reference/entitlement-contract-v1.json`.

If you would rather export nothing, write the key to the file `kscope gate`
names under `key_file`, mode `0600`. The SDK checks only that a key is
**present** — never whether it is good. Validity is decided by the engine and
the control plane; this package is Apache-2.0 and trivially editable, so a check
here would be theatre and a second source of truth.

A refusal arrives as a typed `EntitlementError` carrying this SDK's own
actionable `message`, the engine's bounded and redacted stderr in `diagnostic`,
and the identifier in `reason`. Child stderr is still never streamed anywhere.

## Local test bootstrap

The TypeScript MCP fixture is a test-only Python stdio server, so a clean
checkout needs its ignored Python virtual environment before running `npm test`:

```sh
cd typescript
npm run test:bootstrap
npm test
```

The bootstrap creates `python/.venv`, installs only `mcp==1.29.0`, and runs
`npm ci`. It does not install a Kaleidoscope engine, create a vault, or contact
the account service.

## Licence

Apache-2.0. See LICENSE for the terms and NOTICE for the copyright line that
Section 4(d) requires downstream redistributors to carry forward.

That licence covers this package's own source. It does not cover the `kscope`
memory engine or any other proprietary object-code payload delivered inside a
platform package; those are closed source, are not part of this repository, and
are not licensed by this repository at all — separate terms apply to them.
The engine carries the third-party attribution it has inside the executable, and
states in that same output which attribution is not embedded yet:

    kscope licences

Third-party attribution for this repository's own dependencies is in
THIRD_PARTY_NOTICES.md at the repository root.
