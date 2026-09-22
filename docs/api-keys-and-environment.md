# API keys and the engine's environment

Kaleidoscope is in early access, and the engine needs an API key for the four commands that
read or write memory: `call`, `context`, `mcp` and `serve`. Everything else works without one,
including `--version`, `schema`, `gate`, `where`, `init`, `profile` and `activate`. To get a
key, email [contact@kleosresearch.xyz](mailto:contact@kleosresearch.xyz).

## Store the key once

```bash
kscope activate <your-key>
```

This stores the key on your machine, once, not once per project. Every editor, agent and client
on the machine can then find it. `kscope gate` shows whether a key is installed and where the key
file is.

## Give the key to a client

The Python client finds the key in one of three places. Earlier ones win:

1. **In code.** `KaleidoscopeMemory(profile="default", api_key="ksk_alpha....")`
2. **In the environment.** `export KALEIDOSCOPE_API_KEY=ksk_alpha....`
3. **In the key file** that `kscope activate` wrote.

In TypeScript, pass it as `new PersistentKaleidoscopeSession(descriptor, { apiKey })`, or rely
on the environment or the key file in the same way.

A key passed in code reaches only the engine processes the client starts. The client never
writes it into your own process's environment, so no other subprocess you start can see it.

There is no `.env` file reader, in either language. If a `.env` file seems to work, your shell
or your tooling exported the variable. A reader here would be a fourth source of keys, and it
would mean parsing a file that also holds your other secrets.

## `api_key=` does not reach your editor

`api_key=` configures only the engine processes that this client starts. Claude Code, Cursor,
Codex and OpenCode start the engine themselves from their own MCP configuration, and that never
passes through your Python or TypeScript code. Those editors read the key from
`KALEIDOSCOPE_API_KEY` in their environment, or from the key file.

So a key set only in code gives you a working client and an editor that refuses. Running
`kscope activate` once covers both.

## What the clients do with your key

They carry the key to the engine and report the engine's answer. They never decide whether a
key is valid:

- no checks of prefix, length, characters or checksum;
- no expiry arithmetic: `E_KEY_EXPIRED` and `E_GRACE_EXPIRED` come from the engine, and the
  clients only display them;
- no caching of the engine's verdict.

Before they start the engine, the clients check only that some key is present. That saves
starting a process that would refuse anyway, and it gives you a clearer message. The engine and
Kaleidoscope's key service are the only authorities on whether a key is good.

When key-shaped text appears in the engine's error output, the clients mask it before they put
the output into an exception. This is redaction, not validation: nothing depends on whether a
mask was applied.

## When the engine refuses

Both clients raise an `EntitlementError`. It carries:

- `message`: what happened and what to do, for example to run `kscope activate`;
- `diagnostic`: the engine's own output, shortened and with keys masked;
- `reason`: the refusal code, such as `E_NO_KEY`.

The full list of codes and messages is in `reference/entitlement-contract-v1.json`. A refusal
never changes your vault.

## Which environment variables reach the engine

When a client starts the engine, it builds the engine's environment from nothing and copies in
only twenty variables, by name:

- eighteen ordinary variables that programs need to run, such as `PATH`, `HOME`, `TMPDIR` and
  `XDG_CONFIG_HOME`;
- `KALEIDOSCOPE_API_KEY`, your key, passed on purpose because the engine needs it;
- `KSCOPE_ENTITLEMENT_HOME`, the folder where the engine looks for the key file.

Everything else in your environment stays behind: other providers' API keys, account tokens,
cloud credentials, a database service key, anything loaded from a `.env` file. They are not
copied because they are not named. So the promise is "only these names are copied", not "no
credentials are copied": one of the names is your Kaleidoscope key.

Some related-looking names are deliberately never copied, including `KSCOPE_PROFILE_HOME`,
`KSCOPE_ENTITLEMENT_PROBE` and `KALEIDOSCOPE_CONTROL_PLANE_ORIGIN`. `KSCOPE_PROFILE_HOME` is a
setting that only the `kaleidoscope` manager reads, for its own list of profiles.

The complete lists, both copied and never copied, are in
`reference/entitlement-contract-v1.json`. Both clients are tested against that file.

The `kaleidoscope` manager builds the engine's environment the same way, from a shorter list of
its own. It passes the same two key variables and `KSCOPE_PROFILE_HOME`. It does not pass
`PATH`, which is one reason to point the manager at the engine executable itself rather than at
npm's `kscope` launcher (see [manager.md](manager.md)).

The editor configurations that the manager writes declare an empty environment. The editor
starts the engine with its own environment, so this list does not apply there.
