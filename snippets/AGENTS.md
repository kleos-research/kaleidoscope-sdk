<!-- >>> kaleidoscope-manager owner=kaleidoscope-manager-v1 instruction=agents -->
## Kaleidoscope memory

Kaleidoscope is this project's persistent memory -- decisions already made, preferences already stated, standing constraints, corrections, and what past work actually produced. `search` reads it, `remember` writes it. Everything is local: no network call, nothing leaves this machine.

**Prefer the CLI when you have a shell.** It is much the cheaper surface: one invocation costs a couple of dozen tokens, where the MCP tool definitions sit in your context for the whole session -- roughly 1,800 tokens -- whether or not you ever call them.

```bash
echo '{"query":"how we handle retries","top_k":5}' | kscope call --profile default search
kscope schema remember   # the write contract, fetched only when you need it
```

Use the `search` and `remember` MCP tools when your harness exposes them and you have no shell. Same engine, same vault, same answers.

**Search before you go looking.** Whenever you are about to grep the codebase, read your way around it, or ask the user a question about how this project works -- why something is built this way, what was decided, what they prefer, what has already been tried and rejected -- search memory first. The code shows what *is*; memory shows what was *decided*, and why. A question already settled here is one you must not ask the user twice.

**Write without being asked.** The triggers are: the user states a preference, accepts or rejects a decision, sets a constraint, corrects something you did or said, or a piece of work produces a result worth keeping. "Remember this", "save this" and "note that" are explicit triggers, but do not wait for them -- and do not batch writes to the end of a task. Write when the decision lands, while you still know why it was made.

Never store secrets or credentials, transcripts, ordinary file contents, anything the code or git history already records, or ideas still in flux.

A refused call names the field to fix and what to change it to: correct it and send it again. One refusal is never a reason to stop using memory for the rest of the session.

Full write contract: `.agents/skills/use-kaleidoscope/SKILL.md`, or `kscope schema remember`.
<!-- <<< kaleidoscope-manager owner=kaleidoscope-manager-v1 instruction=agents -->
