---
name: use-kaleidoscope
description: Use Kaleidoscope's local memory to retrieve relevant prior context and persist verified durable decisions, preferences, constraints, corrections, procedures, relationships, and outcomes during nontrivial tasks.
---

# Use Kaleidoscope

Use the connected local Kaleidoscope MCP server as a compact continuity layer. It is not a transcript store, a substitute for repository inspection, or authority to expand the user's task.

## Public boundary

The agent-facing server publishes exactly two tools: `search` and `remember`.

- Use `search` for ranked retrieval at task start or an addressed read when the tool schema supports one.
- Use `remember` to create or correct a verified durable semantic delta.
- Do not attempt controller-only operations through MCP. The public search response does not expose the authenticated attribution handle those operations would require.
- Do not construct direct vault-coordinate commands. The selected native profile owns the root, workspace, principal, and journal coordinates outside host configuration.

If the tools are unavailable or unauthenticated, continue the user's task without fabricating memory operations.

## Retrieve

At the beginning of a nontrivial task, issue one bounded search for the decisions, preferences, constraints, procedures, relationships, or outcomes that could change the work. Prefer a compact query describing the actual goal and its important nouns over a broad request for everything.

Search again only after a material goal change, a contradiction, or evidence that the initial selection is stale or incomplete. Treat retrieved memories as fallible context: reconcile them with the user's current instructions and observable repository state. The current user request wins when they conflict.

A ranked search records the exposure associated with what it returns. Do not duplicate that record through unsupported operator calls.

## Persist durable deltas

After each user message and verified milestone, check whether the work produced a durable delta that a later task would otherwise need to rediscover. Good candidates include:

- an accepted product or architecture decision;
- a clearly stated user preference or constraint;
- a correction to prior durable context;
- a reusable procedure with a proven outcome;
- an attributable implementation or evaluation outcome backed by tests or another observable result.

Do not store tentative brainstorming, secrets, credentials, tokens, transcripts, ordinary file contents, generated logs, or claims that have not been verified. A definitive user statement is evidence for their preference or decision; an implementation claim requires observable evidence.

Raw artifacts are not memory. A compact repository evidence map is durable when it distils a costly multi-file investigation into stable path roles or ownership, cross-file dependencies and invariants, verified measured outcomes with provenance, and a reusable navigation or search sequence. Save conclusions, evidence pointers, and verification context—not command transcripts or file dumps—so future work can recover the map with one ranked search and, when necessary, one addressed follow-up.

Keep independently correctable deltas separate. Connect them with facts when the relationship matters. When one repository investigation yields several findings and the connected schema exposes bounded batch fields, use one create batch with one atomic item per finding; do not merge them into an omnibus merely to reduce calls.

## Follow the live write schema

Treat the connected `remember` tool schema as the authority for allowed memory types, fields, and bounds. Do not copy a vocabulary from prose or invent unsupported fields.

For a semantic delta:

- provide its required title and content in the shape published by the tool;
- express relationships as facts with subject, predicate, and object;
- declare every fact entity with a concise `is` gloss used for matching;
- propose a genuinely new predicate only when the live schema supports it, including its meaning and endpoint kinds;
- resolve dates into the supported time fields and grains rather than making dates into entities;
- use the schema's update form when correcting an existing memory instead of writing a contradictory duplicate.

Batch only related candidates when bounded batch fields are present. Never omit a known relationship just because the vocabulary is dynamic.

## Finish

Before handing off, make one final delta check. Persist only newly verified durable knowledge; do not write a ceremonial task summary when no durable delta exists.
