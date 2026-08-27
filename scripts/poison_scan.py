#!/usr/bin/env python3
"""Reject local paths, raw vault identities, stale binaries, test secrets, and
references to the closed memory engine's internals.

This repository is prepared to be public. The `kscope` memory engine is not: it
lives in a separate private repository and reaches users only as a signed binary
inside a platform package. Everything here therefore has to be sayable in front
of a stranger.

Eight rule classes, each of which fires with the category named:

1.  FORBIDDEN_TEXT      -- developer machine paths, worktree paths, stale binary
                           paths, shared vault basenames, test canaries.
2.  RAW_COORDINATE      -- `wsp_`/`usr_`/`journal:` UUIDs from a real vault.
3.  ENGINE_INTERNAL     -- engine crate names, internal module and symbol names,
                           private documentation trees, and the names of the
                           engine's calibration constants and tuning knobs.
                           Stored as digests; see the next section.
3b. DERIVED_QUANTITY    -- the distinctive arithmetic that discloses one of
                           those constants without naming it. Also digests.
4.  ENGINE_SOURCE_PATH  -- any Rust source file reference this repository does
                           not itself own. Derived from the tree, not from a
                           list, so it cannot go stale as the manager grows or
                           shrinks.
5.  NAMESPACE_TOKEN     -- deny-by-default over this project's own namespace:
                           any project-prefixed token, hyphenated or
                           underscored, whose first word is not on a short
                           reviewed list of public names. Rule 3's table is a
                           snapshot of a workspace this repository cannot read;
                           this rule is what stops that snapshot going stale in
                           silence.
6.  COMMIT_IDENTIFIER   -- a bare 40-hex commit id outside the small set of
                           files whose job is to record build provenance.
7.  INTERNAL_DOCUMENT   -- the engine's numbered design records, cited the way
                           its own working documents cite them. A citation into
                           a document tree the reader cannot open, and a second
                           disclosure besides: the numbering says how many there
                           are and the subject says what was decided.
8.  CREDENTIAL_SHAPE    -- a literal alpha API key. Every other rule here is
                           about DISCLOSURE of a private design; this one is
                           about a live secret, and it is the only rule whose
                           violation is exploitable rather than merely
                           embarrassing. It was absent until 2026-08-26: a tree
                           containing nothing but `KEY = "ksk_alpha.<43 chars>"`
                           scanned clean and exited 0, so a key pasted into a
                           fixture, an example or a README would have reached a
                           public Apache-2.0 repository with CI green. Verified
                           by attempt before the rule was written, and
                           test_poison_scan.py plants one to prove it fires.

WHY RULE 3 IS A TABLE OF DIGESTS AND NOT A TABLE OF NAMES
---------------------------------------------------------
The previous version of this file spelled every forbidden name out, split across
an argument boundary so the scanner would not fail on itself. That defeated the
scanner. It did not defeat a reader: concatenating two adjacent string literals
reconstructed the lot, and what came back was a complete, categorised,
commented inventory of the engine's crate decomposition, its internal module
names and its calibration constants -- organised, helpfully, by what each
disclosure would be worth. A denylist of secrets is itself a secret, and this
one was a better one than any single entry in it.

So the table stores `sha256(salt || token.lower())`, truncated, against a
category. The scanner hashes candidate tokens out of the file it is reading and
looks them up. What this buys and what it does not:

* It stops ENUMERATION. Nobody can read the private names out of this file.
* It does NOT stop CONFIRMATION. The salt is right here, so anyone who already
  guesses a name can check their guess. That is inherent to any client-side
  denylist and is not a defect being hidden -- it is the reason the categories
  below are coarse and the failure message quotes the token out of the reader's
  own file rather than out of this table.

The plaintext authority for this table lives in the private engine repository,
beside the workspace it describes, which is the only place that can notice when
a name is added. Add an entry here with:

    python3 scripts/poison_scan.py --digest      # reads the token from stdin

and paste the printed line into the table with the right category constant.

WHAT IS DELIBERATELY *NOT* FORBIDDEN, AND WHY
---------------------------------------------
The published contract has to stay sayable, or the SDK cannot document itself.
Each of these was checked against the tree before being left out, and each would
have produced a false positive:

* `semantic_delta`, and every field inside it (`facts`, `entities`, `propose`,
  `memory_type`, `occurred_at`, `basis`, `mode`, `grain`, ...). This is the
  PUBLIC write contract. The SDK's whole job is to construct one, and
  `kscope schema remember` prints it to anybody who runs the binary.
* `search`, `remember`, and the operator verb names. Published by
  `kscope schema`, and one of them is in `reference/kaleidoscope-public-contract.json`.
* `graph_recall`. Looks internal; is not. It is published, by name, in the
  public contract's `retired_operations.non_product` list.
* The embedding model's name, bare or with its size suffix. The product
  discloses it itself -- `kscope model` names it, and `kscope licences` MUST
  name it, because the bundled table is MinishLab's under MIT and MIT requires
  its notice to accompany every copy. It is in the tracked public contract for
  that reason. Only the Rust module-path spelling of it is forbidden: that is
  the internal API, not the model.
* The word `crates` followed by a slash, on its own. It occurs inside
  third-party GitHub URLs in `THIRD_PARTY_NOTICES.md`. Only that directory
  qualified by the engine's own name is forbidden.
* A `schemas/` path segment. It is on the engine's never-publish list, and it is
  also the path component of this repository's own published JSON Schema `$id`
  URLs. A public repository that could not name its own schema identifiers would
  have the rule removed within a week; the qualified private spellings are
  covered instead.
* The entitlement variable names -- `KALEIDOSCOPE_API_KEY`,
  `KSCOPE_ENTITLEMENT_HOME`, `KSCOPE_ENTITLEMENT_PROBE`,
  `KALEIDOSCOPE_CONTROL_PLANE_ORIGIN`, `KSCOPE_PROFILE_HOME`. All five are in
  `reference/entitlement-contract-v1.json`, which is a public contract the SDKs
  are asserted against. Naming a variable is not disclosing an engine internal;
  saying which source file reads it is, and rule 4 catches that. The allowlist's
  entire defence is that a reader can see which names are on it, so a scanner
  that forbade the names would forbid the defence.
* This repository's own `kaleidoscope-` names: package names, the ownership
  receipt marker, the backup and lock suffixes, the platform package names, the
  published embedding schema id, and the test fixture prefixes. Rule 5 admits
  them by their first word, one reviewed line each -- see
  `PUBLIC_KALEIDOSCOPE_FIRST_WORDS`.

WHAT THIS RULE SET DOES NOT PROVE
---------------------------------
Rule 3 is a tripwire for *named* things. It cannot catch an engine internal
described in prose without naming it, and it cannot catch a bare numeric
constant, because numbers occur everywhere. Rule 4 matches an unqualified Rust
source reference against this repository's own basenames, so a private file that
happens to share a basename with a manager file would pass; a *qualified* one
has to match a real path here, which is the case that matters.

Rule 5 keys on the first word after the project prefix, so an engine crate whose
first word collided with one of ours would pass. The allowed words were checked
against every crate the engine workspace held on 2026-08-22 and none collides --
but that is a fact about that day's workspace, not a guarantee about tomorrow's.

Rule 3b matches a handful of distinctive derived quantities. A bare numeric
literal is not a usable needle -- `0.40` occurs in prose everywhere -- so this is
a tripwire for named constants and distinctive arithmetic, never a proof that no
value survives. The distribution exclusion manifest says the same thing about its
own content-fingerprint check, and it is right to.

Rule 7 keys on two series names. A design record cited by title rather than by
number passes, and so does a series this repository has never seen.

Two holes are worth naming because they are the ones a reader would otherwise
assume are covered:

* **A private file whose basename collides with one of ours.** Rule 4 admits an
  unqualified `.rs` basename that this repository owns, so a sentence about the
  engine's own `config.rs`, `model.rs` or `error.rs` passes -- the manager has
  files by those names. A *qualified* path still has to match a real path here,
  which is the case that matters and the case a leak actually takes. Widening
  the rule would fire on this repository describing its own source.
* **A token split across a line break.** Candidates are cut at token boundaries
  within a line, so a name that a text reflow wrapped mid-word is not
  reassembled.

Every one of these limits is real. Do not report a green scan as proof that no
internal survives; report it as proof that none of the named categories does.

Usage:

    python3 scripts/poison_scan.py               # scan this repository
    python3 scripts/poison_scan.py --root DIR    # scan DIR (used by the tests)
    python3 scripts/poison_scan.py --digest      # hash a token read from stdin
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = frozenset(
    {
        ".git",
        ".live-home",
        ".profile-home",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "coverage",
        "dist",
        "node_modules",
        "target",
    }
)


def _n(*parts: str) -> str:
    """Join a needle from fragments.

    Used only for rule 1, whose needles are developer-machine paths and test
    canaries rather than engine internals -- a reader who reassembles them
    learns which laptop this was written on, which they can also learn from any
    stack trace. Rule 3 does not use this: see the module docstring for why
    fragmentation was the wrong tool there.
    """

    return "".join(parts)


FORBIDDEN_TEXT = {
    "developer home path": _n("/", "Users", "/"),
    "Codex worktree path": _n(".co", "dex/worktrees"),
    "Claude worktree path": _n(".cl", "aude/worktrees"),
    "stale DX-01 binary": _n("/private/tmp/", "kscope-dx01-"),
    "shared vault basename": _n("session", "-vault"),
    "secret test canary": _n("dx07-secret-", "canary-value"),
}

#: Domain separator for the digest table. Public on purpose -- see the module
#: docstring: hashing here buys non-enumerability, never non-confirmability, and
#: pretending otherwise by hiding the salt would be the worse of the two.
_DIGEST_SALT = "kaleidoscope-sdk poison scan, engine-internal digest table, v1"


def token_digest(token: str) -> str:
    """The table's key for one token. Case-folded, so a capitalised copy fires."""

    payload = (_DIGEST_SALT + "\x00" + token.lower()).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


#: Rule 3's categories. Coarse on purpose. The failure message quotes the
#: offending token out of the file being scanned, so the category only has to
#: say why the class is denied -- it does not have to identify the entry.
CRATE = "engine crate name"
SYMBOL = "engine internal module or symbol"
TREE = "private engine documentation or corpus tree"
CONSTANT = "engine calibration constant"
SWITCH = "internal tuning switch"

#: One token is reachable as both a crate spelling and a switch spelling once
#: case is folded, so it has one digest and is filed once, under the crate
#: category. A reader who trips it sees the token out of their own file, so
#: the slightly-off category label costs nothing and a second entry would be
#: a silent no-op that later looks like coverage.

#: One planted, non-secret token per category. They exist so
#: `test_poison_scan.py` can prove each category's path fires end to end without
#: this repository having to hold a real private name in any form. A canary is
#: not evidence that the real entries are correct -- nothing public can be --
#: which is why the counts below are asserted too, and why the plaintext
#: authority lives beside the workspace it describes.
CANARY_CRATE = "planted canary -- " + CRATE
CANARY_SYMBOL = "planted canary -- " + SYMBOL
CANARY_TREE = "planted canary -- " + TREE
CANARY_CONSTANT = "planted canary -- " + CONSTANT
CANARY_SWITCH = "planted canary -- " + SWITCH

#: Rule 3. Digest -> category. Sorted by category, then by digest; the ordering
#: carries no information the counts do not already publish.
ENGINE_INTERNAL_DIGESTS = {
    "0218b413d545a0f0": CRATE,
    "10e973a3c4ace68b": CRATE,
    "2214a88a58d1a8e5": CRATE,
    "22cc105f8d065b72": CRATE,
    "259158ad08ed17c0": CRATE,
    "2bed9b4540386e7f": CRATE,
    "3a995800139a1976": CRATE,
    "3eefde090cfc0d4b": CRATE,
    "527534fa64f88f82": CRATE,
    "5c51dd61dd33aef6": CRATE,
    "8cf89fbdb703274b": CRATE,
    "8d2d901b13cc48eb": CRATE,
    "a079c0f0b744b23e": CRATE,
    "a0df70a08f6badfe": CRATE,
    "a9adc29dfa2e5243": CRATE,
    "aa2adecc52769fce": CRATE,
    "add108ecd98801cf": CRATE,
    "c7bdde2b883493ee": CRATE,
    "cc43c5f3d7e0d507": CRATE,
    "cc9b62afc3f0adf7": CRATE,
    "ce5aa70798676977": CRATE,
    "db8c64e147f3e8c2": CRATE,
    "dc18ff897d1930f5": CRATE,
    "e05105f328dfde7d": CRATE,
    "ebc9ed11a234bf3d": CRATE,
    "f1bfcc2bfa986fd0": CRATE,
    "f6cccd3b442f21f6": CRATE,
    "931d261e1b7febb2": CANARY_CRATE,
    "1850c95875c24628": SYMBOL,
    "6281b555fef51644": SYMBOL,
    "6ce6f46c167e3b83": SYMBOL,
    "96784edbdf0c9115": SYMBOL,
    "afcaa8e8021abc59": SYMBOL,
    "b87c129533c57429": SYMBOL,
    "d6f7464bca9cfc8b": SYMBOL,
    "d9468a572386ec95": SYMBOL,
    "eca03535f6a4d278": SYMBOL,
    "ee51755a2772fe9e": SYMBOL,
    "99469c60270688d3": CANARY_SYMBOL,
    "0034f0663ce09e1b": TREE,
    "02fea1c96430632b": TREE,
    "0de91428082777d6": TREE,
    "287f54fdc92af511": TREE,
    "2a26512fd0d94b9b": TREE,
    "2f3bc4b311169aba": TREE,
    "35029a3f85588ff3": TREE,
    "3b13a3c37d116a2c": TREE,
    "577d8d6d2a3b082b": TREE,
    "63620afa0bde3287": TREE,
    "6b12f92ee3a0fe0c": TREE,
    "bc67ebdb043812fc": TREE,
    "bff22883ed3f5f13": TREE,
    "c33fd84b797bc389": TREE,
    "ddaeac9fd0167d8a": TREE,
    "e889a9f67a3e40dd": TREE,
    "f8c9323f1b2a934b": TREE,
    "dcbd785ede6108c7": CANARY_TREE,
    "09ba8095334bbfb0": CONSTANT,
    "2a71baa19c8de743": CONSTANT,
    "391b14b7124a18d9": CONSTANT,
    "3993b9220657a0f6": CONSTANT,
    "432a627a6b96bf80": CONSTANT,
    "4f48345478c97d03": CONSTANT,
    "563c81a7aee1bdd3": CONSTANT,
    "588f2a37ffad305f": CONSTANT,
    "5aa94c3c37d2d139": CONSTANT,
    "78f17fa6850dd151": CONSTANT,
    "7bd9491ebef71a4e": CONSTANT,
    "7d5e863e4e7845db": CONSTANT,
    "849bfdf3bddb114d": CONSTANT,
    "a0c41a1205c75697": CONSTANT,
    "aa05b1620c2a23cf": CONSTANT,
    "bab22a1b3d4eadc1": CONSTANT,
    "c051624f2c4f9ece": CONSTANT,
    "c5f42d291b95af40": CONSTANT,
    "daedb5b8cc7345ec": CONSTANT,
    "dd8ef07763ffd1b0": CONSTANT,
    "e14ce40daabf355c": CONSTANT,
    "be79a1695e4a9503": CANARY_CONSTANT,
    "03a920d982413b2c": SWITCH,
    "2ef06686370fec76": SWITCH,
    "46e445a6702ad8d2": SWITCH,
    "5ee79a71782eff01": SWITCH,
    "80573f5c410bf2f2": SWITCH,
    "93f252bb527590d8": SWITCH,
    "a576176b76a64b0e": SWITCH,
    "aa4c75fa7152caf5": SWITCH,
    "d3a97bf4d9a80ca6": SWITCH,
    "ff9991d052fd4d0f": SWITCH,
    "8d23192acd28fa68": CANARY_SWITCH,
}

#: Rule 3b. Distinctive derived quantities, digested the same way.
#:
#: The manifest's content check names these beside the constants, and for a
#: reason worth restating: each discloses a calibration value by arithmetic
#: without naming it, so rule 3 cannot see them. That is not a hypothetical
#: route -- it is the route two of the engine's own excluded design records
#: actually took, one of them twice.
#:
#: Matched against a NORMALISED form (whitespace removed, a trailing `.0`
#: stripped from each numeric component, case folded), because the disclosure is
#: the arithmetic and not the formatting. Deliberately a handful of specific
#: shapes and not a general numeric rule: a bare literal is not a usable needle,
#: and a rule that misfires on ordinary prose is a rule that gets deleted.
DERIVED_QUANTITY_DIGESTS = frozenset(
    {
        "33584fd3b9b71273",
        "67441e922235baa1",
        "d4dc565046f2b7dc",
        "ea05f6e702bc4e56",
        # The canary, for the same reason rule 3 has five.
        "a409c76b68f1644b",
    }
)

RAW_COORDINATE = re.compile(
    r"\b(?:wsp|usr)_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
    r"|\bjournal:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)

#: Rule 4. A reference to a Rust source file: either an unqualified basename or
#: a slash-qualified path. Matched against what this repository actually
#: contains, so the allowlist is derived rather than remembered.
#:
#: The final segment is restricted to `[A-Za-z0-9_]+` because a Rust module file
#: is named after a Rust identifier and identifiers cannot contain a hyphen.
#: That one restriction is what stops the pattern eating crate *repository*
#: names, several of which end in the same two letters.
RUST_SOURCE_REFERENCE = re.compile(r"\b(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_]+\.rs\b")

#: Stripped before rule 4's first pass. A link to a crate's homepage is not a
#: claim about anybody's source layout, and THIRD_PARTY_NOTICES.md is full of
#: them.
URL = re.compile(r"https?://\S+")

#: Rule 4's second pass. Stripping URLs wholesale blinded the rule to the single
#: likeliest form an engine source citation takes in a code comment: a repository
#: blob link. A URL is flagged only when it looks like a path INTO a source tree
#: -- a `/src/` segment and a `.rs` file -- which the crate homepages in
#: THIRD_PARTY_NOTICES.md are not.
URL_SOURCE_REFERENCE = re.compile(r"https?://\S*?/src/\S*?[A-Za-z0-9_]+\.rs\b")

#: Cargo conventions, not files. `THIRD_PARTY_NOTICES.md` and its generator both
#: have to say the first one to explain which crates they exclude, and the
#: second is where Rust documentation lives.
GENERIC_RUST_REFERENCES = frozenset({"build.rs", "docs.rs"})

#: Rule 6. A bare 40-hex token is a git commit id. Naming one is a pointer into
#: a repository the reader cannot open; the exclusion manifest accepts exactly
#: one use for that -- release transport provenance -- and nothing else.
#:
#: Note this cannot match inside a 64-hex SHA-256: the leading `\b` only holds at
#: the start of such a run, and the trailing one then fails. `Cargo.lock` is full
#: of those and none of them fires.
#: Rule 8. A literal alpha key, not a description of one.
#:
#: The body bound is {20,} rather than {43}: a real key is 43 characters, and a
#: TRUNCATED paste of one is still a credential worth refusing. It is not `*`,
#: because `ksk_alpha....` is how every message template and every docstring in
#: this tree writes the shape, and a rule that fired on those would be removed
#: within a week. A backslash between the prefix and the dot -- the regex
#: spelling in descriptor.py -- does not match either, for the same reason.
#:
#: This rule is a TRIPWIRE, not a proof. A key split over a line break, base64
#: wrapped, or assembled from fragments passes, exactly as rule 3's docstring
#: says of its own needles. Do not report a green scan as proof no credential
#: survives; report it as proof no literal one does.
CREDENTIAL_SHAPE = re.compile(r"\bksk_alpha\.[A-Za-z0-9_-]{20,}")

COMMIT_IDENTIFIER = re.compile(r"\b[0-9a-f]{40}\b")

#: The files whose job is to record which build an artefact came from. The
#: manifest's reasoning: a source commit in transport evidence is a pointer, not
#: a disclosure, and it is load-bearing for update provenance. Prose is not on
#: this list -- a hash restated in a README is a second copy with no way to
#: notice it has drifted.
PROVENANCE_FILES = frozenset(
    {
        "reference/binary-pin.json",
        "conformance/run_dx10b_hosts.py",
        "conformance/run_dx10b_non_auth.py",
        "conformance/host-evidence.schema.json",
    }
)
PROVENANCE_PREFIXES = ("conformance/evidence/",)

#: Rule 7. The engine's numbered design records, spelled the way its own
#: documents spell them: a two- or three-letter series and a zero-padded number.
#:
#: Two things leak at once, which is why a rule earns its place here rather than
#: being left to a reviewer. The citation points into a tree the reader cannot
#: open -- rule 3 already denies the tree, and a bare series-and-number reaches
#: past it without ever naming a path. And the *number* is itself a disclosure: a
#: four-digit series discloses roughly how many design decisions exist, and the
#: sentence around it almost always discloses what one of them decided. That is
#: the shape the exclusion manifest is about -- structure is publishable, the
#: specifics are not -- applied to the design record rather than to a constant.
#:
#: This rule fired on this comment while it was being written, on a citation the
#: author had put here as an example. That is the intended experience.
#:
#: `RFC` is deliberately NOT a series here. `RFC 3339` and `RFC 7520` are public
#: internet standards this repository cites correctly and often, and a rule that
#: forbade them would be removed within a week rather than narrowed.
INTERNAL_DOCUMENT = re.compile(r"\b(?:ADR|PRD)[ \t_-]?\d{3,4}\b", re.IGNORECASE)

#: Rule 7's one exemption, and the reason it is safe to grant.
#:
#: `reference/kaleidoscope-public-contract.json` is not prose. It is a captured,
#: digest-pinned copy of what the shipped executable prints -- `kscope --help`,
#: `kscope schema`, `kscope model` -- and the engine's own `remember` schema text
#: cites a design record by number in the field description it prints to every
#: user who runs the binary. So that citation is already public, published by the
#: product itself, and the golden's job is to be byte-equal to that output.
#: Editing it to satisfy this rule would break the only thing it is for.
#:
#: The exemption is one named file and one rule, for the same reason
#: PROVENANCE_FILES is one short list: a capture of published output is a
#: different kind of file from a sentence somebody wrote.
INTERNAL_DOCUMENT_EXEMPT = frozenset(
    {"reference/kaleidoscope-public-contract.json"}
)

#: Rule 5. Deny-by-default over this project's own namespace.
#:
#: Rule 3's table is a snapshot of a workspace a public repository cannot read,
#: so it goes stale silently the day another crate is added there. This rule
#: inverts the default: it flags ANY token of the form `<project prefix>-<word>`
#: whose first word is not on the short list below. A new ENGINE crate is caught
#: automatically; a new PUBLIC name costs one reviewed line here. Loud and cheap
#: beats silent and free.
#:
#: Matching only the FIRST word is what keeps the allowlist small enough to be
#: maintained. Allowlisting whole tokens needs dozens of entries, most of them
#: test temp-directory prefixes that churn every time a test is added -- a rule
#: that has to be edited that often is a rule that gets disabled.
#:
#: Not applied to the short `kscope-` prefix: its hyphenated forms in this tree
#: are overwhelmingly test fixture prefixes, and the engine's internal crates all
#: carry the long prefix. The rule sits where the hazard is.
#:
#: Every crate first-word in the engine workspace as of 2026-08-22 falls outside
#: this set. Checked against the workspace, not assumed.
PUBLIC_KALEIDOSCOPE_FIRST_WORDS = frozenset(
    {
        "backup",  # -backup            bounded backup file suffix
        "darwin",  # -darwin-arm64      platform package name
        "dx10b",  # -dx10b-*           conformance harness identifiers
        "fixture",  # -fixture           test fixture prefix
        "instruction",  # -instruction-owner instruction receipt marker
        "lock",  # -lock              file-lock suffix
        "manager",  # -manager[-v1]      this crate, and its schema id
        "memory",  # -memory-native-*   the withdrawn native companion. The
        #                    Python distribution is `kscope-memory` now, so this
        #                    entry covers only the historical name.
        "native",  # -native-fixture    test fixture prefix
        "owner",  # -owner[.json]      host ownership receipt
        "preflight",  # -preflight-<pid>-<n> writability probe this crate creates
        "potion",  # -potion-base-*     the PUBLIC embedding schema id
        "public",  # -public-contract   the tracked contract golden
        "session",  # -session-start-probe the MCP client name the session-start
        #                    hook uses, and kaleidoscope_session_start, the field
        #                    it emits; both are this crate's own public names
        "sdk",  # -sdk[.git]         this repository
        "specific",  # -specific         ordinary English, in SDK prose
        "vault",  # -vault             documented CLI vocabulary
    }
)

#: Assembled the same way rule 1's needles are: this file may not spell a token
#: that rule 5 would then have to judge. Spelled once, here; the failure message
#: builds on it rather than repeating it.
_PROJECT_NAME = _n("kaleido", "scope")
_PROJECT_PREFIX = _PROJECT_NAME + "-"

#: Both separators, and they are matched differently on purpose.
#:
#: The hyphen form is the Cargo crate name on disk and is matched CASE
#: INSENSITIVELY, because case was a hole wide enough to drive the whole rule
#: through: a capitalised copy of a private crate name passed every rule.
#:
#: The underscore form is the Rust `use`-line spelling and stays lowercase-only.
#: Folding case there would make every `KALEIDOSCOPE_<WORD>_<WORD>` environment
#: variable in the tree read as a namespace token -- `KALEIDOSCOPE_API_KEY`
#: first -- and a rule that fires ninety times on legitimate content is a rule
#: that gets deleted. Rust identifiers are lowercase by convention and by lint,
#: so the hazard the underscore form guards is a lowercase hazard.
KALEIDOSCOPE_HYPHEN_TOKEN = re.compile(
    r"\b" + _PROJECT_NAME + r"-([A-Za-z0-9]+)", re.IGNORECASE
)
KALEIDOSCOPE_UNDERSCORE_TOKEN = re.compile(r"\b" + _PROJECT_NAME + r"_([a-z0-9]+)")

# ---------------------------------------------------------------------------
# Candidate extraction, which is what makes a digest table usable at all
# ---------------------------------------------------------------------------
#
# A denylist of literals can be applied with `in`. A denylist of digests cannot:
# the scanner has to produce, from the file it is reading, every substring a
# needle might be. Sliding a window of every length over every byte is the
# obvious way and is far too slow.
#
# So candidates are cut at token boundaries. Runs of identifier-and-path
# characters are split at every separator, and every substring that starts and
# ends on one of those boundaries becomes a candidate. Every needle in the table
# is boundary-aligned by construction -- crate names, module paths, directory
# prefixes and SCREAMING_CASE constants all are -- so this loses nothing, and it
# is bounded by the maximum needle length rather than by the file size.

_CHUNK = re.compile(r"[A-Za-z0-9_.:/-]{2,}")
_SEPARATORS = frozenset("_.:/-")
_MIN_CANDIDATE = 5
_MAX_CANDIDATE = 48


def candidate_tokens(text: str) -> set[str]:
    """Every boundary-aligned substring that could be a table entry, folded."""

    found: set[str] = set()
    for chunk in _CHUNK.finditer(text):
        piece = chunk.group(0)
        if len(piece) < _MIN_CANDIDATE:
            continue
        bounds = [0]
        for index, character in enumerate(piece):
            if character in _SEPARATORS:
                bounds.append(index)
                bounds.append(index + 1)
        bounds.append(len(piece))
        bounds = sorted(set(bounds))
        for i, start in enumerate(bounds):
            for end in bounds[i + 1 :]:
                width = end - start
                if width > _MAX_CANDIDATE:
                    break
                if width >= _MIN_CANDIDATE:
                    found.add(piece[start:end].lower())
    return found


#: Rule 3b's candidate shapes. Three generic patterns, none of which names
#: anything: a decimal literal, a chain of divisions, and an assignment of a
#: number to a short identifier.
_QUANTITY_PATTERNS = (
    re.compile(r"\d+(?:\.\d+)?(?:\s*/\s*\d+(?:\.\d+)?)+"),
    re.compile(r"\b\d+\.\d+"),
    re.compile(r"\b[A-Za-z_]\w{0,31}\s*=\s*\d+(?:\.\d+)?"),
)
_TRAILING_ZERO = re.compile(r"^(\d+)\.0+$")


def _normalise_quantity(raw: str) -> str:
    compact = re.sub(r"\s+", "", raw).lower()
    parts = []
    for part in compact.split("/"):
        match = _TRAILING_ZERO.match(part)
        parts.append(match.group(1) if match else part)
    return "/".join(parts)


def quantity_tokens(text: str) -> set[str]:
    found: set[str] = set()
    for pattern in _QUANTITY_PATTERNS:
        for match in pattern.finditer(text):
            found.add(_normalise_quantity(match.group(0)))
    return found


# ---------------------------------------------------------------------------
# Reading a file, including the two ways one can hide from a text scanner
# ---------------------------------------------------------------------------

#: A base64 run long enough to hold a private name. Decoded and appended to the
#: scanned text so every rule applies to it. Without this the scanner reads a
#: file, finds nothing, and reports the file as covered.
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{56,}={0,2}")
_MAX_DECODED_OVERLAY = 1 << 20


def readable_text(path: Path) -> str | None:
    """The bytes of `path` as scannable text, or None if it cannot be read.

    A file that does not decode as UTF-8 is decoded with replacement rather than
    skipped. Skipping it was a refusal spelled as an answer: the file counted
    towards the reported total, so the only visible trace of a whole unscanned
    file was a number that read as coverage.
    """

    try:
        raw = path.read_bytes()
    except OSError:
        return None
    text = raw.decode("utf-8", "replace")

    overlay: list[str] = []
    budget = _MAX_DECODED_OVERLAY
    for run in _BASE64_RUN.finditer(text):
        if budget <= 0:
            break
        blob = run.group(0)
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        except Exception:  # noqa: BLE001 -- any decode failure means "not base64"
            continue
        try:
            candidate = decoded.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(1 for character in candidate if character.isprintable() or character in "\n\t")
        if len(candidate) < 8 or printable < 0.9 * len(candidate):
            continue
        overlay.append(candidate)
        budget -= len(candidate)
    if overlay:
        text = text + "\n" + "\n".join(overlay)
    return text


def own_rust_references(root: Path) -> tuple[frozenset[str], frozenset[str]]:
    """Every way this repository may legitimately spell one of its own `.rs` files.

    Two sets, and the difference between them is the point:

    * relative paths (`src/account/mod.rs`) -- what a qualified reference must
      match exactly;
    * basenames (`mod.rs`) -- accepted ONLY for an unqualified reference.

    Without that split, a qualified path into a private module directory would
    be admitted on the strength of some manager file sharing its basename --
    and a qualified path into a private module is precisely the leak this rule
    exists to catch.

    Derived from the same file list the scan walks, not from a filesystem glob.
    A glob widened the allowlist with anything sitting in an ignored directory:
    one `.rs` file dropped into `python/.venv/` or a build tree amnestied that
    basename across the whole repository, and nothing scanned the file that
    granted the amnesty.
    """

    paths: set[str] = set()
    for path in candidate_files(root):
        if path.suffix != ".rs":
            continue
        relative = path.relative_to(root).as_posix()
        paths.add(relative)
        # A reference may also be spelled from any interior directory, e.g.
        # `account/mod.rs` for `src/account/mod.rs`.
        segments = relative.split("/")
        for index in range(1, len(segments)):
            paths.add("/".join(segments[index:]))
    return frozenset(paths), frozenset(Path(item).name for item in paths)


def candidate_files(root: Path) -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if completed.returncode == 0 and completed.stdout:
        return [root / item for item in completed.stdout.decode().split("\0") if item]
    return [
        path
        for path in root.rglob("*")
        if path.is_file()
        and not any(part in SKIP_PARTS or part.startswith(".venv") for part in path.parts)
    ]


def scan(root: Path) -> list[str]:
    """Return one failure line per violation. Empty means the tree is clean."""

    failures: list[str] = []
    qualified, basenames = own_rust_references(root)
    for path in candidate_files(root):
        text = readable_text(path)
        if text is None:
            continue
        relative = path.relative_to(root)
        posix = relative.as_posix()

        for label, needle in FORBIDDEN_TEXT.items():
            if needle in text:
                failures.append(f"{relative}: contains {label}")

        for token in sorted(candidate_tokens(text)):
            category = ENGINE_INTERNAL_DIGESTS.get(token_digest(token))
            if category is not None:
                failures.append(
                    f"{relative}: names a private engine internal "
                    f"({token!r} -- {category})"
                )

        for quantity in sorted(quantity_tokens(text)):
            if token_digest(quantity) in DERIVED_QUANTITY_DIGESTS:
                failures.append(
                    f"{relative}: contains a derived engine calibration quantity "
                    f"({quantity!r})"
                )

        if RAW_COORDINATE.search(text):
            failures.append(f"{relative}: contains a raw vault identity coordinate")

        if CREDENTIAL_SHAPE.search(text):
            # The token is deliberately NOT quoted back, unlike every other
            # failure here. The others quote the offender so the author can find
            # it; this one would print the credential into a CI log, which is
            # the second copy of the leak. The path and the rule name are enough
            # to find it, and `grep -n ksk_alpha` finds it exactly.
            failures.append(
                f"{relative}: contains a literal alpha API key (credential-shape); "
                f"the value is not quoted here on purpose -- printing it would be a "
                f"second copy of the leak. Remove it, then rotate it: a key that "
                f"reached a working tree must be assumed disclosed"
            )

        namespace: set[tuple[str, str]] = set()
        for word in KALEIDOSCOPE_HYPHEN_TOKEN.findall(text):
            namespace.add(("-", word.lower()))
        for word in KALEIDOSCOPE_UNDERSCORE_TOKEN.findall(text):
            namespace.add(("_", word))
        for separator, word in sorted(namespace):
            if word not in PUBLIC_KALEIDOSCOPE_FIRST_WORDS:
                failures.append(
                    f"{relative}: names an unrecognised {_PROJECT_PREFIX}* identifier "
                    f"({_PROJECT_NAME}{separator}{word}); if this is a public name of "
                    f"ours, add '{word}' to PUBLIC_KALEIDOSCOPE_FIRST_WORDS with a "
                    f"comment saying what it is -- if it is an engine crate, it must "
                    f"not be here"
                )

        references = {
            (item, False) for item in RUST_SOURCE_REFERENCE.findall(URL.sub(" ", text))
        }
        for link in URL_SOURCE_REFERENCE.findall(text):
            references.update(
                (item, True) for item in RUST_SOURCE_REFERENCE.findall(link)
            )
        for reference, from_link in sorted(references):
            owned = (
                reference in GENERIC_RUST_REFERENCES
                or reference in qualified
                or ("/" not in reference and reference in basenames)
            )
            # A link carries a scheme, a host and a branch ahead of the path, so
            # a link to THIS repository's own source can never match `qualified`
            # exactly. Accepting a suffix match is what stops the rule firing on
            # the project's own documentation links. It does mean a link ending
            # in a path we happen to own is admitted -- the same suffix weakness
            # rule 4 already accepts for basenames, and for the same reason: a
            # path this repository genuinely owns has to stay sayable.
            if from_link and not owned:
                owned = any(reference.endswith("/" + item) for item in qualified)
            if not owned:
                failures.append(
                    f"{relative}: names a Rust source file this repository does not "
                    f"own ({reference}); the engine's source layout is private"
                )

        is_provenance = posix in PROVENANCE_FILES or posix.startswith(PROVENANCE_PREFIXES)
        if not is_provenance and COMMIT_IDENTIFIER.search(text):
            failures.append(
                f"{relative}: names a bare commit identifier; a commit id points "
                f"into a repository the reader cannot open, and belongs only in the "
                f"provenance files that record which build an artefact came from"
            )

        if posix not in INTERNAL_DOCUMENT_EXEMPT:
            for citation in sorted(set(INTERNAL_DOCUMENT.findall(text))):
                failures.append(
                    f"{relative}: cites an internal design record ({citation}); "
                    f"those live in a document tree the reader cannot open, and "
                    f"the number and the sentence around it disclose how many "
                    f"decisions exist and what one of them decided"
                )
    return sorted(failures)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan a tree for publication poison.")
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="directory to scan (default: this repository)",
    )
    parser.add_argument(
        "--digest",
        action="store_true",
        help="read one token per line from stdin and print its table key",
    )
    arguments = parser.parse_args(argv)

    if arguments.digest:
        for line in sys.stdin:
            token = line.strip()
            if token:
                print(f'    "{token_digest(token)}": CATEGORY,')
        return 0

    root = arguments.root.resolve()
    failures = scan(root)
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"poison scan passed ({len(candidate_files(root))} source files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
