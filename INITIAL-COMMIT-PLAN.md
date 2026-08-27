# Initial commit plan for `kleos-research/kaleidoscope-sdk`

**Nothing in this file has been run.** Writing it is the deliverable. No commit
was created from it, no repository was created, nothing was pushed, and no
visibility was changed.

It describes how to turn the current working tree into a fresh, single-commit
history suitable for a public repository, and what to leave out.

---

## 1. Why the existing history cannot be published

`HEAD` is currently `35c1ff6` on a branch with fourteen reachable commits. Three
independent reasons to discard all of them, any one of which is sufficient:

1. **Internal slice identifiers in commit subjects.** `ee01e26` reads
   *"feat: consolidate SDK and stage DX10B conformance"* and `3b1ec66` reads
   *"fix: align DX04 MSRV and default init evidence"*. A slice identifier names
   an internal delivery plan. It is exactly the register that must not appear on
   a public surface, and a commit subject is permanent and un-editable once
   cloned.
2. **A developer home path in `e3b5f19`.** `src/account/fake.rs` and
   `src/account/protocol.rs` carried an absolute developer home path at that
   commit. It was fixed later, so the working-tree scan cannot see it — the
   scanner reads the tree, and history is invisible to it. Running the hardened
   scanner against `git archive` of each reachable commit reports `e3b5f19` red
   and every other commit green.
3. **A former package name.** Five commits (`ee01e26` … `9cd4b58`) carry an
   earlier, since-renamed name for the TypeScript client in
   `typescript/package.json` and `package-lock.json`. Harmless, but it is a name
   we no longer tell a story for, and it is a second reason not to publish this
   history. It is also rule 5 of the poison scanner proving itself against real
   content rather than planted content: the scanner refuses this very file for
   spelling it, which is why the sentence you are reading does not.

4. **Twelve of the fourteen commits are red under the current scanner.** Not an
   inference — measured, by archiving each reachable commit and scanning the
   archive:

   ```bash
   for rev in $(git rev-list HEAD); do
     d=$(mktemp -d); git archive "$rev" | tar x -C "$d"
     python3 scripts/poison_scan.py --root "$d" >/dev/null 2>&1        && echo "green $rev" || echo "RED   $rev"
   done
   ```

   Only `3b1ec66` and `5c5b69a`, the two earliest, come back green. Ten of the
   twelve are red for the commit identifiers that `README.md` and
   `COMPATIBILITY.md` restated in prose until this week; six also for the former
   package name; one for the developer home path. The working tree is green and
   its own history is not, which is the whole point: **the scanner reads the
   tree, and a published history is not the tree.**

5. **`HEAD` itself is red, and on the scanner.** The sharpest instance of the
   point above, worth stating separately because it is the least intuitive.
   `35c1ff6` — the current commit — fails the current scan on
   `scripts/poison_scan.py`, because the version of the scanner committed at
   that revision still held its denylist as plaintext engine names. The
   working-tree scanner is a table of digests and passes; the *committed* one
   is the inventory it replaced, and publishing this history would publish
   that inventory in a file whose whole purpose is to prevent it.

   A commit whose subject is *"A hand-written leak list does not know when it
   is incomplete"* is the commit that would leak the list. Nothing is wrong
   with the commit — it was a step — but a step is exactly what a fresh
   history exists to discard.

A history rewrite is not a remedy for any of these once a clone exists. It is
free right now, because no clone exists. That asymmetry is the whole argument
for doing this before the repository is created rather than after.

---

## 2. Before running anything

Run all five gates and require all five green. A fresh-history commit freezes
whatever the tree contains at that moment, so this is the last cheap moment to
find anything.

```bash
export PATH="$HOME/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin:$PATH"
export CARGO_TARGET_DIR="$PWD/target"

python3 scripts/poison_scan.py                                  # expect: rc 0
python/.venv/bin/python -m pytest python/tests -q               # expect: rc 0
( cd typescript && npm run build && npm test )                  # expect: rc 0
cargo test --offline --all-features                             # expect: rc 0
python/.venv/bin/python scripts/third_party_notices.py --check   # expect: rc 0
```

Two things about that list that are easy to get wrong and both fail quietly:

* **`third_party_notices.py --check` needs `cargo` on `PATH`.** Without the
  export above it raises `FileNotFoundError: 'cargo'`, and
  `test_licensing.py::test_the_notices_generator_check_mode_agrees_with_the_committed_file`
  converts that same absence into a **skip**. On a machine with no toolchain the
  suite is green and the exact drift check did not run.
* **`python3` on this machine is 3.10 and cannot run either the suite or the
  generator** (`tomllib`). `python/.venv/bin/python` is 3.13 and is what those
  two lines need. `scripts/poison_scan.py` runs on either.

---

## 3. The command sequence — DO NOT RUN

This tree is a linked worktree: its `.git` is a *file* holding a `gitdir:`
pointer into another repository's administrative directory, not a directory of
its own. Deleting or re-initialising it in place would damage the parent
repository. So the sequence below **copies the tree out** and initialises the
copy. The original is left exactly as it is, which also means it stays available
as the reference if the copy turns out wrong.

```bash
# 0. Names, in one place. Run this from inside the tree being published, so
#    the source path is read rather than typed.
SOURCE="$(git rev-parse --show-toplevel)"
TARGET="$HOME/kaleidoscope-sdk-public"        # must not exist yet

# 1. Refuse to overwrite anything.
test ! -e "$TARGET" || { echo "$TARGET exists; choose another path"; exit 1; }

# 2. Copy exactly the file set git would track, and nothing else.
#    `git ls-files --cached --others --exclude-standard` is the same list the
#    poison scanner walks, so what is copied is what was scanned. Using rsync or
#    `cp -R` instead would sweep in target/, node_modules/, .venv/, .ruff_cache/
#    and any untracked local file, none of which was scanned.
mkdir -p "$TARGET"
( cd "$SOURCE" && git ls-files --cached --others --exclude-standard -z ) \
  | ( cd "$SOURCE" && rsync -a --files-from=- --from0 . "$TARGET/" )

# 3. Remove the files listed in section 5 below. Each line is a decision;
#    delete the ones you agree with and keep the rest.
rm -f "$TARGET/conformance/evidence/dx10b-hosts.local.json"
rm -f "$TARGET/conformance/evidence/dx10b-non-auth.local.json"
rm -f "$TARGET/INITIAL-COMMIT-PLAN.md"      # this file; see section 5

# 4. Prove the copy is clean on its own terms, before it has a history.
#    The scanner falls back to a filesystem walk when there is no git repo, so
#    this works before `git init` and is worth running there: it is the last
#    check on the exact bytes, with no index in the way.
python3 "$SOURCE/scripts/poison_scan.py" --root "$TARGET"     # expect: rc 0

# 5. A fresh history. No remote is added and nothing is pushed.
cd "$TARGET"
git init -b main
git add .                     # `.` and not `-A`: there is no index to sweep
git status --short            # READ THIS. It is the last look at the file set.
git -c user.name="Kleos Research" \
    -c user.email="engineering@kleosresearch.xyz" \
    commit -F - <<'MESSAGE'
Kaleidoscope SDK

The public client surfaces for Kaleidoscope, under Apache-2.0:

  * kaleidoscope-manager, a local control-plane binary that initialises and
    selects engine profiles, validates the launch descriptor, configures and
    reverts agent hosts, and produces redacted offline diagnostics.
  * kaleidoscope-memory, the Python client, and @kleos-research/kaleidoscope,
    the TypeScript client. Both hold one engine process per session and expose
    the two tools a model sees: search and remember.
  * Integration examples for the common agent frameworks, host configuration
    renderers, and the shared goldens all three implementations are asserted
    against.
  * skills/use-kaleidoscope, the agent-facing skill.

The kscope memory engine itself is closed source. It is not in this repository
and is not covered by this licence; it is delivered as a signed binary inside a
platform package under separate terms. LICENSE, NOTICE and
THIRD_PARTY_NOTICES.md state that boundary, and scripts/poison_scan.py is the
check that keeps this repository on the public side of it.
MESSAGE

# 6. Verify the result. Two commits' worth of paranoia, none of it optional.
git log --oneline                       # expect: exactly one line
git count-objects -v                    # sanity on size
python3 scripts/poison_scan.py          # expect: rc 0, now against the index
git ls-files | wc -l                    # compare against section 4's number
```

**Still not done after step 6.** Creating the repository, adding a remote and
pushing are separate, deliberate acts, gated on section 6 of this file. Nothing
above touches a network.

---

## 4. What the initial commit would contain

142 files as the tree stands, in ten top-level entries:

| Path | Files | What |
| --- | ---: | --- |
| `python/` | 41 | the Python package, its examples and its tests |
| `typescript/` | 35 | the TypeScript package, its examples and its tests |
| `src/` | 22 | the Rust manager |
| `conformance/` | 15 | the local host and non-auth probes and their schemas |
| `reference/` | 11 | shared goldens: public contract, launch, errors, hosts, batches, entitlement |
| `snippets/` | 3 | reversible harness instruction fragments |
| `scripts/` | 3 | `poison_scan.py`, `third_party_notices.py`, source-boundary check |
| `tests/` | 2 | the manager's functional contract tests |
| `skills/` | 1 | `use-kaleidoscope/SKILL.md` |
| root | 9 | `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, `README.md`, `COMPATIBILITY.md`, `Cargo.toml`, `Cargo.lock`, `.gitignore`, `INITIAL-COMMIT-PLAN.md` |

Two files removed by step 3 bring `conformance/` to 13, and removing this file
brings root to 8 and the total to **139**. Re-derive the number rather than
trusting it — `git ls-files --cached --others --exclude-standard | wc -l` in the
source tree, minus the three deletions — because the tree moves and this line
does not.

---

## 5. Files present in the tree that should NOT be in the initial commit

### Remove — a run record of one machine, not a repository artefact

* **`conformance/evidence/dx10b-hosts.local.json`**
* **`conformance/evidence/dx10b-non-auth.local.json`**

  Both are currently tracked. Nothing reads them: they appear in `README.md` and
  `conformance/README.md` only as `--output` paths, and no test or script loads
  them. Their content is a record of one execution on one machine — a
  `generated_at` timestamp, a `platform` block, and a `dependency_held` map whose
  values state which agent CLIs are and are not installed on the machine that ran
  it (*"host CLI is not installed on the executing machine"*). That is a fact
  about a laptop, published forever, in exchange for nothing a reader can use.

  The `.local.json` suffix already says what they are. Regenerating them is one
  documented command. If you disagree and want them kept as published evidence,
  keep them — they carry no engine internal, and the poison scanner's provenance
  allowlist covers the commit identifier inside them either way. It is a
  judgement about noise and machine privacy, not a leak.

### Remove — this file, once it has been acted on

* **`INITIAL-COMMIT-PLAN.md`**

  It documents an internal migration, names the discarded commits by hash, and is
  addressed to whoever performs the migration rather than to a user of the SDK.
  Delete it in step 3 alongside the evidence files, or keep it out of the copy in
  step 2. Nothing else references it.

### Already excluded, and worth confirming rather than assuming

None of these is in the file set, because `.gitignore` already covers them.
Confirm with `git status --short` at step 5 rather than trusting the list:

`target/` · `python/.venv/` · `python/build/` · `python/dist/` ·
`typescript/node_modules/` · `typescript/dist/` · `conformance/node_modules/` ·
`conformance/.work/` · `.ruff_cache/` · `__pycache__/` · `.env*` ·
`.kaleidoscope/` · `.profile-home/` · `.live-home/` · `.DS_Store`

The two that matter most are `.env*` and `.kaleidoscope/`. A live vault holds
the developer's actual memories and every exposure record written against them,
and neither is visible to `git ls-files` — so neither would be caught by any
check that derives its file set from the index. They are excluded by pattern,
which is why step 2 copies from `git ls-files` rather than from the filesystem.

---

## 6. `.gitignore` additions

Two lines were added during this work and are already in the file:

```gitignore
# Regenerated test debug output, never a repository artefact. Both are written
# on every run by the parity suites and read by nothing.
python/tests/artifacts/
typescript/test/artifacts/
```

Both directories existed on disk and were untracked. `test_parity.py` and
`parity.test.ts` write them on every run for debugging and neither reads them
back. Untracked-and-regenerated is one `git add <dir>` away from tracked, and
the fresh `git add .` in step 5 is exactly that command — so the ignore rule had
to exist before the plan did.

Consider adding, if you take the section 5 decision:

```gitignore
conformance/evidence/*.local.json
```

Deliberately **not** added here. Those two files are tracked today; adding the
pattern would silently drop them from the fresh commit without the deletion in
step 3 ever being written down. A decision that changes what gets published
should appear as a `rm` somebody had to type, not as a line in an ignore file.

---

## 7. What still blocks publication after this plan is executed

Doing everything above produces a clean single-commit local repository. It does
not make the repository publishable. See the OUTSTANDING section of the work
report; the short form is:

1. **No end-user terms exist for the engine.** `NOTICE` and both package READMEs
   now say separate terms apply and are a precondition of first publication.
   They are not written, and the release archive admits exactly one member, so
   there is no route to deliver them beside the payload either.
2. **`@kleos-research/kaleidoscope` is generated by two repositories under
   contradictory licences.** `typescript/package.json` in this repository claims
   that name under `Apache-2.0`, and `NOTICE` names it as Apache-2.0-covered.
   The engine repository's release pipeline builds a manifest under the *same*
   name with `"license": "UNLICENSED"` — its packaging script sets the entry
   package name in one place and that licence field in another, and a second
   script asserts the built manifest's name equals it, so both halves are live
   rather than vestigial. Verified by reading those scripts, not inferred.

   npm has one licence field per package name and the first publication sets
   it. Whichever repository publishes first makes the other one's claim false on
   a channel that cannot be taken back. **This is a decision, not a defect**, and
   it belongs to whoever owns the release channel: either the engine pipeline
   stops emitting that name, or this repository does. Neither can be fixed from
   inside the other, and a comment in either will not hold — the losing side
   needs an assertion in its own test suite that it emits no manifest under that
   name.
3. **Neither gate runs in CI.** `poison_scan.py` is reached only indirectly,
   through `python/tests/test_repository_contract.py`, and CI has been dark since
   2026-08-04. A control described as enforced while running nowhere is the
   pattern this repository spent the week removing from other people's code.
4. **`DX-07`, `DX-10B` and `DX04` appear throughout the tree** — in
   `COMPATIBILITY.md`'s title, in two conformance runner filenames, and inside
   two evidence `schema_version` strings. The commit subjects are fixed by this
   plan; the file contents are not. Renaming them is a real refactor with golden
   files on the other end of it, and it is a decision about public register
   rather than a defect.

---

## 8. Two limits of the scanner, so a green scan is read for what it is

Neither is a blocker and neither is new. They are written here because this file
is the last thing read before somebody decides the tree is safe, and a green
`rc 0` is the easiest thing in this repository to over-read.

* **A private source file whose basename collides with one of the manager's.**
  Rule 4 admits an unqualified `.rs` basename that this repository owns. The
  manager has `config.rs`, `model.rs`, `error.rs`, `host.rs`, `engine.rs` and
  about fifteen more, so a sentence describing the *engine's* file of the same
  name passes. Measured against this exact tree: a planted line reading *"the
  engine config.rs reads the settings; model.rs loads the embedding table"*
  scans green. A **qualified** path still has to match a real path here, which
  is the form an actual citation takes and the form the known leak took.
  Widening the rule would make the repository unable to describe its own source.

* **A token split across a line break.** Candidates are cut at token boundaries
  within a line, so a name that a text reflow wrapped mid-word is not
  reassembled. Also measured green on this tree.

The scanner's own module docstring carries both, in the same words. Do not
report a green scan as proof that no internal survives — report it as proof that
none of the eight named categories does.
