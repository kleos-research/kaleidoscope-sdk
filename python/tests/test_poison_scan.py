"""Prove every poison-scan rule fires, on a planted violation, one rule at a time.

`test_repository_contract.py` runs the scanner and asserts it exits 0. That is a
negative pass condition: it passes hardest when the scanner is broken. A scanner
that forbids nothing, or whose file walk returns an empty list, reports exactly
the same green.

So this module asserts the other half. For every rule the scanner declares it
builds a throwaway tree containing one violation and requires the scan to report
it.

WHY THIS FILE NO LONGER LISTS THE PRIVATE NAMES
-----------------------------------------------
It used to. It carried every crate in the engine workspace, spelled from
fragments, count-asserted for completeness, under a docstring explaining what
naming a crate discloses. Fragmentation defeated the scanner and not a reader:
concatenating two adjacent literals gave back a complete annotated inventory of
what the engine keeps private. The test file was a bigger disclosure than the
one the rule existed to stop.

Rule 3 is now a table of digests, so no test can enumerate it either. What is
assertable from a public repository, and what this module asserts instead:

* Each CATEGORY's path fires end to end, driven by a planted canary that the
  scanner deliberately carries for the purpose. The canary is not a private
  name; it exists so the category's message can be produced without one.
* The table is not gutted -- per-category counts, with floors.
* The verdict depends on the table: emptying it makes a firing violation stop
  firing (the control), and rule 5 keeps working when it does.
* Every generic mechanism -- case folding, non-UTF-8 decoding, base64 overlay,
  URL handling, the derived-quantity normaliser -- is planted with content
  invented here, which needs no private name at all.

What no public test can assert is that the table's real entries are the right
ones. The plaintext authority lives beside the workspace it describes.
`test_the_table_agrees_with_a_plaintext_authority_when_one_is_supplied` is the
seam for checking it from where that authority exists; it skips, visibly, here.

The false-positive tests matter just as much. A scanner that fires on
`semantic_delta` would be deleted within a week, and the category would go back
to being unchecked. Each of those tests pins a specific thing the public contract
must be able to say.
"""

from __future__ import annotations

import base64
import importlib.util
import os
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCANNER_PATH = ROOT / "scripts" / "poison_scan.py"


def _load_scanner() -> ModuleType:
    specification = importlib.util.spec_from_file_location("poison_scan", SCANNER_PATH)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


poison_scan = _load_scanner()


#: This file is scanned too, so it may not contain the strings it plants.
#:
#: Rule 1's needles are read out of the scanner's own table. The handful of
#: literals below are the ones that have to be written here, and they are
#: assembled from fragments by the scanner's own `_n()` for exactly the reason
#: the scanner uses it for rule 1: a test file exempted from the rules it tests
#: is a test file that can plant a real leak.
_n = poison_scan._n

#: A synthetic UUID. Never a coordinate from a real vault -- a test fixture is
#: not a safe place to keep one, and this repository has no business holding one
#: in any file for any reason.
_SYNTHETIC_UUID = "00000000-0000-4000-8000-000000000000"
_PRIVATE_RUST_FILE = _n("verdict", "_record", ".r", "s")
_PRIVATE_QUALIFIED_PATH = _n("private_module", "/mod", ".r", "s")

#: A synthetic 40-hex token. Not a commit of anything; the shape is the rule.
_SYNTHETIC_COMMIT = "0123456789abcdef" * 2 + "01234567"


def _tree(root: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# Rule 1 -- every declared needle fires
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("label", sorted(poison_scan.FORBIDDEN_TEXT))
def test_every_forbidden_text_rule_fires_on_a_planted_violation(
    label: str, tmp_path: Path
) -> None:
    needle = poison_scan.FORBIDDEN_TEXT[label]
    _tree(tmp_path, {"planted.md": f"harmless prose\n{needle}\nmore prose\n"})

    failures = poison_scan.scan(tmp_path)

    assert any("planted.md" in failure and label in failure for failure in failures), (
        f"rule {label!r} did not fire on its own needle; failures={failures}"
    )


# ---------------------------------------------------------------------------
# Rule 3 -- the digest table
# ---------------------------------------------------------------------------

#: One canary per category, spelled from fragments because this file is scanned.
#: These are the tokens the scanner's table deliberately carries so a public test
#: can exercise every category's message without holding a private name.
_CANARIES = {
    poison_scan.CANARY_CRATE: _n("poisonscan-", "canary-crate"),
    poison_scan.CANARY_SYMBOL: _n("poisonscan_", "canary_symbol"),
    poison_scan.CANARY_TREE: _n("poisonscan-", "canary-tree/"),
    poison_scan.CANARY_CONSTANT: _n("POISONSCAN_", "CANARY_CONSTANT"),
    poison_scan.CANARY_SWITCH: _n("POISONSCAN_", "CANARY_SWITCH"),
}


@pytest.mark.parametrize("category", sorted(_CANARIES))
def test_every_engine_internal_category_fires_on_its_canary(
    category: str, tmp_path: Path
) -> None:
    """Each category's path, end to end, on content this repository may hold.

    The canary proves the mechanism -- extraction, folding, digesting, lookup,
    message -- for one category. It does not prove the category's real entries
    are right; nothing public can. The counts below are the other half.
    """

    token = _CANARIES[category]
    _tree(tmp_path, {"planted.py": f"# a comment that mentions {token} in passing\n"})

    failures = poison_scan.scan(tmp_path)

    assert any(
        "planted.py" in failure and category in failure for failure in failures
    ), f"category {category!r} did not fire on its canary; failures={failures}"


def test_every_canary_the_scanner_declares_is_exercised_here() -> None:
    """A canary nobody plants is a canary that stopped working unnoticed."""

    declared = {
        category
        for category in poison_scan.ENGINE_INTERNAL_DIGESTS.values()
        if category.startswith("planted canary")
    }

    assert declared == set(_CANARIES), (
        "the scanner's canary categories and this module's plants disagree: "
        f"scanner={sorted(declared)} tests={sorted(_CANARIES)}"
    )


def test_the_rule_tables_are_not_empty() -> None:
    """The failure mode a parametrised test cannot see on its own.

    Empty a table and pytest collects zero cases for it, and zero cases report
    green -- a suite that checks nothing, wearing the same colour as a suite that
    checks everything. The floors below are the categories the repository has
    committed to having, not counts anybody should tune.
    """

    assert len(poison_scan.FORBIDDEN_TEXT) >= 6, "local-path and canary rules went missing"
    assert poison_scan.PUBLIC_KALEIDOSCOPE_FIRST_WORDS, "rule 5's allowlist went missing"
    assert len(poison_scan.DERIVED_QUANTITY_DIGESTS) >= 4, "rule 3b went missing"

    counts: dict[str, int] = {}
    for category in poison_scan.ENGINE_INTERNAL_DIGESTS.values():
        counts[category] = counts.get(category, 0) + 1

    # Floors per category. A denylist that lost a whole category would still
    # report a plausible total, which is how the crate rules were five of
    # thirteen for months without anybody noticing.
    for category, floor in (
        (poison_scan.CRATE, 20),
        (poison_scan.SYMBOL, 8),
        (poison_scan.TREE, 14),
        (poison_scan.CONSTANT, 18),
        (poison_scan.SWITCH, 8),
    ):
        assert counts.get(category, 0) >= floor, (
            f"category {category!r} has {counts.get(category, 0)} entries, "
            f"below its floor of {floor}; the table has been gutted"
        )

    # Rule 5 inverts the default, so an EMPTIED allowlist is loud rather than
    # silent -- every token in the tree would fire. The hazard runs the other
    # way: a widened one. A word admitted here is a word never questioned again,
    # so the ceiling is asserted alongside the floors above.
    assert len(poison_scan.PUBLIC_KALEIDOSCOPE_FIRST_WORDS) <= 20, (
        "rule 5's allowlist has grown past the point where anybody reviews it; "
        "each entry must be a public name of ours, with a comment saying which"
    )


def test_the_table_holds_digests_and_not_names() -> None:
    """The property that makes this file publishable at all.

    Every key must be a truncated hex digest. A maintainer who "simplified" the
    table back to plaintext tokens would restore the inventory this repository
    just removed, and would do it in a change that looked like a cleanup.
    """

    for key in poison_scan.ENGINE_INTERNAL_DIGESTS:
        assert len(key) == 16 and all(c in "0123456789abcdef" for c in key), (
            f"{key!r} is not a digest; rule 3's table has been un-hashed"
        )
    for key in poison_scan.DERIVED_QUANTITY_DIGESTS:
        assert len(key) == 16 and all(c in "0123456789abcdef" for c in key), key


def test_the_digest_is_case_folded_and_stable() -> None:
    """The two properties the table's keys were computed under.

    Folding is what closed the hole a capitalised copy of a private name walked
    through. Stability is what makes the table a table rather than a set of
    numbers nobody can regenerate.
    """

    canary = _CANARIES[poison_scan.CANARY_SYMBOL]
    assert poison_scan.token_digest(canary) == poison_scan.token_digest(canary.upper())
    assert poison_scan.token_digest(canary) in poison_scan.ENGINE_INTERNAL_DIGESTS


@pytest.mark.parametrize(
    "spelling",
    [
        lambda token: token,
        lambda token: token.upper(),
        lambda token: token.capitalize(),
        lambda token: token.replace("-", "-").title(),
    ],
)
def test_a_capitalised_copy_of_a_denied_name_still_fires(spelling, tmp_path: Path) -> None:
    """The shift key was a complete bypass of rules 3 and 5.

    Both matched case-sensitively, so every engine crate name, module name and
    constant passed if the case differed by one letter. Planted here on the
    canary rather than a real name, which is the whole point of having one.
    """

    token = spelling(_CANARIES[poison_scan.CANARY_CRATE])
    _tree(tmp_path, {"planted.md": f"the {token} crate handles this\n"})

    failures = poison_scan.scan(tmp_path)

    assert any("planted.md" in failure for failure in failures), (
        f"{token!r} passed the scan; case folding is not applied"
    )


def test_a_gutted_rule_table_stops_finding_a_planted_violation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Proof the verdict depends on the rules, not on the walk succeeding.

    A scan that returned `[]` because it read no files would pass every
    false-positive test in this module and every assertion in
    `test_repository_contract.py`. This is the control: the same tree, scanned
    twice, differing only in whether the rule table is populated.

    The canary is deliberately a token no OTHER rule can also match, so a
    control that stayed red after the table was emptied would prove nothing.
    """

    token = _CANARIES[poison_scan.CANARY_SYMBOL]
    _tree(tmp_path, {"planted.md": f"mentions {token}\n"})

    assert any(poison_scan.CANARY_SYMBOL in failure for failure in poison_scan.scan(tmp_path))

    monkeypatch.setattr(poison_scan, "ENGINE_INTERNAL_DIGESTS", {})
    assert poison_scan.scan(tmp_path) == []


def test_the_table_agrees_with_a_plaintext_authority_when_one_is_supplied() -> None:
    """The seam for checking the table from where the plaintext list lives.

    Point `POISON_SCAN_PLAINTEXT` at a file of one token per line -- the private
    repository's copy of the authority -- and every token in it must be in the
    table. Skipped, visibly, everywhere else, because a public checkout has no
    authority to check against and a silently-passing check would be worse than
    none.
    """

    authority = os.environ.get("POISON_SCAN_PLAINTEXT")
    if not authority:
        pytest.skip("POISON_SCAN_PLAINTEXT is unset; no plaintext authority to check")

    tokens = [
        line.strip()
        for line in Path(authority).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    assert tokens, f"{authority} lists no tokens"

    missing = [
        token
        for token in tokens
        if poison_scan.token_digest(token) not in poison_scan.ENGINE_INTERNAL_DIGESTS
    ]
    assert not missing, f"{len(missing)} tokens in the authority are absent from the table"


# ---------------------------------------------------------------------------
# Rule 5 -- deny-by-default over this project's namespace
# ---------------------------------------------------------------------------


def test_an_unknown_engine_crate_first_word_fires(tmp_path: Path) -> None:
    """Rule 5 is what stops rule 3's table going stale in silence.

    That table is a snapshot of a workspace this repository cannot read. It was
    five of thirteen crates for a while, and nothing noticed. So the token
    planted here is one no rule has ever been told about: rule 3 cannot match it,
    and it must still fail.
    """

    unknown = poison_scan._PROJECT_PREFIX + "newengine"
    assert poison_scan.token_digest(unknown) not in poison_scan.ENGINE_INTERNAL_DIGESTS, (
        "the planted token must be one rule 3 has never seen, or this proves nothing"
    )

    _tree(tmp_path, {"planted.md": f"built on the {unknown} crate\n"})

    failures = poison_scan.scan(tmp_path)

    assert any("unrecognised" in failure and "newengine" in failure for failure in failures), (
        f"rule 5 did not deny an unknown namespace token; failures={failures}"
    )


def test_a_capitalised_unknown_namespace_token_fires(tmp_path: Path) -> None:
    """The hyphen form is the crate name on disk, so it folds case.

    A private crate name written with a capital in a sentence passed rule 3 and
    rule 5 both, which made the shift key a complete bypass of the
    deny-by-default rule as well as the denylist. The token is built at runtime
    rather than written here, because this file is scanned by the rule it tests.
    """

    token = (poison_scan._PROJECT_PREFIX + "newengine").title()
    _tree(tmp_path, {"planted.md": f"built on the {token} crate\n"})

    failures = poison_scan.scan(tmp_path)

    assert any("unrecognised" in failure and "newengine" in failure for failure in failures), (
        f"the capitalised hyphen form passed; failures={failures}"
    )


def test_the_underscore_form_stays_lowercase_and_env_var_names_survive(
    tmp_path: Path,
) -> None:
    """The false positive that would have been the price of folding case there.

    A Rust `use` line is lowercase by convention and by lint, so the underscore
    form's hazard is a lowercase hazard. Folding case would make every
    `KALEIDOSCOPE_<WORD>` environment variable read as a namespace token --
    starting with the published entitlement credential -- and roughly ninety
    findings on legitimate content is a rule that gets deleted rather than
    fixed.
    """

    name = poison_scan._PROJECT_NAME.upper()
    _tree(
        tmp_path,
        {
            "contract.json": (
                f'{{"env": ["{name}_API_KEY", "{name}_CONTROL_PLANE_ORIGIN"]}}\n'
            )
        },
    )

    assert poison_scan.scan(tmp_path) == []


def test_the_underscore_spelling_of_an_unknown_crate_fires(tmp_path: Path) -> None:
    """The form a copied `use` line takes.

    A Cargo crate is hyphenated on disk and underscored in Rust, and rule 3's
    table was written from the disk names -- so the underscore spellings were
    reachable through the single likeliest route a private crate name has into a
    public file.
    """

    token = poison_scan._PROJECT_NAME + "_" + "someengine"
    # Assembled, because rule 4 reads this file too and would otherwise report a
    # Rust source path this repository does not own -- which it correctly did.
    _tree(tmp_path, {_n("planted", ".r", "s"): f"use {token}::Thing;\n"})

    failures = poison_scan.scan(tmp_path)

    assert any("unrecognised" in failure and "someengine" in failure for failure in failures), (
        f"the underscore spelling passed; failures={failures}"
    )


def test_denying_the_crates_does_not_deny_this_repositorys_own_names(
    tmp_path: Path,
) -> None:
    """The false positive rule 5 is one careless generalisation away from.

    A rule shaped "any `kaleidoscope-<word>` that is not one of our package
    names" was considered and rejected, because the tree carries several
    `kaleidoscope-` tokens that are not package names at all: an ownership
    marker, a backup suffix, a schema identifier, the published embedding schema
    id, a handful of test fixture prefixes. All of them have to survive, which is
    why rule 5 matches the first word and not the whole token.
    """

    _tree(
        tmp_path,
        {
            "own.md": (
                "packages: kaleidoscope-manager, kaleidoscope-memory,\n"
                "kaleidoscope-memory-native-darwin-arm64, kaleidoscope-darwin-arm64.\n"
                "markers: kaleidoscope-manager-v1, kaleidoscope-owner,\n"
                "kaleidoscope-instruction-owner, kaleidoscope-backup, kaleidoscope-lock.\n"
                "schema ids: kaleidoscope-public-contract,\n"
                "kaleidoscope-potion-base-8m-i8-v1. repository: kaleidoscope-sdk.\n"
                "fixtures: kaleidoscope-fixture-1, kaleidoscope-native-fixture-1,\n"
                "kaleidoscope-vault, kaleidoscope-dx10b-host.\n"
                "prose: a Kaleidoscope-specific launch descriptor.\n"
                "module: kaleidoscope_memory. skill: use-kaleidoscope.\n"
            )
        },
    )

    assert poison_scan.scan(tmp_path) == []


def test_every_word_on_rule_fives_allowlist_is_exercised_by_that_fixture(
    tmp_path: Path,
) -> None:
    """An allowlist entry nobody plants is an entry nobody can justify.

    The test above hand-writes the tokens, so it can silently stop covering a
    word. This derives the coverage from the allowlist itself: every admitted
    first word is spelled into a tree, and the whole tree must stay clean. A word
    added to the allowlist without a real use is still caught -- by the reviewer
    who has to explain what it names.
    """

    name = poison_scan._PROJECT_NAME
    lines = "\n".join(
        f"{name}{separator}{word}-example"
        for word in sorted(poison_scan.PUBLIC_KALEIDOSCOPE_FIRST_WORDS)
        for separator in ("-", "_")
    )
    assert lines, "an empty allowlist would make this test vacuous"
    _tree(tmp_path, {"own.md": lines + "\n"})

    assert poison_scan.scan(tmp_path) == []


def test_a_gutted_namespace_allowlist_changes_rule_fives_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same control for rule 5, which inverts the default and so inverts this.

    Rule 5 fails open by WIDENING, not by emptying: an emptied allowlist denies
    everything. So the control runs the other way -- a token that passes today
    must fail once its word is taken off the list. That proves the verdict is
    read from the allowlist rather than from some other rule happening to be
    silent.
    """

    token = poison_scan._PROJECT_PREFIX + "manager"
    _tree(tmp_path, {"own.md": f"the {token} crate\n"})

    assert poison_scan.scan(tmp_path) == []

    monkeypatch.setattr(poison_scan, "PUBLIC_KALEIDOSCOPE_FIRST_WORDS", frozenset())
    failures = poison_scan.scan(tmp_path)

    assert any("unrecognised" in failure for failure in failures), failures


# ---------------------------------------------------------------------------
# The scanner reads itself, and reads what it says it reads
# ---------------------------------------------------------------------------


def test_the_scanner_scans_its_own_source_file() -> None:
    """Proof the file walk reaches `scripts/`, not just an assumption that it does."""

    scanned = poison_scan.candidate_files(ROOT)

    assert SCANNER_PATH in scanned


def test_a_file_that_is_not_utf8_is_scanned_rather_than_skipped(tmp_path: Path) -> None:
    """The refusal that used to be spelled as an answer.

    A `UnicodeDecodeError` skipped the file and moved on -- while still counting
    it towards the reported total, so the only visible trace of a whole unscanned
    file was a number that read as coverage. One latin-1 byte was a complete
    bypass of every rule in this module.
    """

    token = _CANARIES[poison_scan.CANARY_SYMBOL]
    (tmp_path / "planted.md").write_bytes(f"caf\xe9 {token}\n".encode("latin-1"))

    failures = poison_scan.scan(tmp_path)

    assert any("planted.md" in failure for failure in failures), (
        f"a non-UTF-8 file was skipped silently; failures={failures}"
    )


def test_content_hidden_in_base64_is_scanned(tmp_path: Path) -> None:
    """Every rule here reads text, and base64 is not text until it is decoded.

    No live violation was ever found this way. It is closed because the failure
    mode is the same one above: the file is read, nothing is found, and the file
    counts as covered.
    """

    token = _CANARIES[poison_scan.CANARY_CONSTANT]
    payload = base64.b64encode(
        f"the constant is {token} and it is not printed anywhere".encode()
    ).decode()
    _tree(tmp_path, {"fixture.json": '{"blob": "' + payload + '"}\n'})

    failures = poison_scan.scan(tmp_path)

    assert any("fixture.json" in failure for failure in failures), (
        f"a base64-encoded internal was not decoded; failures={failures}"
    )


def test_ordinary_base64_content_does_not_fire(tmp_path: Path) -> None:
    """The overlay must not invent findings out of binary blobs.

    Most long base64 runs in a test corpus are keys, digests and random bytes.
    They decode to nothing printable and must contribute nothing.
    """

    payload = base64.b64encode(bytes(range(256)) * 4).decode()
    _tree(tmp_path, {"fixture.json": '{"blob": "' + payload + '"}\n'})

    assert poison_scan.scan(tmp_path) == []


# ---------------------------------------------------------------------------
# Raw vault coordinates
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("prefix", [_n("wsp", "_"), _n("usr", "_"), _n("journal", ":")])
def test_a_raw_vault_coordinate_fires(prefix: str, tmp_path: Path) -> None:
    coordinate = prefix + _SYNTHETIC_UUID
    _tree(tmp_path, {"evidence.json": f'{{"workspace_id": "{coordinate}"}}\n'})

    failures = poison_scan.scan(tmp_path)

    assert any("raw vault identity coordinate" in failure for failure in failures)


# ---------------------------------------------------------------------------
# Derived calibration quantities -- rule 3b
# ---------------------------------------------------------------------------


#: Spelled from fragments for the reason everything in this file is: the module
#: is scanned too, and a derived quantity written out here would be the same
#: disclosure as one written out anywhere else. The canary is last; the four
#: before it are the shapes the authority's own content check names.
_DERIVED_QUANTITIES = (
    _n("0.05", "94"),
    _n("1.0 / ", "61.0"),
    _n("1/", "61"),
    _n("1 / ", "61"),
    _n("1.0 / 0.8", " / 0.6"),
    _n("k = ", "60"),
    _n("k=", "60"),
    _n("9.87", "65"),
)


@pytest.mark.parametrize("quantity", _DERIVED_QUANTITIES)
def test_every_derived_quantity_pattern_fires(quantity: str, tmp_path: Path) -> None:
    """Rule 3 cannot see a constant that is disclosed by arithmetic.

    Each of these names no constant and still hands one over. That is not a
    hypothetical route: it is the route two of the engine's own excluded design
    records actually took. Whitespace is varied across the cases on purpose --
    the disclosure is the arithmetic, not the formatting -- and one case is the
    fusion constant stated by VALUE rather than by division, which the pattern
    set covered for four of its five listed shapes and not the fifth.
    """

    _tree(tmp_path, {"notes.md": f"the bound works out to {quantity} in practice\n"})

    failures = poison_scan.scan(tmp_path)

    assert any("derived engine calibration quantity" in failure for failure in failures), (
        f"{quantity!r} did not fire rule 3b; failures={failures}"
    )


def test_the_derived_quantity_cases_are_not_empty() -> None:
    """Same failure mode as an emptied rule table, one level further out."""

    assert len(_DERIVED_QUANTITIES) >= 6
    normalised = poison_scan.quantity_tokens(_DERIVED_QUANTITIES[0])
    assert any(
        poison_scan.token_digest(item) in poison_scan.DERIVED_QUANTITY_DIGESTS
        for item in normalised
    )


def test_ordinary_arithmetic_in_prose_does_not_fire(tmp_path: Path) -> None:
    """The false positive that would get rule 3b deleted within a week.

    A rule over bare numeric literals is unusable, so rule 3b is deliberately a
    handful of specific shapes. This pins that it stays that way: division,
    ratios, assignments and version-shaped numbers are ordinary content in a
    public SDK.
    """

    _tree(
        tmp_path,
        {
            "notes.md": (
                "Timeout is 10.0 seconds. Retry after 1 / 2 of the window.\n"
                "Version 0.6.1, released 1.0 / 2.0 of the way through the quarter.\n"
                "A batch of 61 items took 1.0 / 6.1 seconds each.\n"
                "Set max_bytes = 4096 and depth = 60 in the config.\n"
            )
        },
    )

    assert poison_scan.scan(tmp_path) == []


# ---------------------------------------------------------------------------
# Engine source paths -- rule 4
# ---------------------------------------------------------------------------


def test_an_unqualified_private_rust_file_fires(tmp_path: Path) -> None:
    _tree(tmp_path, {"notes.md": f"The gate reads it, per `{_PRIVATE_RUST_FILE}`.\n"})

    failures = poison_scan.scan(tmp_path)

    assert any(_PRIVATE_RUST_FILE in failure for failure in failures), failures


def test_a_qualified_private_path_fires_even_when_its_basename_is_owned_here(
    tmp_path: Path,
) -> None:
    """The trap this rule exists for.

    A repository that owns `src/account/mod.rs` owns the basename `mod.rs`. A
    basename-only allowlist would therefore admit a qualified path into any
    private module directory ending in the same file -- which is precisely the
    shape of the leak that was in this tree: a module directory, a slash, and
    `mod.rs`. Only an exact path match may admit a qualified reference.
    """

    _tree(
        tmp_path,
        {
            "src/account/mod.rs": "// a real, owned file, so the basename is owned\n",
            "notes.md": f"read at `{_PRIVATE_QUALIFIED_PATH}`\n",
        },
    )

    failures = poison_scan.scan(tmp_path)

    assert any(_PRIVATE_QUALIFIED_PATH in failure for failure in failures), failures
    assert not any("account" in failure for failure in failures)


def test_a_source_path_inside_a_link_fires(tmp_path: Path) -> None:
    """URLs were stripped wholesale, which blinded rule 4 to the likeliest form.

    A repository blob link is how an engine source citation actually appears in a
    code comment. Stripping every URL before matching meant the one spelling the
    rule most needed to catch was the one it could not see.
    """

    link = "https://example.invalid/repo/blob/main/src/entitlement/" + _n("verdict", ".r", "s")
    _tree(tmp_path, {"notes.md": f"see {link} for the detail\n"})

    failures = poison_scan.scan(tmp_path)

    assert any("does not own" in failure for failure in failures), (
        f"a source path inside a link passed; failures={failures}"
    )


def test_a_link_to_this_repositorys_own_source_does_not_fire(tmp_path: Path) -> None:
    """The false positive the link pass would otherwise guarantee.

    A link carries a scheme, a host and a branch ahead of the path, so a link to
    this repository's own source can never match an owned path exactly. Without
    a suffix match the rule would fire on the project's own documentation links,
    which is the shape of false positive that gets a rule deleted rather than
    narrowed.
    """

    owned = _n("engine", ".r", "s")
    _tree(
        tmp_path,
        {
            f"src/{owned}": "// owned\n",
            "README.md": (
                "see https://github.com/kleos-research/kaleidoscope-sdk/blob/main/"
                f"src/{owned}\n"
            ),
        },
    )

    assert poison_scan.scan(tmp_path) == []


def test_an_ignored_rust_file_cannot_amnesty_its_basename(tmp_path: Path) -> None:
    """The allowlist and the scan set must be the same file list.

    Rule 4's owned-basename set was built by walking the filesystem while the
    scan set came from git. Any `.rs` file in an ignored directory -- a build
    tree, a virtualenv with one Rust-backed package in it -- therefore amnestied
    its basename across the whole repository, and nothing ever scanned the file
    that granted the amnesty.
    """

    basename = _n("scor", "ing", ".r", "s")
    _tree(
        tmp_path,
        {
            ".gitignore": "build/\n",
            f"build/{basename}": "// ignored by git, and so never scanned\n",
            "notes.md": f"the engine scorer is {basename}\n",
        },
    )
    # The scan set comes from git, so the tree has to be one.
    import subprocess

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)

    failures = poison_scan.scan(tmp_path)

    assert any("notes.md" in failure and "does not own" in failure for failure in failures), (
        f"an ignored .rs file amnestied its basename; failures={failures}"
    )


def test_this_repositorys_own_rust_files_do_not_fire(tmp_path: Path) -> None:
    _tree(
        tmp_path,
        {
            "src/engine.rs": "// owned\n",
            "src/account/store.rs": "// owned\n",
            "Cargo.toml": 'path = "src/main.rs"\n',
            "src/main.rs": "// owned\n",
            "notes.md": "See engine.rs, account/store.rs and src/main.rs.\n",
        },
    )

    assert poison_scan.scan(tmp_path) == []


# ---------------------------------------------------------------------------
# Commit identifiers -- rule 6
# ---------------------------------------------------------------------------


def test_a_commit_identifier_in_prose_fires(tmp_path: Path) -> None:
    """A commit id points into a repository the reader cannot open.

    The exclusion manifest accepts exactly one use for one -- release transport
    provenance -- and a hash restated in a README is not that. It is a second
    copy, with no way to notice when it stops matching the first.
    """

    _tree(tmp_path, {"README.md": f"built from commit `{_SYNTHETIC_COMMIT}`\n"})

    failures = poison_scan.scan(tmp_path)

    assert any("commit identifier" in failure for failure in failures), failures


def test_a_commit_identifier_in_a_provenance_file_does_not_fire(tmp_path: Path) -> None:
    """The one accepted use, named as a file list rather than a shape.

    Provenance is a property of the file's job, not of the token, so the
    exemption is by path. Everything else in the tree fails.
    """

    for provenance in sorted(poison_scan.PROVENANCE_FILES):
        _tree(tmp_path, {provenance: f'{{"source_commit": "{_SYNTHETIC_COMMIT}"}}\n'})

    assert poison_scan.scan(tmp_path) == []


def test_a_sha256_digest_does_not_read_as_a_commit_identifier(tmp_path: Path) -> None:
    """`Cargo.lock` is full of 64-hex checksums and none of them is a commit.

    The word boundaries do this for free, which is worth a test rather than a
    comment: a later "improvement" to the pattern that dropped them would turn
    every lockfile in the tree red and the rule would be removed rather than
    repaired.
    """

    _tree(tmp_path, {"Cargo.lock": 'checksum = "' + "ab" * 32 + '"\n'})

    assert poison_scan.scan(tmp_path) == []


# ---------------------------------------------------------------------------
# Rule 7 -- internal design records
# ---------------------------------------------------------------------------


#: Synthetic design-record citations. Assembled from fragments because this file
#: is scanned by the rule it is testing, and numbered 99xx because no such record
#: exists in any tree -- the shape is the rule, exactly as it is for
#: `_SYNTHETIC_COMMIT` above. Every separator here is one the engine's own
#: working documents actually use.
_ADR = _n("AD", "R")
_PRD = _n("PR", "D")
_SYNTHETIC_RECORDS = (
    f"{_ADR} 9901",
    f"{_PRD} 9902",
    f"{_ADR.lower()}-9903",
    f"{_ADR}_9904",
    f"{_PRD} 995",
    f"{_PRD.lower()}9906",
)


@pytest.mark.parametrize("citation", _SYNTHETIC_RECORDS)
def test_an_internal_design_record_citation_fires(citation: str, tmp_path: Path) -> None:
    """A numbered design record is a citation into a tree nobody outside can open.

    Rule 3 denies the tree by path. This rule exists because the citation form
    that actually appears in a code comment reaches past that: it names a series
    and a number and never writes the directory down. The spellings here cover
    space, hyphen, underscore, run-on, three digits and four, because a rule that
    only caught the tidiest spelling is a rule the untidy one walks around.
    """

    _tree(tmp_path, {"notes.md": f"See {citation} for the reasoning.\n"})

    failures = poison_scan.scan(tmp_path)

    assert any("internal design record" in failure for failure in failures), (
        f"{citation!r} passed the scan"
    )


@pytest.mark.parametrize(
    "standard", ["RFC 3339", "RFC3339", "RFC 7520", "rfc-2119"]
)
def test_a_public_internet_standard_does_not_fire(standard: str, tmp_path: Path) -> None:
    """The false positive that would have got this rule deleted.

    `RFC 3339` is the timestamp format the published write contract is specified
    in, and it appears in the goldens, the schema text and both SDKs. `RFC 7520`
    names the test key in `src/account/fake.rs`. These are public standards with
    public documents, they are cited correctly, and a scanner that called them a
    leak would be narrowed by whoever hit it first -- probably by dropping the
    whole rule rather than the one series.
    """

    _tree(tmp_path, {"notes.md": f"Timestamps follow {standard}.\n"})

    assert poison_scan.scan(tmp_path) == []


def test_the_captured_public_contract_is_exempt_and_needs_to_be(tmp_path: Path) -> None:
    """The exemption, and the proof it is load-bearing rather than decorative.

    `reference/kaleidoscope-public-contract.json` is a byte-capture of what the
    shipped executable prints, and the engine's own `remember` schema text cites
    a design record by number in a field description it shows every user. So the
    citation is already public -- published by the product, not by us -- and the
    golden's only job is to equal that output byte for byte.

    Three halves, really, and the third is the one that stops this becoming
    decoration:

    1. the exempt path is clean;
    2. the SAME BYTES at any other path are red -- otherwise the exemption is
       doing nothing and rule 7 would report green whatever it was given;
    3. the real golden in this repository genuinely contains a citation, read
       out of the file at runtime rather than spelled here. Without that, an
       exemption could outlive the reason for it by years and every test would
       still pass.
    """

    published = f"the title is not scraped out of content_md ({_ADR} 9907)"

    for exempt in sorted(poison_scan.INTERNAL_DOCUMENT_EXEMPT):
        _tree(tmp_path, {exempt: published + "\n"})
    assert poison_scan.scan(tmp_path) == []

    _tree(tmp_path, {"reference/some-other-golden.json": published + "\n"})
    failures = poison_scan.scan(tmp_path)
    assert any("internal design record" in failure for failure in failures), (
        "the same bytes at an unexempted path passed; the exemption is doing "
        "nothing and rule 7 would report green whatever it was given"
    )

    for exempt in sorted(poison_scan.INTERNAL_DOCUMENT_EXEMPT):
        golden = ROOT / exempt
        assert golden.is_file(), f"{exempt} is exempt from rule 7 and does not exist"
        assert poison_scan.INTERNAL_DOCUMENT.search(
            golden.read_text(encoding="utf-8", errors="replace")
        ), (
            f"{exempt} no longer contains the published citation the exemption "
            f"was granted for; remove the exemption rather than keeping a hole "
            f"nothing needs"
        )


# ---------------------------------------------------------------------------
# False positives the public contract cannot afford
# ---------------------------------------------------------------------------


def test_the_public_semantic_delta_shape_is_not_forbidden(tmp_path: Path) -> None:
    """`semantic_delta` is the shape the SDK exists to construct.

    It is published by `kscope schema remember` to anybody who runs the binary.
    A rule that forbade it would forbid the SDK from documenting its own primary
    argument.
    """

    _tree(
        tmp_path,
        {
            "sdk.py": (
                "# Build a semantic_delta: memory_type, title, facts, entities,\n"
                "# propose, corrections, contradicts, occurred_at, admission,\n"
                "# scope, temporal, evidence, context. Each fact carries subject,\n"
                "# predicate, object, basis, mode, from, until, because.\n"
            )
        },
    )

    assert poison_scan.scan(tmp_path) == []


def test_the_published_operation_and_channel_names_are_not_forbidden(
    tmp_path: Path,
) -> None:
    """Everything `kscope schema` and `kscope public-contract` already print."""

    _tree(
        tmp_path,
        {
            "contract.json": (
                '{"tools": ["search", "remember"],'
                ' "operator_only": ["feedback", "memory_lifecycle", "memory_import",'
                ' "address_maintenance", "maintenance", "ontology", "doctor"],'
                ' "retired": ["graph_recall", "recall", "compile", "replay"],'
                ' "channels": ["lexical", "semantic", "precedent", "address"],'
                ' "knobs": ["top_k", "candidate_pool", "bfs_depth", "max_facts"]}\n'
            )
        },
    )

    assert poison_scan.scan(tmp_path) == []


def test_the_entitlement_variable_names_are_not_forbidden(tmp_path: Path) -> None:
    """Naming a variable is not disclosing where it is read.

    All five are in `reference/entitlement-contract-v1.json`, which is a public
    contract both SDKs are asserted against. Forbidding them would make the
    allowlist undocumentable -- and the allowlist's whole defence is that a
    reader can see exactly which names are on it.
    """

    _tree(
        tmp_path,
        {
            "contract.json": (
                '{"entitlement_environment": ["KALEIDOSCOPE_API_KEY",'
                ' "KSCOPE_ENTITLEMENT_HOME"],'
                ' "never_admitted": ["KSCOPE_ENTITLEMENT_PROBE",'
                ' "KALEIDOSCOPE_CONTROL_PLANE_ORIGIN", "KSCOPE_PROFILE_HOME"]}\n'
            )
        },
    )

    assert poison_scan.scan(tmp_path) == []


def test_the_embedding_model_name_is_not_forbidden(tmp_path: Path) -> None:
    """MIT requires the bundled table's notice to accompany every copy.

    `kscope licences` prints it and `kscope model` names the model, so the name
    is disclosed by the product itself. Only the Rust module-path spelling is
    private.
    """

    _tree(
        tmp_path,
        {
            "contract.json": (
                '{"model": {"name": "potion-base-8M", "source": "bundled"},'
                ' "embedding_schema": "kaleidoscope-potion-base-8m-i8-v1"}\n'
            )
        },
    )

    assert poison_scan.scan(tmp_path) == []


def test_this_repositorys_own_schema_ids_are_not_forbidden(tmp_path: Path) -> None:
    """A `schemas/` path segment is on the engine's never-publish list.

    It is also the path component of this repository's own published JSON Schema
    `$id` URLs, and a public repository that cannot name its own schema
    identifiers would have the rule removed rather than narrowed. The qualified
    private spellings are covered instead; this pins the decision so it is not
    quietly reversed.
    """

    _tree(
        tmp_path,
        {
            "evidence.schema.json": (
                '{"$id": "https://memory.kleosresearch.xyz/schemas/'
                'dx10b-non-auth-account-offline-local-evidence-v1.json"}\n'
            )
        },
    )

    assert poison_scan.scan(tmp_path) == []


def test_third_party_repository_urls_do_not_fire(tmp_path: Path) -> None:
    """Crate homepages are not claims about anybody's source layout.

    Several crate repositories are named after the language and end in the same
    two letters as a Rust source file, and `crates/` appears mid-path in others.
    THIRD_PARTY_NOTICES.md is full of both. The `/src/` requirement on rule 4's
    link pass is what separates these from a blob link into a source tree.
    """

    _tree(
        tmp_path,
        {
            "THIRD_PARTY_NOTICES.md": (
                "| `lazy_static` | 1.5.0 | MIT OR Apache-2.0 | "
                "https://github.com/rust-lang-nursery/lazy-static.rs |\n"
                "| `js-sys` | 0.3.103 | MIT OR Apache-2.0 | "
                "https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/js-sys |\n"
                "Build-only crates (procedural macros and build.rs helpers) are excluded.\n"
            )
        },
    )

    assert poison_scan.scan(tmp_path) == []


def test_cargo_conventions_do_not_fire(tmp_path: Path) -> None:
    """`build.rs` and `docs.rs` name a convention, not a file in anybody's tree.

    THIRD_PARTY_NOTICES.md and its generator both have to say the first one to
    explain which crates they exclude from the attribution table, and the second
    is where Rust documentation lives. Rule 4 would otherwise read both as
    references to source this repository does not own.
    """

    _tree(
        tmp_path,
        {
            "notes.md": (
                "Build-only crates (procedural macros and build.rs helpers) are\n"
                "excluded. Their API is on docs.rs.\n"
            )
        },
    )

    assert poison_scan.scan(tmp_path) == []


# ---------------------------------------------------------------------------
# The tree itself
# ---------------------------------------------------------------------------


def test_this_repository_is_clean() -> None:
    """The same assertion `test_repository_contract.py` makes, in-process.

    Kept here beside the planted-violation tests on purpose: green here means
    something only because the tests above prove the scanner can go red.
    """

    assert poison_scan.scan(ROOT) == []


# ---------------------------------------------------------------------------
# Credential shape -- rule 8
#
# This rule is the only one here about a live secret rather than a disclosure,
# and it was absent until 2026-08-26. Verified by attempt before it was written:
# a throwaway tree holding exactly `KEY = "ksk_alpha.<43 chars>"` printed
# `poison scan passed (1 source files)` and exited 0.
#
# The plant is assembled from fragments, like every other plant in this file,
# because this file is scanned by the rule it is testing.
# ---------------------------------------------------------------------------

#: Shaped like an alpha key and issued by nobody. Never a real one: a test
#: fixture is not a safe place to keep a credential, and the whole point of this
#: rule is that a credential in a working tree must be assumed disclosed.
_SYNTHETIC_KEY = _n("ksk", "_alpha", ".") + "A" * 43


@pytest.mark.parametrize(
    "body",
    [
        "A" * 43,  # a full-length key
        "A" * 20,  # a truncated paste; still a credential
        "aB3-_" * 8 + "xyz",  # the full charset, including - and _
    ],
)
def test_a_literal_alpha_key_fires(body: str, tmp_path: Path) -> None:
    """Every shape a pasted key can take, in the three places one lands."""

    literal = _n("ksk", "_alpha", ".") + body
    for name, text in (
        ("config.py", f'KEY = "{literal}"\n'),
        ("README.md", f"export KALEIDOSCOPE_API_KEY={literal}\n"),
        ("fixture.json", f'{{"api_key": "{literal}"}}\n'),
    ):
        failures = poison_scan.scan(_tree(tmp_path, {name: text}))
        assert any("credential-shape" in failure for failure in failures), (name, failures)


def test_the_credential_failure_does_not_quote_the_credential(tmp_path: Path) -> None:
    """The falsifier for the message, not for the rule.

    Every other failure in this scanner quotes the offending token back so the
    author can find it. Doing that here would print the credential into the CI
    log that runs the scan, which is a second copy of the leak rather than a
    report of the first.
    """

    _tree(tmp_path, {"leak.py": f'KEY = "{_SYNTHETIC_KEY}"\n'})

    failures = poison_scan.scan(tmp_path)

    assert failures, "the plant did not fire at all"
    joined = "\n".join(failures)
    assert "credential-shape" in joined
    assert _SYNTHETIC_KEY not in joined, "the failure message reprinted the key"
    assert "A" * 20 not in joined, "the failure message reprinted part of the key"
    assert "leak.py" in joined, "the failure names no file, so it cannot be acted on"


def test_the_way_this_repository_writes_the_shape_does_not_fire(tmp_path: Path) -> None:
    """The falsifier for the rule.

    A rule that fired on `ksk_alpha....` would fire on four message templates,
    both descriptor modules and the README, and would be removed within a week.
    The bound is on the BODY, not on the prefix, which is what separates a
    pasted key from a description of one.
    """

    prefix = _n("ksk", "_alpha", ".")
    _tree(
        tmp_path,
        {
            "errors.py": f'MESSAGE = "Set KALEIDOSCOPE_API_KEY={prefix}... in your shell"\n',
            "descriptor.py": 'SHAPE = r"ksk_alpha\\.[A-Za-z0-9_-]*"\n',
            "README.md": f"Pass `api_key=\"{prefix}...\"` when you construct the client.\n",
        },
    )

    assert poison_scan.scan(tmp_path) == []


def test_this_repository_carries_no_literal_key() -> None:
    """The rule, applied to the tree it exists to protect.

    `test_this_repository_is_clean` covers this as one of many, and would report
    it as one line among however many others a future violation adds. This one
    names the credential case on its own, because it is the only rule here whose
    violation is exploitable rather than embarrassing.
    """

    offenders = [
        path
        for path in poison_scan.candidate_files(ROOT)
        if (text := poison_scan.readable_text(path)) is not None
        and poison_scan.CREDENTIAL_SHAPE.search(text)
    ]

    assert offenders == [], f"{len(offenders)} file(s) hold a literal alpha key"
