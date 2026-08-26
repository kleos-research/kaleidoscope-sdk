"""Cross-language BEHAVIOURAL parity for the entitlement refusal path.

The existing cross-language goldens keep *declared constants* in parity. They
cannot see a divergence in what the two SDKs actually do: which error type is
raised, which identifier it carries, and which sentence the user reads. This
file closes that, and it is the test decision 5 is really asking for.

There are two mechanisms here, deliberately, because neither alone is enough.

* A **committed golden** (reference/entitlement-behaviour-golden.json), asserted
  every run. The spec's "each language writes a file, a third step diffs them"
  arrangement only compares if BOTH suites have already run, so a run of one
  language alone compares against nothing and reports green. Against a committed
  golden each language fails on its own.
* A **committed ROW golden** (reference/entitlement-parity-rows-v1.json) that
  BOTH languages assert against, every run, independently.

**The rendezvous arrangement this file used to describe never ran once.** It
guarded on `TYPESCRIPT_ARTIFACT.exists()` and fell through to a `print` -- and
nothing in the TypeScript tree ever wrote that file, so the branch that was
documented as "the only thing that can catch a divergence the committed golden
was updated to match on one side only" took the else every time and reported
green. The header claimed the two artifacts had been measured byte-identical;
one of them did not exist.

A rendezvous cannot be repaired by making the missing side write the file,
either. Whichever suite runs second is the only one that compares, a suite run
alone compares against a stale file from a previous run, and running the two
concurrently races on a shared mutable path -- observed, intermittently red.

So the rendezvous is replaced rather than repaired: the row golden is committed,
and each language asserts the full row set against it on its own. A divergence
in either SDK fails a test in THAT SDK's suite, with no ordering, no staleness
and no race. The artifacts are still written, for debugging only, and nothing
is asserted from them.

Regenerate the committed golden with:

    PYTHONPATH=src .venv/bin/python -m pytest tests/test_parity.py \\
        --regenerate-entitlement-parity
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

from kaleidoscope_memory.descriptor import _MAX_DIAGNOSTIC_BYTES, load_launch_descriptor
from kaleidoscope_memory.entitlement import clear_gate_status_cache
from kaleidoscope_memory.errors import (
    ENTITLEMENT_MESSAGES as GOLDEN_MESSAGES,
    ENTITLEMENT_REFUSAL_IDENTIFIERS,
    EntitlementError,
)
from kaleidoscope_memory.session import PersistentKaleidoscopeSession

GOLDEN_PATH = Path(__file__).parents[2] / "reference" / "entitlement-behaviour-golden.json"

#: The machine-specific path both languages must normalise away, exactly as
#: test_cross_language_golden.py normalises the binary to __KSCOPE_BINARY__.
KEY_FILE_PLACEHOLDER = "__KEY_FILE__"

BOGUS_KEY = "ksk_alpha." + "Z" * 43


def _normalize(text: str, key_file: str) -> str:
    return text.replace(key_file, KEY_FILE_PLACEHOLDER)


async def _observe(fake_binary: Path, directory: Path, identifier: str) -> dict[str, object]:
    """Drive one refusal through the real spawn path and record what arrived."""

    clear_gate_status_cache()
    profile = f"refusal.{identifier}.{uuid.uuid4().hex[:8]}"
    descriptor = load_launch_descriptor(fake_binary, profile)
    key_file = str(directory / "api-key")
    with pytest.raises(EntitlementError) as caught:
        async with PersistentKaleidoscopeSession(descriptor):
            pass
    error = caught.value
    return {
        "reason": error.reason,
        "code": error.code,
        "error_class": type(error).__name__,
        "message": _normalize(str(error), key_file),
        "key_file": _normalize(error.key_file or "", key_file),
        # The engine's prose is deliberately NOT compared: it is the engine's,
        # not the SDK's, and it is redacted. Only that it arrived and is bounded.
        "diagnostic_present": bool(error.diagnostic),
        "diagnostic_bounded": len(error.diagnostic.encode("utf-8")) <= _MAX_DIAGNOSTIC_BYTES * 3,
    }


@pytest.mark.asyncio
async def test_entitlement_refusals_match_the_cross_language_behaviour_golden(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    for name in list(os.environ):
        if name.startswith(("KALEIDOSCOPE_", "KSCOPE_")):
            monkeypatch.delenv(name, raising=False)
    directory = tmp_path / "entitlement"
    directory.mkdir(parents=True)
    (directory / "fixture-gate.json").write_text('{"entitlement_build": true}', encoding="utf-8")
    monkeypatch.setenv("KSCOPE_ENTITLEMENT_HOME", str(directory))
    monkeypatch.setenv("KALEIDOSCOPE_API_KEY", BOGUS_KEY)

    observed = {
        identifier: await _observe(fake_binary, directory, identifier)
        for identifier in ENTITLEMENT_REFUSAL_IDENTIFIERS
    }
    payload = {
        "_comment": (
            "Observed behaviour of the alpha entitlement refusal path, driven through a "
            "real SDK spawn against python/tests/fixtures/fake_kscope_mcp.py. Both SDKs "
            "assert against this file; a divergence in what the caller receives fails a "
            "test instead of reaching a user. Regenerate from Python only."
        ),
        "contract_version": 1,
        "key_file_placeholder": KEY_FILE_PLACEHOLDER,
        "scenarios": observed,
    }

    if request.config.getoption("--regenerate-entitlement-parity"):
        GOLDEN_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    golden = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    assert golden["scenarios"] == observed
    assert set(golden["scenarios"]) == set(ENTITLEMENT_REFUSAL_IDENTIFIERS)
    # Non-vacuous: the golden must actually carry content, not eight empty rows.
    for identifier, record in golden["scenarios"].items():
        assert record["error_class"] == "EntitlementError"
        assert record["code"] == "entitlement"
        assert record["reason"] == identifier
        assert record["diagnostic_present"] is True
        assert record["diagnostic_bounded"] is True
        assert record["message"].endswith("Your local vault data is intact and unchanged.")
    assert (
        KEY_FILE_PLACEHOLDER in golden["scenarios"]["E_NO_KEY"]["message"]
    ), "E_NO_KEY names the key file, so normalisation must be exercised"


def test_the_behaviour_golden_carries_no_machine_specific_path() -> None:
    """A golden that leaked an absolute path would pass in one checkout only."""

    text = GOLDEN_PATH.read_text(encoding="utf-8")
    assert str(Path.home()) not in text
    assert tempfile.gettempdir() not in text
    assert sys.prefix not in text


# ---------------------------------------------------------------------------
# The COMMITTED row golden both languages assert against, independently.
#
# The row shape, the row order, the key order and the `diagnostic_length_bounded`
# predicate are all part of the contract, so the two SDKs compare equal only when
# they genuinely behave the same -- including the `<= 4096 + 64` bound, which is
# the allowance for the redaction rewriting `api_key: x` (16 B) to
# `api_key=<redacted>` (18 B). A different predicate on one side would compare
# unequal while both SDKs were behaving identically.
#
# `parity-python.json` is still written beside the tests, for a human diffing a
# failure. NOTHING is asserted from it, and nothing is asserted from the
# TypeScript artifact either: a file written by the run that is being checked
# cannot check that run.
# ---------------------------------------------------------------------------

ARTIFACT_PATH = Path(__file__).parent / "artifacts" / "parity-python.json"
ROW_GOLDEN_PATH = (
    Path(__file__).parents[2] / "reference" / "entitlement-parity-rows-v1.json"
)
_TS_DIAGNOSTIC_BOUND = 4096 + 64


async def _native_refusal_row(fake_binary: Path, directory: Path, identifier: str) -> dict:
    from kaleidoscope_memory.native import Controller

    clear_gate_status_cache()
    descriptor = load_launch_descriptor(fake_binary, "test")
    key_file = str(directory / "api-key")
    with pytest.raises(EntitlementError) as caught:
        await Controller(descriptor, timeout_seconds=10.0).search_raw(
            {"_fixture_mode": "entitlement_refusal", "_entitlement_code": identifier}
        )
    error = caught.value
    return {
        "scenario": identifier,
        "reason": error.reason,
        "code": error.code,
        "message": str(error).replace(key_file, KEY_FILE_PLACEHOLDER),
        "diagnostic_length_bounded": len(error.diagnostic.encode("utf-8")) <= _TS_DIAGNOSTIC_BOUND,
        "diagnostic_carries_marker": f"kscope-entitlement-refusal: {identifier}"
        in error.diagnostic,
    }


@pytest.mark.asyncio
async def test_the_two_sdks_behave_identically_on_the_same_nine_refusals(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    for name in list(os.environ):
        if name.startswith(("KALEIDOSCOPE_", "KSCOPE_")):
            monkeypatch.delenv(name, raising=False)
    directory = tmp_path / "entitlement"
    directory.mkdir(parents=True)
    (directory / "fixture-gate.json").write_text('{"entitlement_build": true}', encoding="utf-8")
    monkeypatch.setenv("KSCOPE_ENTITLEMENT_HOME", str(directory))
    monkeypatch.setenv("KALEIDOSCOPE_API_KEY", BOGUS_KEY)

    rows = [
        await _native_refusal_row(fake_binary, directory, identifier)
        for identifier in ENTITLEMENT_REFUSAL_IDENTIFIERS
    ]

    # Held to the FROZEN CONTRACT before anything is written. An artifact that
    # merely recorded whatever this SDK happened to do would compare equal to a
    # TypeScript artifact recording the same drift.
    for row in rows:
        assert row["code"] == "entitlement"
        assert row["reason"] == row["scenario"]
        assert row["message"] == GOLDEN_MESSAGES[row["reason"]].replace(
            "{key_file}", KEY_FILE_PLACEHOLDER
        )
        assert row["diagnostic_length_bounded"] is True
        assert row["diagnostic_carries_marker"] is True
    assert [row["scenario"] for row in rows] == list(ENTITLEMENT_REFUSAL_IDENTIFIERS)

    ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT_PATH.write_text(
        json.dumps({"language": "python", "rows": rows}, indent=2) + "\n", encoding="utf-8"
    )

    payload = {
        "_comment": (
            "The refusal rows both SDKs must produce, asserted independently by "
            "python/tests/test_parity.py and typescript/test/parity.test.ts. "
            "Committed rather than exchanged at run time: a rendezvous file only "
            "compares when both suites have already run, is stale when one runs "
            "alone, and races when they run together. Regenerate from Python with "
            "pytest --regenerate-entitlement-parity."
        ),
        "contract_version": 1,
        "key_file_placeholder": KEY_FILE_PLACEHOLDER,
        "rows": rows,
    }
    if request.config.getoption("--regenerate-entitlement-parity"):
        ROW_GOLDEN_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    # NOT guarded on existence. A missing golden is a failure, not a skip: the
    # branch this replaced guarded on a file nothing wrote and printed instead
    # of failing, so it reported green for its entire life.
    assert ROW_GOLDEN_PATH.exists(), (
        f"{ROW_GOLDEN_PATH} is missing. Regenerate it with "
        "--regenerate-entitlement-parity; it is asserted, never optional."
    )
    golden_rows = json.loads(ROW_GOLDEN_PATH.read_text(encoding="utf-8"))["rows"]
    assert rows == golden_rows, (
        "this SDK's refusal rows differ from the committed cross-language golden"
    )


# ---------------------------------------------------------------------------
# The MCP path's cause chain, which is a per-PATH property and therefore not in
# the shared row golden.
#
# The golden's rows are produced here from the MCP path and asserted by
# TypeScript from the NATIVE path, so a field that legitimately differs between
# the two paths cannot live in it -- putting `cause_present` there compared
# Python-over-MCP against TypeScript-over-native and failed for the right value
# on the wrong axis.
#
# On the MCP path there IS an exception to chain from: the transport failure the
# refusal was diagnosed out of. Python raised `... from exc`; TypeScript
# constructed without a `cause`, so a caller walking the chain saw
# `McpError: Connection closed` in one language and nothing in the other, for
# the same refusal from the same engine. Both attach it now. The native path
# chains nothing in either language, and that is correct: there is no exception
# in hand there, only an exit code and a stderr buffer, and fabricating a cause
# would be worse than having none.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_mcp_path_chains_the_transport_failure_as_the_cause(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for name in list(os.environ):
        if name.startswith(("KALEIDOSCOPE_", "KSCOPE_")):
            monkeypatch.delenv(name, raising=False)
    directory = tmp_path / "entitlement"
    directory.mkdir(parents=True)
    (directory / "fixture-gate.json").write_text('{"entitlement_build": true}', encoding="utf-8")
    monkeypatch.setenv("KSCOPE_ENTITLEMENT_HOME", str(directory))
    monkeypatch.setenv("KALEIDOSCOPE_API_KEY", BOGUS_KEY)

    clear_gate_status_cache()
    # The fixture selects which refusal to emit from the profile name, exactly
    # as `_observe` does.
    descriptor = load_launch_descriptor(fake_binary, f"refusal.E_REVOKED.{uuid.uuid4().hex[:8]}")
    with pytest.raises(EntitlementError) as caught:
        async with PersistentKaleidoscopeSession(descriptor):
            pass
    assert caught.value.reason == "E_REVOKED"
    # Presence only. The transport's own message belongs to the MCP SDK and
    # would drift; what must not drift is whether a caller can reach it at all.
    assert caught.value.__cause__ is not None


@pytest.mark.asyncio
async def test_the_native_path_deliberately_chains_nothing(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The falsifier for the test above.

    Without it, that test would pass just as well against an SDK that attached a
    fabricated cause everywhere, and the asymmetry it is really asserting would
    go unmeasured.
    """

    from kaleidoscope_memory.native import Controller

    for name in list(os.environ):
        if name.startswith(("KALEIDOSCOPE_", "KSCOPE_")):
            monkeypatch.delenv(name, raising=False)
    directory = tmp_path / "entitlement"
    directory.mkdir(parents=True)
    (directory / "fixture-gate.json").write_text('{"entitlement_build": true}', encoding="utf-8")
    monkeypatch.setenv("KSCOPE_ENTITLEMENT_HOME", str(directory))
    monkeypatch.setenv("KALEIDOSCOPE_API_KEY", BOGUS_KEY)

    clear_gate_status_cache()
    descriptor = load_launch_descriptor(fake_binary, "test")
    with pytest.raises(EntitlementError) as caught:
        await Controller(descriptor, timeout_seconds=10.0).search_raw(
            {"_fixture_mode": "entitlement_refusal", "_entitlement_code": "E_REVOKED"}
        )
    assert caught.value.__cause__ is None
