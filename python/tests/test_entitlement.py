"""The alpha entitlement seam, end to end through the real SDK spawn paths.

Every test here makes a mechanism fire, and where a pass condition is negative
("no other variable reached the child", "this was not classified as a refusal")
it is paired with a positive assertion on real content -- a negative pass
condition fails hardest when the check itself is broken.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

from kaleidoscope_memory.descriptor import (
    _BOOTSTRAP_ENV_KEYS,
    _ENTITLEMENT_ENV_KEYS,
    _MAX_DIAGNOSTIC_BYTES,
    _SAFE_ENV_KEYS,
    _bounded_diagnostic,
    load_launch_descriptor,
    safe_bootstrap_environment,
)
from kaleidoscope_memory.entitlement import (
    GateStatus,
    classify_refusal,
    clear_gate_status_cache,
    entitlement_preflight,
    gate_status,
    key_is_present,
)
from kaleidoscope_memory.errors import (
    ENTITLEMENT_MESSAGES,
    ENTITLEMENT_REFUSAL_IDENTIFIERS,
    ChildProcessError,
    EntitlementError,
    render_entitlement_message,
)
from kaleidoscope_memory.native import Controller
from kaleidoscope_memory.session import PersistentKaleidoscopeSession

REFERENCE = Path(__file__).parents[2] / "reference"
GOLDEN = json.loads((REFERENCE / "entitlement-contract-v1.json").read_text())

#: Obviously not a secret, and identical in shape to the engine suite's KEY_A.
VALID_KEY = "ksk_alpha." + "A" * 43
#: Syntactically well formed, certainly not issued. The SDK must not care.
BOGUS_KEY = "ksk_alpha." + "Z" * 43
MALFORMED_KEY = "ksk_alpha.short"

_KALEIDOSCOPE_LIKE = ("KALEIDOSCOPE_", "KSCOPE_")


def _nonce() -> str:
    return uuid.uuid4().hex[:8]


def _spawn_marker(profile: str) -> Path:
    return Path(tempfile.gettempdir()) / f"kscope-fixture-{profile}.starts"


def _runtime_injected_names() -> set[str]:
    """Names a freshly exec'd child gives itself, whatever environment it got.

    Measured, not listed: a hand-written list would go stale on a new platform
    and would then read as a leak, or -- worse -- excuse one.
    """

    completed = subprocess.run(
        [sys.executable, "-c", "import os, json; print(json.dumps(sorted(os.environ)))"],
        check=True,
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", "")},
    )
    return set(json.loads(completed.stdout)) - {"PATH"}


def _clear_entitlement_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every KALEIDOSCOPE_*/KSCOPE_* name this process happens to carry."""

    for name in list(os.environ):
        if name.startswith(_KALEIDOSCOPE_LIKE):
            monkeypatch.delenv(name, raising=False)


def _entitlement_home(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    enforcing: bool = True,
    gate_exit: int = 0,
) -> Path:
    """Point the fixture engine at a private entitlement directory."""

    directory = tmp_path / "entitlement"
    directory.mkdir(parents=True, exist_ok=True)
    control: dict[str, object] = {}
    if enforcing:
        control["entitlement_build"] = True
    if gate_exit:
        control["gate_exit"] = gate_exit
    if control:
        (directory / "fixture-gate.json").write_text(json.dumps(control), encoding="utf-8")
    monkeypatch.setenv("KSCOPE_ENTITLEMENT_HOME", str(directory))
    clear_gate_status_cache()
    return directory


def _write_key_file(directory: Path, key: str, *, mode: int = 0o600) -> Path:
    path = directory / "api-key"
    path.write_text(key + "\n", encoding="utf-8")
    path.chmod(mode)
    return path


def _assert_diagnostic_is_bounded(diagnostic: str) -> None:
    """The bound `_bounded_diagnostic` actually enforces, stated exactly.

    It keeps the last `_MAX_DIAGNOSTIC_BYTES` of child stderr and THEN redacts,
    and redaction rewrites `api_key: hunter2` (16 bytes) to
    `api_key=<redacted>` (18 bytes). So the retained INPUT is hard-bounded and
    the rendered output can be slightly larger. The security-relevant property
    -- how much child stderr can reach an exception -- is the input bound, and
    the expansion factor is bounded by the shortest match rewriting to the
    replacement, which cannot exceed 3x.

    Asserting `<= _MAX_DIAGNOSTIC_BYTES` on the OUTPUT is what a reader of the
    spec would write, and it is false; it is pinned here rather than quietly
    dropped, because the two SDKs share this function's behaviour byte for byte.
    """

    assert len(diagnostic.encode("utf-8")) <= _MAX_DIAGNOSTIC_BYTES * 3


async def _environment_report(descriptor, session_profile_hint: str = "") -> dict:
    del session_profile_hint
    async with PersistentKaleidoscopeSession(descriptor) as memory:
        return json.loads(await memory.search_raw({"query": "__environment__"}))


# ---------------------------------------------------------------------------
# A1 - the key reaches the engine
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_entitlement_key_reaches_the_engine(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _clear_entitlement_environment(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path)
    monkeypatch.setenv("KALEIDOSCOPE_API_KEY", VALID_KEY)
    descriptor = load_launch_descriptor(fake_binary, f"gated.{_nonce()}")
    report = await _environment_report(descriptor)
    assert report["api_key_seen"] is True
    assert report["api_key_matches"] is True


@pytest.mark.asyncio
async def test_no_key_in_the_parent_means_no_key_in_the_child(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A1's falsifier: a fixture that hardcoded `true` would fail here."""

    _clear_entitlement_environment(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path, enforcing=False)
    descriptor = load_launch_descriptor(fake_binary, "test")
    report = await _environment_report(descriptor)
    assert report["api_key_seen"] is False
    assert report["api_key_matches"] is False


# ---------------------------------------------------------------------------
# A2 - nothing else reaches the child
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_other_environment_variable_reaches_the_child(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _clear_entitlement_environment(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path, enforcing=False)
    monkeypatch.setenv("KALEIDOSCOPE_API_KEY", VALID_KEY)
    forbidden = {
        "KALEIDOSCOPE_TEST_SECRET": "must-not-reach-child",
        "AZURE_OPENAI_API_KEY": "must-not-reach-child",
        "SUPABASE_SECRET_KEY": "must-not-reach-child",
        "OPENAI_API_KEY": "must-not-reach-child",
        "KSCOPE_PROFILE_HOME": str(tmp_path / "wrong-profile-home"),
        "KALEIDOSCOPE_TOKEN": "must-not-reach-child",
        # The sharp one. It is a KSCOPE_* entitlement-family name that is
        # deliberately NOT admitted, so a prefix-based widening of the allowlist
        # passes every other assertion in this test and fails this one.
        "KSCOPE_ENTITLEMENT_PROBE": str(tmp_path / "attacker-probe"),
    }
    for name, value in forbidden.items():
        monkeypatch.setenv(name, value)

    descriptor = load_launch_descriptor(fake_binary, "test")
    report = await _environment_report(descriptor)

    received = set(report["environment_names"])
    for name in forbidden:
        assert name not in received, name
    # Cannot be satisfied by a leak of any name at all, named here or not --
    # except the handful a child's own runtime creates for itself after exec
    # (CPython's C-locale coercion sets LC_CTYPE; macOS CoreFoundation sets
    # __CF_USER_TEXT_ENCODING). That exemption is EARNED here rather than
    # asserted: a control child launched with PATH and nothing else reports the
    # same names, which proves this SDK did not copy them.
    assert received - _runtime_injected_names() <= set(_SAFE_ENV_KEYS), sorted(
        received - _runtime_injected_names() - set(_SAFE_ENV_KEYS)
    )
    # Positive half: the child really did run and really did receive the key.
    assert report["api_key_matches"] is True


# ---------------------------------------------------------------------------
# A3 - the allowlist matches the shared golden
# ---------------------------------------------------------------------------


def test_allowlist_matches_the_shared_golden() -> None:
    assert list(_BOOTSTRAP_ENV_KEYS) == GOLDEN["bootstrap_environment"]
    assert list(_ENTITLEMENT_ENV_KEYS) == GOLDEN["entitlement_environment"]
    assert list(_SAFE_ENV_KEYS) == (
        GOLDEN["bootstrap_environment"] + GOLDEN["entitlement_environment"]
    )
    assert set(_SAFE_ENV_KEYS).isdisjoint(GOLDEN["never_admitted"])
    # Eighteen bootstrap names plus TWO entitlement names. It was 21 until an
    # audit asked what actually consumes KALEIDOSCOPE_CONTROL_PLANE_ORIGIN and
    # the answer was nothing: the engine fixes its control-plane origin when it
    # is built and constructs the environment of anything it spawns, so an
    # inherited value could not redirect it. Forwarding the name was inert and
    # implied a capability that does not exist. It is now in the golden's
    # `never_admitted` list, so the isdisjoint assertion above states its
    # exclusion positively rather than leaving it to this count.
    assert len(_SAFE_ENV_KEYS) == 20
    assert "KALEIDOSCOPE_CONTROL_PLANE_ORIGIN" in GOLDEN["never_admitted"]


def test_the_bootstrap_environment_drops_exported_function_definitions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The `()` filter TypeScript always had and Python did not."""

    monkeypatch.setenv("KALEIDOSCOPE_API_KEY", "() { :; }; echo shellshock")
    monkeypatch.setenv("TERM", "xterm-256color")
    built = safe_bootstrap_environment()
    assert "KALEIDOSCOPE_API_KEY" not in built
    assert built["TERM"] == "xterm-256color"


# ---------------------------------------------------------------------------
# A4 - the refusal surfaces as the typed error with the exact message
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("identifier", ENTITLEMENT_REFUSAL_IDENTIFIERS)
@pytest.mark.asyncio
async def test_refusal_surfaces_as_the_typed_error_on_the_mcp_path(
    identifier: str, fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _clear_entitlement_environment(monkeypatch)
    directory = _entitlement_home(monkeypatch, tmp_path)
    monkeypatch.setenv("KALEIDOSCOPE_API_KEY", BOGUS_KEY)
    descriptor = load_launch_descriptor(fake_binary, f"refusal.{identifier}.{_nonce()}")

    with pytest.raises(EntitlementError) as caught:
        async with PersistentKaleidoscopeSession(descriptor):
            pass

    error = caught.value
    assert error.code == "entitlement"
    assert error.reason == identifier
    assert error.key_file == str(directory / "api-key")
    assert str(error) == render_entitlement_message(identifier, str(directory / "api-key"))
    assert str(error) == GOLDEN["messages"][identifier].replace(
        "{key_file}", str(directory / "api-key")
    )
    assert error.diagnostic
    _assert_diagnostic_is_bounded(error.diagnostic)
    # The engine's own instructional line is destroyed by redaction, which is
    # exactly why the message above has to be the SDK's own.
    assert "KALEIDOSCOPE_API_KEY=<redacted>" in error.diagnostic


@pytest.mark.parametrize("identifier", ENTITLEMENT_REFUSAL_IDENTIFIERS)
@pytest.mark.asyncio
async def test_refusal_surfaces_as_the_typed_error_on_the_native_path(
    identifier: str, fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _clear_entitlement_environment(monkeypatch)
    directory = _entitlement_home(monkeypatch, tmp_path)
    monkeypatch.setenv("KALEIDOSCOPE_API_KEY", BOGUS_KEY)
    descriptor = load_launch_descriptor(fake_binary, "test")

    with pytest.raises(EntitlementError) as caught:
        await Controller(descriptor).search_raw(
            {"_fixture_mode": "entitlement_refusal", "_entitlement_code": identifier}
        )

    error = caught.value
    assert error.code == "entitlement"
    assert error.reason == identifier
    assert str(error) == GOLDEN["messages"][identifier].replace(
        "{key_file}", str(directory / "api-key")
    )
    assert error.diagnostic
    _assert_diagnostic_is_bounded(error.diagnostic)


# ---------------------------------------------------------------------------
# A5 - a non-entitlement failure is unchanged (A4's falsifier)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_non_entitlement_startup_failure_is_unchanged_on_the_mcp_path(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _clear_entitlement_environment(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path)
    monkeypatch.setenv("KALEIDOSCOPE_API_KEY", VALID_KEY)
    descriptor = load_launch_descriptor(fake_binary, f"startupfail.{_nonce()}")

    with pytest.raises(BaseException) as caught:
        async with PersistentKaleidoscopeSession(descriptor):
            pass

    error = caught.value
    assert not isinstance(error, EntitlementError)
    # Measured before and after this change: `mcp.shared.exceptions.McpError`.
    assert type(error).__name__ == "McpError"
    assert "Connection closed" in str(error)
    # Positive half: the child really did start and really did refuse.
    assert _spawn_marker(descriptor.profile).exists()


@pytest.mark.asyncio
async def test_a_non_entitlement_failure_is_unchanged_on_the_native_path(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _clear_entitlement_environment(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path)
    monkeypatch.setenv("KALEIDOSCOPE_API_KEY", VALID_KEY)
    descriptor = load_launch_descriptor(fake_binary, "test")

    with pytest.raises(ChildProcessError) as caught:
        await Controller(descriptor).search_raw({"_fixture_mode": "opaque_failure"})

    assert not isinstance(caught.value, EntitlementError)


def test_the_classifier_does_not_answer_for_everything() -> None:
    """The unit-level falsifier: a classifier that always answers is useless."""

    assert classify_refusal(b"kscope: the vault root is not a vault\n", 2) is None
    assert classify_refusal(b"", 0) is None
    assert classify_refusal(b"", None) is None
    # Exit 4 with no marker at all is still an entitlement refusal, but an
    # unrecognised one -- never silence.
    assert classify_refusal(b"something\n", 4) == "E_UNKNOWN"
    # A marker this SDK does not know maps to E_UNKNOWN, never to None.
    assert classify_refusal(b"kscope-entitlement-refusal: E_FUTURE_CODE\n", 4) == "E_UNKNOWN"
    assert classify_refusal(b"kscope-entitlement-refusal: E_REVOKED\n", 4) == "E_REVOKED"


# ---------------------------------------------------------------------------
# A6 - the SDK performs no local validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_sdk_performs_no_local_validation_of_a_well_formed_bogus_key(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _clear_entitlement_environment(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path)
    monkeypatch.setenv("KALEIDOSCOPE_API_KEY", BOGUS_KEY)
    profile = f"refusal.E_UNVERIFIED.{_nonce()}"
    descriptor = load_launch_descriptor(fake_binary, profile)

    with pytest.raises(EntitlementError) as caught:
        async with PersistentKaleidoscopeSession(descriptor):
            pass

    # The marker is what distinguishes "refused THERE" from "refused HERE".
    assert _spawn_marker(profile).exists()
    assert caught.value.reason == "E_UNVERIFIED"
    assert caught.value.reason not in ("E_NO_KEY", "E_MALFORMED_KEY")


@pytest.mark.asyncio
async def test_the_sdk_performs_no_local_validation_of_a_malformed_key(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _clear_entitlement_environment(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path)
    monkeypatch.setenv("KALEIDOSCOPE_API_KEY", MALFORMED_KEY)
    profile = f"gated.{_nonce()}"
    descriptor = load_launch_descriptor(fake_binary, profile)

    with pytest.raises(EntitlementError) as caught:
        async with PersistentKaleidoscopeSession(descriptor):
            pass

    # An SDK that grew a local shape check would never write this marker, and
    # would raise E_MALFORMED_KEY from the wrong side of the process boundary.
    assert _spawn_marker(profile).exists()
    assert caught.value.reason == "E_MALFORMED_KEY"


def test_key_is_present_never_inspects_the_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_entitlement_environment(monkeypatch)
    monkeypatch.setenv("KALEIDOSCOPE_API_KEY", "not-a-key-at-all")
    assert key_is_present(GateStatus(enforcing=True, key_file=None)) is True

    monkeypatch.delenv("KALEIDOSCOPE_API_KEY", raising=False)
    unusable = tmp_path / "api-key"
    unusable.write_text("nonsense", encoding="utf-8")
    unusable.chmod(0o644)
    # Wrong mode, wrong content: still PRESENT. The engine decides usability.
    assert key_is_present(GateStatus(enforcing=True, key_file=str(unusable))) is True

    empty = tmp_path / "empty-key"
    empty.write_text("", encoding="utf-8")
    assert key_is_present(GateStatus(enforcing=True, key_file=str(empty))) is False
    assert key_is_present(GateStatus(enforcing=True, key_file=str(tmp_path / "absent"))) is False


# ---------------------------------------------------------------------------
# A7 - the key-file route works with no key in the environment
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_key_file_route_works_with_an_explicit_entitlement_home(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _clear_entitlement_environment(monkeypatch)
    directory = _entitlement_home(monkeypatch, tmp_path)
    _write_key_file(directory, VALID_KEY)
    assert "KALEIDOSCOPE_API_KEY" not in os.environ

    descriptor = load_launch_descriptor(fake_binary, f"gated.{_nonce()}")
    async with PersistentKaleidoscopeSession(descriptor) as memory:
        report = json.loads(await memory.search_raw({"query": "__environment__"}))
        served = json.loads(await memory.search_raw({"query": "fixture"}))

    assert report["key_file_seen"] is True
    assert report["api_key_seen"] is False
    # A real search envelope, not merely "no exception was raised".
    assert served["query"] == "fixture" and served["records"] == []


@pytest.mark.skipif(sys.platform == "win32", reason="platform-default path lane is POSIX here")
@pytest.mark.asyncio
async def test_the_key_file_route_works_with_nothing_set_at_all(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """No KSCOPE_* and no KALEIDOSCOPE_* anywhere: HOME and a file, nothing else."""

    _clear_entitlement_environment(monkeypatch)
    home = tmp_path / "home"
    if sys.platform == "darwin":
        directory = home / "Library" / "Application Support" / "kaleidoscope" / "entitlement"
    else:
        directory = home / ".config" / "kaleidoscope" / "entitlement"
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    directory.mkdir(parents=True)
    (directory / "fixture-gate.json").write_text('{"entitlement_build": true}', encoding="utf-8")
    _write_key_file(directory, VALID_KEY)
    monkeypatch.setenv("HOME", str(home))
    clear_gate_status_cache()

    assert not [name for name in os.environ if name.startswith(_KALEIDOSCOPE_LIKE)]
    status = gate_status(str(fake_binary))
    assert status.enforcing is True
    assert status.key_file == str(directory / "api-key")

    descriptor = load_launch_descriptor(fake_binary, f"gated.{_nonce()}")
    async with PersistentKaleidoscopeSession(descriptor) as memory:
        report = json.loads(await memory.search_raw({"query": "__environment__"}))
        served = json.loads(await memory.search_raw({"query": "fixture"}))

    assert report["key_file_seen"] is True
    assert served["query"] == "fixture"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
@pytest.mark.asyncio
async def test_an_unusable_key_file_is_not_reported_as_a_missing_key(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _clear_entitlement_environment(monkeypatch)
    directory = _entitlement_home(monkeypatch, tmp_path)
    _write_key_file(directory, VALID_KEY, mode=0o644)

    descriptor = load_launch_descriptor(fake_binary, f"gated.{_nonce()}")
    with pytest.raises(EntitlementError) as caught:
        async with PersistentKaleidoscopeSession(descriptor):
            pass

    # The repair for a 0644 key file is `chmod`. Telling this user to set a key
    # they have already set would be a refusal spelled as a different, wrong
    # answer -- the named defect class here.
    assert caught.value.reason == "E_KEY_FILE_UNUSABLE"
    assert caught.value.reason != "E_NO_KEY"
    assert "permissions 0600" in str(caught.value)


# ---------------------------------------------------------------------------
# A8 - the preflight fires, and fails open
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_preflight_refuses_before_spawning_a_gated_command(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _clear_entitlement_environment(monkeypatch)
    directory = _entitlement_home(monkeypatch, tmp_path)
    profile = f"gated.{_nonce()}"
    descriptor = load_launch_descriptor(fake_binary, profile)

    with pytest.raises(EntitlementError) as caught:
        async with PersistentKaleidoscopeSession(descriptor):
            pass

    assert caught.value.reason == "E_NO_KEY"
    assert caught.value.key_file == str(directory / "api-key")
    # Nothing was spawned beyond `gate`: the marker the mcp arm writes is absent.
    assert not _spawn_marker(profile).exists()


@pytest.mark.asyncio
async def test_the_native_preflight_refuses_before_spawning_a_gated_command(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The NATIVE twin of the test above, which did not exist.

    `native.py::_call` had a preflight and no test: replacing it with `pass`
    left the suite at exactly its baseline count, byte for byte, while the same
    break in TypeScript reddened two tests. An untested guard is indistinguish-
    able from an absent one, and this is the path `Controller.search_raw` --
    every non-MCP caller -- takes.

    The assertion is on the spawn MARKER, not on the error: an SDK that had lost
    the preflight would still raise `EntitlementError` here, just from the engine
    after a spawn instead of from the preflight before one. Only the marker can
    tell those two apart, which is the whole property being tested.
    """

    from kaleidoscope_memory.native import Controller

    _clear_entitlement_environment(monkeypatch)
    directory = _entitlement_home(monkeypatch, tmp_path)
    profile = f"gated-native.{_nonce()}"
    descriptor = load_launch_descriptor(fake_binary, profile)

    with pytest.raises(EntitlementError) as caught:
        await Controller(descriptor, timeout_seconds=10.0).search_raw({"query": "x"})

    assert caught.value.reason == "E_NO_KEY"
    assert caught.value.key_file == str(directory / "api-key")
    assert not _spawn_marker(profile).exists()


@pytest.mark.asyncio
async def test_an_ungated_engine_is_never_blocked_by_the_preflight(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The regression that matters most: a keyless user of a default build."""

    _clear_entitlement_environment(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path, enforcing=False)
    assert gate_status(str(fake_binary)) == GateStatus(enforcing=False, key_file=None)

    descriptor = load_launch_descriptor(fake_binary, "test")
    async with PersistentKaleidoscopeSession(descriptor) as memory:
        served = json.loads(await memory.search_raw({"query": "fixture"}))
    assert served["query"] == "fixture"


@pytest.mark.asyncio
async def test_an_engine_with_no_gate_command_fails_open(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An older engine answers `gate` with a usage error. The SDK proceeds."""

    _clear_entitlement_environment(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path, enforcing=True, gate_exit=2)
    assert gate_status(str(fake_binary)) == GateStatus(enforcing=False, key_file=None)
    entitlement_preflight(str(fake_binary))  # must not raise

    descriptor = load_launch_descriptor(fake_binary, "test")
    async with PersistentKaleidoscopeSession(descriptor) as memory:
        served = json.loads(await memory.search_raw({"query": "fixture"}))
    assert served["query"] == "fixture"


def test_gate_status_fails_open_on_an_unreadable_or_unparsable_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_entitlement_environment(monkeypatch)
    assert gate_status(str(tmp_path / "not-an-executable")) == GateStatus(False, None)


# ---------------------------------------------------------------------------
# A9 - the marker survives redaction and truncation
# ---------------------------------------------------------------------------


def test_the_marker_survives_redaction_and_truncation() -> None:
    flood = b"api_key: hunter2\n" * 600
    assert len(flood) > 8 * 1024
    raw = flood + b"kscope-entitlement-refusal: E_GRACE_EXPIRED\n"

    # Classification runs on the raw bytes and finds the LAST marker.
    assert classify_refusal(raw, 4) == "E_GRACE_EXPIRED"

    bounded = _bounded_diagnostic(raw)
    _assert_diagnostic_is_bounded(bounded)
    # The redaction pattern requires token/secret/password/authorization/api_key
    # immediately before the separator; "refusal" is none of those.
    assert bounded.splitlines()[-1] == "kscope-entitlement-refusal: E_GRACE_EXPIRED"
    assert "hunter2" not in bounded
    assert "api_key=<redacted>" in bounded
    # And the bounded text is still classifiable, which is the property a future
    # redaction edit would break.
    assert classify_refusal(bounded.encode("utf-8"), 4) == "E_GRACE_EXPIRED"


def test_a_marker_at_the_head_would_not_survive_truncation() -> None:
    """Why the marker is specified as the LAST line, demonstrated."""

    head = b"kscope-entitlement-refusal: E_REVOKED\n" + b"noise line\n" * 600
    assert classify_refusal(head, 4) == "E_REVOKED"
    assert classify_refusal(_bounded_diagnostic(head).encode("utf-8"), None) is None


# ---------------------------------------------------------------------------
# A10 - the messages match the shared golden
# ---------------------------------------------------------------------------


def test_messages_match_the_shared_golden() -> None:
    golden = GOLDEN["messages"]
    assert set(ENTITLEMENT_MESSAGES) == set(golden)
    assert set(ENTITLEMENT_MESSAGES) == set(GOLDEN["refusal_identifiers"]) | set(
        GOLDEN["sdk_only_identifiers"]
    )
    for identifier, template in ENTITLEMENT_MESSAGES.items():
        assert template == golden[identifier], identifier
        assert template.endswith("Your local vault data is intact and unchanged."), identifier
    with_placeholder = {k for k, v in ENTITLEMENT_MESSAGES.items() if "{key_file}" in v}
    # Five, since the code route was added. It used to be two: the three
    # replacement templates said "or the key file" in prose and named no path,
    # so a user told to write a replacement to a file was not told which file.
    # They now carry the same instruction sentence as E_NO_KEY, which is the
    # only sentence in this table that names all three routes.
    assert with_placeholder == {
        "E_NO_KEY",
        "E_KEY_FILE_UNUSABLE",
        "E_UNKNOWN_KEY",
        "E_REVOKED",
        "E_KEY_EXPIRED",
    }
    # The code route is stated wherever the user is told how to supply a key,
    # and nowhere else. A template that instructs without naming `api_key=` is
    # an instruction that is now incomplete.
    instructional = {k for k, v in ENTITLEMENT_MESSAGES.items() if "KALEIDOSCOPE_API_KEY" in v}
    assert instructional == {"E_NO_KEY", "E_UNKNOWN_KEY", "E_REVOKED", "E_KEY_EXPIRED"}
    for identifier in instructional:
        assert "api_key=" in ENTITLEMENT_MESSAGES[identifier], identifier
    assert GOLDEN["missing_key_file_placeholder"] == "the key file"
    assert render_entitlement_message("E_NO_KEY", None).count("the key file") == 1


def test_the_golden_pins_the_wire_level_contract() -> None:
    assert GOLDEN["contract_version"] == 1
    assert GOLDEN["exit_codes"]["entitlement_refused"] == 4
    assert GOLDEN["refusal_marker_prefix"] == "kscope-entitlement-refusal: "
    assert list(ENTITLEMENT_REFUSAL_IDENTIFIERS) == GOLDEN["refusal_identifiers"]
    assert GOLDEN["gate_report_keys"] == [
        "status",
        "entitlement_build",
        "gated_commands",
        "entitlement_home",
        "key_file",
        "build_features",
        "marker",
    ]


# ---------------------------------------------------------------------------
# A12 - the native path does not retry an entitlement refusal
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_native_path_does_not_retry_an_entitlement_refusal(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _clear_entitlement_environment(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path)
    monkeypatch.setenv("KALEIDOSCOPE_API_KEY", BOGUS_KEY)
    marker = tmp_path / "invocations"
    descriptor = load_launch_descriptor(fake_binary, "test")

    with pytest.raises(EntitlementError):
        await Controller(descriptor).search_raw(
            {
                "_fixture_mode": "entitlement_refusal",
                "_entitlement_code": "E_REVOKED",
                "marker": str(marker),
            }
        )

    assert marker.read_text(encoding="utf-8") == "1"


@pytest.mark.asyncio
async def test_the_invocation_counter_can_reach_two(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A12's control: proves the counter works and only entitlement is exempt."""

    _clear_entitlement_environment(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path, enforcing=False)
    marker = tmp_path / "invocations"
    descriptor = load_launch_descriptor(fake_binary, "test")

    result = await Controller(descriptor).search_raw(
        {"_fixture_mode": "crash_once", "marker": str(marker)}
    )
    assert result["invocation"] == 2
    assert marker.read_text(encoding="utf-8") == "2"


# ---------------------------------------------------------------------------
# A13 - the new constants and fixture keys survive the repository poison scan
# ---------------------------------------------------------------------------


def test_the_shared_contract_is_committed_where_the_poison_scan_reaches_it() -> None:
    path = REFERENCE / "entitlement-contract-v1.json"
    assert path.is_file()
    assert "COPIES" in GOLDEN["_comment"]
    # test_repository_contract.py runs scripts/poison_scan.py over this whole
    # tree, so this file and the fixture's obviously-fake keys are in its scope.
    assert VALID_KEY == "ksk_alpha." + "A" * 43


# ---------------------------------------------------------------------------
# A14 - the gate memo is keyed on the DIRECTORY VARIABLES, not the binary alone
# ---------------------------------------------------------------------------


def test_the_gate_memo_is_keyed_on_the_directory_variables(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """One binary path serves many gate answers, so the binary is not the key.

    `key_file` in the gate report is DERIVED from KSCOPE_ENTITLEMENT_HOME /
    HOME / APPDATA / XDG_CONFIG_HOME. Keyed on (path, mtime, size) alone, a
    process that changed the entitlement home between calls was served the
    PREVIOUS configuration's answer -- one memo entry wearing two
    configurations. Nothing about that looks wrong from the outside.

    The consequence was not cosmetic. With a key file present under the second
    home, the stale answer made `key_is_present` false, the preflight refused
    locally without spawning anything, and the message instructed the user to
    write their key to a path under the FIRST home -- which the engine would
    never read. Following the instruction is a no-op.

    Deliberately NOT calling clear_gate_status_cache() between the two probes:
    the cache is the mechanism under test, and clearing it is exactly what hid
    this from the parity harness, whose helpers clear it before every row.
    """

    _clear_entitlement_environment(monkeypatch)

    first = tmp_path / "home-a" / "entitlement"
    first.mkdir(parents=True)
    (first / "fixture-gate.json").write_text('{"entitlement_build": true}', encoding="utf-8")
    second = tmp_path / "home-b" / "entitlement"
    second.mkdir(parents=True)
    (second / "fixture-gate.json").write_text('{"entitlement_build": true}', encoding="utf-8")

    clear_gate_status_cache()
    monkeypatch.setenv("KSCOPE_ENTITLEMENT_HOME", str(first))
    a = gate_status(str(fake_binary))
    monkeypatch.setenv("KSCOPE_ENTITLEMENT_HOME", str(second))
    b = gate_status(str(fake_binary))

    assert a.enforcing is True and b.enforcing is True
    assert a.key_file == str(first / "api-key")
    assert b.key_file == str(second / "api-key"), (
        "the second configuration was served the first configuration's memo entry"
    )
    assert a.key_file != b.key_file


@pytest.mark.asyncio
async def test_a_stale_gate_memo_cannot_name_the_wrong_key_file_in_a_refusal(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The user-visible half of the test above, driven through a real spawn."""

    _clear_entitlement_environment(monkeypatch)
    first = tmp_path / "home-a" / "entitlement"
    first.mkdir(parents=True)
    (first / "fixture-gate.json").write_text('{"entitlement_build": true}', encoding="utf-8")
    second = tmp_path / "home-b" / "entitlement"
    second.mkdir(parents=True)
    (second / "fixture-gate.json").write_text('{"entitlement_build": true}', encoding="utf-8")

    clear_gate_status_cache()
    monkeypatch.setenv("KSCOPE_ENTITLEMENT_HOME", str(first))
    gate_status(str(fake_binary))  # warm the memo under the first home

    monkeypatch.setenv("KSCOPE_ENTITLEMENT_HOME", str(second))
    profile = f"stale.{_nonce()}"
    descriptor = load_launch_descriptor(fake_binary, profile)
    with pytest.raises(EntitlementError) as caught:
        async with PersistentKaleidoscopeSession(descriptor):
            pass

    assert caught.value.reason == "E_NO_KEY"
    assert caught.value.key_file == str(second / "api-key")
    assert str(first) not in str(caught.value), (
        "the refusal named a key file under a home the user never configured"
    )


# ---------------------------------------------------------------------------
# A15 - presence and the spawn agree about the API key
# ---------------------------------------------------------------------------


def test_presence_agrees_with_the_spawn_on_a_shellshock_shaped_key(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A value the allowlist drops must not be counted as present.

    `safe_bootstrap_environment` drops values beginning with `()`, so such a key
    never reaches the child. `key_is_present` read `os.environ` directly and said
    "set" anyway: the SDK spawned, the engine saw no key at all, and told the
    user to set a variable they HAD set. The two now read the same source, so
    the disagreement is unrepresentable rather than merely fixed.

    This is emphatically NOT the SDK judging the key. It judges nothing about
    the value; it asks only "will the child receive this", which is a fact about
    the SDK's own allowlist, not about the credential.
    """

    _clear_entitlement_environment(monkeypatch)
    directory = _entitlement_home(monkeypatch, tmp_path)
    monkeypatch.setenv("KALEIDOSCOPE_API_KEY", "() { :; }; echo shellshock")

    status = gate_status(str(fake_binary))
    assert status.enforcing is True
    assert "KALEIDOSCOPE_API_KEY" not in safe_bootstrap_environment()
    assert key_is_present(status) is False, (
        "presence said set for a value the spawn drops"
    )
    with pytest.raises(EntitlementError) as caught:
        entitlement_preflight(str(fake_binary))
    assert caught.value.reason == "E_NO_KEY"
    assert caught.value.key_file == str(directory / "api-key")


def test_a_normal_key_is_still_present(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The falsifier for the test above: presence must not have become False."""

    _clear_entitlement_environment(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path)
    monkeypatch.setenv("KALEIDOSCOPE_API_KEY", "ksk_alpha." + "Q" * 43)
    status = gate_status(str(fake_binary))
    assert key_is_present(status) is True
    entitlement_preflight(str(fake_binary))  # must not raise


# ---------------------------------------------------------------------------
# A16 - the stderr drain is bounded in MEMORY, not merely in what it reports
# ---------------------------------------------------------------------------


def test_the_stderr_drain_reads_a_bounded_tail_not_the_whole_file() -> None:
    """A flooding child must not be able to size the parent's memory.

    `_drain_errlog_and_classify` did `errlog.read()` on the whole temporary
    file, and `_bounded_diagnostic` then decoded a second full copy, so the
    parent's peak RSS tracked the child's stderr at roughly 2x. Measured on this
    instrument: a 400 MB stderr grew the parent by **800.1 MB** before the fix
    and by **0.0 MB** after, and BOTH forms returned the correct `E_REVOKED`
    with a full 4,095-byte diagnostic -- so nothing about the outcome looked
    wrong either way. The comment above the call even asserted "the practical
    bound is under a kilobyte", which was an expectation about a well-behaved
    engine standing in for a bound.

    The assertion is on BYTES READ rather than on RSS: RSS is noisy, allocator-
    dependent and not portable, and a test that measures it would be flaky in
    exactly the direction that gets it deleted. The file object counts reads
    instead, which is the mechanism itself.

    The marker assertion is the other half. A bounded read that lost the
    discriminator would be a refusal spelled as no refusal at all, and the tail
    is sound only because the marker is the LAST line by contract.
    """

    import tempfile as _tempfile

    from kaleidoscope_memory.session import PersistentKaleidoscopeSession

    flood = 8 * 1024 * 1024
    handle = _tempfile.TemporaryFile(mode="w+b")
    handle.write(b"x" * flood)
    handle.write(b"\nkscope-entitlement-refusal: E_REVOKED\n")
    handle.flush()

    read_total = 0
    real_read = handle.read

    def counting_read(*arguments: object) -> bytes:
        nonlocal read_total
        data = real_read(*arguments)  # type: ignore[arg-type]
        read_total += len(data)
        return data

    handle.read = counting_read  # type: ignore[method-assign]

    session = PersistentKaleidoscopeSession.__new__(PersistentKaleidoscopeSession)
    session._diagnostic = ""
    session._errlog = handle

    reason = session._drain_errlog_and_classify()

    assert reason == "E_REVOKED", "the bounded read lost the marker"
    assert read_total <= _MAX_DIAGNOSTIC_BYTES, (
        f"the drain read {read_total} bytes of an {flood} byte stderr; "
        f"it must read at most the last {_MAX_DIAGNOSTIC_BYTES}"
    )
    # Non-vacuous: it did read something, and the diagnostic is real content.
    assert read_total > 0
    assert session._diagnostic


# ---------------------------------------------------------------------------
# The allowlist's argument, and the fact that it says one thing in two languages
# ---------------------------------------------------------------------------
#
# The comment above `_ENTITLEMENT_ENV_KEYS` is not decoration. It is the reason
# the list is two names rather than three, and it is the only thing standing
# between a future reader and re-adding the third by arguing the category. Two
# copies of that argument -- one per language -- is two copies that can drift,
# and one of them already had.

_SDK_ROOT = Path(__file__).parents[2]
_PY_DESCRIPTOR = _SDK_ROOT / "python" / "src" / "kaleidoscope_memory" / "descriptor.py"
_TS_DESCRIPTOR = _SDK_ROOT / "typescript" / "src" / "descriptor.ts"

#: The three names the comment must reject, each for its own reason.
_REJECTED_NAMES = (
    "KSCOPE_ENTITLEMENT_PROBE",
    "KALEIDOSCOPE_CONTROL_PLANE_ORIGIN",
    "KSCOPE_PROFILE_HOME",
)


def _python_comment_above(anchor: str) -> list[str]:
    """The `#:` block immediately above a definition, markers stripped."""

    lines = _PY_DESCRIPTOR.read_text(encoding="utf-8").splitlines()
    index = next(i for i, line in enumerate(lines) if line.startswith(anchor))
    block: list[str] = []
    while index > 0 and lines[index - 1].startswith("#:"):
        index -= 1
        block.append(lines[index][2:].lstrip(" ") if lines[index][2:] else "")
    return list(reversed(block))


def _typescript_comment_above(anchor: str) -> list[str]:
    """The `/** ... */` block immediately above a declaration, markers stripped."""

    lines = _TS_DESCRIPTOR.read_text(encoding="utf-8").splitlines()
    index = next(i for i, line in enumerate(lines) if line.startswith(anchor))
    end = index - 1
    assert lines[end].strip() == "*/", f"no block comment above {anchor!r}"
    start = end
    while lines[start].strip() != "/**":
        start -= 1
    block = []
    for line in lines[start + 1 : end]:
        stripped = line.strip()
        assert stripped.startswith("*"), f"unexpected line in block comment: {line!r}"
        block.append(stripped[1:].lstrip(" ") if stripped[1:] else "")
    return block


def test_the_entitlement_comment_is_identical_in_both_languages() -> None:
    """One argument, written once, rendered twice.

    Before this test the two copies had already diverged: the Python one named
    both canaries and the TypeScript one named a single canary, so a reader of
    the TypeScript SDK was shown a weaker version of the reason a prefix rule is
    forbidden. Nothing failed. Nothing could.
    """

    python_block = _python_comment_above("_ENTITLEMENT_ENV_KEYS = (")
    typescript_block = _typescript_comment_above("export const ENTITLEMENT_ENVIRONMENT_KEYS")

    # Non-vacuous: two empty blocks are trivially equal, and a comment deleted
    # from both files would pass an equality assertion on its own.
    assert len(python_block) > 30, f"the Python comment shrank to {len(python_block)} lines"
    assert len(typescript_block) > 30, (
        f"the TypeScript comment shrank to {len(typescript_block)} lines"
    )
    assert python_block == typescript_block, (
        "the entitlement allowlist's argument has drifted between the two SDKs"
    )


def test_the_bootstrap_docstring_says_the_same_thing_in_both_languages() -> None:
    """The same convergence for the function the allowlist feeds.

    Three tokens are legitimately language-specific -- the two constant names and
    the word for the container they are written in -- so those are normalised
    away, and paragraph line-wrapping with them. Everything that survives that
    normalisation is content, and content may not differ.
    """

    def normalise(text: str) -> str:
        for token in (
            "_BOOTSTRAP_ENV_KEYS",
            "BOOTSTRAP_ENVIRONMENT_KEYS",
            "_ENTITLEMENT_ENV_KEYS",
            "ENTITLEMENT_ENVIRONMENT_KEYS",
            # The allowlist's own name, and the two language-specific spellings
            # of "this process's environment" and of the key parameter. Each is
            # a name for the same thing in the two languages; normalising them
            # is what leaves only CONTENT to compare, which is the point.
            "_SAFE_ENV_KEYS",
            "SAFE_ENVIRONMENT_KEYS",
        ):
            text = text.replace(token, "<the list>")
        text = text.replace("os.environ", "<the process environment>")
        text = text.replace("process.env", "<the process environment>")
        text = text.replace("apiKey", "api_key")
        return " ".join(text.replace("tuples", "lists").replace("arrays", "lists").split())

    python_source = _PY_DESCRIPTOR.read_text(encoding="utf-8")
    start = python_source.index('"""Build the child environment')
    python_doc = python_source[start + 3 : python_source.index('"""', start + 3)]

    typescript_block = _typescript_comment_above("export function safeBootstrapEnvironment")

    normalised_python = normalise(python_doc)
    normalised_typescript = normalise("\n".join(typescript_block))

    assert len(normalised_python) > 400, "the Python docstring shrank"
    assert normalised_python == normalised_typescript, (
        "the bootstrap allowlist's promise has drifted between the two SDKs"
    )


def test_the_allowlist_is_two_names_and_the_comment_states_the_count_correctly() -> None:
    """The stale count is exactly how a fourth name once survived.

    Both descriptors said "the three alpha entitlement variables" while the list
    held two, and the README said twenty-one against an asserted twenty. A
    sentence that miscounts the thing it sits above is a sentence nobody is
    reading, and the name it fails to account for is the name nobody removes.
    """

    assert len(_ENTITLEMENT_ENV_KEYS) == 2
    assert len(_SAFE_ENV_KEYS) == len(_BOOTSTRAP_ENV_KEYS) + 2

    comment = "\n".join(_python_comment_above("_ENTITLEMENT_ENV_KEYS = ("))
    assert "Two names pass" in comment
    assert "three alpha" not in comment.lower()
    for name in _ENTITLEMENT_ENV_KEYS:
        assert name in comment, f"{name} is admitted and the comment does not justify it"


def test_each_rejected_name_is_refused_for_its_own_stated_reason() -> None:
    """The load-bearing half of the argument, and the half easiest to lose.

    "Not admitted" has to be a conclusion reached per name. If the three reasons
    were one reason repeated, a reader could readmit any of them by defeating the
    category once -- which is how the control-plane name got in the first time.
    """

    comment = "\n".join(_python_comment_above("_ENTITLEMENT_ENV_KEYS = ("))
    never_admitted = set(GOLDEN["never_admitted"])

    # Scoped to the refusal section on purpose: one of the three also appears
    # further up as a canary, and reading a reason from there would report a
    # sentence about something else as this name's justification.
    marker = "Three names that look like they belong here and do not."
    assert marker in comment, "the refusal section has been retitled or removed"
    refusals = comment.split(marker, 1)[1]

    reasons: dict[str, str] = {}
    for name in _REJECTED_NAMES:
        assert name in never_admitted, f"{name} is not in the published contract's refusals"
        assert name in refusals, f"{name} is refused and the comment does not say why"
        after = refusals.split(name, 1)[1]
        # The reason runs to the next blank line; the block is one bullet each.
        reasons[name] = after.split("\n\n")[0].strip()
        assert len(reasons[name]) > 80, f"{name}'s reason is too short to be one"

    distinct = {reason for reason in reasons.values()}
    assert len(distinct) == len(_REJECTED_NAMES), (
        "two of the three refusals share a reason; the per-name argument is gone"
    )
