"""The programmatic API key: where it goes, and every place it must not.

Every test here either makes the mechanism fire or makes a refusal fire, and
every negative assertion ("the decoy did not reach the child", "the key is not
in argv") is paired with a positive one on real content in the SAME assertion.
A negative pass condition fails hardest when the check itself is broken: a child
that received NOTHING would pass a decoy-only test, so the positive control has
to be inside the test that claims the decoy was blocked.

The other rule this module is written to: the SDK is never an authority on
whether a key is GOOD. `test_a_malformed_code_key_is_refused_there_not_here` is
the test that would go red if somebody added a local shape check, and it is red
for the right reason -- it asserts the child STARTED, not merely that an error
came back.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import json
import logging
import os
import subprocess
import sys
import tempfile
import traceback
import uuid
from pathlib import Path

import pytest

from kaleidoscope_memory import KaleidoscopeMemory
from kaleidoscope_memory.descriptor import (
    _BOOTSTRAP_ENV_KEYS,
    _ENTITLEMENT_ENV_KEYS,
    _SAFE_ENV_KEYS,
    API_KEY_VARIABLE,
    LaunchDescriptor,
    _bounded_diagnostic,
    _ungated_environment,
    _validated_api_key,
    hold_api_key,
    load_launch_descriptor,
    safe_bootstrap_environment,
)
from kaleidoscope_memory.entitlement import (
    GateStatus,
    _gate_status_cached,
    clear_gate_status_cache,
    entitlement_preflight,
    gate_status,
    key_is_present,
)
from kaleidoscope_memory.errors import DescriptorError, EntitlementError
from kaleidoscope_memory.manager import ManagerAccountClient, ManagerAccountCommand
from kaleidoscope_memory.session import PersistentKaleidoscopeSession

ROOT = Path(__file__).parents[2]
REFERENCE = ROOT / "reference"
GOLDEN = json.loads((REFERENCE / "entitlement-contract-v1.json").read_text())
PACKAGE = Path(__file__).parents[1] / "src" / "kaleidoscope_memory"
FAKE_MANAGER = Path(__file__).parent / "fixtures" / "fake_manager.py"
#: The fixtures write their record inside a directory the allowlist DOES
#: forward, because a variable of the record's own could not reach them -- see
#: the comment on `record_environment` in tests/fixtures/fake_kscope_mcp.py.
RECORD_NAME = "fixture-environment.jsonl"

#: Obviously not a secret. Shaped like an alpha key so the fixture's own
#: well-formedness check accepts it, and identical to the fixture's `expected`.
VALID_KEY = "ksk_alpha." + "A" * 43
#: A DIFFERENT well-formed key, for the precedence tests. The fixture compares
#: against VALID_KEY, so "the ambient one won" and "the code one won" produce
#: different answers rather than the same one twice.
OTHER_KEY = "ksk_alpha." + "B" * 43
MALFORMED_KEY = "ksk_alpha.short"
#: Key-SHAPED and issued by nobody, assembled from fragments so that this file
#: does not trip `scripts/poison_scan.py`'s credential-shape rule -- which it
#: did, on the first run after that rule was added. The scanner is a shape rule
#: and correctly does not care that this one is synthetic; every other plant in
#: this suite is fragmented for the same reason.
SHAPED_NON_KEY = "ksk" + "_alpha." + "NOT_A_REAL_KEY_AT_ALL_1234567890"

_KALEIDOSCOPE_LIKE = ("KALEIDOSCOPE_", "KSCOPE_")

#: Real names of real secrets a developer's shell is likely to hold. Every one
#: is in the shared contract's `never_admitted` list.
DECOYS = {
    "OPENAI_API_KEY": "decoy-openai",
    "AZURE_OPENAI_API_KEY": "decoy-azure",
    "SUPABASE_SECRET_KEY": "decoy-supabase",
    "ANTHROPIC_API_KEY": "decoy-anthropic",
    "AWS_SECRET_ACCESS_KEY": "decoy-aws",
    "KALEIDOSCOPE_TEST_SECRET": "must-not-reach-child",
    "KSCOPE_ENTITLEMENT_PROBE": "/tmp/decoy-probe",
    "KALEIDOSCOPE_CONTROL_PLANE_ORIGIN": "https://decoy.invalid/",
    "KSCOPE_PROFILE_HOME": "/tmp/decoy-profile-home",
}


def _nonce() -> str:
    return uuid.uuid4().hex[:8]


def _spawn_marker(profile: str) -> Path:
    return Path(tempfile.gettempdir()) / f"kscope-fixture-{profile}.starts"


def _runtime_injected_names() -> set[str]:
    """Names a freshly exec'd child gives itself, whatever environment it got."""

    completed = subprocess.run(
        [sys.executable, "-c", "import os, json; print(json.dumps(sorted(os.environ)))"],
        check=True,
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", "")},
    )
    return set(json.loads(completed.stdout)) - {"PATH"}


def _clear(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if name.startswith(_KALEIDOSCOPE_LIKE):
            monkeypatch.delenv(name, raising=False)


def _entitlement_home(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, enforcing: bool = True
) -> Path:
    directory = tmp_path / "entitlement"
    directory.mkdir(parents=True, exist_ok=True)
    if enforcing:
        (directory / "fixture-gate.json").write_text(
            json.dumps({"entitlement_build": True}), encoding="utf-8"
        )
    monkeypatch.setenv("KSCOPE_ENTITLEMENT_HOME", str(directory))
    clear_gate_status_cache()
    return directory


async def _report(descriptor: LaunchDescriptor, **kwargs: object) -> dict:
    async with PersistentKaleidoscopeSession(descriptor, **kwargs) as memory:  # type: ignore[arg-type]
        return json.loads(await memory.search_text({"query": "__environment__"}))


def _records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


# ---------------------------------------------------------------------------
# T-A1..T-A3, T-A5 -- the key reaches the child, and only the key does
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_code_key_reaches_the_child_with_the_environment_cleared(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Both halves in one assertion, because either alone passes a broken build.

    A build that delivered nothing fails `api_key_matches`. A build that
    delivered the key by WIDENING the door passes that and fails the second
    assertion, which bounds the child's whole environment by the allowlist.
    """

    _clear(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path)
    assert API_KEY_VARIABLE not in os.environ

    descriptor = load_launch_descriptor(fake_binary, f"gated.{_nonce()}")
    report = await _report(descriptor, api_key=VALID_KEY)

    assert report["api_key_matches"] is True
    assert report["api_key_length"] == len(VALID_KEY), "the key arrived truncated"
    delivered = set(report["environment_names"]) - _runtime_injected_names()
    assert delivered <= set(_SAFE_ENV_KEYS), sorted(delivered - set(_SAFE_ENV_KEYS))


@pytest.mark.asyncio
async def test_a_code_key_beats_an_ambient_one_and_the_environment_still_works(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Fails in BOTH directions, which a one-sided test cannot.

    An implementation that always used the code key -- including when it is
    None -- passes case one and fails case two. An implementation that ignored
    the code key fails case one.
    """

    _clear(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path)

    monkeypatch.setenv(API_KEY_VARIABLE, OTHER_KEY)
    descriptor = load_launch_descriptor(fake_binary, f"gated.{_nonce()}")
    assert (await _report(descriptor, api_key=VALID_KEY))["api_key_matches"] is True

    monkeypatch.setenv(API_KEY_VARIABLE, VALID_KEY)
    clear_gate_status_cache()
    assert (await _report(descriptor, api_key=None))["api_key_matches"] is True

    monkeypatch.setenv(API_KEY_VARIABLE, OTHER_KEY)
    clear_gate_status_cache()
    inherited = await _report(descriptor, api_key=None)
    assert inherited["api_key_seen"] is True
    assert inherited["api_key_matches"] is False, "the ambient key was not the one used"


def test_no_key_supplied_reproduces_todays_environment_byte_for_byte(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two dicts compared, not "did not raise".

    Randomised over every allowlisted name set and unset, plus the `()` values
    the shellshock predicate drops, so a regression that made the `api_key=None`
    path take a different branch shows up as a diff rather than as nothing.
    """

    for index, name in enumerate(_SAFE_ENV_KEYS):
        if index % 3 == 0:
            monkeypatch.delenv(name, raising=False)
        elif index % 3 == 1:
            monkeypatch.setenv(name, f"value-{index}")
        else:
            monkeypatch.setenv(name, "() { :; }; echo shellshock")

    assert safe_bootstrap_environment() == safe_bootstrap_environment(api_key=None)


def test_the_allowlist_did_not_grow() -> None:
    assert len(_SAFE_ENV_KEYS) == 20
    assert tuple(_SAFE_ENV_KEYS) == tuple(
        GOLDEN["bootstrap_environment"] + GOLDEN["entitlement_environment"]
    )
    assert API_KEY_VARIABLE in _ENTITLEMENT_ENV_KEYS
    assert len(_BOOTSTRAP_ENV_KEYS) == 18


@pytest.mark.asyncio
async def test_a_decoy_secret_in_the_environment_never_reaches_the_child(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Nine real secret names, with the positive control in the same test.

    A child that received NOTHING would pass a decoy-only assertion, so
    `api_key_matches` is asserted here too: "the decoy was blocked" and "the key
    arrived" have to hold together, or the result is indistinguishable from a
    spawn that never happened.
    """

    _clear(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path)
    for name, value in DECOYS.items():
        monkeypatch.setenv(name, value)
    clear_gate_status_cache()

    descriptor = load_launch_descriptor(fake_binary, f"gated.{_nonce()}")
    report = await _report(descriptor, api_key=VALID_KEY)

    assert report["api_key_matches"] is True, "positive control: nothing arrived at all"
    assert report["secret"] == "absent"
    delivered = set(report["environment_names"])
    for name in DECOYS:
        assert name not in delivered, name
    for name in GOLDEN["never_admitted"]:
        assert name not in delivered, name


# ---------------------------------------------------------------------------
# T-A6..T-A8 -- refused THERE, not HERE
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_malformed_code_key_is_refused_there_not_here(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The guard against this whole design becoming validation theatre.

    The spawn marker is the discriminator. An SDK that grew a local shape check
    would raise BEFORE the child ran, the marker would be absent, and this test
    would fail -- which is the only way to tell "the engine refused it" from
    "the SDK decided it was bad", since both surface as an exception.
    """

    _clear(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path)
    profile = f"gated.{_nonce()}"
    marker = _spawn_marker(profile)
    marker.unlink(missing_ok=True)

    descriptor = load_launch_descriptor(fake_binary, profile)
    with pytest.raises(EntitlementError) as caught:
        await _report(descriptor, api_key=MALFORMED_KEY)

    assert marker.exists(), "the SDK refused before the engine ever ran"
    assert caught.value.reason == "E_MALFORMED_KEY"
    marker.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_a_shellshock_shaped_code_key_reaches_the_child_verbatim(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Which refusal comes back is the assertion, not whether one does.

    The `()` predicate exists to stop an INHERITED exported function definition
    being laundered into a child; it must not apply to a value the caller handed
    over as a string. Dropped, the engine would answer E_NO_KEY for a key that
    was supplied. Delivered, it answers E_MALFORMED_KEY. Two identifiers, so the
    test can tell the two apart.
    """

    _clear(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path)
    shellshock = "() { :; }; " + MALFORMED_KEY

    assert API_KEY_VARIABLE in safe_bootstrap_environment(api_key=shellshock)

    descriptor = load_launch_descriptor(fake_binary, f"gated.{_nonce()}")
    with pytest.raises(EntitlementError) as caught:
        await _report(descriptor, api_key=shellshock)
    assert caught.value.reason == "E_MALFORMED_KEY", (
        "E_NO_KEY here would mean the value was silently dropped on the way out"
    )


@pytest.mark.parametrize("value", ["", "   ", "\t\n "])
def test_an_empty_code_key_is_a_usage_error_not_a_fallback(
    value: str, fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An implementation that fell back to the environment would SUCCEED here."""

    _clear(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path)
    monkeypatch.setenv(API_KEY_VARIABLE, VALID_KEY)
    profile = f"gated.{_nonce()}"
    marker = _spawn_marker(profile)
    marker.unlink(missing_ok=True)

    with pytest.raises(DescriptorError, match="empty"):
        KaleidoscopeMemory(binary=fake_binary, profile=profile, api_key=value)

    assert not marker.exists(), "a child was spawned for an argument error"


@pytest.mark.parametrize("value", ["ksk_alpha.a\nb", "ksk_alpha.a\x00b", "ksk_alpha.a\rb"])
def test_a_key_that_cannot_ride_in_an_environment_variable_is_refused(
    value: str, fake_binary: Path
) -> None:
    """Transport, not validity. A NUL cannot be put in an environment block."""

    with pytest.raises(DescriptorError, match="newline or NUL"):
        KaleidoscopeMemory(binary=fake_binary, api_key=value)


def test_the_sdk_still_performs_no_validity_check() -> None:
    """The falsifier for every refusal above.

    Each of these is well formed as far as transport is concerned and absurd as
    a key. The SDK accepts all of them, because deciding is the engine's job.
    """

    for absurd in ("x", "not-a-key", "ksk_alpha.", "K" * 4096, "ksk_beta.whatever"):
        assert _validated_api_key(absurd) == absurd


# ---------------------------------------------------------------------------
# T-A9..T-A11 -- the ungated children
# ---------------------------------------------------------------------------


def test_the_ungated_environment_is_a_strict_subset(monkeypatch: pytest.MonkeyPatch) -> None:
    """A set comparison. A second hand-written allowlist would not be a subset."""

    for name in _SAFE_ENV_KEYS:
        monkeypatch.setenv(name, "set")

    ungated = set(_ungated_environment())
    full = set(safe_bootstrap_environment())

    assert ungated < full
    assert full - ungated == {API_KEY_VARIABLE}
    assert API_KEY_VARIABLE not in _ungated_environment()


def test_the_ungated_children_never_see_the_api_key(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Recorded from inside three real children, with a positive control each.

    Removing the whole entitlement group would pass the first assertion and fail
    the second: KSCOPE_ENTITLEMENT_HOME must still arrive, because it is what
    tells the engine where the key file lives, and an ungated child that lost it
    would resolve a different entitlement directory from a gated one.
    """

    _clear(monkeypatch)
    directory = _entitlement_home(monkeypatch, tmp_path)
    monkeypatch.setenv(API_KEY_VARIABLE, VALID_KEY)
    record = directory / RECORD_NAME
    clear_gate_status_cache()

    status = gate_status(str(fake_binary))
    assert status.enforcing is True
    load_launch_descriptor(fake_binary, "ungated-probe")
    from kaleidoscope_memory.native import load_profile

    load_profile(fake_binary, "ungated-probe")

    seen = _records(record)
    assert {row["command"] for row in seen} == {"gate", "profile_launch", "profile_show"}
    for row in seen:
        assert row["api_key_seen"] is False, row["command"]
        assert API_KEY_VARIABLE not in row["environment_names"], row["command"]
        assert "KSCOPE_ENTITLEMENT_HOME" in row["environment_names"], row["command"]
    assert str(directory) == os.environ["KSCOPE_ENTITLEMENT_HOME"]


def test_the_manager_child_never_sees_the_api_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Same structure, other binary, with the manager's own names as the control."""

    FAKE_MANAGER.chmod(0o755)
    _clear(monkeypatch)
    monkeypatch.setenv(API_KEY_VARIABLE, VALID_KEY)
    config_home = tmp_path / "config"
    config_home.mkdir()
    monkeypatch.setenv("KALEIDOSCOPE_CONFIG_HOME", str(config_home))
    record = config_home / RECORD_NAME
    account = {
        "KALEIDOSCOPE_ACCOUNT_ORIGIN": "https://account.example.invalid/",
        "KALEIDOSCOPE_ACCOUNT_ISSUER": "https://issuer.example.invalid/",
        "KALEIDOSCOPE_ACCOUNT_AUDIENCE": "kaleidoscope-fixture",
        "KALEIDOSCOPE_ACCOUNT_CLIENT_ID": "kaleidoscope-native-fixture",
    }

    client = ManagerAccountClient(FAKE_MANAGER.resolve(), account_environment=account)
    client.invoke(ManagerAccountCommand.status())

    (row,) = _records(record)
    assert row["api_key_seen"] is False
    assert API_KEY_VARIABLE not in row["environment_names"]
    for name in account:
        assert name in row["environment_names"], name
    assert "KALEIDOSCOPE_CONFIG_HOME" in row["environment_names"]


# ---------------------------------------------------------------------------
# T-A12..T-A16 -- the routes the key must never take
# ---------------------------------------------------------------------------


def test_every_environment_call_site_is_gated_or_threads_the_key() -> None:
    """An AST walk, so a call site added later fails here rather than shipping.

    This is where the tool API and the key meet. If `api_key=` threads through
    the session but a framework binding still calls the nullary form, the
    parameter works for a direct session and silently does nothing for CrewAI --
    one API wearing two behaviours, with nothing that looks wrong.

    `_ungated_environment` is the OTHER legal answer, and it is legal precisely
    because it cannot carry a key.
    """

    gated_names = {"safe_bootstrap_environment", "_safe_process_environment"}
    #: The one legal nullary call. It is legal because the next statement in
    #: that function removes the credential, so the call cannot deliver one.
    #: Named as a FUNCTION rather than as a line number: pinning the line would
    #: make this test fail on an unrelated edit above it, and a test that cries
    #: wolf gets its expectation updated rather than read.
    exempt = ("descriptor.py", "_ungated_environment")

    offenders: list[str] = []
    checked = 0
    for path in sorted(PACKAGE.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        # Every node's nearest enclosing def, computed once. A call at MODULE
        # level gets "<module>" rather than being skipped -- a nullary call
        # there is the one an "enclosing function" walk would silently miss,
        # and a check with a blind spot is worse than no check.
        enclosing: dict[int, str] = {}
        for parent in ast.walk(tree):
            label = (
                parent.name
                if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))
                else None
            )
            for child in ast.iter_child_nodes(parent):
                enclosing[id(child)] = label or enclosing.get(id(parent), "<module>")

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            name = (
                function.id if isinstance(function, ast.Name) else getattr(function, "attr", "")
            )
            if name not in gated_names:
                continue
            checked += 1
            if any(keyword.arg == "api_key" for keyword in node.keywords):
                continue
            where = enclosing.get(id(node), "<module>")
            if (path.name, where) == exempt:
                continue
            offenders.append(f"{path.name}:{where}:{node.lineno}")

    assert checked >= 4, "the walk found almost no call sites; it is not looking"
    assert offenders == [], offenders


@pytest.mark.asyncio
async def test_the_key_never_appears_in_any_child_argv(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The same report proves the child ran AND got the key by the other route."""

    _clear(monkeypatch)
    directory = _entitlement_home(monkeypatch, tmp_path)
    record = directory / RECORD_NAME
    clear_gate_status_cache()

    descriptor = load_launch_descriptor(fake_binary, f"gated.{_nonce()}")
    report = await _report(descriptor, api_key=VALID_KEY)

    assert report["api_key_matches"] is True, "positive control"
    everything = list(report["argv"]) + [
        entry for row in _records(record) for entry in row["argv"]
    ]
    assert everything, "no argv was captured, so this test proved nothing"
    for entry in everything:
        assert VALID_KEY not in entry
        assert VALID_KEY[:12] not in entry


@pytest.mark.asyncio
async def test_constructing_with_a_key_does_not_mutate_os_environ(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Dict equality before and after a real open, not absence-of-error.

    `os.environ[...] = key` is process-global: it would leak the key to every
    OTHER child the caller's process spawns, which is the exact class the
    allowlist exists to prevent.
    """

    _clear(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path)
    before = dict(os.environ)

    descriptor = load_launch_descriptor(fake_binary, f"gated.{_nonce()}")
    report = await _report(descriptor, api_key=VALID_KEY)

    assert report["api_key_matches"] is True, "positive control"
    assert dict(os.environ) == before


def test_gate_status_cache_signature_carries_no_key() -> None:
    """`lru_cache` retains argument tuples for the life of the process."""

    parameters = tuple(inspect.signature(_gate_status_cached.__wrapped__).parameters)
    assert parameters == ("command", "mtime_ns", "size", "directory")
    assert tuple(inspect.signature(gate_status).parameters) == ("command",)


def test_launch_descriptor_environment_is_still_exactly_empty(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`as_dict()` is what a host config renderer serialises into a user file."""

    _clear(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path)
    memory = KaleidoscopeMemory(binary=fake_binary, profile="descriptor", api_key=VALID_KEY)

    descriptor = memory.descriptor

    assert descriptor.environment == {}
    assert descriptor.as_dict()["environment"] == {}
    rendered = json.dumps(dataclasses.asdict(descriptor))
    assert VALID_KEY not in rendered and VALID_KEY[:12] not in rendered


def test_no_repr_surface_reveals_the_key(fake_binary: Path) -> None:
    """Six real rendering surfaces.

    This used to end with a seventh: `raise ValueError(f"boom {secret!r}")`
    caught and rendered with `traceback.format_exc()`. That assertion could not
    fail for two independent reasons -- `format_exc()` never renders frame
    locals at all, and the exception was raised in THIS frame, which never holds
    the plaintext. It passed while the key was live in
    `session.__aenter__`'s locals. The frame-locals property now has its own
    tests below, driven through the real connect, with a control that proves the
    instrument can see a key that IS there.
    """

    memory = KaleidoscopeMemory(binary=fake_binary, api_key=VALID_KEY)
    session = PersistentKaleidoscopeSession.__new__(PersistentKaleidoscopeSession)
    session._api_key = hold_api_key(VALID_KEY)  # type: ignore[attr-defined]
    secret = hold_api_key(VALID_KEY)
    assert secret is not None

    surfaces = [
        repr(memory),
        str(memory),
        repr(vars(memory)),
        f"{secret!r} {secret!s} {secret}",
        repr(GateStatus(enforcing=True, key_file="/tmp/api-key")),
        repr(vars(session)),
    ]

    for rendered in surfaces:
        assert VALID_KEY not in rendered, rendered[:200]
        assert VALID_KEY[:12] not in rendered, rendered[:200]

    # The falsifier: a wrapper that had simply lost the value would pass every
    # assertion above.
    assert secret.reveal() == VALID_KEY
    # Identity comparison, so nothing leaks by an accidental `==` to a str.
    assert secret != VALID_KEY
    assert secret == secret


def _locals_rendering(exc: BaseException) -> str:
    """The surface `pytest --showlocals` and Sentry's default both produce.

    `traceback.format_exc()` is NOT that surface -- it never renders locals --
    which is why the test this replaces could not observe the property it named.
    """

    return "".join(
        traceback.TracebackException.from_exception(exc, capture_locals=True).format()
    )


def _sdk_frames_only(rendered: str) -> str:
    """Drop the frames belonging to this test file.

    The probe deliberately holds the key in its own local so that the control
    below can fire; the claim is about the SDK's frames, so the test's own are
    excluded here rather than the probe being weakened.
    """

    kept: list[str] = []
    in_test_frame = False
    for line in rendered.splitlines():
        stripped = line.strip()
        if stripped.startswith('File "'):
            in_test_frame = __file__ in stripped
        if not in_test_frame:
            kept.append(line)
    return "\n".join(kept)


def test_a_failed_connect_puts_the_key_in_no_sdk_frame_local(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The accident `_Secret` exists to prevent, driven through the real connect.

    `startupfail.` makes the child exit non-zero AFTER recording that it
    started, so the exception is raised with `session.__aenter__` -- and the MCP
    SDK's `stdio_client` frame, which holds the parameters object for the whole
    session -- still on the stack. Before the fix, `key` and `parameters` both
    rendered the credential here.
    """

    _clear(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path)
    profile = f"startupfail.{_nonce()}"

    with pytest.raises(BaseException) as caught:  # noqa: PT011 - any failure will do
        with KaleidoscopeMemory(binary=fake_binary, profile=profile, api_key=VALID_KEY):
            pass  # pragma: no cover - the connect never succeeds

    rendered = _sdk_frames_only(_locals_rendering(caught.value))

    # Positive control INSIDE the negative test: the probe really did walk SDK
    # frames that held the session, so an empty rendering cannot pass this.
    assert "session.py" in rendered, rendered[:400]
    assert VALID_KEY not in rendered, rendered[:2000]
    assert VALID_KEY[:20] not in rendered, rendered[:2000]
    # The child really started, so this is a connect that got as far as spawning.
    assert _spawn_marker(profile).exists()


def test_the_frame_local_probe_can_see_a_key_that_is_there() -> None:
    """The control. Without it, the test above is a probe that cannot succeed.

    A frame that binds the plaintext to a name is exactly what
    `session.__aenter__` used to do. If `capture_locals` could not see it, the
    test above would pass on a broken instrument.
    """

    def frame_that_binds_the_key() -> None:
        key = hold_api_key(VALID_KEY).reveal()  # type: ignore[union-attr]
        assert key
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError) as caught:
        frame_that_binds_the_key()

    assert VALID_KEY in _locals_rendering(caught.value)


def test_a_failed_native_call_puts_the_key_in_no_sdk_frame_local(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`native._call`'s retry loop is the second frame that outlives an await."""

    import asyncio

    from kaleidoscope_memory.native import _NativeCaller

    _clear(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path)
    descriptor = LaunchDescriptor(
        version=1,
        transport="stdio",
        command=str(fake_binary),
        args=("mcp", "--profile", f"refusal.E_REVOKED.{_nonce()}"),
        tools=("search", "remember"),
        environment={},
    )
    caller = _NativeCaller(descriptor, api_key=VALID_KEY, timeout_seconds=10.0, attempts=1)

    with pytest.raises(BaseException) as caught:  # noqa: PT011
        # `_fixture_mode: refuse` makes the child exit non-zero after it has
        # started, so the failure is raised with `_call`'s frame -- and its
        # retry loop -- still live.
        asyncio.run(caller._call("search", {"_fixture_mode": "refuse"}))

    rendered = _sdk_frames_only(_locals_rendering(caught.value))
    assert "native.py" in rendered, rendered[:400]
    assert VALID_KEY not in rendered, rendered[:2000]
    assert VALID_KEY[:20] not in rendered, rendered[:2000]


def test_mcp_server_config_carries_the_key_and_does_not_print_it(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The handover dict must WORK and must not print the credential.

    Both halves in one test on purpose: a config that had simply dropped the key
    would pass the negative assertion and break every framework that uses it.
    """

    _clear(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path)
    memory = KaleidoscopeMemory(binary=fake_binary, profile="handover", api_key=VALID_KEY)

    config = memory.mcp_server_config()

    # It works: the real key is in the mapping the framework spawns with.
    assert config["env"][API_KEY_VARIABLE] == VALID_KEY
    assert dict(config["env"])[API_KEY_VARIABLE] == VALID_KEY
    assert {**config["env"]}[API_KEY_VARIABLE] == VALID_KEY
    assert json.loads(json.dumps(config["env"]))[API_KEY_VARIABLE] == VALID_KEY

    # And the two lines a user actually writes next do not print it.
    for rendered in (repr(config), str(config), repr(config["env"]), f"{config}"):
        assert VALID_KEY not in rendered, rendered[:400]
        assert "<redacted>" in rendered


def test_the_api_key_secret_refuses_to_be_pickled() -> None:
    """`__slots__` does not stop pickle; without `__reduce__` the value is in the stream.

    Hardening rather than a live leak: nothing the SDK hands out is picklable
    today. Asserted with a positive control so it cannot pass on an object that
    is simply broken.
    """

    import copy
    import pickle

    secret = hold_api_key(VALID_KEY)
    assert secret is not None

    for attempt in (
        lambda: pickle.dumps(secret),
        lambda: copy.copy(secret),
        lambda: copy.deepcopy(secret),
    ):
        with pytest.raises(TypeError, match="not serialisable"):
            attempt()

    # The control: the object still holds the value it refuses to serialise.
    assert secret.reveal() == VALID_KEY


def test_the_package_installs_no_logging_handler() -> None:
    """A handler that can see an environment dict is a handler that can log one."""

    import importlib

    importlib.import_module("kaleidoscope_memory")

    assert logging.getLogger("kaleidoscope_memory").handlers == []
    assert logging.getLogger().handlers == [] or all(
        "kaleidoscope" not in type(handler).__module__
        for handler in logging.getLogger().handlers
    )


# ---------------------------------------------------------------------------
# T-A17..T-A19 -- redaction
# ---------------------------------------------------------------------------


#: The five real stderr forms. Three of them LEAKED before the shape rule was
#: added, and each leaked for its own reason -- which is why they are five
#: cases and not one: the name rule could not see any of the last three.
STDERR_FORMS = {
    "environment assignment": f"KALEIDOSCOPE_API_KEY={VALID_KEY}\n",
    "named field": f"token={VALID_KEY}\n",
    "bare prose": f"kscope: refused key {VALID_KEY} is unknown\n",
    "json": json.dumps({"api_key": VALID_KEY}),
    "command line": f"failed: kscope call --api-key {VALID_KEY}\n",
}


@pytest.mark.parametrize("form", sorted(STDERR_FORMS))
def test_the_key_shape_is_redacted_in_five_stderr_forms(form: str) -> None:
    text = STDERR_FORMS[form]

    diagnostic = _bounded_diagnostic(text.encode("utf-8"))

    assert VALID_KEY not in diagnostic, form
    assert "A" * 20 not in diagnostic, form
    assert "<redacted>" in diagnostic, form


def test_a_truncated_key_at_the_diagnostic_boundary_is_still_redacted() -> None:
    """A `{43}` rule passes the test above and fails this one.

    `_bounded_diagnostic` keeps the LAST 4096 bytes, so the cut can land
    anywhere inside a key. The pattern has no length arithmetic for exactly this
    reason, and a truncated credential is still a credential.
    """

    for offset in range(1, 40):
        head = "x" * (4096 - offset)
        text = (head + VALID_KEY + " trailing\n").encode("utf-8")

        diagnostic = _bounded_diagnostic(text)

        assert VALID_KEY not in diagnostic
        assert "A" * 12 not in diagnostic, offset
    # The falsifier: the retained tail really did contain part of the key, so
    # this loop was not passing by keeping nothing.
    assert "trailing" in _bounded_diagnostic(("x" * 4090 + VALID_KEY + " trailing").encode())


@pytest.mark.asyncio
async def test_the_marker_survives_the_new_redaction(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Asserted on the IDENTIFIER, not on the absence of an error.

    `classify_refusal` runs on the raw child bytes. A regression that ran it on
    the redacted copy would eat the discriminator and the identifier would come
    back E_UNKNOWN -- a refusal reported as a version skew that does not exist.
    """

    _clear(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path)
    descriptor = load_launch_descriptor(fake_binary, f"refusal.E_REVOKED.{_nonce()}")

    with pytest.raises(EntitlementError) as caught:
        await _report(descriptor, api_key=VALID_KEY)

    assert caught.value.reason == "E_REVOKED"
    assert VALID_KEY not in caught.value.diagnostic
    assert "kscope-entitlement-refusal" in caught.value.diagnostic


def test_redaction_is_not_validation() -> None:
    """Nothing branches on whether the shape matched, and this pins it.

    A string that matches is masked whether or not it could be a real key; a
    string that does not match is not treated as bad. Both directions, because
    the temptation is to reuse the regex as a checker.
    """

    masked = _bounded_diagnostic(f"kscope: saw {SHAPED_NON_KEY}".encode("utf-8"))
    assert "<redacted>" in masked

    kept = _bounded_diagnostic(b"kscope: the vault root is not a Kaleidoscope vault")
    assert kept == "kscope: the vault root is not a Kaleidoscope vault"

    # And a key-shaped string is still ACCEPTED as an argument, because
    # redaction has no vote on admission.
    assert _validated_api_key(SHAPED_NON_KEY) is not None


# ---------------------------------------------------------------------------
# Preflight: the code key is what presence sees
# ---------------------------------------------------------------------------


def test_preflight_sees_the_code_key_when_the_environment_has_none(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Both directions, so the guard is not simply always-open."""

    _clear(monkeypatch)
    _entitlement_home(monkeypatch, tmp_path)
    status = gate_status(str(fake_binary))
    assert status.enforcing is True

    assert key_is_present(status) is False
    assert key_is_present(status, api_key=VALID_KEY) is True

    with pytest.raises(EntitlementError) as caught:
        entitlement_preflight(str(fake_binary))
    assert caught.value.reason == "E_NO_KEY"

    assert entitlement_preflight(str(fake_binary), api_key=VALID_KEY).enforcing is True
