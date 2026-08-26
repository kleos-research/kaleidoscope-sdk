"""The alpha entitlement seam: what the engine's gate needs and how it refuses.

Two invariants shape everything in this module.

**The engine and the control plane are the only authorities.** Every check here
is a UX affordance that saves a spawn or produces a better message. When a check
cannot run it *fails open* and the engine still refuses. That is the deliberate
opposite of a release gate's posture. A gate is an authority over an artefact
nobody can re-inspect once it is published, so it must fail *closed* on absent
evidence; this is a courtesy in front of an authority that is still there.

**A refusal is never spelled as an answer.** Nothing here returns empty, abstains
or exits zero in place of refusing. `entitlement_preflight` raises; the two
classifiers return `None` only when the failure genuinely was not an entitlement
refusal, and `test_entitlement.py` makes both branches fire.
"""

# ---------------------------------------------------------------------------
# WHAT THIS SDK MUST NEVER DO WITH AN API KEY, AND WHY.
#
# This SDK CARRIES the credential and REPORTS the engine's verdict. It is never
# an authority on whether a key is good. Concretely, and permanently:
#
#   NO VALIDITY DECISION. No signature check, no prefix check, no length check,
#   no charset check, no checksum. `key_is_present` checks presence and nothing
#   else, and it is the only function allowed to look at a key at all.
#
#   NO EXPIRY ARITHMETIC. Nothing here parses a date out of a key, compares a
#   timestamp, or reasons about a grace window. E_KEY_EXPIRED and
#   E_GRACE_EXPIRED are identifiers the engine emits and this SDK renders.
#
#   NO VERDICT CACHING. `gate_status` memoises what the engine says about its
#   own BUILD -- enforcing or not, and where the key file is. That report reads
#   no key. A key must never enter `_gate_status_cached`'s signature:
#   `functools.lru_cache` retains every argument tuple for the life of the
#   process, so that would pin the credential in a module-level cache.
#
# WHY, so nobody helpfully adds it:
#
#   This package is Apache-2.0 and trivially editable. Any validity rule here is
#   theatre against an adversary and a SECOND SOURCE OF TRUTH against everyone
#   else. When the engine's rule and this copy of it disagree, the SDK refuses a
#   key that works, or admits one that does not, and in both cases the user is
#   told something false by the layer that had no standing to say it. There is
#   one authority: the engine, and behind it the control plane.
#
#   Two things this makes CHEAPER, not more expensive: (a) an engine that adds a
#   key format needs no SDK release; (b) a refusal always names the real reason,
#   because the only component that can produce one is the only component that
#   knows.
#
# The permitted preflight is exactly this: is a key PRESENT and non-empty, and
# is it a thing that can be put in an environment variable at all. That saves a
# spawn and produces a better message. It decides nothing.
#
# The redaction rules in descriptor.py match a key SHAPE. Redaction is not
# validation: a string that matches is masked whether or not it is a real key,
# a string that does not match is not treated as bad, and NOTHING BRANCHES ON
# THE RESULT. If you find yourself using the redaction regex to make a decision,
# you are writing the thing this block forbids.
#
# ON THE `api_key=` PARAMETER, AND THE ARGUMENT AGAINST ONE.
#
#   The engine's own source argues, in a comment, that an SDK could read a key
#   file and inject KALEIDOSCOPE_API_KEY into a child; that this would leave
#   every non-SDK caller still broken for a file-route user; and that it would
#   put key bytes in SDK memory for no benefit. One authority, one route, all
#   callers.
#
#   That comment is correct and this parameter does not contradict it. It argues
#   against the SDK READING THE KEY FILE, and this SDK does not: the file route
#   is the engine's and is never opened here. The benefit the comment says is
#   absent is the one this parameter supplies -- configuring the key in code,
#   which the file route cannot do at all. Precedence is unchanged, because a
#   code key becomes an environment value in the child and the engine's own
#   environment-before-file rule then ranks it correctly with no SDK
#   involvement.
#
#   The boundary that comment is really about still holds: `api_key=` configures
#   THIS SDK'S OWN CHILDREN. A harness that spawns the engine itself -- Claude
#   Code, Cursor, Codex, OpenCode -- never passes through this code and takes
#   its key from the environment or the key file, as before.
# ---------------------------------------------------------------------------

from __future__ import annotations

import functools
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .descriptor import (
    API_KEY_VARIABLE,
    _ENTITLEMENT_ENV_KEYS,
    _ungated_environment,
    _validated_api_key,
    safe_bootstrap_environment,
)
from .errors import (
    ENTITLEMENT_MESSAGES,
    ENTITLEMENT_REFUSAL_IDENTIFIERS,
    ENTITLEMENT_SDK_ONLY_IDENTIFIER,
    MISSING_KEY_FILE_PLACEHOLDER,
    EntitlementError,
    render_entitlement_message,
)

__all__ = [
    "API_KEY_VARIABLE",
    "ENTITLEMENT_ENV_KEYS",
    "ENTITLEMENT_MESSAGES",
    "GateStatus",
    "MISSING_KEY_FILE_PLACEHOLDER",
    "REFUSAL_IDENTIFIERS",
    "SDK_ONLY_IDENTIFIER",
    "classify_refusal",
    "clear_gate_status_cache",
    "entitlement_preflight",
    "gate_status",
    "key_is_present",
    "render_entitlement_message",
]

#: Re-exported so a caller can name the seam without reaching into descriptor.
ENTITLEMENT_ENV_KEYS = _ENTITLEMENT_ENV_KEYS

REFUSAL_IDENTIFIERS = frozenset(ENTITLEMENT_REFUSAL_IDENTIFIERS)
SDK_ONLY_IDENTIFIER = ENTITLEMENT_SDK_ONLY_IDENTIFIER

#: The one machine-readable discriminator the SDK parses out of engine stderr.
#:
#: It is the LAST line of an entitlement refusal, and that is load-bearing:
#: `_bounded_diagnostic` keeps the last 4096 bytes, so a marker at the head does
#: not survive a flooded stderr and a marker at the tail does. Anchored per line
#: and matched against the identifier alphabet only -- never against the
#: engine's English prose, which gets edited and would drift in silence.
_MARKER = re.compile(r"^kscope-entitlement-refusal: ([A-Z][A-Z0-9_]{2,39})$", re.MULTILINE)

#: Exactly the keys `kscope gate` prints. A report with any other key set is not
#: a report this SDK understands, and is treated as "no answer" (fail open).
_GATE_REPORT_KEYS = frozenset(
    {
        "status",
        "entitlement_build",
        "gated_commands",
        "entitlement_home",
        "key_file",
        "build_features",
        "marker",
    }
)

#: The exit code the engine uses for "refused by the alpha entitlement gate,
#: nothing applied". Distinct from 2, which is also every usage error.
ENTITLEMENT_EXIT_CODE = 4

_GATE_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True, slots=True)
class GateStatus:
    """What the engine says about its own build. Never about a key."""

    enforcing: bool
    key_file: str | None


#: The variables the engine's own directory resolution reads. They belong in the
#: cache key because the gate report's `entitlement_home` and `key_file` are
#: DERIVED from them: keyed on the binary alone, a process that changed
#: KSCOPE_ENTITLEMENT_HOME between calls is served the previous configuration's
#: key_file, and the refusal then names a path the user never configured.
#: Nothing about that looks wrong from the outside, which is why the cache key
#: has to carry every input the cached answer was derived from.
#:
#: This list is the Python half of `typescript/src/entitlement.ts`'s
#: DIRECTORY_VARIABLES and the two must agree; test_parity.py drives both.
_DIRECTORY_VARIABLES = ("KSCOPE_ENTITLEMENT_HOME", "HOME", "APPDATA", "XDG_CONFIG_HOME")


def _directory_key() -> str:
    return "|".join(f"{name}={os.environ.get(name, '')}" for name in _DIRECTORY_VARIABLES)


@functools.lru_cache(maxsize=8)
def _gate_status_cached(command: str, mtime_ns: int, size: int, directory: str) -> GateStatus:
    # identity only: swapping the binary or the directory variables invalidates
    # the entry, which is the whole reason all four are in the signature.
    del mtime_ns, size, directory
    try:
        completed = subprocess.run(
            [command, "gate"],
            check=False,
            capture_output=True,
            # `gate` reads no key -- it reports where the key file WOULD be and
            # whether this build enforces. Handing it the credential would be a
            # grant the command has no use for.
            env=_ungated_environment(),
            timeout=_GATE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return GateStatus(enforcing=False, key_file=None)
    if completed.returncode != 0:
        return GateStatus(enforcing=False, key_file=None)
    try:
        report = json.loads(completed.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return GateStatus(enforcing=False, key_file=None)
    if not isinstance(report, dict) or set(report) != _GATE_REPORT_KEYS:
        return GateStatus(enforcing=False, key_file=None)
    # `is True`, not truthiness: a report that answered with a string or a 1 is
    # a report from something this SDK does not understand.
    if report["entitlement_build"] is not True:
        return GateStatus(enforcing=False, key_file=None)
    key_file = report["key_file"]
    return GateStatus(
        enforcing=True,
        key_file=key_file if isinstance(key_file, str) and key_file else None,
    )


def clear_gate_status_cache() -> None:
    """Drop the memoised gate answers.

    Exists for tests, which point one fixture path at several different engine
    configurations, and for a caller that has replaced the binary in place
    without changing its size or mtime.
    """

    _gate_status_cached.cache_clear()


def gate_status(command: str) -> GateStatus:
    """Ask the engine whether it enforces the alpha gate. UX only; never authority.

    Memoised on the binary (path, mtime, size) AND the directory variables the
    report is derived from, so swapping either invalidates it.

    FAILS OPEN. `kscope gate` is a new command: an older engine answers it with a
    usage error, and a future one may answer with keys this SDK does not know.
    Either way the answer is ``GateStatus(enforcing=False, key_file=None)``, the
    preflight is skipped, and the engine decides -- which is the whole point.
    """

    try:
        info = Path(command).stat()
    except OSError:
        return GateStatus(enforcing=False, key_file=None)
    return _gate_status_cached(command, info.st_mtime_ns, info.st_size, _directory_key())


def key_is_present(status: GateStatus, *, api_key: str | None = None) -> bool:
    """PRESENCE, never validity.

    True iff either

    * a key will be delivered to the child in ``KALEIDOSCOPE_API_KEY`` -- either
      the ``api_key`` argument, or this process's own value -- and it is
      non-empty after ``strip()``, or
    * ``status.key_file`` names a regular file whose size is greater than zero.

    This function never opens the key file, never checks its mode or ownership,
    never checks the key's prefix, length or charset, and never contacts
    anything. The Python and TypeScript SDKs are Apache-2.0 and trivially
    editable; a validity check here would be theatre and a second source of
    truth. The engine and the control plane decide -- see
    test_entitlement.py::test_the_sdk_performs_no_local_validation.

    The environment half is read through `safe_bootstrap_environment()` rather
    than off `os.environ` directly, so this function sees exactly what the child
    will see. Read directly, the two disagreed for one class of value: a key
    beginning with ``()`` is dropped by the shellshock predicate on the way to
    the child, while presence here said "set" -- so the SDK spawned, the engine
    saw no key at all, and told the user to set a variable they had set. Asking
    the allowlist makes the disagreement unrepresentable rather than merely
    fixed.

    `api_key` is passed straight through to that same call, so presence and
    delivery still cannot disagree: this asks the ONE function that builds the
    child's environment what it would build, rather than reimplementing its
    precedence rule.
    """

    if safe_bootstrap_environment(api_key=api_key).get(API_KEY_VARIABLE, "").strip():
        return True
    if status.key_file is None:
        return False
    try:
        info = Path(status.key_file).stat()
    except OSError:
        return False
    return Path(status.key_file).is_file() and info.st_size > 0


def entitlement_preflight(command: str, *, api_key: str | None = None) -> GateStatus:
    """Refuse before spawning a gated command that cannot possibly succeed, and
    return the gate status the caller should quote for the rest of this call.

    Fires on exactly one case: the engine enforces the gate and the user has
    configured nothing at all. A key file that is present but unusable (wrong
    mode, too large) is *present* here and is refused by the engine with
    E_KEY_FILE_UNUSABLE, which is the correct division of labour -- the SDK asks
    "did the user configure anything", the engine asks "is this usable".

    It RETURNS the status rather than being asked again later, so the `key_file`
    a refusal names is the one that was in force when the command ran. Asking
    twice let the two answers differ, and a message naming a path the user never
    configured is a refusal spelled as the wrong answer.
    """

    status = gate_status(command)
    if not status.enforcing:
        return status
    if key_is_present(status, api_key=_validated_api_key(api_key)):
        return status
    raise EntitlementError("E_NO_KEY", key_file=status.key_file)


def classify_refusal(stderr: bytes, returncode: int | None = None) -> str | None:
    """Which entitlement refusal this is, or None if it is not one.

    Reads only the marker line. Never matches on the engine's English prose.

    Call this on the RAW child stderr, not on `_bounded_diagnostic`'s output: a
    future addition to the redaction pattern must not be able to silently take
    the discriminator with it.
    """

    text = stderr.decode("utf-8", errors="replace")
    matches = _MARKER.findall(text)
    if matches:
        return matches[-1] if matches[-1] in REFUSAL_IDENTIFIERS else SDK_ONLY_IDENTIFIER
    if returncode == ENTITLEMENT_EXIT_CODE:
        return SDK_ONLY_IDENTIFIER
    return None
