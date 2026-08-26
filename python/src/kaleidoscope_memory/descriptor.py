"""Load and validate Kaleidoscope's closed v1 profile launch descriptor."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, final

from .errors import ChildProcessError, DescriptorError, MissingBinaryError

EXPECTED_TOOLS = ("search", "remember")
_DESCRIPTOR_KEYS = frozenset(
    {"version", "transport", "command", "args", "tools", "environment"}
)
_PROFILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
#: Conventional, non-secret process/bootstrap variables. Nothing here is a
#: credential and nothing here is Kaleidoscope-specific.
#:
#: XDG_CONFIG_HOME was added 2026-08-22. It is not an entitlement variable; it
#: was always missing. On Linux the engine resolves its config directory from
#: $XDG_CONFIG_HOME in preference to $HOME/.config, so without it an
#: SDK-spawned engine and a shell-run engine read two different directories.
_BOOTSTRAP_ENV_KEYS = (
    "APPDATA",
    "HOME",
    "HOMEDRIVE",
    "HOMEPATH",
    "LOCALAPPDATA",
    "LOGNAME",
    "PATH",
    "PATHEXT",
    "SHELL",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "TEMP",
    "TERM",
    "TMPDIR",
    "USER",
    "USERNAME",
    "USERPROFILE",
    "XDG_CONFIG_HOME",
)

#: The alpha entitlement variables, admitted BY NAME and by name only.
#:
#: This is an allowlist, so naming two entries does not weaken protection of
#: anything else: AZURE_OPENAI_API_KEY, SUPABASE_SECRET_KEY and every other
#: variable in the caller's environment remain stripped because they are not named
#: here. A prefix rule (KALEIDOSCOPE_*) would readmit them and is forbidden; the
#: KALEIDOSCOPE_TEST_SECRET and KSCOPE_ENTITLEMENT_PROBE canaries in both test
#: suites exist to fail exactly that shortcut.
#:
#: The admission test is not "is it a Kaleidoscope variable" and not "does it look
#: harmless". It is: the published entitlement contract
#: (reference/entitlement-contract-v1.json) says the engine reads this one, AND a
#: supported SDK flow fails without it. Two names pass that test:
#:
#:   KALEIDOSCOPE_API_KEY -- the alpha credential the entitlement gate
#:   authenticates. Every gated command refuses without it, so no SDK path works
#:   without it.
#:
#:   KSCOPE_ENTITLEMENT_HOME -- selects the entitlement directory, and therefore
#:   the key file the gate falls back to when no API key is in the environment.
#:   Without it an SDK-spawned engine and a shell-run engine can disagree about
#:   where the key lives.
#:
#: Three names that look like they belong here and do not. Each is in the
#: never_admitted list of the same published contract, and the reason differs in
#: each case -- which is the point: "not admitted" is a conclusion reached per
#: name, never a category.
#:
#:   KSCOPE_ENTITLEMENT_PROBE redirects part of the engine's entitlement check
#:   to a caller-named path. Handing a child a caller-controlled path to
#:   something that will be given the API key is the shape of an attack, and it
#:   buys nothing: a supported install needs no override.
#:
#:   KALEIDOSCOPE_CONTROL_PLANE_ORIGIN was admitted here for a while, on the
#:   assumption that handing it over would redirect where a key is checked. The
#:   published contract says otherwise: it sits in never_admitted beside the two
#:   other names here and beside the plain secrets. Forwarding a name the
#:   contract does not admit changes nothing a caller can observe, while
#:   implying a redirection capability the contract does not offer. It was one
#:   name over the minimum and the justification for it was simply wrong.
#:
#:   KSCOPE_PROFILE_HOME is the Rust manager's documented, non-secret profile
#:   registry override. The manager honours it; the SDKs have never forwarded it
#:   and still do not.
#:
#: The rule the three share: a name earns a place here by having a documented
#: consumer and a demonstrated failure mode, not by being adjacent to one.
#:
#: Widening this list is a deliberate, reviewed edit in three places at once --
#: this list, its twin in the other language, and
#: reference/entitlement-contract-v1.json -- never a prefix and never a pattern.
_ENTITLEMENT_ENV_KEYS = (
    "KALEIDOSCOPE_API_KEY",
    "KSCOPE_ENTITLEMENT_HOME",
)

#: Bootstrap first, then entitlement; both groups alphabetical within
#: themselves. The order is pinned by reference/entitlement-contract-v1.json so
#: the TypeScript SDK cannot drift from it.
_SAFE_ENV_KEYS = _BOOTSTRAP_ENV_KEYS + _ENTITLEMENT_ENV_KEYS
_MAX_DIAGNOSTIC_BYTES = 4_096

#: The one name a programmatic key rides in. It is already in the allowlist
#: above; the assertion below is what keeps that true if either tuple is edited.
API_KEY_VARIABLE = "KALEIDOSCOPE_API_KEY"
assert API_KEY_VARIABLE in _ENTITLEMENT_ENV_KEYS


def _validated_api_key(value: str | None) -> str | None:
    """PRESENCE and TRANSPORT only. Never validity. See entitlement.py's block.

    Checked: it is a string; it is not empty after strip; it contains no NUL and
    no newline. The last two are not opinions about keys -- a NUL cannot be put
    in an environment variable by the OS at all, and a newline splits the value
    on the platforms that parse env blocks textually.

    NOT checked, and must never be: prefix, length, charset, checksum, expiry.
    """

    if value is None:
        return None
    if not isinstance(value, str):
        raise DescriptorError("api_key must be a string or None")
    if not value.strip():
        # An explicitly supplied empty string is a CALLER error, not a bad key.
        # Falling back to the environment here would make "I passed a key" and
        # "I passed nothing" indistinguishable -- a refusal spelled as an answer.
        raise DescriptorError(
            "api_key was supplied but is empty; pass None to use the environment"
        )
    if "\x00" in value or "\n" in value or "\r" in value:
        raise DescriptorError("api_key must not contain a newline or NUL")
    return value


@final
class _Secret:
    """Holds one credential and refuses to render it.

    Not encryption and not obfuscation -- `.reveal()` is one call away, and that
    is fine, because this defends against ACCIDENT, not against the process
    owner. What it makes impossible is the accident that actually happens: a
    dataclass repr, a pydantic ValidationError, a %r in an f-string, or a
    traceback frame printing a credential into a log or an issue report.

    It lives here rather than in `tools.py` for one mechanical reason: `session`
    and `native` both hold one, and both are imported BY `tools`, so a
    definition there would be a cycle. `tools` re-exports the name.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "<kaleidoscope api key: redacted>"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        # Identity, never value: this can neither leak by timing nor make an
        # accidental `secret == "ksk_alpha..."` comparison succeed anywhere.
        return self is other

    def __hash__(self) -> int:
        return id(self)

    def __reduce__(self) -> Any:
        # `__slots__` alone does not stop pickle: without this, `pickle.dumps`
        # of a _Secret emits the plaintext value in the stream, and a pickled
        # stream is a thing people write to disk and to caches. Nothing the SDK
        # hands out is picklable today -- KaleidoscopeMemory, the LangChain tool
        # and the CrewAI tool all refuse -- so this closes a door that is not
        # currently reachable rather than one that is. Hardening, stated as
        # hardening.
        raise TypeError("a Kaleidoscope api key is not serialisable")

    __copy__ = __deepcopy__ = None  # type: ignore[assignment]


#: What a redacted credential renders as. One spelling, asserted from the tests.
REDACTED_PLACEHOLDER = "<redacted>"


@final
class RedactedEnvironment(dict):
    """A child environment whose repr does not print the credential.

    Exactly a `dict` for every purpose that matters -- `[]`, `.get`, `**`,
    `dict(...)`, `json.dumps` -- so a framework handed one spawns the same
    child with the same key. The single difference is `repr`/`str`, which masks
    the value of KALEIDOSCOPE_API_KEY.

    This exists because `mcp_server_config()` must return the real key (the
    framework owns the child from there and cannot spawn it otherwise), while
    `print(config)` and `log.info("launching %s", config)` are the two most
    natural next lines a user writes. A plain dict prints the credential into
    their log; this does not. It is the same trick as `_Secret`, applied to the
    one container the SDK cannot keep the key out of.
    """

    def __repr__(self) -> str:
        return repr(
            {
                key: (REDACTED_PLACEHOLDER if key == API_KEY_VARIABLE else value)
                for key, value in self.items()
            }
        )

    __str__ = __repr__


def redacted_environment_items(environment: Mapping[str, Any]) -> dict[str, Any]:
    """A display copy of a child environment with the credential masked.

    For rendering only. Never pass the result to a spawn -- it carries the
    placeholder where the key should be, which would make the engine report
    E_UNKNOWN_KEY for a key that was supplied.
    """

    return {
        key: (REDACTED_PLACEHOLDER if key == API_KEY_VARIABLE else value)
        for key, value in environment.items()
    }


def hold_api_key(value: str | None) -> "_Secret | None":
    """Validate transport, then wrap. The one constructor callers should use."""

    validated = _validated_api_key(value)
    return None if validated is None else _Secret(validated)


def reveal_api_key(secret: "_Secret | None") -> str | None:
    return None if secret is None else secret.reveal()


def safe_bootstrap_environment(*, api_key: str | None = None) -> dict[str, str]:
    """Build the child environment from a closed, by-name allowlist.

    Two groups, both literal: conventional process/bootstrap variables
    (`_BOOTSTRAP_ENV_KEYS`), and the two alpha entitlement variables
    (`_ENTITLEMENT_ENV_KEYS`), one of which -- KALEIDOSCOPE_API_KEY -- is a
    credential and is passed deliberately, because the engine's entitlement gate
    reads it and no SDK path works without it.

    The promise this makes is narrower than "never credentials" and it is the
    one that is actually kept: **only the names listed above are copied.** Every
    other variable in the caller's environment -- other providers' API keys, a
    Supabase service-role key that bypasses row-level security, anything in a
    .env file -- is not copied, because it is not named. Widening this list is a
    deliberate, reviewed edit to two literal tuples and to
    reference/entitlement-contract-v1.json, never a prefix or a pattern.

    `api_key` is the programmatic route. **The allowlist does not grow to carry
    it**: the value is placed in KALEIDOSCOPE_API_KEY, a name already admitted,
    replacing whatever the caller's own environment held. The allowlist
    is still 20 names and the shared contract is untouched. `os.environ` is never
    mutated, so the key is scoped to the children this SDK spawns and reaches no
    other subprocess the caller's process starts.
    """

    environment = {
        key: os.environ[key]
        for key in _SAFE_ENV_KEYS
        # Shellshock-style exported function definitions are never a value we
        # want to hand a child. TypeScript has always dropped these; Python did
        # not, and the divergence is closed here.
        if key in os.environ and not os.environ[key].startswith("()")
    }
    if api_key is not None:
        # The shellshock `()` predicate is deliberately NOT applied to this
        # value. It exists to stop an exported bash function definition
        # INHERITED from the caller's environment being laundered into a child.
        # A value handed over as a Python string was not inherited from
        # anywhere; dropping it here would silently discard a key the caller
        # explicitly passed, and the engine would then report E_NO_KEY for a key
        # that WAS supplied -- a refusal spelled as the wrong answer, which is
        # exactly what `key_is_present`'s docstring records having happened once
        # already for the inherited case.
        environment[API_KEY_VARIABLE] = api_key
    return environment


def _ungated_environment() -> dict[str, str]:
    """The same allowlist, minus the credential, for children that read no key.

    NOT a second allowlist. It is `safe_bootstrap_environment()` with one name
    removed, so it can only ever be a subset -- pinned by
    test_the_ungated_environment_is_a_strict_subset. Used by the ungated spawn
    sites (`profile launch`, `profile show`, `schema`, `gate`) and by the
    manager, none of which reads KALEIDOSCOPE_API_KEY: the engine's gated
    command list is ["mcp","context","call","serve"], and the gate report reads
    no key by its own comment.

    Narrowing is the only direction this can move, and it is done by removing a
    name from the ONE list above -- never by adding to a second one.
    """

    environment = safe_bootstrap_environment()
    environment.pop(API_KEY_VARIABLE, None)
    return environment


# Internal native callers share the same public, audited boundary.
_safe_process_environment = safe_bootstrap_environment


#: The code points both SDKs strip from the ends of a diagnostic.
#:
#: Neither language's built-in is usable here, because the two disagree on two
#: classes and the disagreement is silent. Python's `str.strip()` treats the
#: file/group/record/unit separators U+001C-U+001F as whitespace and U+FEFF as
#: not; JavaScript's `String.trim()` does exactly the reverse. Measured over 25
#: differential cases, a trailing U+001C and a trailing U+FEFF were the only two
#: that produced different diagnostics from identical child bytes -- a parity
#: divergence no test in either tree could see, because the shared case file was
#: read by one language only.
#:
#: So the set is written out: the UNION of both languages' notions, pinned in
#: reference/entitlement-contract-v1.json and asserted from both sides. The
#: union rather than the intersection, because a diagnostic is display text and
#: stripping one separator too many is harmless, whereas the two built-ins
#: disagreeing is exactly the defect being closed.
#:
#: Written as code points, not as literal characters: several of these are
#: invisible, and a source file carrying them raw cannot be reviewed.
DIAGNOSTIC_EDGE_CODE_POINTS: tuple[int, ...] = (
    # Agreed by both languages.
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680,
    0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008,
    0x2009, 0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
    # Python only: str.isspace() is true for these; String.trim() is not.
    0x1C, 0x1D, 0x1E, 0x1F,
    # JavaScript only: trim() strips the BOM; Python's strip() does not.
    0xFEFF,
)

_DIAGNOSTIC_EDGE = "".join(chr(point) for point in DIAGNOSTIC_EDGE_CODE_POINTS)


#: The SHAPE of an alpha key, for redaction only.
#:
#: One pattern, no length arithmetic. It matches the full 53-character key and
#: also a key sliced in half by the 4096-byte diagnostic bound, which a `{43}`
#: rule would miss. Pinned in reference/redaction-contract-v1.json and asserted
#: from both SDKs.
#:
#: REDACTION IS NOT VALIDATION. A string that matches is masked whether or not
#: it is a real key; a string that does not match is not treated as bad; and
#: nothing anywhere branches on whether this matched. Using this regex to make a
#: decision is the thing entitlement.py's constraint block forbids.
API_KEY_SHAPE_PATTERN = r"ksk_alpha\.[A-Za-z0-9_-]*"
_API_KEY_SHAPE = re.compile(API_KEY_SHAPE_PATTERN)


def _bounded_diagnostic(value: bytes) -> str:
    data = value[-_MAX_DIAGNOSTIC_BYTES:]
    text = data.decode("utf-8", errors="replace").strip(_DIAGNOSTIC_EDGE)
    # Shape first: an alpha key is masked wherever it appears, including inside
    # prose and inside JSON, where the name rule below cannot see it. Measured
    # against five real stderr forms, the name rule alone leaked three:
    # `refused key ksk_alpha....` (no name before it), `{"api_key": "ksk_..."}`
    # (the quote breaks `api_key\s*[:=]`), and `--api-key ksk_alpha....`.
    text = _API_KEY_SHAPE.sub("<redacted>", text)
    # Diagnostics are never meant to carry secrets; mask the common accidental
    # forms before including a bounded suffix in an exception.
    return re.sub(
        r"(?i)(token|secret|password|authorization|api[_-]?key)\s*[:=]\s*\S+",
        r"\1=<redacted>",
        text,
    )


def _canonical_executable(command: object) -> str:
    if not isinstance(command, str) or not command:
        raise DescriptorError("descriptor command must be a non-empty string")
    path = Path(command)
    if not path.is_absolute():
        raise DescriptorError("descriptor command must be absolute")
    try:
        resolved = path.resolve(strict=True)
        mode = resolved.stat().st_mode
    except FileNotFoundError as exc:
        raise MissingBinaryError("Kaleidoscope executable does not exist") from exc
    except OSError as exc:
        raise DescriptorError("descriptor command does not exist") from exc
    if resolved != path:
        raise DescriptorError("descriptor command must already be canonical and non-symlinked")
    if not stat.S_ISREG(mode) or not os.access(path, os.X_OK):
        raise DescriptorError("descriptor command must be a regular executable")
    return str(path)


def validate_profile_name(value: object) -> str:
    if not isinstance(value, str) or _PROFILE_RE.fullmatch(value) is None:
        raise DescriptorError("descriptor profile name is not portable")
    return value


@dataclass(frozen=True, slots=True)
class LaunchDescriptor:
    """The only supported profile-first stdio launch shape."""

    version: int
    transport: str
    command: str
    args: tuple[str, ...]
    tools: tuple[str, ...]
    environment: Mapping[str, str]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "LaunchDescriptor":
        if set(value) != _DESCRIPTOR_KEYS:
            missing = sorted(_DESCRIPTOR_KEYS - set(value))
            extra = sorted(set(value) - _DESCRIPTOR_KEYS)
            raise DescriptorError(f"descriptor fields differ from v1 (missing={missing}, extra={extra})")

        if type(value["version"]) is not int or value["version"] != 1:
            raise DescriptorError("descriptor version must be exactly 1")
        if value["transport"] != "stdio":
            raise DescriptorError("descriptor transport must be exactly 'stdio'")

        command = _canonical_executable(value["command"])

        raw_args = value["args"]
        if not isinstance(raw_args, list) or any(not isinstance(item, str) for item in raw_args):
            raise DescriptorError("descriptor args must be a string array")
        args = tuple(raw_args)
        if len(args) != 3 or args[:2] != ("mcp", "--profile"):
            raise DescriptorError("descriptor args must be ['mcp', '--profile', NAME]")
        validate_profile_name(args[2])

        raw_tools = value["tools"]
        if not isinstance(raw_tools, list) or tuple(raw_tools) != EXPECTED_TOOLS:
            raise DescriptorError("descriptor tools must be exactly ['search', 'remember']")

        raw_environment = value["environment"]
        if not isinstance(raw_environment, dict) or raw_environment:
            raise DescriptorError("descriptor environment must be exactly empty")

        return cls(
            version=1,
            transport="stdio",
            command=command,
            args=args,
            tools=EXPECTED_TOOLS,
            environment={},
        )

    @classmethod
    def from_json(cls, payload: str | bytes) -> "LaunchDescriptor":
        try:
            value = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise DescriptorError("profile launch did not return valid JSON") from exc
        if not isinstance(value, dict):
            raise DescriptorError("profile launch descriptor must be an object")
        return cls.from_mapping(value)

    @property
    def profile(self) -> str:
        return self.args[2]

    def as_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "transport": self.transport,
            "command": self.command,
            "args": list(self.args),
            "tools": list(self.tools),
            "environment": {},
        }

    def stdio_parameters(self) -> dict[str, object]:
        """Return SDK-neutral stdio parameters without ambient authority."""

        return {"command": self.command, "args": list(self.args)}


def read_launch_descriptor(path: str | Path) -> LaunchDescriptor:
    try:
        payload = Path(path).read_bytes()
    except OSError as exc:
        raise DescriptorError(f"cannot read launch descriptor: {path}") from exc
    return LaunchDescriptor.from_json(payload)


def executable_sha256(path: str | Path) -> str:
    command = _canonical_executable(str(path))
    digest = hashlib.sha256()
    with open(command, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_launch_descriptor(
    binary: str | Path,
    profile: str,
    *,
    expected_sha256: str | None = None,
    timeout_seconds: float = 10.0,
) -> LaunchDescriptor:
    """Ask one pinned executable for a descriptor, then validate it closed-world.

    This read-only manager call inherits only bootstrap environment variables.
    The returned MCP descriptor must still carry an exactly empty environment.

    No `api_key` parameter, deliberately: `profile launch` is not in the
    engine's gated command list, so this child has no use for a credential and
    is spawned with `_ungated_environment()`. Handing it one would be a wider
    grant than the command needs, for no observable difference.
    """

    command = _canonical_executable(str(binary))
    validate_profile_name(profile)
    if expected_sha256 is not None and executable_sha256(command) != expected_sha256.lower():
        raise DescriptorError("Kaleidoscope executable SHA-256 does not match the caller's pin")
    try:
        completed = subprocess.run(
            [command, "profile", "launch", profile],
            check=False,
            capture_output=True,
            env=_ungated_environment(),
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise ChildProcessError("profile launch timed out") from exc
    except OSError as exc:
        raise ChildProcessError("profile launch could not start") from exc
    if completed.returncode != 0:
        detail = _bounded_diagnostic(completed.stderr)
        suffix = f": {detail}" if detail else ""
        raise ChildProcessError(f"profile launch exited {completed.returncode}{suffix}")
    descriptor = LaunchDescriptor.from_json(completed.stdout)
    if descriptor.command != command or descriptor.profile != profile:
        raise DescriptorError("profile launch changed the requested command or profile")
    return descriptor
