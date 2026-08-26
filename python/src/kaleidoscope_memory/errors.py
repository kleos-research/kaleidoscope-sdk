"""Stable controller-side error categories.

The public MCP server returns typed refusal envelopes as text. These exceptions
classify failures without pretending a refusal is a transport failure.
"""

from __future__ import annotations


class IntegrationError(RuntimeError):
    """Base class for the unpublished integration layer."""

    code = "integration_error"


class DescriptorError(IntegrationError):
    """The v1 launch descriptor is missing, unsafe, or incompatible."""

    code = "invalid_descriptor"


class MissingBinaryError(DescriptorError):
    """The explicitly selected executable is absent."""

    code = "missing_binary"


class ChildProcessError(IntegrationError):
    """The descriptor command could not be started or exited unexpectedly."""

    code = "child_crash"


class ManagerCommandError(ChildProcessError):
    """The local manager refused an account command with a redacted diagnostic."""

    code = "manager_command"

    def __init__(
        self,
        arguments: tuple[str, ...],
        returncode: int,
        diagnostic: str,
    ) -> None:
        rendered = " ".join(arguments)
        suffix = f": {diagnostic}" if diagnostic else ""
        super().__init__(f"manager command {rendered!r} exited {returncode}{suffix}")
        self.arguments = arguments
        self.returncode = returncode


class DeadlineExceededError(ChildProcessError):
    """The original operation deadline elapsed; the final outcome may be uncertain."""

    code = "deadline_exceeded"


class OutputLimitError(ChildProcessError):
    """A child exceeded a controller output bound."""

    code = "output_limit"


#: The refusal identifiers the engine's alpha entitlement gate can emit, plus
#: the one identifier only an SDK ever produces.
#:
#: These are parsed off the engine's machine-readable marker line, never off its
#: English prose: prose gets edited and a substring match on it drifts silently
#: with nothing to announce it.
#: E_UNKNOWN_KEY is the ninth, and this tuple carried only eight until an audit
#: found the gap. The engine distinguishes a key the control plane has never
#: issued from one it issued and revoked, and emits a distinct identifier for
#: each. An SDK that knew only eight collapsed the first into E_UNKNOWN -- whose
#: message blames a version skew between an engine and an SDK that were the same
#: version. A refusal spelled as the wrong answer: the user is told to upgrade,
#: and upgrading cannot help.
#:
#: The fix is not "add one more string". It is that the identifier set is frozen
#: in reference/entitlement-contract-v1.json and asserted from all three
#: implementations -- this SDK, the TypeScript SDK, and the engine's own
#: contract test -- against that one file. A tenth identifier therefore cannot
#: reach a user through an SDK that has not been taught it: the three fail
#: together, at test time, instead of one of them degrading at run time.
ENTITLEMENT_REFUSAL_IDENTIFIERS = (
    "E_NO_KEY",
    "E_KEY_FILE_UNUSABLE",
    "E_MALFORMED_KEY",
    "E_UNVERIFIED",
    "E_UNKNOWN_KEY",
    "E_REVOKED",
    "E_KEY_EXPIRED",
    "E_GRACE_EXPIRED",
    "E_CLOCK_BACKWARDS",
)

#: Emitted by this SDK alone: exit 4 or a marker identifier this version does
#: not know. Never produced by the engine.
ENTITLEMENT_SDK_ONLY_IDENTIFIER = "E_UNKNOWN"

#: What `{key_file}` renders as when `kscope gate` could not resolve a path.
#: Pinned, so the two SDKs can compare rendered output byte for byte.
MISSING_KEY_FILE_PLACEHOLDER = "the key file"

#: This SDK's own actionable text, one template per identifier.
#:
#: These are deliberately NOT the engine's prose. The engine's prose reaches the
#: caller as `EntitlementError.diagnostic`, bounded and redacted -- and the
#: redaction rewrites the engine's own instructional
#: `KALEIDOSCOPE_API_KEY=ksk_alpha....` line to `KALEIDOSCOPE_API_KEY=<redacted>`,
#: destroying exactly the sentence that would have helped. So the instruction the
#: user reads has to be ours.
#:
#: `{key_file}` is the only placeholder. It appears in every template that
#: tells the user where to put a key -- five of them, since the code route
#: was added. Every template ends with the same sentence; see
#: test_entitlement.py::test_messages_match_the_shared_golden.
ENTITLEMENT_MESSAGES: dict[str, str] = {
    "E_NO_KEY": (
        "Kaleidoscope alpha: no API key was found, so the engine refused to start.\n"
        "Pass it as api_key= when you construct the client, set KALEIDOSCOPE_API_KEY in\n"
        "your environment, or write the key to {key_file} with permissions 0600.\n"
        "Ask the alpha owner for a key if you do not have one.\n"
        "Your local vault data is intact and unchanged."
    ),
    "E_KEY_FILE_UNUSABLE": (
        "Kaleidoscope alpha: the key file at {key_file} could not be used.\n"
        "It must be a regular file, no larger than 256 bytes, owned by you and set to\n"
        "permissions 0600, containing the key and nothing else.\n"
        "Your local vault data is intact and unchanged."
    ),
    "E_MALFORMED_KEY": (
        "Kaleidoscope alpha: the API key is not a well-formed alpha key.\n"
        'It must be "ksk_alpha." followed by 43 characters. Check for a truncated\n'
        "paste, a stray quote, or surrounding whitespace.\n"
        "Your local vault data is intact and unchanged."
    ),
    "E_UNVERIFIED": (
        "Kaleidoscope alpha: this API key has not been verified on this machine yet.\n"
        "A background revalidation has been started. Connect to the network and try\n"
        "again. If it keeps failing, ask the alpha owner to confirm the key is active.\n"
        "Your local vault data is intact and unchanged."
    ),
    "E_UNKNOWN_KEY": (
        "Kaleidoscope alpha: the control plane does not recognise this API key.\n"
        "This is not a revocation. Check for a truncated paste, then ask the alpha owner\n"
        "to confirm the key was issued for this alpha.\n"
        "Pass it as api_key= when you construct the client, set KALEIDOSCOPE_API_KEY in\n"
        "your environment, or write the key to {key_file} with permissions 0600.\n"
        "Your local vault data is intact and unchanged."
    ),
    "E_REVOKED": (
        "Kaleidoscope alpha: this API key has been revoked by the alpha owner.\n"
        "Contact the alpha owner for a replacement key. Nothing you do locally will\n"
        "restore this one.\n"
        "Pass it as api_key= when you construct the client, set KALEIDOSCOPE_API_KEY in\n"
        "your environment, or write the key to {key_file} with permissions 0600.\n"
        "Your local vault data is intact and unchanged."
    ),
    "E_KEY_EXPIRED": (
        "Kaleidoscope alpha: this API key has expired.\n"
        "Contact the alpha owner for a replacement key.\n"
        "Pass it as api_key= when you construct the client, set KALEIDOSCOPE_API_KEY in\n"
        "your environment, or write the key to {key_file} with permissions 0600.\n"
        "Your local vault data is intact and unchanged."
    ),
    "E_GRACE_EXPIRED": (
        "Kaleidoscope alpha: this API key could not be revalidated within its grace\n"
        "window, so gated commands have stopped working.\n"
        "Reconnect to the network and try again; the key itself may still be fine.\n"
        "Your local vault data is intact and unchanged."
    ),
    "E_CLOCK_BACKWARDS": (
        "Kaleidoscope alpha: the system clock has moved backwards since the last\n"
        "entitlement check, so the grace window cannot be evaluated.\n"
        "Correct the system clock and try again.\n"
        "Your local vault data is intact and unchanged."
    ),
    "E_UNKNOWN": (
        "Kaleidoscope alpha: the engine refused this command for an entitlement reason\n"
        "this SDK does not recognise. The engine and this SDK may be different versions.\n"
        "See the engine diagnostic attached to this error.\n"
        "Your local vault data is intact and unchanged."
    ),
}


def render_entitlement_message(reason: str, key_file: str | None = None) -> str:
    """Render one template. An unknown identifier renders as E_UNKNOWN.

    `str.replace`, not `str.format`: the templates are user-facing prose and a
    stray brace in a future edit must not raise from inside an error path.
    """

    template = ENTITLEMENT_MESSAGES.get(reason, ENTITLEMENT_MESSAGES[ENTITLEMENT_SDK_ONLY_IDENTIFIER])
    return template.replace("{key_file}", key_file or MISSING_KEY_FILE_PLACEHOLDER)


class EntitlementError(IntegrationError):
    """The engine refused a gated command for an alpha entitlement reason.

    Not a `ChildProcessError`: the child started fine and refused deliberately,
    which is the distinction this module's docstring exists to keep. It is also
    not a subclass of this module's `ChildProcessError` for a second reason --
    that name shadows the builtin `OSError` subclass, so inheriting from it would
    make a caller's `except OSError` start swallowing entitlement refusals.

    `message` is this SDK's own actionable text. `diagnostic` is the engine's
    bounded, redacted stderr, attached as evidence and never as the instruction.
    """

    code = "entitlement"

    def __init__(
        self,
        reason: str,
        *,
        diagnostic: str = "",
        key_file: str | None = None,
    ) -> None:
        super().__init__(render_entitlement_message(reason, key_file))
        self.reason = reason
        self.diagnostic = diagnostic
        self.key_file = key_file


class ProtocolError(IntegrationError):
    """The child violated the exact public MCP boundary."""

    code = "protocol_contract"


class NativeRefusalError(IntegrationError):
    """A direct native call returned a parsed refusal and was not retried."""

    code = "native_refusal"

    def __init__(self, operation: str, response: object) -> None:
        super().__init__(f"Kaleidoscope refused native operation {operation!r}")
        self.operation = operation
        self.response = response


class DuplicateSearchError(IntegrationError):
    """A controller-owned turn attempted a second acquisition search."""

    code = "duplicate_search"


class ToolRefusalError(IntegrationError):
    """Kaleidoscope returned an MCP tool-level refusal."""

    code = "tool_refusal"

    def __init__(self, tool: str, text: str) -> None:
        super().__init__(f"Kaleidoscope refused {tool!r}: {text}")
        self.tool = tool
        self.text = text
