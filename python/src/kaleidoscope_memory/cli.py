"""Console entry points that hand control to the installed Kaleidoscope programs."""

from __future__ import annotations

import os
import sys

from .distribution import locate_engine, locate_manager
from .errors import MissingBinaryError


def _located_or_message(locate) -> str:
    """Resolve one program, or exit 1 with the message and no traceback.

    Measured before this existed: `kaleidoscope init --help` from a source
    checkout exited 1 with an unhandled traceback. The traceback was accurate
    and useless -- the user's first contact with the tool was twelve frames of
    this package's internals and no instruction.

    Deliberately NOT a fallback. There is nothing to fall back to: this package
    is a client and the program it drives is installed separately. `str(exc)`
    is already the whole message, and it names what was looked for, everywhere
    it looked, and the one command that fixes it.
    """

    try:
        return locate().path
    except MissingBinaryError as exc:
        sys.stderr.write(f"{exc}\n")
        raise SystemExit(1) from None


def manager_main() -> int:
    manager = _located_or_message(locate_manager)
    # No `--engine` is injected here any more. The manager runs the SAME four
    # step search this package does (`src/engine.rs`), so passing it a path
    # resolved here can only ever disagree with it -- and when the two disagree
    # the user has no way to see which one won.
    #
    # `execv`, not `execve`, and deliberately: this shim IS the user's own
    # shell. Narrowing the environment here would break KSCOPE_PROFILE_HOME and
    # KALEIDOSCOPE_CONFIG_HOME, which the manager documents and honours, and
    # which the SDK's own child allowlist correctly does not forward -- because
    # the SDK is a library inside somebody else's process and this is not.
    os.execv(manager, [manager, *sys.argv[1:]])
    return 126


def engine_main() -> int:
    engine = _located_or_message(locate_engine)
    os.execv(engine, [engine, *sys.argv[1:]])
    return 126
