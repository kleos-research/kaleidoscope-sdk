"""Console entry points that hand control to the packaged native executables."""

from __future__ import annotations

import os
import sys

from .distribution import (
    InvalidPlatformPackageError,
    MissingPlatformPackageError,
    UnsupportedPlatformError,
    installed_payload_paths,
    selected_native_module,
)


def _payload_or_message() -> object:
    """Resolve the native companion, or exit 1 with one actionable line.

    Measured before this existed: `kaleidoscope init --help` from a source
    checkout exited 1 with an unhandled `MissingPlatformPackageError` traceback.
    The traceback was accurate and useless -- the user's first contact with the
    tool was twelve frames of this package's internals and no instruction.

    Deliberately NOT a fallback. There is nothing to fall back to: the manager
    and the engine are the companion. This exits, and names the package to
    install, which is the whole of what the caller can do about it.
    """

    try:
        return installed_payload_paths()
    except (
        MissingPlatformPackageError,
        InvalidPlatformPackageError,
        UnsupportedPlatformError,
    ) as exc:
        try:
            expected = selected_native_module().replace("_", "-")
        except UnsupportedPlatformError:
            expected = None
        sys.stderr.write(f"kaleidoscope: {exc}\n")
        if expected is not None:
            sys.stderr.write(
                f"kaleidoscope: install it with `pip install {expected}`, or install "
                f"`kaleidoscope-memory`, which depends on it.\n"
            )
        raise SystemExit(1) from None


def manager_main() -> int:
    payload = _payload_or_message()
    arguments = sys.argv[1:]
    if not arguments or arguments[0] in {"-h", "--help", "-V", "--version"}:
        invocation = [payload.manager, *arguments]  # type: ignore[attr-defined]
    else:
        invocation = [
            payload.manager,  # type: ignore[attr-defined]
            "--engine",
            payload.engine,  # type: ignore[attr-defined]
            *arguments,
        ]
    # `execv`, not `execve`, and deliberately: this shim IS the user's own
    # shell. Narrowing the environment here would break KSCOPE_PROFILE_HOME and
    # KALEIDOSCOPE_CONFIG_HOME, which the manager documents and honours, and
    # which the SDK's own child allowlist correctly does not forward -- because
    # the SDK is a library inside somebody else's process and this is not.
    os.execv(payload.manager, invocation)  # type: ignore[attr-defined]
    return 126


def engine_main() -> int:
    engine = _payload_or_message().engine  # type: ignore[attr-defined]
    os.execv(engine, [engine, *sys.argv[1:]])
    return 126
