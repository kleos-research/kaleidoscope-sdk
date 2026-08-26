from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from kaleidoscope_memory import (
    MissingPlatformPackageError,
    NATIVE_PACKAGE_TARGETS,
    UnsupportedPlatformError,
    installed_payload_paths,
    selected_native_module,
)


def test_package_selection_advertises_only_the_native_target() -> None:
    assert NATIVE_PACKAGE_TARGETS == (
        {
            "system": "Darwin",
            "machine": "arm64",
            "distribution": "kaleidoscope-memory-native-darwin-arm64",
            "module": "kaleidoscope_memory_native_darwin_arm64",
        },
    )
    assert selected_native_module("Darwin", "arm64") == "kaleidoscope_memory_native_darwin_arm64"
    assert selected_native_module("Darwin", "aarch64") == "kaleidoscope_memory_native_darwin_arm64"
    with pytest.raises(UnsupportedPlatformError):
        selected_native_module("Linux", "x86_64")


def test_missing_native_companion_is_a_typed_installation_failure() -> None:
    with pytest.raises(MissingPlatformPackageError):
        installed_payload_paths()


# ---------------------------------------------------------------------------
# The console scripts
# ---------------------------------------------------------------------------


def test_a_missing_native_companion_is_a_message_not_a_traceback() -> None:
    """Measured before this was fixed: twelve frames of internals, no instruction.

    Asserted on the ABSENCE of the word Traceback and on the PRESENCE of the
    package name. A bare `exit 1` would pass a weaker test, and so would a
    traceback that happens to mention the package.
    """

    import subprocess
    import sys

    completed = subprocess.run(
        [str(Path(sys.executable).parent / "kaleidoscope"), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    assert "Traceback" not in completed.stderr
    assert "kaleidoscope-memory-native-darwin-arm64" in completed.stderr
    assert "pip install" in completed.stderr


def test_the_console_script_is_a_passthrough_and_inherits_the_users_environment() -> None:
    """`execv`, pinned deliberately, with the reason attached.

    This shim IS the user's own shell, so it must not narrow the environment:
    KSCOPE_PROFILE_HOME and KALEIDOSCOPE_CONFIG_HOME are documented manager
    overrides that the SDK's child allowlist correctly does NOT forward -- the
    SDK is a library inside somebody else's process and this is not. Somebody
    "hardening" `execv` to `execve` here would break both, so the pin is a test
    that says why rather than a comment nobody reads.
    """

    import inspect

    from kaleidoscope_memory import cli

    source = inspect.getsource(cli)
    assert "os.execv(" in source
    assert "os.execve(" not in source
    assert "safe_bootstrap_environment" not in source
    assert "_ungated_environment" not in source


def test_the_package_ships_tools_and_not_examples() -> None:
    """`tools.py` is library; `examples/` is demonstration. Two directions.

    The second half runs from a directory OUTSIDE the repository, so pytest's
    `pythonpath = ["."]` -- the only reason `import examples` works in this
    suite at all -- cannot mask the answer. A user who pip-installs this package
    gets `kaleidoscope_memory.tools` and does not get `examples`.
    """

    import subprocess
    import sys
    import tomllib

    root = Path(__file__).parents[1]
    configuration = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    packages = configuration["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]
    assert packages == ["src/kaleidoscope_memory"]
    assert (root / "src" / "kaleidoscope_memory" / "tools.py").is_file()
    assert not (root / "src" / "kaleidoscope_memory" / "examples").exists()

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import kaleidoscope_memory.tools as t; print(t.KaleidoscopeMemory.__name__);"
            "\ntry:\n import examples\n print('LEAKED')\nexcept ModuleNotFoundError:\n"
            " print('absent')",
        ],
        cwd=tempfile.gettempdir(),
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.split() == ["KaleidoscopeMemory", "absent"]


def test_no_stale_wheel_is_lying_around() -> None:
    """A built artefact on disk is a thing somebody will measure against.

    There was one: `python/dist/*.whl` dated before `entitlement.py` existed,
    which `ImportError`ed at `__init__.py` on import and carried no
    `dist-info/licenses/`. It was removed rather than rebuilt, because a wheel
    in a working tree has no job -- the release build makes its own.
    """

    stale = sorted((Path(__file__).parents[1] / "dist").glob("*.whl"))

    assert stale == [], (
        f"{stale} predates whatever is in src/ right now; delete it or rebuild it, "
        f"and do not reason from it"
    )
