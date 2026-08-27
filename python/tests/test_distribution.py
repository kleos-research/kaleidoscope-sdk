"""Locating the separately installed Kaleidoscope programs.

Every not-found assertion here plants an EMPTY search space and then plants a
findable program in it. Both directions, deliberately.

The suite this replaces asserted only that the engine was absent -- a raised
error, and a console script exiting 1. That test reported the opposite thing
depending on whether the product happened to be installed on the machine
running it: `kscope` is on `PATH` on the author's machine, so a PATH-aware
resolver turns "absent" into "found" there while it still reads "absent" in a
clean CI container. A closed door is not evidence when the door cannot open.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from kaleidoscope_memory import (
    ENGINE_ENVIRONMENT_VARIABLE,
    ENGINE_PROGRAM,
    INSTALL_COMMAND,
    MANAGER_ENVIRONMENT_VARIABLE,
    MANAGER_PROGRAM,
    MissingBinaryError,
    installed_engine_path,
    installed_manager_path,
    locate_engine,
    locate_manager,
)
from kaleidoscope_memory import distribution


#: What a planted stand-in engine does when it is run: echo its arguments, so
#: an `execv` that reached it is visible in stdout.
#:
#: A `#!/bin/sh` script rather than a copy of a system binary, for two reasons.
#: A copied Apple-signed executable is SIGKILLed on Apple Silicon, so the
#: mirror-image "it ran the thing it found" test could not run at all. And the
#: resolver rejects this package's OWN console-script shims by their `#!` shape
#: plus the package name in the body -- planting a script here proves that
#: rejection is that narrow, rather than a blanket refusal of every script.
_STAND_IN = '#!/bin/sh\nprintf \'%s\' "$1"\n'


@pytest.fixture
def empty_search_space(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """No engine, no manager, anywhere the four-step search can reach.

    `PATH` is pointed at an empty directory, the console-script directory is
    pointed at another, and both environment overrides are cleared. Without
    this the answer depends on the machine.
    """

    somewhere_empty = tmp_path / "empty-path"
    somewhere_empty.mkdir()
    scripts = tmp_path / "empty-scripts"
    scripts.mkdir()
    monkeypatch.setenv("PATH", str(somewhere_empty))
    monkeypatch.delenv(ENGINE_ENVIRONMENT_VARIABLE, raising=False)
    monkeypatch.delenv(MANAGER_ENVIRONMENT_VARIABLE, raising=False)
    monkeypatch.setattr(distribution, "_scripts_directory", lambda: scripts)
    return somewhere_empty


def _plant(directory: Path, name: str) -> Path:
    planted = directory / name
    planted.write_text(_STAND_IN, encoding="utf-8")
    planted.chmod(0o755)
    return planted


# ---------------------------------------------------------------------------
# The four steps, each proven to fire
# ---------------------------------------------------------------------------


def test_an_explicit_path_wins_over_everything_else(
    empty_search_space: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    named = _plant(tmp_path, "named-engine")
    decoy = _plant(empty_search_space, ENGINE_PROGRAM)
    monkeypatch.setenv(ENGINE_ENVIRONMENT_VARIABLE, str(decoy))

    located = locate_engine(named)

    assert located.path == str(named.resolve())
    assert located.source == "argument"
    assert located.program == ENGINE_PROGRAM


def test_the_environment_variable_wins_over_the_search(
    empty_search_space: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chosen = _plant(tmp_path, "chosen-engine")
    _plant(empty_search_space, ENGINE_PROGRAM)
    monkeypatch.setenv(ENGINE_ENVIRONMENT_VARIABLE, str(chosen))

    located = locate_engine()

    assert located.path == str(chosen.resolve())
    assert located.source == "environment"


def test_an_empty_environment_variable_is_ignored_rather_than_obeyed(
    empty_search_space: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`export KALEIDOSCOPE_ENGINE=` is an unset variable, not a demand for "".

    The manager's own resolver filters the empty value out (`src/engine.rs`);
    a client that instead refused would make an inherited empty export fatal.
    """

    planted = _plant(empty_search_space, ENGINE_PROGRAM)
    monkeypatch.setenv(ENGINE_ENVIRONMENT_VARIABLE, "")

    located = locate_engine()

    assert located.path == str(planted.resolve())
    assert located.source == "path"


def test_a_program_beside_this_python_is_found_before_path(
    empty_search_space: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    scripts = tmp_path / "empty-scripts"
    beside = _plant(scripts, ENGINE_PROGRAM)
    _plant(empty_search_space, ENGINE_PROGRAM)

    located = locate_engine()

    assert located.path == str(beside.resolve())
    assert located.source == "beside-python"


def test_a_program_on_path_is_found(empty_search_space: Path) -> None:
    planted = _plant(empty_search_space, ENGINE_PROGRAM)

    located = locate_engine()

    assert located.path == str(planted.resolve())
    assert located.source == "path"
    assert installed_engine_path() == str(planted.resolve())


def test_the_manager_is_located_by_its_own_name_and_variable(
    empty_search_space: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    planted = _plant(empty_search_space, MANAGER_PROGRAM)
    assert locate_manager().path == str(planted.resolve())
    assert installed_manager_path() == str(planted.resolve())

    chosen = _plant(tmp_path, "chosen-manager")
    monkeypatch.setenv(MANAGER_ENVIRONMENT_VARIABLE, str(chosen))
    assert locate_manager().source == "environment"
    # And the engine's variable does not steer the manager.
    monkeypatch.setenv(ENGINE_ENVIRONMENT_VARIABLE, str(chosen))
    monkeypatch.delenv(MANAGER_ENVIRONMENT_VARIABLE)
    assert locate_manager().path == str(planted.resolve())


def test_a_symlinked_program_on_path_is_used_and_returned_canonicalised(
    empty_search_space: Path, tmp_path: Path
) -> None:
    """`npm i -g` installs every `bin` entry as a symlink.

    A resolver that refuses symlinks refuses the documented install channel.
    The canonical target is what is returned, so what is validated here is what
    is executed later.
    """

    real = _plant(tmp_path, "real-engine")
    (empty_search_space / ENGINE_PROGRAM).symlink_to(real)

    assert locate_engine().path == str(real.resolve())


# ---------------------------------------------------------------------------
# The failure that will actually happen to users
# ---------------------------------------------------------------------------


def test_a_missing_engine_names_what_where_and_the_fix(empty_search_space: Path) -> None:
    with pytest.raises(MissingBinaryError) as missing:
        locate_engine()

    message = str(missing.value)
    assert ENGINE_PROGRAM in message
    assert INSTALL_COMMAND in message, "the message does not carry the one command that fixes it"
    assert str(empty_search_space) in message, "the message does not say where it looked"
    assert ENGINE_ENVIRONMENT_VARIABLE in message, "the message does not offer the override"
    assert "Traceback" not in message
    # User-facing copy: no module paths, no wheel names, no internals.
    assert "kaleidoscope_memory" not in message
    assert "wheel" not in message


def test_a_missing_manager_names_the_manager_not_the_engine(empty_search_space: Path) -> None:
    with pytest.raises(MissingBinaryError) as missing:
        locate_manager()

    message = str(missing.value)
    assert MANAGER_PROGRAM in message
    assert MANAGER_ENVIRONMENT_VARIABLE in message
    assert INSTALL_COMMAND in message


def test_an_explicit_path_that_is_wrong_is_refused_rather_than_searched_past(
    empty_search_space: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A named path that does not work must not silently run something else.

    "I found a different one" is the failure nobody can debug from outside, so
    steps 1 and 2 are authoritative: they succeed or they refuse.
    """

    _plant(empty_search_space, ENGINE_PROGRAM)
    absent = tmp_path / "not-here"

    with pytest.raises(MissingBinaryError, match="not-here"):
        locate_engine(absent)

    monkeypatch.setenv(ENGINE_ENVIRONMENT_VARIABLE, str(absent))
    with pytest.raises(MissingBinaryError) as missing:
        locate_engine()
    assert ENGINE_ENVIRONMENT_VARIABLE in str(missing.value)


def test_a_non_executable_file_is_not_accepted_as_the_engine(
    empty_search_space: Path,
) -> None:
    unrunnable = empty_search_space / ENGINE_PROGRAM
    unrunnable.write_text("not a program\n", encoding="utf-8")
    unrunnable.chmod(0o644)

    with pytest.raises(MissingBinaryError):
        locate_engine()


def test_a_directory_named_kscope_is_not_accepted_as_the_engine(
    empty_search_space: Path,
) -> None:
    (empty_search_space / ENGINE_PROGRAM).mkdir()

    with pytest.raises(MissingBinaryError):
        locate_engine()


def test_this_packages_own_console_script_is_never_resolved_as_the_engine(
    empty_search_space: Path, tmp_path: Path
) -> None:
    """Otherwise `kscope` execs itself, forever.

    `project.scripts` installs a `kscope` shim into exactly the directory step
    3 searches, and onto `PATH` with it. Without this the console script
    resolves to itself and loops, and a library caller spawns a child that
    does. The rejection is exact -- a `#!` file that imports this package --
    so a user's own wrapper script around the real engine still resolves.
    """

    shim = empty_search_space / ENGINE_PROGRAM
    shim.write_text(
        f"#!{sys.executable}\nfrom kaleidoscope_memory.cli import engine_main\n",
        encoding="utf-8",
    )
    shim.chmod(0o755)

    with pytest.raises(MissingBinaryError):
        locate_engine()

    other = tmp_path / "wrapper"
    other.mkdir()
    wrapper = other / ENGINE_PROGRAM
    wrapper.write_text("#!/bin/sh\nexec /somewhere/kscope \"$@\"\n", encoding="utf-8")
    wrapper.chmod(0o755)
    assert locate_engine(wrapper).path == str(wrapper.resolve())


def test_the_search_order_survives_an_empty_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    monkeypatch.setenv("PATH", "")
    monkeypatch.delenv(ENGINE_ENVIRONMENT_VARIABLE, raising=False)
    monkeypatch.setattr(distribution, "_scripts_directory", lambda: scripts)

    with pytest.raises(MissingBinaryError, match="PATH, which is empty"):
        locate_engine()

    planted = _plant(scripts, ENGINE_PROGRAM)
    assert locate_engine().path == str(planted.resolve())


# ---------------------------------------------------------------------------
# The console scripts
# ---------------------------------------------------------------------------


def _console_script(name: str) -> Path:
    return Path(sys.executable).parent / name


def _clean_environment(search_root: Path) -> dict[str, str]:
    environment = dict(os.environ)
    environment["PATH"] = str(search_root)
    environment.pop(ENGINE_ENVIRONMENT_VARIABLE, None)
    environment.pop(MANAGER_ENVIRONMENT_VARIABLE, None)
    return environment


@pytest.mark.parametrize(
    ("script", "variable"),
    [("kaleidoscope", MANAGER_ENVIRONMENT_VARIABLE), ("kscope", ENGINE_ENVIRONMENT_VARIABLE)],
)
def test_a_missing_program_is_a_message_not_a_traceback(
    script: str, variable: str, tmp_path: Path
) -> None:
    """Measured before this was fixed: twelve frames of internals, no instruction.

    Asserted on the ABSENCE of the word Traceback and on the PRESENCE of the
    install command. A bare `exit 1` would pass a weaker test, and so would a
    traceback that happens to name the program.
    """

    empty = tmp_path / "empty"
    empty.mkdir()
    completed = subprocess.run(
        [str(_console_script(script)), "--help"],
        capture_output=True,
        text=True,
        check=False,
        env=_clean_environment(empty),
    )

    assert completed.returncode == 1
    assert "Traceback" not in completed.stderr
    assert INSTALL_COMMAND in completed.stderr
    assert variable in completed.stderr


@pytest.mark.parametrize("script", ["kaleidoscope", "kscope"])
def test_the_console_script_runs_the_program_it_finds(script: str, tmp_path: Path) -> None:
    """The mirror image of the test above, and the reason it is trustworthy.

    A console script that exits 1 unconditionally would satisfy every
    missing-binary assertion in this file. This one plants a real executable
    where the search must reach it and requires the shim to `execv` it -- so
    "not found" is a claim that can be falsified.
    """

    found = tmp_path / "found"
    found.mkdir()
    _plant(found, script)

    completed = subprocess.run(
        [str(_console_script(script)), "hello-from-the-located-program"],
        capture_output=True,
        text=True,
        check=False,
        env=_clean_environment(found),
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "hello-from-the-located-program"


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
