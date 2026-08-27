"""Find the Kaleidoscope programs that are installed on this machine.

This package is a CLIENT. It does not contain the memory engine, it does not
install it, and it does not download it. `kscope` (the engine) and
`kaleidoscope` (the local manager) are installed separately, once, by the user;
everything here does is find them and hand back an absolute path.

That is a deliberate replacement for what this module used to do, which was to
import a platform wheel and ask it where its payload lived. The wheel was a
mandatory dependency that nothing built and no registry carried, so the package
could not be installed at all -- and a name that resolves to nothing on an index
is a name somebody else can claim. There is nothing to fall back to and nothing
to import: a program is on this machine or it is not.

RESOLUTION ORDER
----------------

Four steps, in this order, matching the manager's own `Engine::resolve`
(`src/engine.rs`) step for step. Two clients that disagree about where the
engine is are two clients that behave differently on the same machine, so the
order is copied rather than reinvented:

1. an explicit path passed by the caller;
2. ``$KALEIDOSCOPE_ENGINE`` (``$KALEIDOSCOPE_MANAGER`` for the manager),
   ignored when it is set but empty;
3. the directory this Python installs its own console scripts into, so a
   virtualenv that has both the SDK and the CLI works without touching `PATH`;
4. each directory on ``$PATH``, in order.

Steps 1 and 2 are AUTHORITATIVE. A caller who names a path, or exports the
environment variable, and gets it wrong is told exactly that -- the search does
not quietly continue and serve a different program, because "I found something
else" is the failure that is impossible to debug from the outside.

Every candidate is canonicalised BEFORE it is checked, and the canonical path is
what is returned and later executed. `npm i -g` installs every `bin` entry as a
symlink, so a resolver that refuses symlinks refuses the documented install
channel, and one that validates the link while running the target never
described what it ran.
"""

from __future__ import annotations

import os
import stat
import sysconfig
from dataclasses import dataclass
from pathlib import Path

from .errors import MissingBinaryError

#: The engine: the program that owns the vault and answers `search`/`remember`.
ENGINE_PROGRAM = "kscope"

#: The local manager: profiles, host wiring, account commands.
MANAGER_PROGRAM = "kaleidoscope"

ENGINE_ENVIRONMENT_VARIABLE = "KALEIDOSCOPE_ENGINE"
MANAGER_ENVIRONMENT_VARIABLE = "KALEIDOSCOPE_MANAGER"

#: The one command a user with nothing installed has to run. Both programs come
#: from this single package, so there is one instruction and not two.
INSTALL_COMMAND = "npm install -g @kleos-research/kaleidoscope"

#: How many `PATH` directories the not-found message lists before summarising.
#: A user with a 40-entry `PATH` needs to see that `PATH` was searched, not to
#: read all forty.
_MAX_LISTED_DIRECTORIES = 10


@dataclass(frozen=True, slots=True)
class LocatedProgram:
    """One resolved program, and which of the four steps produced it.

    `source` exists so a caller -- or a support conversation -- can answer "why
    is it running THAT one?" without re-deriving the search.
    """

    program: str
    path: str
    source: str


def _file_names(program: str) -> tuple[str, ...]:
    if os.name == "nt":
        return (f"{program}.exe", program)
    return (program,)


def _is_this_packages_console_script(path: Path) -> bool:
    """Is this candidate our own `kscope`/`kaleidoscope` shim?

    It always is, in any environment where this package is installed:
    `project.scripts` puts a `kscope` in exactly the directory step 3 searches
    and, once that directory is on `PATH`, in step 4 as well. Without this
    check the engine `kscope` shim resolves to itself and `os.execv`s in a loop,
    and a library caller spawns a child that does the same.

    The test is exact rather than a heuristic about scripts in general: a pip
    console script is a text file beginning `#!` whose body imports this
    package. A wrapper script somebody wrote around the real engine is not
    rejected, because it does not import us.
    """

    try:
        with path.open("rb") as handle:
            head = handle.read(4096)
    except OSError:
        return False
    return head.startswith(b"#!") and b"kaleidoscope_memory" in head


def _accept(path: Path, program: str, source: str) -> LocatedProgram | None:
    """Canonicalise, then validate what will actually be executed."""

    try:
        resolved = path.resolve(strict=True)
        mode = resolved.stat().st_mode
    except OSError:
        return None
    if not stat.S_ISREG(mode) or not os.access(resolved, os.X_OK):
        return None
    if _is_this_packages_console_script(resolved):
        return None
    return LocatedProgram(program=program, path=str(resolved), source=source)


def _scripts_directory() -> Path | None:
    directory = sysconfig.get_path("scripts")
    return Path(directory) if directory else None


def _path_directories() -> tuple[Path, ...]:
    entries = os.environ.get("PATH", "")
    return tuple(Path(entry) for entry in entries.split(os.pathsep) if entry)


def _explicit_failure(program: str, source: str, value: str) -> MissingBinaryError:
    return MissingBinaryError(
        f"Kaleidoscope could not use the {program} program at {value}.\n"
        f"It was named by {source}, so nothing else was tried.\n"
        f"That path must be an existing file you have permission to run.\n"
        f"Your local vault data is intact and unchanged."
    )


def _not_found_message(
    program: str,
    environment_variable: str,
    scripts_directory: Path | None,
    path_directories: tuple[Path, ...],
) -> str:
    looked: list[str] = []
    value = os.environ.get(environment_variable)
    if value:
        looked.append(f"  - {value} (from {environment_variable})")
    else:
        looked.append(f"  - the {environment_variable} setting, which is not set")
    if scripts_directory is not None:
        looked.append(f"  - {scripts_directory} (next to the Python running this)")
    if path_directories:
        for directory in path_directories[:_MAX_LISTED_DIRECTORIES]:
            looked.append(f"  - {directory} (on PATH)")
        remaining = len(path_directories) - _MAX_LISTED_DIRECTORIES
        if remaining > 0:
            looked.append(f"  - and {remaining} more director"
                          f"{'y' if remaining == 1 else 'ies'} on PATH")
    else:
        looked.append("  - PATH, which is empty")

    return (
        f"Kaleidoscope is not installed, or is installed somewhere this search did\n"
        f"not reach: the {program} program could not be found.\n"
        f"\n"
        f"Install it with:\n"
        f"\n"
        f"    {INSTALL_COMMAND}\n"
        f"\n"
        f"then check it with `{program} --version`.\n"
        f"\n"
        f"If it is already installed elsewhere, set {environment_variable} to its\n"
        f"full path.\n"
        f"\n"
        f"Looked for {program} in:\n"
        + "\n".join(looked)
    )


def locate_program(
    program: str,
    *,
    environment_variable: str,
    explicit: str | Path | None = None,
) -> LocatedProgram:
    """Run the four-step search for one program. See the module docstring."""

    if explicit is not None:
        located = _accept(Path(explicit), program, "argument")
        if located is None:
            raise _explicit_failure(program, "the path you passed", str(explicit))
        return located

    from_environment = os.environ.get(environment_variable)
    if from_environment:
        located = _accept(Path(from_environment), program, "environment")
        if located is None:
            raise _explicit_failure(program, environment_variable, from_environment)
        return located

    scripts_directory = _scripts_directory()
    path_directories = _path_directories()
    searched: list[tuple[Path, str]] = []
    if scripts_directory is not None:
        searched.append((scripts_directory, "beside-python"))
    searched.extend((directory, "path") for directory in path_directories)

    for directory, source in searched:
        for name in _file_names(program):
            located = _accept(directory / name, program, source)
            if located is not None:
                return located

    raise MissingBinaryError(
        _not_found_message(program, environment_variable, scripts_directory, path_directories)
    )


def locate_engine(explicit: str | Path | None = None) -> LocatedProgram:
    return locate_program(
        ENGINE_PROGRAM,
        environment_variable=ENGINE_ENVIRONMENT_VARIABLE,
        explicit=explicit,
    )


def locate_manager(explicit: str | Path | None = None) -> LocatedProgram:
    return locate_program(
        MANAGER_PROGRAM,
        environment_variable=MANAGER_ENVIRONMENT_VARIABLE,
        explicit=explicit,
    )


def installed_engine_path() -> str:
    """The engine's absolute canonical path, or `MissingBinaryError`."""

    return locate_engine().path


def installed_manager_path() -> str:
    """The manager's absolute canonical path, or `MissingBinaryError`."""

    return locate_manager().path
