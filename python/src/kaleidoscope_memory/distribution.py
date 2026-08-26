"""Resolve the signed native companion installed beside the public wrapper."""

from __future__ import annotations

import importlib
import os
import platform
import stat
from dataclasses import dataclass
from pathlib import Path


class UnsupportedPlatformError(RuntimeError):
    """The current machine has no natively tested package coordinate."""


class MissingPlatformPackageError(RuntimeError):
    """The selected optional native wheel was not installed."""


class InvalidPlatformPackageError(RuntimeError):
    """The installed native wheel does not have the fixed payload layout."""


@dataclass(frozen=True, slots=True)
class InstalledPayloadPaths:
    manager: str
    engine: str
    manifest: str


NATIVE_PACKAGE_TARGETS = (
    {
        "system": "Darwin",
        "machine": "arm64",
        "distribution": "kaleidoscope-memory-native-darwin-arm64",
        "module": "kaleidoscope_memory_native_darwin_arm64",
    },
)


def selected_native_module(
    system: str | None = None,
    machine: str | None = None,
) -> str:
    system = system or platform.system()
    machine = machine or platform.machine()
    normalized_machine = "arm64" if machine == "aarch64" and system == "Darwin" else machine
    for target in NATIVE_PACKAGE_TARGETS:
        if target["system"] == system and target["machine"] == normalized_machine:
            return target["module"]
    supported = ", ".join(
        f'{target["system"]}/{target["machine"]}' for target in NATIVE_PACKAGE_TARGETS
    )
    raise UnsupportedPlatformError(
        f"Kaleidoscope has no natively tested package for {system}/{machine}; supported: {supported}"
    )


def _package_file(path: Path, label: str, *, executable: bool) -> str:
    try:
        resolved = path.resolve(strict=True)
        mode = resolved.stat().st_mode
    except OSError as exc:
        raise InvalidPlatformPackageError(
            f"installed platform package has no valid {label}"
        ) from exc
    if not stat.S_ISREG(mode) or (executable and not os.access(resolved, os.X_OK)):
        raise InvalidPlatformPackageError(
            f"installed platform package has no valid {label}"
        )
    return str(resolved)


def installed_payload_paths() -> InstalledPayloadPaths:
    module_name = selected_native_module()
    try:
        native = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name != module_name:
            raise InvalidPlatformPackageError(
                f"{module_name} could not load its payload locator"
            ) from exc
        raise MissingPlatformPackageError(
            f"{module_name.replace('_', '-')} is missing; install the matching native companion"
        ) from exc
    locator = getattr(native, "payload_paths", None)
    if not callable(locator):
        raise InvalidPlatformPackageError(
            f"{module_name} does not export its manager/engine/manifest locator"
        )
    value = locator()
    if not isinstance(value, dict) or set(value) != {"manager", "engine", "manifest"}:
        raise InvalidPlatformPackageError(f"{module_name} exports invalid payload paths")
    if any(not isinstance(value[key], str) for key in value):
        raise InvalidPlatformPackageError(f"{module_name} exports invalid payload paths")
    return InstalledPayloadPaths(
        manager=_package_file(Path(value["manager"]), "kaleidoscope manager", executable=True),
        engine=_package_file(Path(value["engine"]), "kscope engine", executable=True),
        manifest=_package_file(
            Path(value["manifest"]),
            "signed release manifest",
            executable=False,
        ),
    )


def installed_manager_path() -> str:
    return installed_payload_paths().manager


def installed_engine_path() -> str:
    return installed_payload_paths().engine
