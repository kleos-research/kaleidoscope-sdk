"""Account commands for the public manager, separate from engine and MCP APIs."""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from uuid import UUID

from .descriptor import (
    _bounded_diagnostic,
    _canonical_executable,
    _ungated_environment,
)
from .errors import (
    ChildProcessError,
    DeadlineExceededError,
    ManagerCommandError,
    OutputLimitError,
    ProtocolError,
)

ACCOUNT_ENVIRONMENT_KEYS = (
    "KALEIDOSCOPE_ACCOUNT_ORIGIN",
    "KALEIDOSCOPE_ACCOUNT_ISSUER",
    "KALEIDOSCOPE_ACCOUNT_AUDIENCE",
    "KALEIDOSCOPE_ACCOUNT_CLIENT_ID",
)
_MANAGER_CONTEXT_KEYS = (
    "KALEIDOSCOPE_CONFIG_HOME",
    "KALEIDOSCOPE_USER_HOME",
)
_MAX_MANAGER_OUTPUT_BYTES = 64 * 1024
_PROVIDER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_STATUS_KEYS = frozenset({"version", "state", "account_id", "device_id", "stale"})


def _uuid(value: str | UUID, label: str) -> str:
    try:
        return str(UUID(str(value)))
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{label} must be a UUID") from exc


def _validate_account_arguments(arguments: tuple[str, ...]) -> None:
    if not isinstance(arguments, tuple) or any(
        not isinstance(value, str) for value in arguments
    ):
        raise ValueError("arguments must be an immutable string tuple")
    fixed = {
        ("status", "--json"),
        ("login",),
        ("login", "--device"),
        ("logout",),
        ("logout", "--all-devices"),
        ("logout", "--local-only"),
        ("account", "identities"),
        ("account", "revoke-session"),
        ("devices", "list"),
    }
    if arguments in fixed:
        return
    if len(arguments) == 3 and arguments[:2] == ("account", "link"):
        if _PROVIDER.fullmatch(arguments[2]) is not None:
            return
    if len(arguments) == 3 and arguments[:2] in {
        ("account", "unlink"),
        ("devices", "revoke"),
    }:
        _uuid(arguments[2], "manager account identifier")
        return
    raise ValueError("arguments are not a closed manager account command")


@dataclass(frozen=True, slots=True)
class ManagerAccountCommand:
    """One closed manager CLI invocation. It cannot carry a memory payload."""

    arguments: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_account_arguments(self.arguments)

    @classmethod
    def status(cls) -> "ManagerAccountCommand":
        return cls(("status", "--json"))

    @classmethod
    def login(cls, *, device: bool = False) -> "ManagerAccountCommand":
        return cls(("login", "--device") if device else ("login",))

    @classmethod
    def logout(
        cls,
        *,
        all_devices: bool = False,
        local_only: bool = False,
    ) -> "ManagerAccountCommand":
        if all_devices and local_only:
            raise ValueError("all_devices and local_only are mutually exclusive")
        suffix = (
            "--all-devices" if all_devices else "--local-only" if local_only else None
        )
        return cls(("logout", *([suffix] if suffix else [])))

    @classmethod
    def link(cls, provider: str) -> "ManagerAccountCommand":
        if _PROVIDER.fullmatch(provider) is None:
            raise ValueError("provider must be a portable identifier")
        return cls(("account", "link", provider))

    @classmethod
    def unlink(cls, external_identity_id: str | UUID) -> "ManagerAccountCommand":
        return cls(
            ("account", "unlink", _uuid(external_identity_id, "external_identity_id"))
        )

    @classmethod
    def identities(cls) -> "ManagerAccountCommand":
        return cls(("account", "identities"))

    @classmethod
    def revoke_session(cls) -> "ManagerAccountCommand":
        return cls(("account", "revoke-session"))

    @classmethod
    def devices(cls) -> "ManagerAccountCommand":
        return cls(("devices", "list"))

    @classmethod
    def revoke_device(cls, device_id: str | UUID) -> "ManagerAccountCommand":
        return cls(("devices", "revoke", _uuid(device_id, "device_id")))


@dataclass(frozen=True, slots=True)
class AccountStatus:
    """Closed version-1 projection returned by ``kaleidoscope status --json``."""

    version: int
    state: str
    account_id: str | None
    device_id: str | None
    stale: bool

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "AccountStatus":
        if set(value) != _STATUS_KEYS or type(value.get("version")) is not int:
            raise ProtocolError("manager status differs from the closed v1 shape")
        if value["version"] != 1 or type(value.get("stale")) is not bool:
            raise ProtocolError("manager status differs from the closed v1 shape")
        state = value.get("state")
        if not isinstance(state, str) or state not in {
            "signed_out",
            "online",
            "offline_stale",
            "revoked",
        }:
            raise ProtocolError("manager status has an unknown state")
        raw_account_id = value.get("account_id")
        raw_device_id = value.get("device_id")
        if (raw_account_id is None) != (raw_device_id is None):
            raise ProtocolError("manager status has a partial account identity")
        if raw_account_id is None:
            account_id = device_id = None
        elif isinstance(raw_account_id, str) and isinstance(raw_device_id, str):
            try:
                account_id = _uuid(raw_account_id, "account_id")
                device_id = _uuid(raw_device_id, "device_id")
            except ValueError as exc:
                raise ProtocolError(
                    "manager status has an invalid account identity"
                ) from exc
        else:
            raise ProtocolError("manager status has an invalid account identity")
        stale = value["stale"]
        if state in {"signed_out", "revoked"} and (account_id is not None or stale):
            raise ProtocolError("signed-out manager status retained account state")
        if state == "online" and (account_id is None or stale):
            raise ProtocolError("online manager status is internally inconsistent")
        if state == "offline_stale" and (account_id is None or not stale):
            raise ProtocolError("offline manager status is internally inconsistent")
        return cls(1, state, account_id, device_id, stale)


class ManagerAccountClient:
    """Invoke account-only manager JSON commands without resolving the engine."""

    def __init__(
        self,
        manager: str | Path,
        *,
        timeout_seconds: float = 30.0,
        account_environment: Mapping[str, str] | None = None,
    ) -> None:
        self.manager = _canonical_executable(str(manager))
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.timeout_seconds = timeout_seconds
        source = (
            {
                key: os.environ[key]
                for key in ACCOUNT_ENVIRONMENT_KEYS
                if key in os.environ
            }
            if account_environment is None
            else dict(account_environment)
        )
        unknown = set(source) - set(ACCOUNT_ENVIRONMENT_KEYS)
        if unknown:
            raise ValueError(f"unsupported account environment keys: {sorted(unknown)}")
        for key, value in source.items():
            if not isinstance(value, str) or not value or "\0" in value:
                raise ValueError(f"{key} must be a non-empty string")
        # The manager binary runs account commands only. None of them is in the
        # engine's gated command list and nothing in the manager reads
        # KALEIDOSCOPE_API_KEY, so this child is spawned without it.
        environment = _ungated_environment()
        # The same shellshock predicate `safe_bootstrap_environment` applies,
        # applied to these merges too. Without it the six manager keys reached
        # the child past the guard that function's own comment says covers every
        # value handed to a child -- an allowlisted name carrying an exported
        # function definition. The SDK never execs a shell, so this was never
        # exploitable here; it was a hole in a stated invariant, which is the
        # thing that goes unnoticed until something downstream does exec one.
        environment.update(
            {
                key: os.environ[key]
                for key in _MANAGER_CONTEXT_KEYS
                if key in os.environ and not os.environ[key].startswith("()")
            }
        )
        environment.update(
            {key: value for key, value in source.items() if not value.startswith("()")}
        )
        self._environment = environment

    def argv(self, command: ManagerAccountCommand) -> tuple[str, ...]:
        if not isinstance(command, ManagerAccountCommand):
            raise TypeError("command must be a ManagerAccountCommand")
        _validate_account_arguments(command.arguments)
        return (self.manager, *command.arguments)

    def invoke(
        self,
        command: ManagerAccountCommand,
        *,
        interactive: bool = False,
    ) -> dict[str, Any]:
        """Run one account command with empty stdin and a closed environment.

        Interactive mode streams the manager's browser/device instructions to
        the caller's terminal while retaining stdout for the final JSON result.
        """

        try:
            completed = subprocess.run(
                self.argv(command),
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=None if interactive else subprocess.PIPE,
                env=self._environment,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise DeadlineExceededError("manager account command timed out") from exc
        except OSError as exc:
            raise ChildProcessError("manager account command could not start") from exc
        if (
            len(completed.stdout) > _MAX_MANAGER_OUTPUT_BYTES
            or len(completed.stderr or b"") > _MAX_MANAGER_OUTPUT_BYTES
        ):
            raise OutputLimitError("manager account output exceeded 65536 bytes")
        if completed.returncode != 0:
            raise ManagerCommandError(
                command.arguments,
                completed.returncode,
                _bounded_diagnostic(completed.stderr or b""),
            )
        try:
            value = json.loads(completed.stdout)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ProtocolError(
                "manager account command did not return one JSON value"
            ) from exc
        if not isinstance(value, dict) or type(value.get("version")) is not int:
            raise ProtocolError(
                "manager account command did not return a versioned object"
            )
        if value["version"] != 1:
            raise ProtocolError(
                "manager account command returned an unsupported version"
            )
        return value

    def status(self) -> AccountStatus:
        return AccountStatus.from_mapping(self.invoke(ManagerAccountCommand.status()))

    def login(self, *, device: bool = False) -> dict[str, Any]:
        return self.invoke(ManagerAccountCommand.login(device=device), interactive=True)

    def logout(
        self,
        *,
        all_devices: bool = False,
        local_only: bool = False,
    ) -> dict[str, Any]:
        return self.invoke(
            ManagerAccountCommand.logout(
                all_devices=all_devices,
                local_only=local_only,
            )
        )

    def link(self, provider: str) -> dict[str, Any]:
        return self.invoke(ManagerAccountCommand.link(provider), interactive=True)

    def unlink(self, external_identity_id: str | UUID) -> dict[str, Any]:
        return self.invoke(ManagerAccountCommand.unlink(external_identity_id))

    def identities(self) -> dict[str, Any]:
        return self.invoke(ManagerAccountCommand.identities())

    def revoke_session(self) -> dict[str, Any]:
        """Revoke only the current token family; this does not deactivate an account."""

        return self.invoke(ManagerAccountCommand.revoke_session())

    def devices(self) -> dict[str, Any]:
        return self.invoke(ManagerAccountCommand.devices())

    def revoke_device(self, device_id: str | UUID) -> dict[str, Any]:
        return self.invoke(ManagerAccountCommand.revoke_device(device_id))
