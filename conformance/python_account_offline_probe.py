#!/usr/bin/env python3
"""Exercise the Python manager account facade without an OIDC provider or keychain."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from kaleidoscope_memory import ManagerAccountClient, ManagerAccountCommand

ACCOUNT_ENVIRONMENT = {
    "KALEIDOSCOPE_ACCOUNT_ORIGIN": "https://account.example.invalid/",
    "KALEIDOSCOPE_ACCOUNT_ISSUER": "https://issuer.example.invalid/",
    "KALEIDOSCOPE_ACCOUNT_AUDIENCE": "kaleidoscope-fixture",
    "KALEIDOSCOPE_ACCOUNT_CLIENT_ID": "kaleidoscope-native-fixture",
}
EXTERNAL_IDENTITY = "55555555-5555-4555-8555-555555555555"
DEVICE_ID = "33333333-3333-4333-8333-333333333333"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manager", type=Path, required=True)
    args = parser.parse_args()
    client = ManagerAccountClient(
        args.manager.resolve(strict=True),
        account_environment=ACCOUNT_ENVIRONMENT,
    )
    command_arguments = [
        ManagerAccountCommand.status().arguments,
        ManagerAccountCommand.login().arguments,
        ManagerAccountCommand.login(device=True).arguments,
        ManagerAccountCommand.logout().arguments,
        ManagerAccountCommand.logout(all_devices=True).arguments,
        ManagerAccountCommand.logout(local_only=True).arguments,
        ManagerAccountCommand.link("github").arguments,
        ManagerAccountCommand.identities().arguments,
        ManagerAccountCommand.unlink(EXTERNAL_IDENTITY).arguments,
        ManagerAccountCommand.revoke_session().arguments,
        ManagerAccountCommand.devices().arguments,
        ManagerAccountCommand.revoke_device(DEVICE_ID).arguments,
    ]
    status = client.status()
    results = [
        client.login(),
        client.login(device=True),
        client.logout(),
        client.logout(all_devices=True),
        client.logout(local_only=True),
        client.link("github"),
        client.identities(),
        client.unlink(EXTERNAL_IDENTITY),
        client.revoke_session(),
        client.devices(),
        client.revoke_device(DEVICE_ID),
    ]
    print(
        json.dumps(
            {
                "status": status.state,
                "stale": status.stale,
                "account_identity_present": status.account_id is not None,
                "command_count": len(command_arguments),
                "invocation_count": len(results) + 1,
                "engine_or_mcp_arguments_present": any(
                    value in {"--engine", "mcp", "call", "search", "remember"}
                    for arguments in command_arguments
                    for value in arguments
                ),
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
