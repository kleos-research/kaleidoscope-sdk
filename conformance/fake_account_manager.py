#!/usr/bin/env python3
"""Credential-free fixture for the manager's closed account JSON CLI."""

from __future__ import annotations

import json
import os
import sys

ACCOUNT_KEYS = (
    "KALEIDOSCOPE_ACCOUNT_ORIGIN",
    "KALEIDOSCOPE_ACCOUNT_ISSUER",
    "KALEIDOSCOPE_ACCOUNT_AUDIENCE",
    "KALEIDOSCOPE_ACCOUNT_CLIENT_ID",
)
ACCOUNT_ID = "11111111-1111-4111-8111-111111111111"
DEVICE_ID = "22222222-2222-4222-8222-222222222222"


def publish(value: object) -> None:
    print(json.dumps(value, separators=(",", ":"), sort_keys=True))


def main() -> int:
    if sys.stdin.buffer.read():
        raise SystemExit("manager account commands must not receive stdin payloads")
    forbidden = {
        "KALEIDOSCOPE_TOKEN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
    }
    if any(key in os.environ for key in forbidden) or any(
        key.startswith("KSCOPE_") for key in os.environ
    ):
        raise SystemExit("manager account command inherited forbidden authority")
    if not all(os.environ.get(key) for key in ACCOUNT_KEYS):
        print(
            "kaleidoscope: account provider is not configured; "
            "authorization=fixture-sensitive-value",
            file=sys.stderr,
        )
        return 2

    arguments = tuple(sys.argv[1:])
    if arguments == ("status", "--json"):
        publish(
            {
                "version": 1,
                "state": "signed_out",
                "account_id": None,
                "device_id": None,
                "stale": False,
            }
        )
    elif arguments in {("login",), ("login", "--device")}:
        publish(
            {
                "version": 1,
                "status": "signed_in",
                "account_id": ACCOUNT_ID,
                "device_id": DEVICE_ID,
            }
        )
    elif arguments in {
        ("logout",),
        ("logout", "--all-devices"),
        ("logout", "--local-only"),
        ("account", "revoke-session"),
    }:
        publish(
            {
                "version": 1,
                "status": "already_signed_out",
                "remote_revoked": False,
                "local_credential_removed": False,
                "warning": None,
            }
        )
    elif len(arguments) == 3 and arguments[:2] == ("account", "link"):
        publish(
            {
                "version": 1,
                "status": "fresh_auth_required",
                "verification_uri": "https://account.example.invalid/external-identities/verify",
                "expires_at": 1_900_000_120,
            }
        )
    elif len(arguments) == 3 and arguments[:2] == ("account", "unlink"):
        publish(
            {
                "version": 1,
                "status": "unlinked",
                "external_identity_id": arguments[2],
            }
        )
    elif arguments == ("account", "identities"):
        publish(
            {
                "version": 1,
                "external_identities": [
                    {
                        "external_identity_id": "55555555-5555-4555-8555-555555555555",
                        "issuer": "https://issuer.example.invalid/",
                        "linked_at": 1_900_000_000,
                    }
                ],
            }
        )
    elif arguments == ("devices", "list"):
        publish({"version": 1, "devices": []})
    elif len(arguments) == 3 and arguments[:2] == ("devices", "revoke"):
        publish({"version": 1, "status": "revoked", "device_id": arguments[2]})
    else:
        print("unsupported fake manager account command", file=sys.stderr)
        return 64
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
