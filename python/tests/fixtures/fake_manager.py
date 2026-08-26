#!/usr/bin/env python3
"""Test-only manager stand-in that reports the environment it was handed.

`conformance/fake_account_manager.py` is the behavioural double for the account
commands and answers them properly. This one answers `status --json` with the
minimum the client will accept and exists for exactly one purpose: to say, from
INSIDE the child, which environment variables it received.

That distinction is the whole point. "The SDK did not put the key in that call"
is a claim about the parent and is checked by reading the parent's source. "The
manager child never saw the key" is the property, and only the child can report
it.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

#: The record lands beside the manager's own config home, which is one of the
#: two manager context names the client forwards. A dedicated variable of its
#: own was tried first and never arrived: the allowlist does not name it. The
#: instrument could not be plumbed in by the route it was measuring, which is
#: the neatest available proof that the route is closed.
RECORD_DIRECTORY_VARIABLE = "KALEIDOSCOPE_CONFIG_HOME"
RECORD_NAME = "fixture-environment.jsonl"


def main() -> int:
    target = os.environ.get(RECORD_DIRECTORY_VARIABLE)
    if target:
        path = Path(target) / RECORD_NAME
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as output:
            output.write(
                json.dumps(
                    {
                        "command": "manager",
                        "pid": os.getpid(),
                        "argv": sys.argv,
                        # Compared by the test, never echoed.
                        "api_key_seen": bool(os.environ.get("KALEIDOSCOPE_API_KEY")),
                        "environment_names": sorted(os.environ),
                    },
                    separators=(",", ":"),
                )
                + "\n"
            )
    print(
        json.dumps(
            {
                "version": 1,
                "state": "signed_out",
                "account_id": None,
                "device_id": None,
                "stale": False,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
