from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--regenerate-entitlement-parity",
        action="store_true",
        default=False,
        help="rewrite reference/entitlement-behaviour-golden.json from observed behaviour",
    )


@pytest.fixture(scope="session")
def fake_binary() -> Path:
    path = Path(__file__).parent / "fixtures" / "fake_kscope_mcp.py"
    path.chmod(0o755)
    # The fixture's env shebang resolves the interpreter from PATH. Put the
    # currently tested environment first without passing that path in the v1
    # launch descriptor's deliberately empty environment field.
    os.environ["PATH"] = f"{Path(sys.executable).parent}{os.pathsep}{os.environ.get('PATH', '')}"
    return path.resolve()


@pytest.fixture(autouse=True)
def _reset_gate_status_cache() -> None:
    """Forget the memoised `kscope gate` answer between tests.

    Production keys the memo on (path, mtime, size), which is right for a real
    installation. The suite points ONE fixture path at several different engine
    configurations, so without this every test after the first would read the
    first one's answer -- and a stale "ungated" answer makes an entitlement test
    pass by not running the mechanism at all.
    """

    from kaleidoscope_memory.entitlement import clear_gate_status_cache

    clear_gate_status_cache()
