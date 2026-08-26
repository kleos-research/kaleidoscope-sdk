#!/bin/sh
# Install only the ignored test-only Python runtime used by the TypeScript MCP
# fixture. This never installs a Kaleidoscope engine or writes account state.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_python=${KSCOPE_TEST_PYTHON:-python3}
venv_python="$repo_dir/python/.venv/bin/python"

"$test_python" -m venv "$repo_dir/python/.venv"
"$venv_python" -m pip install --disable-pip-version-check "mcp==1.29.0"

(cd "$repo_dir/typescript" && npm ci)

printf '%s\n' "TypeScript test prerequisites are ready. Run: cd typescript && npm test"
