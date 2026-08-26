#!/usr/bin/env python3
"""Run credential-free native host management and generic MCP discovery.

This lane deliberately never invokes a model, account command, browser, IDE, or
network-dependent operation. It proves only the local CLI/configuration behavior
reported in its evidence manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

SCHEMA_VERSION = "kaleidoscope.dx10b-native-host-local-evidence.v1"
SDK_SOURCE_COMMIT = "05948a3acfbf0a325f06ecfe6057db484f02e5a1"
ENGINE_SOURCE_COMMIT = "d96355632cc52816472106d0776ce63d73631fef"
ISOLATED_CANDIDATE_SHA256 = (
    "988192ac9677d5dd55a3642b2da493a0806bb860b5b3c0f509b37ddadee08825"
)
PUBLIC_CONTRACT_SHA256 = (
    "a2357ed6c00e3e143d08581590571447e31d24fd0e7d2466d28a211a0515c75e"
)
MCP_PROTOCOL_REVISION = "2025-11-25"
EXPECTED_TOOLS = ("search", "remember")
CODEX_MCP_DOCUMENTATION = "https://developers.openai.com/codex/mcp"
RAW_COORDINATE = re.compile(
    r"\b(?:wsp|usr)_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
    r"|\bjournal:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class HostDefinition:
    evidence_name: str
    executable_names: tuple[str, ...]
    adapter: str | None


HOST_DEFINITIONS = {
    "codex": HostDefinition("codex", ("codex",), "codex-mcp-cli"),
    "claude-code": HostDefinition("claude_code", ("claude",), None),
    "cursor": HostDefinition("cursor", ("cursor", "cursor-agent"), None),
    "opencode": HostDefinition("opencode", ("opencode",), None),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manager", type=Path, required=True)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--manager-provenance", type=Path, required=True)
    parser.add_argument("--codex", type=Path)
    parser.add_argument(
        "--host-binary",
        action="append",
        default=[],
        metavar="HOST=PATH",
        help=(
            "override host inventory; supported host names are codex, "
            "claude-code, cursor, opencode"
        ),
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_object(payload: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise AssertionError(f"{label} did not return JSON") from error
    if not isinstance(value, dict):
        raise AssertionError(f"{label} did not return one object")
    return value


def parse_array(payload: str, label: str) -> list[Any]:
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise AssertionError(f"{label} did not return JSON") from error
    if not isinstance(value, list):
        raise AssertionError(f"{label} did not return one array")
    return value


def run_process(
    argv: Sequence[str | os.PathLike[str]],
    *,
    env: Mapping[str, str],
    cwd: Path | None = None,
    input_text: str | None = None,
    timeout: float = 60,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        [os.fspath(value) for value in argv],
        check=False,
        capture_output=True,
        text=True,
        input=input_text,
        env=dict(env),
        cwd=cwd,
        timeout=timeout,
    )
    if completed.returncode != 0:
        diagnostic = completed.stderr[-2048:].replace("\n", " ").strip()
        raise AssertionError(
            f"command {Path(os.fspath(argv[0])).name!r} exited "
            f"{completed.returncode}: {diagnostic}"
        )
    return completed


def tree_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    if not root.exists():
        digest.update(b"missing")
        return digest.hexdigest()
    for path in sorted(root.rglob("*"), key=lambda value: value.as_posix()):
        relative = path.relative_to(root).as_posix().encode()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        if path.is_symlink():
            digest.update(b"symlink")
            digest.update(os.readlink(path).encode())
        elif path.is_file():
            digest.update(b"file")
            digest.update(path.read_bytes())
        elif path.is_dir():
            digest.update(b"directory")
        else:
            digest.update(b"other")
    return digest.hexdigest()


def assert_private_values_absent(
    payloads: Sequence[bytes | str], *, private_values: Sequence[str]
) -> None:
    for payload in payloads:
        text = payload.decode("utf-8") if isinstance(payload, bytes) else payload
        for value in private_values:
            if value and value in text:
                raise AssertionError("a private runtime value reached public evidence")
        if RAW_COORDINATE.search(text):
            raise AssertionError("a raw vault identity reached public evidence")


def validate_repository_base(repository: Path) -> None:
    completed = subprocess.run(
        ["git", "merge-base", "--is-ancestor", SDK_SOURCE_COMMIT, "HEAD"],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if completed.returncode != 0:
        raise AssertionError("runner checkout is not based on the frozen SDK commit")


def validate_manager_provenance(
    path: Path, *, manager_sha256: str, engine_sha256: str
) -> str:
    provenance = parse_object(path.read_text(), "manager provenance")
    predicate = provenance.get("predicate")
    if not isinstance(predicate, dict):
        raise AssertionError("manager provenance omitted its predicate")
    build_definition = predicate.get("buildDefinition")
    if not isinstance(build_definition, dict):
        raise AssertionError("manager provenance omitted its build definition")
    dependencies = build_definition.get("resolvedDependencies")
    if not isinstance(dependencies, list):
        raise AssertionError("manager provenance omitted resolved dependencies")
    manager_source_verified = any(
        isinstance(item, dict)
        and item.get("uri") == "urn:kaleidoscope:public-manager-source"
        and isinstance(item.get("digest"), dict)
        and item["digest"].get("gitCommit") == SDK_SOURCE_COMMIT
        for item in dependencies
    )
    if not manager_source_verified:
        raise AssertionError("manager provenance is not bound to the frozen SDK commit")

    subjects = provenance.get("subject")
    if not isinstance(subjects, list):
        raise AssertionError("manager provenance omitted subjects")
    required_subjects = {
        "bin/kaleidoscope": manager_sha256,
        "libexec/kaleidoscope/kscope": engine_sha256,
    }
    for name, expected in required_subjects.items():
        if not any(
            isinstance(item, dict)
            and item.get("name") == name
            and isinstance(item.get("digest"), dict)
            and item["digest"].get("sha256") == expected
            for item in subjects
        ):
            raise AssertionError(f"manager provenance does not bind {name}")
    return sha256_file(path)


def parse_host_overrides(values: Sequence[str]) -> dict[str, Path]:
    overrides: dict[str, Path] = {}
    for value in values:
        name, separator, raw_path = value.partition("=")
        if not separator or name not in HOST_DEFINITIONS or not raw_path:
            raise AssertionError("--host-binary must be one supported HOST=PATH pair")
        if name in overrides:
            raise AssertionError(f"duplicate host override for {name}")
        overrides[name] = Path(raw_path).expanduser().resolve(strict=True)
    return overrides


def resolve_host_binary(
    name: str, *, overrides: Mapping[str, Path], codex: Path | None
) -> Path | None:
    if name in overrides:
        return overrides[name]
    if name == "codex" and codex is not None:
        return codex.expanduser().resolve(strict=True)
    definition = HOST_DEFINITIONS[name]
    for executable in definition.executable_names:
        resolved = shutil.which(executable)
        if resolved:
            return Path(resolved).resolve(strict=True)
    if name == "codex" and platform.system() == "Darwin":
        bundled = Path("/Applications/ChatGPT.app/Contents/Resources/codex")
        if bundled.is_file() and os.access(bundled, os.X_OK):
            return bundled.resolve(strict=True)
    return None


def minimal_environment(root: Path) -> dict[str, str]:
    home = root / "home"
    codex_home = root / "codex-home"
    manager_config = root / "manager-config"
    manager_data = root / "manager-data"
    xdg_config = root / "xdg-config"
    xdg_data = root / "xdg-data"
    xdg_cache = root / "xdg-cache"
    temporary = root / "tmp"
    for directory in (
        home,
        codex_home,
        manager_config,
        manager_data,
        xdg_config,
        xdg_data,
        xdg_cache,
        temporary,
    ):
        directory.mkdir(parents=True)
    return {
        "HOME": str(home),
        "USERPROFILE": str(home),
        "CODEX_HOME": str(codex_home),
        "KALEIDOSCOPE_USER_HOME": str(home),
        "KALEIDOSCOPE_CONFIG_HOME": str(manager_config),
        "KALEIDOSCOPE_DATA_HOME": str(manager_data),
        "XDG_CONFIG_HOME": str(xdg_config),
        "XDG_DATA_HOME": str(xdg_data),
        "XDG_CACHE_HOME": str(xdg_cache),
        "TMPDIR": str(temporary),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "SHELL": "/bin/sh",
        "TERM": "dumb",
        "USER": "dx10b-local",
        "LOGNAME": "dx10b-local",
        "NO_COLOR": "1",
        "HTTP_PROXY": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "ALL_PROXY": "http://127.0.0.1:9",
        "NO_PROXY": "",
    }


def validate_codex_server(
    server: Mapping[str, Any], *, engine: Path, profile: str, includes_tools: bool
) -> None:
    if server.get("name") != "kaleidoscope" or server.get("enabled") is not True:
        raise AssertionError("Codex did not return the enabled Kaleidoscope server")
    transport = server.get("transport")
    if not isinstance(transport, dict):
        raise AssertionError("Codex server omitted its transport")
    if (
        transport.get("type") != "stdio"
        or transport.get("command") != str(engine)
        or transport.get("args") != ["mcp", "--profile", profile]
        or transport.get("env") is not None
        or transport.get("env_vars") != []
        or transport.get("cwd") is not None
    ):
        raise AssertionError("Codex returned a divergent stdio launch descriptor")
    if includes_tools and (
        server.get("enabled_tools") is not None
        or server.get("disabled_tools") is not None
    ):
        raise AssertionError("Codex CLI add unexpectedly wrote a tool policy")


def run_codex_cli_lane(
    codex: Path,
    *,
    engine: Path,
    profile: str,
    environment: Mapping[str, str],
    project: Path,
    private_values: Sequence[str],
) -> dict[str, Any]:
    codex_home = Path(environment["CODEX_HOME"])
    config = codex_home / "config.toml"
    baseline = b'# existing local fixture\nmodel = "fixture-model"\n'
    config.write_bytes(baseline)
    project_before = tree_fingerprint(project)

    version = run_process([codex, "--version"], env=environment, cwd=project).stdout.strip()
    help_text = run_process(
        [codex, "mcp", "--help"], env=environment, cwd=project
    ).stdout
    for command in ("add", "list", "get", "remove"):
        if command not in help_text:
            raise AssertionError(f"Codex MCP help omitted {command}")

    initial = parse_array(
        run_process(
            [codex, "mcp", "list", "--json"], env=environment, cwd=project
        ).stdout,
        "initial Codex MCP list",
    )
    if initial:
        raise AssertionError("isolated Codex home was not empty before registration")

    run_process(
        [
            codex,
            "mcp",
            "add",
            "kaleidoscope",
            "--",
            engine,
            "mcp",
            "--profile",
            profile,
        ],
        env=environment,
        cwd=project,
    )
    configured = config.read_bytes()
    if not configured or configured == baseline:
        raise AssertionError("Codex MCP add did not change the isolated configuration")
    assert_private_values_absent([configured], private_values=private_values)
    configured_text = configured.decode("utf-8")
    if "[mcp_servers.kaleidoscope.env]" in configured_text or re.search(
        r"(?m)^\s*(?:env|env_vars)\s*=", configured_text
    ):
        raise AssertionError("Codex configuration carried environment fields")

    listed = parse_array(
        run_process(
            [codex, "mcp", "list", "--json"], env=environment, cwd=project
        ).stdout,
        "Codex MCP list",
    )
    if len(listed) != 1 or not isinstance(listed[0], dict):
        raise AssertionError("Codex MCP list did not return exactly one server")
    validate_codex_server(listed[0], engine=engine, profile=profile, includes_tools=False)

    selected = parse_object(
        run_process(
            [codex, "mcp", "get", "kaleidoscope", "--json"],
            env=environment,
            cwd=project,
        ).stdout,
        "Codex MCP get",
    )
    validate_codex_server(selected, engine=engine, profile=profile, includes_tools=True)
    assert_private_values_absent(
        [json.dumps(listed), json.dumps(selected)], private_values=private_values
    )

    run_process(
        [codex, "mcp", "remove", "kaleidoscope"],
        env=environment,
        cwd=project,
    )
    if config.read_bytes() != baseline:
        raise AssertionError("Codex MCP remove was not a byte-exact rollback")
    final = parse_array(
        run_process(
            [codex, "mcp", "list", "--json"], env=environment, cwd=project
        ).stdout,
        "final Codex MCP list",
    )
    if final:
        raise AssertionError("Codex MCP remove left a configured server")
    if tree_fingerprint(project) != project_before:
        raise AssertionError("Codex user-scope commands changed the disposable project")

    return {
        "status": "pass",
        "acceptance_level": "native_cli_configuration_only",
        "version": version,
        "binary_sha256": sha256_file(codex),
        "commands": ["add", "list", "get", "remove"],
        "transport": "stdio",
        "isolated_codex_home": True,
        "configuration_environment_fields": False,
        "vault_coordinates_in_configuration": False,
        "byte_exact_remove_rollback": True,
        "project_unchanged": True,
        "model_invocations": 0,
        "account_commands_invoked": False,
        "tui_or_ide_invoked": False,
    }


def extract_exact_tool_names(response: Mapping[str, Any]) -> list[str]:
    result = response.get("result")
    if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
        raise AssertionError("MCP tools/list omitted its tools array")
    tools = result["tools"]
    names = [tool.get("name") for tool in tools if isinstance(tool, dict)]
    if len(names) != len(tools) or any(not isinstance(name, str) for name in names):
        raise AssertionError("MCP tools/list returned an invalid tool name")
    if len(names) != len(set(names)) or set(names) != set(EXPECTED_TOOLS):
        raise AssertionError(
            f"MCP discovery must expose exactly {list(EXPECTED_TOOLS)!r}; got {names!r}"
        )
    return list(EXPECTED_TOOLS)


def run_generic_mcp_discovery(
    engine: Path, *, profile: str, environment: Mapping[str, str]
) -> dict[str, Any]:
    messages = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_REVISION,
                "capabilities": {},
                "clientInfo": {
                    "name": "kaleidoscope-dx10b-host-conformance",
                    "version": "1",
                },
            },
        },
        {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        },
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    payload = "".join(
        json.dumps(message, sort_keys=True, separators=(",", ":")) + "\n"
        for message in messages
    )
    completed = run_process(
        [engine, "mcp", "--profile", profile],
        env=environment,
        input_text=payload,
        timeout=30,
    )
    try:
        responses = [json.loads(line) for line in completed.stdout.splitlines() if line]
    except json.JSONDecodeError as error:
        raise AssertionError("generic MCP discovery returned non-JSON output") from error
    by_id = {
        response.get("id"): response
        for response in responses
        if isinstance(response, dict) and "id" in response
    }
    initialize = by_id.get(1)
    tools_response = by_id.get(2)
    if not isinstance(initialize, dict) or not isinstance(tools_response, dict):
        raise AssertionError("generic MCP discovery omitted a response")
    initialize_result = initialize.get("result")
    if (
        not isinstance(initialize_result, dict)
        or initialize_result.get("protocolVersion") != MCP_PROTOCOL_REVISION
    ):
        raise AssertionError("generic MCP discovery negotiated a divergent protocol")
    tools = extract_exact_tool_names(tools_response)
    return {
        "status": "pass",
        "client": "dependency-free-json-rpc-stdio",
        "protocol_revision": MCP_PROTOCOL_REVISION,
        "tools": tools,
        "tool_count": len(tools),
        "process_exited": True,
        "tool_calls": 0,
        "model_invocations": 0,
    }


def held_host_cell(name: str, binary: Path | None) -> dict[str, Any]:
    return {
        "status": "held",
        "detected": binary is not None,
        "reason": (
            "native CLI adapter is not implemented in this Codex-only lane"
            if binary is not None
            else "host CLI is not installed on the executing machine"
        ),
        "native_cli_acceptance": False,
        "live_model_acceptance": False,
        "ide_acceptance": False,
        "host": name,
    }


def validate_evidence(evidence: Mapping[str, Any]) -> None:
    if evidence.get("schema_version") != SCHEMA_VERSION:
        raise AssertionError("host evidence schema version changed")
    tests = evidence.get("tests")
    if not isinstance(tests, dict):
        raise AssertionError("host evidence omitted tests")
    codex = tests.get("codex_cli_management")
    discovery = tests.get("generic_mcp_discovery")
    if not isinstance(codex, dict) or codex.get("status") != "pass":
        raise AssertionError("Codex native CLI cell did not pass")
    if (
        not isinstance(discovery, dict)
        or discovery.get("status") != "pass"
        or discovery.get("tools") != list(EXPECTED_TOOLS)
    ):
        raise AssertionError("generic MCP discovery cell did not pass exactly")
    promotion = evidence.get("promotion")
    if promotion != {"authorized": False, "release_readiness_claimed": False}:
        raise AssertionError("host evidence attempted to authorize promotion")


def main() -> int:
    args = parse_args()
    repository = Path(__file__).resolve().parents[1]
    validate_repository_base(repository)
    manager = args.manager.expanduser().resolve(strict=True)
    engine = args.engine.expanduser().resolve(strict=True)
    provenance = args.manager_provenance.expanduser().resolve(strict=True)
    output = args.output.expanduser().resolve(strict=False)
    if not os.access(manager, os.X_OK) or not os.access(engine, os.X_OK):
        raise AssertionError("manager and engine must be executable files")
    if platform.system() != "Darwin" or platform.machine().lower() not in {
        "arm64",
        "aarch64",
    }:
        raise SystemExit("this native host lane currently supports macOS arm64 only")

    engine_sha256 = sha256_file(engine)
    manager_sha256 = sha256_file(manager)
    if engine_sha256 != ISOLATED_CANDIDATE_SHA256:
        raise AssertionError("engine does not match the exact isolated candidate")
    pin = parse_object(
        (repository / "reference/binary-pin.json").read_text(), "binary pin"
    )
    if (
        pin.get("source_commit") != ENGINE_SOURCE_COMMIT
        or pin.get("sha256") != ISOLATED_CANDIDATE_SHA256
        or pin.get("public_contract_sha256") != PUBLIC_CONTRACT_SHA256
        or pin.get("mcp_protocol_revision") != MCP_PROTOCOL_REVISION
    ):
        raise AssertionError("repository binary pin differs from the host lane")
    public_contract = repository / "reference/kaleidoscope-public-contract.json"
    if sha256_file(public_contract) != PUBLIC_CONTRACT_SHA256:
        raise AssertionError("public contract fixture digest changed")
    contract = parse_object(public_contract.read_text(), "public contract")
    if (
        not isinstance(contract.get("executable"), dict)
        or contract["executable"].get("sha256") != engine_sha256
    ):
        raise AssertionError("public contract executable does not match the engine")
    provenance_sha256 = validate_manager_provenance(
        provenance, manager_sha256=manager_sha256, engine_sha256=engine_sha256
    )

    overrides = parse_host_overrides(args.host_binary)
    host_paths = {
        name: resolve_host_binary(name, overrides=overrides, codex=args.codex)
        for name in HOST_DEFINITIONS
    }
    codex = host_paths["codex"]
    if codex is None or not os.access(codex, os.X_OK):
        raise AssertionError("the required native Codex CLI was not found")

    with tempfile.TemporaryDirectory(prefix="kaleidoscope-dx10b-hosts-") as raw_temp:
        temporary_root = Path(raw_temp).resolve()
        project = temporary_root / "project with spaces"
        project.mkdir()
        environment = minimal_environment(temporary_root)
        profile = "dx10b-codex-host"
        vault = temporary_root / "vault"

        manager_version = run_process(
            [manager, "--version"], env=environment
        ).stdout.strip()
        engine_version = run_process([engine, "--version"], env=environment).stdout.strip()
        model = parse_object(
            run_process([engine, "model"], env=environment).stdout, "engine model"
        )
        if model.get("status") != "bundled" or model.get("bundled_build") is not True:
            raise AssertionError("engine does not carry the required bundled model")

        initialized_raw = run_process(
            [
                manager,
                "--engine",
                engine,
                "init",
                "--root",
                vault,
                "--profile",
                profile,
                "--durability",
                "process-local",
            ],
            env=environment,
            cwd=project,
            timeout=90,
        ).stdout
        initialized = parse_object(initialized_raw, "manager init")
        profile_summary = initialized.get("profile")
        if (
            initialized.get("status") != "initialized"
            or not isinstance(profile_summary, dict)
            or profile_summary.get("name") != profile
            or profile_summary.get("root") != "<redacted>"
        ):
            raise AssertionError("manager did not initialize a redacted isolated profile")
        shown = parse_object(
            run_process(
                [manager, "--engine", engine, "profile", "show", profile],
                env=environment,
                cwd=project,
            ).stdout,
            "profile show",
        )
        if shown.get("root") != str(vault) or shown.get("name") != profile:
            raise AssertionError("manager profile did not bind the disposable vault")
        descriptor = parse_object(
            run_process(
                [
                    manager,
                    "--engine",
                    engine,
                    "config",
                    "--profile",
                    profile,
                    "--json",
                ],
                env=environment,
                cwd=project,
            ).stdout,
            "manager config",
        )
        if descriptor != {
            "version": 1,
            "transport": "stdio",
            "command": str(engine),
            "args": ["mcp", "--profile", profile],
            "tools": list(EXPECTED_TOOLS),
            "environment": {},
        }:
            raise AssertionError("manager launch descriptor changed")

        private_values = [
            str(temporary_root),
            str(vault),
            str(shown.get("workspace_id", "")),
            str(shown.get("principal_id", "")),
            str(shown.get("journal", "")),
        ]
        codex_result = run_codex_cli_lane(
            codex,
            engine=engine,
            profile=profile,
            environment=environment,
            project=project,
            private_values=private_values,
        )
        discovery = run_generic_mcp_discovery(
            engine, profile=profile, environment=environment
        )

        host_inventory = {
            "codex": {
                "status": "pass",
                "detected": True,
                "native_cli_acceptance": True,
                "acceptance_level": codex_result["acceptance_level"],
            },
            **{
                HOST_DEFINITIONS[name].evidence_name: held_host_cell(
                    name, host_paths[name]
                )
                for name in ("claude-code", "cursor", "opencode")
            },
        }

        poison = run_process(
            [sys.executable, repository / "scripts/poison_scan.py"],
            env=environment,
            cwd=repository,
        )
        if "poison scan passed" not in poison.stdout:
            raise AssertionError("source poison scan did not report success")

        evidence: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "scope": "credential-free-native-host-management-and-generic-mcp-discovery",
            "platform": {
                "os": "darwin",
                "architecture": "arm64",
                "native_tested": True,
            },
            "sdk_input": {
                "source_commit": SDK_SOURCE_COMMIT,
                "manager_sha256": manager_sha256,
                "manager_version": manager_version,
                "provenance_sha256": provenance_sha256,
                "provenance_subject_and_source_verified": True,
            },
            "candidate": {
                "engine_source_commit": ENGINE_SOURCE_COMMIT,
                "engine_sha256": engine_sha256,
                "engine_version": engine_version,
                "public_contract_sha256": PUBLIC_CONTRACT_SHA256,
                "bundled_model": True,
                "signature_verified": False,
            },
            "host_inventory": host_inventory,
            "tests": {
                "isolated_profile_and_vault": {
                    "status": "pass",
                    "temporary_home": True,
                    "temporary_codex_home": True,
                    "temporary_xdg_roots": True,
                    "temporary_project": True,
                    "temporary_profile": True,
                    "temporary_vault": True,
                    "user_configuration_read_or_written": False,
                },
                "codex_cli_management": codex_result,
                "generic_mcp_discovery": discovery,
                "privacy": {
                    "status": "pass",
                    "configuration_environment_fields": False,
                    "vault_coordinates_in_configuration_or_evidence": False,
                    "raw_identity_coordinates_in_evidence": False,
                    "source_poison": "pass",
                },
                "execution_boundary": {
                    "status": "pass",
                    "model_invocations": 0,
                    "account_commands_invoked": False,
                    "browser_invoked": False,
                    "ide_or_tui_invoked": False,
                    "network_dependent_commands_invoked": False,
                    "blackhole_proxy_configured": True,
                },
            },
            "contract_sources": [
                {
                    "url": CODEX_MCP_DOCUMENTATION,
                    "claims": [
                        "local stdio MCP servers are supported",
                        "the default user configuration is ~/.codex/config.toml",
                        "codex mcp add/list/help are documented CLI workflows",
                    ],
                }
            ],
            "dependency_held": {
                "codex_model_or_tui_acceptance": (
                    "requires an explicitly authorized live host/model run"
                ),
                "codex_ide_acceptance": "requires an explicitly authorized isolated IDE runner",
                "claude_code_native_acceptance": host_inventory["claude_code"]["reason"],
                "cursor_native_acceptance": host_inventory["cursor"]["reason"],
                "opencode_native_acceptance": host_inventory["opencode"]["reason"],
                "live_oidc_and_keychain": (
                    "requires staging issuer credentials and native acceptance runners"
                ),
                "production_publication": "requires separate final approval",
            },
            "promotion": {
                "authorized": False,
                "release_readiness_claimed": False,
            },
        }
        validate_evidence(evidence)
        encoded = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
        assert_private_values_absent([encoded], private_values=private_values)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded)

    print(f"DX-10B native host conformance passed; evidence: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
