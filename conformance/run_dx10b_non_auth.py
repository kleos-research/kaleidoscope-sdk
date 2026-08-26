#!/usr/bin/env python3
"""Run the bounded local-only non-auth and account-offline DX-10B lane."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

SCHEMA_VERSION = "kaleidoscope.dx10b-non-auth-account-offline-local-evidence.v1"
MANAGER_FOUNDATION_COMMIT = "3b1ec66d4fc96ff2e77bf7c382b107502ccc7b8d"
AUTH_MANAGER_COMMIT = "048bf90854a1e38a1b88d14de88b681a206e5790"
INTEGRATION_FOUNDATION_COMMIT = "fd0b1877f70b1bb57e1b67c4c559e8b2e1d44290"
ENGINE_SOURCE_COMMIT = "d96355632cc52816472106d0776ce63d73631fef"
ISOLATED_CANDIDATE_SHA256 = (
    "988192ac9677d5dd55a3642b2da493a0806bb860b5b3c0f509b37ddadee08825"
)
PUBLIC_CONTRACT_SHA256 = (
    "a2357ed6c00e3e143d08581590571447e31d24fd0e7d2466d28a211a0515c75e"
)
SHARED_VAULT_RUNTIME_SHA256 = (
    "9eeae09b2f5912c6ee49a8b6a5d7fd523addad9d0424aee6438804f1a86fc594"
)
RAW_COORDINATE = re.compile(
    r"\b(?:wsp|usr)_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
    r"|\bjournal:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
HOST_PATHS = {
    "codex": Path(".codex/config.toml"),
    "claude-code": Path(".mcp.json"),
    "cursor": Path(".cursor/mcp.json"),
    "opencode": Path("opencode.json"),
}
INSTRUCTION_PATHS = {
    "skill": Path(".agents/skills/use-kaleidoscope/SKILL.md"),
    "agents": Path("AGENTS.md"),
    "claude": Path("CLAUDE.md"),
    "cursor": Path(".cursor/rules/kaleidoscope.mdc"),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manager", type=Path, required=True)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--node", default="node")
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
        diagnostic = completed.stderr[-4096:].replace("\n", " ").strip()
        raise AssertionError(
            f"command {Path(os.fspath(argv[0])).name!r} exited {completed.returncode}: {diagnostic}"
        )
    return completed


def parse_object(payload: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise AssertionError(f"{label} did not return JSON") from error
    if not isinstance(value, dict):
        raise AssertionError(f"{label} did not return one object")
    return value


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode()


def write_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)


def tree_fingerprint(root: Path) -> str:
    """Hash disposable state without publishing any path or vault content."""

    digest = hashlib.sha256()
    if not root.exists():
        digest.update(b"missing")
        return digest.hexdigest()
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
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
    payloads: Sequence[bytes | str],
    *,
    private_values: Sequence[str],
) -> None:
    for payload in payloads:
        text = payload.decode("utf-8") if isinstance(payload, bytes) else payload
        for value in private_values:
            if value and value in text:
                raise AssertionError(
                    "a private runtime value reached a public manager surface"
                )
        if RAW_COORDINATE.search(text):
            raise AssertionError(
                "a raw identity coordinate reached a public manager surface"
            )


def owner_receipt(path: Path) -> Path:
    return path.with_name(path.name + ".kaleidoscope-owner.json")


def instruction_receipt(path: Path) -> Path:
    return path.with_name(path.name + ".kaleidoscope-instruction-owner.json")


def main() -> int:
    args = parse_args()
    repository = Path(__file__).resolve().parents[1]
    manager = args.manager.resolve(strict=True)
    engine = args.engine.resolve(strict=True)
    python = args.python.absolute()
    if not python.is_file() or not os.access(python, os.X_OK):
        raise AssertionError("the selected Python interpreter is not executable")
    output = args.output.resolve(strict=False)

    if platform.system() != "Darwin" or platform.machine().lower() not in {
        "arm64",
        "aarch64",
    }:
        raise SystemExit("this candidate lane is native-tested only on macOS arm64")

    pin = parse_object(
        (repository / "reference/binary-pin.json").read_text(), "binary pin"
    )
    required_pin_values = {
        "source_commit": ENGINE_SOURCE_COMMIT,
        "sha256": ISOLATED_CANDIDATE_SHA256,
        "isolated_distribution_candidate_sha256": ISOLATED_CANDIDATE_SHA256,
        "shared_vault_runtime_sha256": SHARED_VAULT_RUNTIME_SHA256,
        "public_contract_sha256": PUBLIC_CONTRACT_SHA256,
    }
    for key, expected in required_pin_values.items():
        if pin.get(key) != expected:
            raise AssertionError(
                f"reference binary pin {key} does not match the frozen input"
            )
    if sha256_file(engine) != ISOLATED_CANDIDATE_SHA256:
        raise AssertionError("engine does not match the isolated DX-06 candidate hash")
    contract_path = repository / "reference/kaleidoscope-public-contract.json"
    contract_sha256 = sha256_file(contract_path)
    if pin.get("public_contract_sha256") != contract_sha256:
        raise AssertionError("public contract fixture does not match its frozen digest")
    contract = parse_object(contract_path.read_text(), "public contract")
    executable = contract.get("executable")
    if (
        not isinstance(executable, dict)
        or executable.get("sha256") != ISOLATED_CANDIDATE_SHA256
        or executable.get("sha256") != sha256_file(engine)
    ):
        raise AssertionError(
            "public contract executable hash does not match the live engine"
        )

    base_environment = {
        key: value
        for key, value in os.environ.items()
        if key in {"PATH", "SHELL", "TERM", "TMPDIR", "USER", "LOGNAME"}
    }
    base_environment.setdefault("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
    engine_version = run_process(
        [engine, "--version"], env=base_environment
    ).stdout.strip()
    model = parse_object(
        run_process([engine, "model"], env=base_environment).stdout,
        "engine model",
    )
    model_detail = model.get("model")
    if (
        model.get("status") != "bundled"
        or model.get("bundled_build") is not True
        or not isinstance(model_detail, dict)
        or model_detail.get("source") != "bundled"
    ):
        raise AssertionError(
            "candidate does not report the required bundled embedding model"
        )
    manager_version = run_process(
        [manager, "--version"], env=base_environment
    ).stdout.strip()
    python_version = run_process(
        [python, "--version"], env=base_environment
    ).stdout.strip()
    node_version = run_process(
        [args.node, "--version"], env=base_environment
    ).stdout.strip()

    with tempfile.TemporaryDirectory(prefix="kaleidoscope-dx10b-") as raw_temp:
        temp = Path(raw_temp).resolve()
        home = temp / "home with spaces ü"
        project = temp / "project with spaces ü"
        config_home = temp / "manager-config"
        data_home = temp / "manager-data"
        tmp = temp / "tmp"
        for directory in (home, project, config_home, data_home, tmp):
            directory.mkdir(parents=True)

        secret_values = [
            "dx10b-openai-" + "canary",
            "dx10b-anthropic-" + "canary",
            "dx10b-aws-" + "canary",
            "dx10b-manager-" + "canary",
            "dx10b-root-" + "canary",
            "dx10b-workspace-" + "canary",
            "dx10b-principal-" + "canary",
            "dx10b-journal-" + "canary",
        ]
        runtime_environment = {
            **base_environment,
            "HOME": str(home),
            "USERPROFILE": str(home),
            "KALEIDOSCOPE_USER_HOME": str(home),
            "KALEIDOSCOPE_CONFIG_HOME": str(config_home),
            "KALEIDOSCOPE_DATA_HOME": str(data_home),
            "TMPDIR": str(tmp),
            "OPENAI_API_KEY": secret_values[0],
            "ANTHROPIC_API_KEY": secret_values[1],
            "AWS_SECRET_ACCESS_KEY": secret_values[2],
            "KALEIDOSCOPE_TOKEN": secret_values[3],
            "KSCOPE_ROOT": secret_values[4],
            "KSCOPE_WORKSPACE": secret_values[5],
            "KSCOPE_PRINCIPAL": secret_values[6],
            "KSCOPE_JOURNAL": secret_values[7],
        }

        def manager_call(*arguments: str) -> subprocess.CompletedProcess[str]:
            return run_process(
                [manager, "--engine", engine, *arguments],
                env=runtime_environment,
                timeout=90,
            )

        initialized_raw = manager_call("init").stdout
        initialized = parse_object(initialized_raw, "manager init")
        if initialized.get("status") != "initialized":
            raise AssertionError(
                "friendly manager init did not initialize the default profile"
            )
        profile_summary = initialized.get("profile")
        if (
            not isinstance(profile_summary, dict)
            or profile_summary.get("name") != "default"
        ):
            raise AssertionError("friendly init did not select the default profile")
        if profile_summary.get("root") != "<redacted>":
            raise AssertionError("friendly init exposed the profile root")

        profile_list_raw = manager_call("profile", "list").stdout
        if "default" not in profile_list_raw:
            raise AssertionError("profile list omitted the initialized profile")
        profile_show_raw = manager_call("profile", "show", "default").stdout
        profile_show = parse_object(profile_show_raw, "profile show")
        expected_root = data_home / "vaults/default"
        if profile_show.get("root") != str(expected_root):
            raise AssertionError(
                "profile show did not resolve the friendly default vault"
            )
        private_identity_values = [
            str(expected_root),
            str(profile_show.get("workspace_id", "")),
            str(profile_show.get("principal_id", "")),
            str(profile_show.get("journal", "")),
            *secret_values,
        ]
        manager_call("profile", "use", "default")
        descriptor_raw = manager_call("config", "--json").stdout
        descriptor = parse_object(descriptor_raw, "manager config")
        if descriptor != {
            "version": 1,
            "transport": "stdio",
            "command": str(engine),
            "args": ["mcp", "--profile", "default"],
            "tools": ["search", "remember"],
            "environment": {},
        }:
            raise AssertionError(
                "manager config differed from the closed launch descriptor"
            )

        host_baselines = {
            "codex": b'model = "local-fixture"\n',
            "claude-code": canonical_json({"keep": "claude", "mcpServers": {}}),
            "cursor": canonical_json({"keep": "cursor", "mcpServers": {}}),
            "opencode": canonical_json({"keep": "opencode", "mcp": {}}),
        }
        host_files = {name: project / relative for name, relative in HOST_PATHS.items()}
        for name, path in host_files.items():
            write_bytes(path, host_baselines[name])

        host_results: dict[str, dict[str, bool]] = {}
        runtime_surfaces: list[bytes | str] = [initialized_raw, descriptor_raw]
        for host, path in host_files.items():
            before = path.read_bytes()
            manager_call(
                "connect",
                host,
                "--profile",
                "default",
                "--project",
                str(project),
                "--dry-run",
            )
            if path.read_bytes() != before or owner_receipt(path).exists():
                raise AssertionError(f"{host} dry-run changed configuration")
            manager_call(
                "connect",
                host,
                "--profile",
                "default",
                "--project",
                str(project),
                "--yes",
            )
            connected = path.read_bytes()
            receipt = owner_receipt(path)
            if connected == before or not receipt.is_file():
                raise AssertionError(f"{host} connect did not create owned state")
            manager_call(
                "connect",
                host,
                "--profile",
                "default",
                "--project",
                str(project),
                "--yes",
            )
            if path.read_bytes() != connected:
                raise AssertionError(f"{host} repeated connect was not idempotent")
            runtime_surfaces.extend([connected, receipt.read_bytes()])
            host_results[host] = {
                "connect_idempotent": True,
                "dry_run_no_write": True,
                "profile_first": True,
            }

        instruction_baselines: dict[str, bytes | None] = {
            "skill": None,
            "agents": b"# Existing agent instructions\n\nKeep this byte-exact.\n",
            "claude": b"# Existing Claude instructions\n\nKeep this byte-exact.\n",
            "cursor": None,
        }
        instruction_files = {
            name: project / relative for name, relative in INSTRUCTION_PATHS.items()
        }
        for name, baseline in instruction_baselines.items():
            if baseline is not None:
                write_bytes(instruction_files[name], baseline)

        instruction_results: dict[str, dict[str, bool]] = {}
        for target, path in instruction_files.items():
            baseline = instruction_baselines[target]
            manager_call(
                "instructions",
                "install",
                target,
                "--project",
                str(project),
                "--dry-run",
            )
            if (path.read_bytes() if path.exists() else None) != baseline:
                raise AssertionError(f"{target} instruction dry-run changed the file")
            manager_call(
                "instructions",
                "install",
                target,
                "--project",
                str(project),
                "--yes",
            )
            installed = path.read_bytes()
            receipt = instruction_receipt(path)
            if not receipt.is_file():
                raise AssertionError(
                    f"{target} instruction owner receipt was not written"
                )
            manager_call(
                "instructions",
                "install",
                target,
                "--project",
                str(project),
                "--yes",
            )
            if path.read_bytes() != installed:
                raise AssertionError(
                    f"{target} repeated instruction install was not idempotent"
                )
            runtime_surfaces.extend([installed, receipt.read_bytes()])
            instruction_results[target] = {
                "dry_run_no_write": True,
                "install_idempotent": True,
            }

        doctor_raw = manager_call("doctor", "--project", str(project)).stdout
        doctor = parse_object(doctor_raw, "doctor")
        checks = doctor.get("checks")
        if (
            doctor.get("status") != "ready"
            or doctor.get("offline") is not True
            or doctor.get("redacted") is not True
            or not isinstance(checks, list)
            or any(
                isinstance(check, dict) and check.get("status") != "ok"
                for check in checks
            )
        ):
            raise AssertionError("offline doctor did not report a redacted ready state")
        runtime_surfaces.append(doctor_raw)

        probe_environment = {
            **runtime_environment,
            "PYTHONPATH": str(repository / "python/src"),
        }
        account_state_before = {
            "config": tree_fingerprint(config_home),
            "data": tree_fingerprint(data_home),
        }
        provider_not_configured = subprocess.run(
            [manager, "status", "--json"],
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=runtime_environment,
            timeout=30,
        )
        if provider_not_configured.returncode == 0 or (
            "account provider is not configured" not in provider_not_configured.stderr
        ):
            raise AssertionError(
                "manager account status did not fail closed without a provider"
            )
        assert_private_values_absent(
            [provider_not_configured.stdout, provider_not_configured.stderr],
            private_values=private_identity_values,
        )
        fake_account_manager = repository / "conformance/fake_account_manager.py"
        python_account_probe_raw = run_process(
            [
                python,
                repository / "conformance/python_account_offline_probe.py",
                "--manager",
                fake_account_manager,
            ],
            env=probe_environment,
            cwd=repository,
            timeout=60,
        ).stdout
        python_account_probe = parse_object(
            python_account_probe_raw,
            "Python manager account offline probe",
        )
        typescript_account_probe_raw = run_process(
            [
                args.node,
                "--import",
                "tsx",
                repository / "conformance/typescript_account_offline_probe.ts",
                "--manager",
                fake_account_manager,
            ],
            env=probe_environment,
            cwd=repository / "typescript",
            timeout=60,
        ).stdout
        typescript_account_probe = parse_object(
            typescript_account_probe_raw,
            "TypeScript manager account offline probe",
        )
        for language, account_probe in {
            "Python": python_account_probe,
            "TypeScript": typescript_account_probe,
        }.items():
            if account_probe != {
                "status": "signed_out",
                "stale": False,
                "account_identity_present": False,
                "command_count": 12,
                "invocation_count": 12,
                "engine_or_mcp_arguments_present": False,
            }:
                raise AssertionError(f"{language} manager account offline probe failed")
        account_state_after = {
            "config": tree_fingerprint(config_home),
            "data": tree_fingerprint(data_home),
        }
        if account_state_after != account_state_before:
            raise AssertionError(
                "offline account checks changed the local profile or vault"
            )
        runtime_surfaces.extend(
            [
                provider_not_configured.stdout,
                provider_not_configured.stderr,
                python_account_probe_raw,
                typescript_account_probe_raw,
            ]
        )
        python_probe = parse_object(
            run_process(
                [
                    python,
                    repository / "conformance/python_persistent_probe.py",
                    "--engine",
                    engine,
                    "--expected-sha256",
                    ISOLATED_CANDIDATE_SHA256,
                    "--profile",
                    "default",
                ],
                env=probe_environment,
                cwd=repository,
                timeout=180,
            ).stdout,
            "Python persistent MCP probe",
        )
        memory_id = python_probe.get("memory_id")
        if not isinstance(memory_id, str):
            raise AssertionError(
                "Python probe omitted the cross-language memory identity"
            )

        typescript_probe = parse_object(
            run_process(
                [
                    args.node,
                    "--import",
                    "tsx",
                    repository / "conformance/typescript_persistent_probe.ts",
                    "--engine",
                    engine,
                    "--expected-sha256",
                    ISOLATED_CANDIDATE_SHA256,
                    "--profile",
                    "default",
                ],
                env=probe_environment,
                cwd=repository / "typescript",
                input_text=json.dumps({"memory_id": memory_id}),
                timeout=180,
            ).stdout,
            "TypeScript persistent MCP probe",
        )

        for target, path in instruction_files.items():
            manager_call(
                "instructions",
                "remove",
                target,
                "--project",
                str(project),
                "--yes",
            )
            baseline = instruction_baselines[target]
            restored = path.read_bytes() if path.exists() else None
            if restored != baseline or instruction_receipt(path).exists():
                raise AssertionError(f"{target} instruction removal was not byte-exact")
            instruction_results[target]["remove_exact_rollback"] = True

        for host, path in host_files.items():
            manager_call(
                "disconnect",
                host,
                "--project",
                str(project),
                "--yes",
            )
            if (
                path.read_bytes() != host_baselines[host]
                or owner_receipt(path).exists()
            ):
                raise AssertionError(f"{host} disconnect was not byte-exact")
            host_results[host]["disconnect_exact_rollback"] = True

        manager_config = config_home / "manager.json"
        runtime_surfaces.append(manager_config.read_bytes())
        assert_private_values_absent(
            runtime_surfaces,
            private_values=private_identity_values,
        )

        poison = run_process(
            [python, repository / "scripts/poison_scan.py"],
            env={**base_environment, "HOME": str(home)},
            cwd=repository,
            timeout=60,
        )
        if "poison scan passed" not in poison.stdout:
            raise AssertionError("source poison scan did not report success")

        evidence = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "scope": "local-only-non-auth-account-offline",
            "platform": {
                "os": "darwin",
                "architecture": "arm64",
                "native_tested": True,
            },
            "candidate": {
                "engine_source_commit": ENGINE_SOURCE_COMMIT,
                "isolated_distribution_candidate_sha256": ISOLATED_CANDIDATE_SHA256,
                "local_live_candidate_sha256": ISOLATED_CANDIDATE_SHA256,
                "shared_vault_development_runtime_sha256": SHARED_VAULT_RUNTIME_SHA256,
                "shared_vault_runtime_is_release_candidate": False,
                "public_contract_sha256": contract_sha256,
                "public_contract_executable_sha256": executable["sha256"],
                "engine_version": engine_version,
                "bundled_model": True,
                "signature_verified": False,
            },
            "sdk_inputs": {
                "manager_foundation_commit": MANAGER_FOUNDATION_COMMIT,
                "auth_manager_commit": AUTH_MANAGER_COMMIT,
                "integration_foundation_commit": INTEGRATION_FOUNDATION_COMMIT,
                "manager_sha256": sha256_file(manager),
                "manager_version": manager_version,
                "python_version": python_version,
                "node_version": node_version,
            },
            "tests": {
                "friendly_init_and_profile": {"status": "pass"},
                "host_configuration": {"status": "pass", "hosts": host_results},
                "instructions": {"status": "pass", "targets": instruction_results},
                "offline_doctor": {
                    "status": "pass",
                    "redacted": True,
                    "network_calls": 0,
                },
                "manager_account_offline": {
                    "status": "pass",
                    "provider_not_configured_fail_closed": True,
                    "python_signed_out_status": True,
                    "typescript_signed_out_status": True,
                    "closed_command_count": 12,
                    "engine_or_mcp_arguments_present": False,
                    "profile_and_vault_unchanged": True,
                    "live_oidc_credentials_required": False,
                    "real_keychain_write_required": False,
                },
                "python_generic_mcp": {
                    "status": "pass",
                    "sessions": python_probe.get("sessions"),
                    "calls": python_probe.get("calls"),
                    "restart_persisted": python_probe.get("restart_persisted"),
                    "processes_distinct": python_probe.get("processes_distinct"),
                    "teardown": python_probe.get("teardown"),
                    "tools": python_probe.get("tools"),
                },
                "typescript_generic_mcp": {
                    "status": "pass",
                    "sessions": typescript_probe.get("sessions"),
                    "calls": typescript_probe.get("calls"),
                    "restart_persisted": typescript_probe.get("restart_persisted"),
                    "processes_distinct": typescript_probe.get("processes_distinct"),
                    "teardown": typescript_probe.get("teardown"),
                    "tools": typescript_probe.get("tools"),
                },
                "generic_harness_restart_and_teardown": {"status": "pass"},
                "runtime_privacy": {
                    "status": "pass",
                    "canaries_absent": True,
                    "raw_coordinates_absent_from_public_surfaces": True,
                },
                "source_poison": {"status": "pass"},
                "exact_configuration_rollback": {"status": "pass"},
            },
            "dependency_held": {
                "live_oidc_login_and_native_keychain": "staging issuer credentials and native acceptance runners",
                "live_codex_claude_cursor_opencode_acceptance": "native host runners and pinned host versions",
                "machine_restart": "clean native VM runner",
                "signed_install_update_rollback": "DX-06 signing identities and DX-10A installed candidate",
                "non_darwin_arm64_platforms": "native platform artifacts and runners",
                "production_publication": "separate final approval",
            },
            "promotion": {
                "authorized": False,
                "release_readiness_claimed": False,
            },
        }
        encoded = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
        assert_private_values_absent([encoded], private_values=private_identity_values)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded)

    print(
        f"DX-10B local non-auth/account-offline conformance passed; evidence: {output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
