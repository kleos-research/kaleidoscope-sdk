from __future__ import annotations

import json
from pathlib import Path

import pytest

from kaleidoscope_memory import (
    ManagerAccountClient,
    ManagerAccountCommand,
    ManagerCommandError,
)

ROOT = Path(__file__).parents[2]
GOLDEN = json.loads((ROOT / "reference/manager-account-golden.json").read_text())
ACCOUNT_ENVIRONMENT = {
    "KALEIDOSCOPE_ACCOUNT_ORIGIN": "https://account.example.invalid/",
    "KALEIDOSCOPE_ACCOUNT_ISSUER": "https://issuer.example.invalid/",
    "KALEIDOSCOPE_ACCOUNT_AUDIENCE": "kaleidoscope-fixture",
    "KALEIDOSCOPE_ACCOUNT_CLIENT_ID": "kaleidoscope-native-fixture",
}
EXTERNAL_IDENTITY = "55555555-5555-4555-8555-555555555555"
DEVICE_ID = "33333333-3333-4333-8333-333333333333"


@pytest.fixture(scope="session")
def fake_manager() -> Path:
    path = ROOT / "conformance/fake_account_manager.py"
    path.chmod(0o755)
    return path.resolve()


def command_shapes() -> dict[str, list[str]]:
    return {
        "status": list(ManagerAccountCommand.status().arguments),
        "login_loopback": list(ManagerAccountCommand.login().arguments),
        "login_device": list(ManagerAccountCommand.login(device=True).arguments),
        "logout_current": list(ManagerAccountCommand.logout().arguments),
        "logout_all": list(ManagerAccountCommand.logout(all_devices=True).arguments),
        "logout_local": list(ManagerAccountCommand.logout(local_only=True).arguments),
        "link_github": list(ManagerAccountCommand.link("github").arguments),
        "identities": list(ManagerAccountCommand.identities().arguments),
        "unlink": list(ManagerAccountCommand.unlink(EXTERNAL_IDENTITY).arguments),
        "revoke_session": list(ManagerAccountCommand.revoke_session().arguments),
        "devices": list(ManagerAccountCommand.devices().arguments),
        "revoke_device": list(ManagerAccountCommand.revoke_device(DEVICE_ID).arguments),
    }


def test_account_command_builders_match_the_authoritative_manager_cli() -> None:
    assert command_shapes() == GOLDEN["commands"]
    with pytest.raises(ValueError, match="mutually exclusive"):
        ManagerAccountCommand.logout(all_devices=True, local_only=True)
    with pytest.raises(ValueError, match="provider"):
        ManagerAccountCommand.link("not a provider")
    with pytest.raises(ValueError, match="UUID"):
        ManagerAccountCommand.revoke_device("not-a-uuid")
    with pytest.raises(ValueError, match="closed manager account command"):
        ManagerAccountCommand(("call", "--profile", "default", "search"))


def test_signed_out_status_and_account_invocations_use_only_the_manager(
    fake_manager: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = tmp_path / "user-owned-vault" / "sentinel.bin"
    sentinel.parent.mkdir()
    sentinel.write_bytes(b"unchanged-local-memory")
    monkeypatch.setenv("KSCOPE_ROOT", str(sentinel.parent))
    monkeypatch.setenv("KSCOPE_WORKSPACE", "wsp_should-not-cross-manager-boundary")
    monkeypatch.setenv("KSCOPE_PRINCIPAL", "usr_should-not-cross-manager-boundary")
    monkeypatch.setenv("KSCOPE_JOURNAL", "journal:should-not-cross-manager-boundary")
    monkeypatch.setenv("KALEIDOSCOPE_TOKEN", "manager-token-should-not-be-inherited")

    client = ManagerAccountClient(fake_manager, account_environment=ACCOUNT_ENVIRONMENT)
    status = client.status()
    assert {
        "version": status.version,
        "state": status.state,
        "account_id": status.account_id,
        "device_id": status.device_id,
        "stale": status.stale,
    } == GOLDEN["signed_out"]
    assert client.login()["status"] == "signed_in"
    assert client.login(device=True)["status"] == "signed_in"
    assert client.logout()["status"] == "already_signed_out"
    assert client.logout(all_devices=True)["status"] == "already_signed_out"
    assert client.logout(local_only=True)["status"] == "already_signed_out"
    assert client.link("github")["status"] == "fresh_auth_required"
    assert client.identities()["external_identities"][0]["external_identity_id"] == EXTERNAL_IDENTITY
    assert client.unlink(EXTERNAL_IDENTITY)["status"] == "unlinked"
    assert client.revoke_session()["status"] == "already_signed_out"
    assert client.devices()["devices"] == []
    assert client.revoke_device(DEVICE_ID)["device_id"] == DEVICE_ID
    assert sentinel.read_bytes() == b"unchanged-local-memory"
    assert list(sentinel.parent.iterdir()) == [sentinel]


def test_provider_not_configured_diagnostic_is_redacted(
    fake_manager: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KSCOPE_ROOT", "/vault-coordinate-must-not-cross")
    with pytest.raises(ManagerCommandError) as failure:
        ManagerAccountClient(fake_manager, account_environment={}).status()
    assert failure.value.returncode == 2
    assert failure.value.arguments == ("status", "--json")
    assert "account provider is not configured" in str(failure.value)
    assert "authorization=<redacted>" in str(failure.value)
    assert "fixture-sensitive-value" not in str(failure.value)
