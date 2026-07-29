"""Integration tests for MS365Collector's PowerShell bridge wiring.

These tests use a fake PowerShellBridge (no real pwsh/subprocess involved)
to verify key distribution, per-key error propagation, and the "not
configured" regression guard.
"""

from unittest.mock import AsyncMock

import pytest

from sspm.providers.ms365.collector import (
    _EXCHANGE_KEYS,
    _SHAREPOINT_KEYS,
    _TEAMS_KEYS,
    MS365Collector,
)
from sspm.providers.ms365.powershell_bridge import PowerShellConfig, PowerShellResult


class _FakeAuth:
    @property
    def bearer_header(self):
        return {"Authorization": "Bearer fake"}


def _make_collector(ps_bridge=None, ps_config=None) -> MS365Collector:
    return MS365Collector(_FakeAuth(), ps_bridge=ps_bridge, ps_config=ps_config)


class TestNoBridgeConfigured:
    """Regression guard: identical behavior to before the bridge existed."""

    async def test_exchange_keys_are_none_without_bridge(self):
        collector = _make_collector()
        await collector._collect_exchange_via_powershell()
        for key in _EXCHANGE_KEYS:
            assert collector._data[key] is None
        assert collector._errors == {}

    async def test_teams_keys_are_none_without_bridge(self):
        collector = _make_collector()
        await collector._collect_teams_via_powershell()
        for key in _TEAMS_KEYS:
            assert collector._data[key] is None
        assert collector._errors == {}

    async def test_bridge_present_but_unavailable_is_treated_as_not_configured(self):
        fake_bridge = AsyncMock()
        fake_bridge.available = False
        config = PowerShellConfig(app_id="app", tenant_id="tenant", cert_path="/cert.pfx")
        collector = _make_collector(ps_bridge=fake_bridge, ps_config=config)

        await collector._collect_exchange_via_powershell()

        fake_bridge.run_script.assert_not_called()
        for key in _EXCHANGE_KEYS:
            assert collector._data[key] is None

    async def test_module_disabled_via_config_flag(self):
        fake_bridge = AsyncMock()
        fake_bridge.available = True
        config = PowerShellConfig(
            app_id="app", tenant_id="tenant", cert_path="/cert.pfx",
            enable_exchange=False,
        )
        collector = _make_collector(ps_bridge=fake_bridge, ps_config=config)

        await collector._collect_exchange_via_powershell()

        fake_bridge.run_script.assert_not_called()
        for key in _EXCHANGE_KEYS:
            assert collector._data[key] is None


class TestBridgeConfigured:
    async def test_key_distribution_on_success(self):
        fake_bridge = AsyncMock()
        fake_bridge.available = True
        script_result = {key: {"value": key} for key in _EXCHANGE_KEYS}
        fake_bridge.run_script.return_value = PowerShellResult(
            ok=True, data={"result": script_result, "errors": {}}
        )
        config = PowerShellConfig(
            app_id="app", tenant_id="tenant", cert_path="/cert.pfx",
            organization="contoso.onmicrosoft.com",
        )
        collector = _make_collector(ps_bridge=fake_bridge, ps_config=config)

        await collector._collect_exchange_via_powershell()

        fake_bridge.run_script.assert_awaited_once()
        for key in _EXCHANGE_KEYS:
            assert collector._data[key] == {"value": key}
        assert collector._errors == {}

    async def test_per_key_errors_propagated(self):
        fake_bridge = AsyncMock()
        fake_bridge.available = True
        script_result = {k: None for k in _EXCHANGE_KEYS if k != "organization_config"}
        fake_bridge.run_script.return_value = PowerShellResult(
            ok=True,
            data={
                "result": script_result,
                "errors": {"organization_config": "cmdlet not found"},
            },
        )
        config = PowerShellConfig(app_id="app", tenant_id="tenant", cert_path="/cert.pfx")
        collector = _make_collector(ps_bridge=fake_bridge, ps_config=config)

        await collector._collect_exchange_via_powershell()

        assert collector._errors["organization_config"] == "cmdlet not found"
        assert "organization_config" not in collector._data

    async def test_total_script_failure_errors_every_key(self):
        fake_bridge = AsyncMock()
        fake_bridge.available = True
        fake_bridge.run_script.return_value = PowerShellResult(
            ok=False, error="pwsh exited with code 1"
        )
        config = PowerShellConfig(app_id="app", tenant_id="tenant", cert_path="/cert.pfx")
        collector = _make_collector(ps_bridge=fake_bridge, ps_config=config)

        await collector._collect_teams_via_powershell()

        for key in _TEAMS_KEYS:
            assert collector._errors[key] == "pwsh exited with code 1"
            assert key not in collector._data

    async def test_cert_password_passed_as_env_extra(self):
        fake_bridge = AsyncMock()
        fake_bridge.available = True
        fake_bridge.run_script.return_value = PowerShellResult(
            ok=True, data={"result": {}, "errors": {}}
        )
        config = PowerShellConfig(
            app_id="app", tenant_id="tenant", cert_path="/cert.pfx",
            cert_password="super-secret",
        )
        collector = _make_collector(ps_bridge=fake_bridge, ps_config=config)

        await collector._collect_exchange_via_powershell()

        _, kwargs = fake_bridge.run_script.call_args
        assert kwargs["env_extra"] == {"SSPM_MS365_CERT_PASSWORD": "super-secret"}


class TestSharePointBridge:
    """Connect-SPOService is the one module with no access-token auth path."""

    async def test_keys_are_none_without_bridge(self):
        collector = _make_collector()
        await collector._collect_sharepoint_via_powershell()
        for key in _SHAREPOINT_KEYS:
            assert collector._data[key] is None
        assert collector._errors == {}

    async def test_client_secret_alone_does_not_run_the_script(self):
        # Exchange and Teams work from the secret alone; SharePoint cannot,
        # and must not leave the script waiting on a mandatory -CertificatePath.
        fake_bridge = AsyncMock()
        fake_bridge.available = True
        config = PowerShellConfig(
            app_id="app", tenant_id="tenant", client_secret="s3cret",
            sharepoint_admin_url="https://contoso-admin.sharepoint.com",
        )
        collector = _make_collector(ps_bridge=fake_bridge, ps_config=config)

        await collector._collect_sharepoint_via_powershell()

        fake_bridge.run_script.assert_not_called()
        for key in _SHAREPOINT_KEYS:
            assert collector._data[key] is None

    async def test_collects_spo_tenant_with_a_certificate(self):
        fake_bridge = AsyncMock()
        fake_bridge.available = True
        fake_bridge.run_script.return_value = PowerShellResult(
            ok=True,
            data={"result": {"spo_tenant": {"DefaultLinkPermission": "View"}}, "errors": {}},
        )
        config = PowerShellConfig(
            app_id="app", tenant_id="tenant", cert_path="/cert.pfx",
            sharepoint_admin_url="https://contoso-admin.sharepoint.com",
        )
        collector = _make_collector(ps_bridge=fake_bridge, ps_config=config)

        await collector._collect_sharepoint_via_powershell()

        args, _ = fake_bridge.run_script.call_args
        assert "-AdminUrl" in args[1]
        assert "https://contoso-admin.sharepoint.com" in args[1]
        assert collector._data["spo_tenant"] == {"DefaultLinkPermission": "View"}
        assert collector._errors == {}

    async def test_script_failure_errors_every_key(self):
        fake_bridge = AsyncMock()
        fake_bridge.available = True
        fake_bridge.run_script.return_value = PowerShellResult(
            ok=False, error="Connect-SPOService failed"
        )
        config = PowerShellConfig(
            app_id="app", tenant_id="tenant", cert_path="/cert.pfx",
            sharepoint_admin_url="https://contoso-admin.sharepoint.com",
        )
        collector = _make_collector(ps_bridge=fake_bridge, ps_config=config)

        await collector._collect_sharepoint_via_powershell()

        for key in _SHAREPOINT_KEYS:
            assert collector._errors[key] == "Connect-SPOService failed"
            assert key not in collector._data
