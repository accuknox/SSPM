"""Unit tests for all Azure CIS rules."""

from __future__ import annotations

import pytest

from sspm.core.models import FindingStatus
from sspm.providers.base import CollectedData

# Section 2 – Analytics (Databricks)
from sspm.providers.azure.rules.section2_analytics.cis_2_1_1 import CIS_2_1_1
from sspm.providers.azure.rules.section2_analytics.cis_2_1_2 import CIS_2_1_2
from sspm.providers.azure.rules.section2_analytics.cis_2_1_3 import CIS_2_1_3
from sspm.providers.azure.rules.section2_analytics.cis_2_1_4 import CIS_2_1_4
from sspm.providers.azure.rules.section2_analytics.cis_2_1_5 import CIS_2_1_5
from sspm.providers.azure.rules.section2_analytics.cis_2_1_6 import CIS_2_1_6
from sspm.providers.azure.rules.section2_analytics.cis_2_1_7 import CIS_2_1_7
from sspm.providers.azure.rules.section2_analytics.cis_2_1_8 import CIS_2_1_8
from sspm.providers.azure.rules.section2_analytics.cis_2_1_9 import CIS_2_1_9
from sspm.providers.azure.rules.section2_analytics.cis_2_1_10 import CIS_2_1_10
from sspm.providers.azure.rules.section2_analytics.cis_2_1_11 import CIS_2_1_11
from sspm.providers.azure.rules.section2_analytics.cis_2_1_12 import CIS_2_1_12

# Section 3 – Compute
from sspm.providers.azure.rules.section3_compute.cis_3_1_1 import CIS_3_1_1

# Section 5 – Identity
from sspm.providers.azure.rules.section5_identity.cis_5_1_1 import CIS_5_1_1
from sspm.providers.azure.rules.section5_identity.cis_5_1_2 import CIS_5_1_2
from sspm.providers.azure.rules.section5_identity.cis_5_1_3 import CIS_5_1_3
from sspm.providers.azure.rules.section5_identity.cis_5_1_4 import CIS_5_1_4
from sspm.providers.azure.rules.section5_identity.cis_5_3_1 import CIS_5_3_1
from sspm.providers.azure.rules.section5_identity.cis_5_3_2 import CIS_5_3_2
from sspm.providers.azure.rules.section5_identity.cis_5_3_3 import CIS_5_3_3
from sspm.providers.azure.rules.section5_identity.cis_5_3_4 import CIS_5_3_4
from sspm.providers.azure.rules.section5_identity.cis_5_3_5 import CIS_5_3_5
from sspm.providers.azure.rules.section5_identity.cis_5_3_6 import CIS_5_3_6
from sspm.providers.azure.rules.section5_identity.cis_5_3_7 import CIS_5_3_7
from sspm.providers.azure.rules.section5_identity.cis_5_4 import CIS_5_4
from sspm.providers.azure.rules.section5_identity.cis_5_5 import CIS_5_5
from sspm.providers.azure.rules.section5_identity.cis_5_6 import CIS_5_6
from sspm.providers.azure.rules.section5_identity.cis_5_7 import CIS_5_7

# Section 6 – Logging
from sspm.providers.azure.rules.section6_logging.cis_6_1_1_1 import CIS_6_1_1_1
from sspm.providers.azure.rules.section6_logging.cis_6_1_1_2 import CIS_6_1_1_2
from sspm.providers.azure.rules.section6_logging.cis_6_1_1_3 import CIS_6_1_1_3
from sspm.providers.azure.rules.section6_logging.cis_6_1_1_4 import CIS_6_1_1_4
from sspm.providers.azure.rules.section6_logging.cis_6_1_1_5 import CIS_6_1_1_5
from sspm.providers.azure.rules.section6_logging.cis_6_1_1_6 import CIS_6_1_1_6
from sspm.providers.azure.rules.section6_logging.cis_6_1_1_7 import CIS_6_1_1_7
from sspm.providers.azure.rules.section6_logging.cis_6_1_1_8 import CIS_6_1_1_8
from sspm.providers.azure.rules.section6_logging.cis_6_1_1_9 import CIS_6_1_1_9
from sspm.providers.azure.rules.section6_logging.cis_6_1_2_1 import CIS_6_1_2_1
from sspm.providers.azure.rules.section6_logging.cis_6_1_2_2 import CIS_6_1_2_2
from sspm.providers.azure.rules.section6_logging.cis_6_1_2_3 import CIS_6_1_2_3
from sspm.providers.azure.rules.section6_logging.cis_6_1_2_4 import CIS_6_1_2_4
from sspm.providers.azure.rules.section6_logging.cis_6_1_2_5 import CIS_6_1_2_5
from sspm.providers.azure.rules.section6_logging.cis_6_1_2_6 import CIS_6_1_2_6
from sspm.providers.azure.rules.section6_logging.cis_6_1_2_7 import CIS_6_1_2_7
from sspm.providers.azure.rules.section6_logging.cis_6_1_2_8 import CIS_6_1_2_8
from sspm.providers.azure.rules.section6_logging.cis_6_1_2_9 import CIS_6_1_2_9
from sspm.providers.azure.rules.section6_logging.cis_6_1_2_10 import CIS_6_1_2_10
from sspm.providers.azure.rules.section6_logging.cis_6_1_2_11 import CIS_6_1_2_11
from sspm.providers.azure.rules.section6_logging.cis_6_1_3_1 import CIS_6_1_3_1
from sspm.providers.azure.rules.section6_logging.cis_6_1_4 import CIS_6_1_4
from sspm.providers.azure.rules.section6_logging.cis_6_1_5 import CIS_6_1_5
from sspm.providers.azure.rules.section6_logging.cis_6_2 import CIS_6_2

# Section 7 – Networking
from sspm.providers.azure.rules.section7_networking.cis_7_1 import CIS_7_1
from sspm.providers.azure.rules.section7_networking.cis_7_2 import CIS_7_2
from sspm.providers.azure.rules.section7_networking.cis_7_3 import CIS_7_3
from sspm.providers.azure.rules.section7_networking.cis_7_4 import CIS_7_4
from sspm.providers.azure.rules.section7_networking.cis_7_5 import CIS_7_5
from sspm.providers.azure.rules.section7_networking.cis_7_6 import CIS_7_6
from sspm.providers.azure.rules.section7_networking.cis_7_7 import CIS_7_7
from sspm.providers.azure.rules.section7_networking.cis_7_8 import CIS_7_8
from sspm.providers.azure.rules.section7_networking.cis_7_9 import CIS_7_9
from sspm.providers.azure.rules.section7_networking.cis_7_10 import CIS_7_10
from sspm.providers.azure.rules.section7_networking.cis_7_11 import CIS_7_11
from sspm.providers.azure.rules.section7_networking.cis_7_12 import CIS_7_12
from sspm.providers.azure.rules.section7_networking.cis_7_13 import CIS_7_13
from sspm.providers.azure.rules.section7_networking.cis_7_14 import CIS_7_14
from sspm.providers.azure.rules.section7_networking.cis_7_15 import CIS_7_15
from sspm.providers.azure.rules.section7_networking.cis_7_16 import CIS_7_16

# Section 8 – Security Center / Defender
from sspm.providers.azure.rules.section8_security.cis_8_1_1_1 import CIS_8_1_1_1
from sspm.providers.azure.rules.section8_security.cis_8_1_2_1 import CIS_8_1_2_1
from sspm.providers.azure.rules.section8_security.cis_8_1_3_1 import CIS_8_1_3_1
from sspm.providers.azure.rules.section8_security.cis_8_1_3_2 import CIS_8_1_3_2
from sspm.providers.azure.rules.section8_security.cis_8_1_3_3 import CIS_8_1_3_3
from sspm.providers.azure.rules.section8_security.cis_8_1_3_4 import CIS_8_1_3_4
from sspm.providers.azure.rules.section8_security.cis_8_1_3_5 import CIS_8_1_3_5
from sspm.providers.azure.rules.section8_security.cis_8_1_4_1 import CIS_8_1_4_1
from sspm.providers.azure.rules.section8_security.cis_8_1_5_1 import CIS_8_1_5_1
from sspm.providers.azure.rules.section8_security.cis_8_1_5_2 import CIS_8_1_5_2
from sspm.providers.azure.rules.section8_security.cis_8_1_6_1 import CIS_8_1_6_1
from sspm.providers.azure.rules.section8_security.cis_8_1_7_1 import CIS_8_1_7_1
from sspm.providers.azure.rules.section8_security.cis_8_1_7_2 import CIS_8_1_7_2
from sspm.providers.azure.rules.section8_security.cis_8_1_7_3 import CIS_8_1_7_3
from sspm.providers.azure.rules.section8_security.cis_8_1_7_4 import CIS_8_1_7_4
from sspm.providers.azure.rules.section8_security.cis_8_1_8_1 import CIS_8_1_8_1
from sspm.providers.azure.rules.section8_security.cis_8_1_9_1 import CIS_8_1_9_1
from sspm.providers.azure.rules.section8_security.cis_8_1_10 import CIS_8_1_10
from sspm.providers.azure.rules.section8_security.cis_8_1_11 import CIS_8_1_11
from sspm.providers.azure.rules.section8_security.cis_8_1_12 import CIS_8_1_12
from sspm.providers.azure.rules.section8_security.cis_8_1_13 import CIS_8_1_13
from sspm.providers.azure.rules.section8_security.cis_8_1_14 import CIS_8_1_14
from sspm.providers.azure.rules.section8_security.cis_8_1_15 import CIS_8_1_15
from sspm.providers.azure.rules.section8_security.cis_8_1_16 import CIS_8_1_16
from sspm.providers.azure.rules.section8_security.cis_8_2_1 import CIS_8_2_1
from sspm.providers.azure.rules.section8_security.cis_8_3_1 import CIS_8_3_1
from sspm.providers.azure.rules.section8_security.cis_8_3_2 import CIS_8_3_2
from sspm.providers.azure.rules.section8_security.cis_8_3_3 import CIS_8_3_3
from sspm.providers.azure.rules.section8_security.cis_8_3_4 import CIS_8_3_4
from sspm.providers.azure.rules.section8_security.cis_8_3_5 import CIS_8_3_5
from sspm.providers.azure.rules.section8_security.cis_8_3_6 import CIS_8_3_6
from sspm.providers.azure.rules.section8_security.cis_8_3_7 import CIS_8_3_7
from sspm.providers.azure.rules.section8_security.cis_8_3_8 import CIS_8_3_8
from sspm.providers.azure.rules.section8_security.cis_8_3_9 import CIS_8_3_9
from sspm.providers.azure.rules.section8_security.cis_8_3_10 import CIS_8_3_10
from sspm.providers.azure.rules.section8_security.cis_8_3_11 import CIS_8_3_11
from sspm.providers.azure.rules.section8_security.cis_8_4_1 import CIS_8_4_1
from sspm.providers.azure.rules.section8_security.cis_8_5 import CIS_8_5

# Section 9 – Storage
from sspm.providers.azure.rules.section9_storage.cis_9_1_1 import CIS_9_1_1
from sspm.providers.azure.rules.section9_storage.cis_9_1_2 import CIS_9_1_2
from sspm.providers.azure.rules.section9_storage.cis_9_1_3 import CIS_9_1_3
from sspm.providers.azure.rules.section9_storage.cis_9_2_1 import CIS_9_2_1
from sspm.providers.azure.rules.section9_storage.cis_9_2_2 import CIS_9_2_2
from sspm.providers.azure.rules.section9_storage.cis_9_2_3 import CIS_9_2_3
from sspm.providers.azure.rules.section9_storage.cis_9_3_1_1 import CIS_9_3_1_1
from sspm.providers.azure.rules.section9_storage.cis_9_3_1_2 import CIS_9_3_1_2
from sspm.providers.azure.rules.section9_storage.cis_9_3_1_3 import CIS_9_3_1_3
from sspm.providers.azure.rules.section9_storage.cis_9_3_2_1 import CIS_9_3_2_1
from sspm.providers.azure.rules.section9_storage.cis_9_3_2_2 import CIS_9_3_2_2
from sspm.providers.azure.rules.section9_storage.cis_9_3_2_3 import CIS_9_3_2_3
from sspm.providers.azure.rules.section9_storage.cis_9_3_3_1 import CIS_9_3_3_1
from sspm.providers.azure.rules.section9_storage.cis_9_3_4 import CIS_9_3_4
from sspm.providers.azure.rules.section9_storage.cis_9_3_5 import CIS_9_3_5
from sspm.providers.azure.rules.section9_storage.cis_9_3_6 import CIS_9_3_6
from sspm.providers.azure.rules.section9_storage.cis_9_3_7 import CIS_9_3_7
from sspm.providers.azure.rules.section9_storage.cis_9_3_8 import CIS_9_3_8
from sspm.providers.azure.rules.section9_storage.cis_9_3_9 import CIS_9_3_9
from sspm.providers.azure.rules.section9_storage.cis_9_3_10 import CIS_9_3_10
from sspm.providers.azure.rules.section9_storage.cis_9_3_11 import CIS_9_3_11


def _azure(**kwargs) -> CollectedData:
    return CollectedData(provider="azure", target="test-subscription-id", data=kwargs)


# ---------------------------------------------------------------------------
# Helpers – minimal compliant/non-compliant Databricks workspace
# ---------------------------------------------------------------------------

def _ws_vnet_ok():
    return {
        "name": "ws1",
        "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Databricks/workspaces/ws1",
        "location": "eastus",
        "properties": {
            "parameters": {
                "customVirtualNetworkId": {"value": "/subscriptions/sub/virtualNetworks/vnet1"},
                "customPublicSubnetName": {"value": "public-subnet"},
                "customPrivateSubnetName": {"value": "private-subnet"},
            },
            "enableNoPublicIp": False,
            "publicNetworkAccess": "Disabled",
            "privateEndpointConnections": [{"id": "pe1"}],
        },
    }


def _ws_minimal():
    """Minimal workspace with no custom vnet / subnets / no-public-ip."""
    return {
        "name": "ws1",
        "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Databricks/workspaces/ws1",
        "location": "eastus",
        "properties": {"parameters": {}},
    }


# ---------------------------------------------------------------------------
# Helper – minimal activity log alert
# ---------------------------------------------------------------------------

def _alert(operation: str, enabled: bool = True):
    return {
        "properties": {
            "enabled": enabled,
            "condition": {
                "allOf": [
                    {"field": "operationName", "equals": operation},
                ]
            }
        }
    }


def _category_alert(category: str, enabled: bool = True):
    return {
        "properties": {
            "enabled": enabled,
            "condition": {
                "allOf": [
                    {"field": "category", "equals": category},
                ]
            }
        }
    }


# ---------------------------------------------------------------------------
# Helper – minimal NSG
# ---------------------------------------------------------------------------

def _nsg_allow(port: int, protocol: str = "TCP"):
    return {
        "name": "open-nsg",
        "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/open-nsg",
        "properties": {
            "securityRules": [{
                "name": "allow-all",
                "properties": {
                    "protocol": protocol,
                    "access": "Allow",
                    "direction": "Inbound",
                    "destinationPortRange": str(port),
                    "sourceAddressPrefix": "*",
                    "destinationAddressPrefix": "*",
                    "priority": 100,
                }
            }]
        }
    }


def _nsg_deny_all():
    return {
        "name": "deny-nsg",
        "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/deny-nsg",
        "properties": {"securityRules": []}
    }


# ---------------------------------------------------------------------------
# Helper – minimal Defender pricing plan
# ---------------------------------------------------------------------------

def _pricing(name: str, tier: str = "Standard"):
    return {"name": name, "properties": {"pricingTier": tier}}


# ============================================================
# SECTION 2 – Analytics
# ============================================================

class TestCIS_Az_2_1_1:
    @pytest.fixture
    def rule(self):
        return CIS_2_1_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_workspaces(self, rule):
        finding = await rule.check(_azure(databricks_workspaces=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_custom_vnet(self, rule):
        ws = _ws_vnet_ok()
        finding = await rule.check(_azure(databricks_workspaces=[ws]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_custom_vnet(self, rule):
        ws = _ws_minimal()
        finding = await rule.check(_azure(databricks_workspaces=[ws]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_2_1_2:
    @pytest.fixture
    def rule(self):
        return CIS_2_1_2()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_workspaces(self, rule):
        finding = await rule.check(_azure(databricks_workspaces=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_custom_subnets(self, rule):
        ws = _ws_vnet_ok()
        finding = await rule.check(_azure(databricks_workspaces=[ws]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_subnets(self, rule):
        ws = _ws_minimal()
        finding = await rule.check(_azure(databricks_workspaces=[ws]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_2_1_3:
    @pytest.fixture
    def rule(self):
        return CIS_2_1_3()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_2_1_4:
    @pytest.fixture
    def rule(self):
        return CIS_2_1_4()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_2_1_5:
    @pytest.fixture
    def rule(self):
        return CIS_2_1_5()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_2_1_6:
    @pytest.fixture
    def rule(self):
        return CIS_2_1_6()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_2_1_7:
    """Rule checks workspaces exist then always returns SKIP (diagnostic settings not collected)."""

    @pytest.fixture
    def rule(self):
        return CIS_2_1_7()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_workspaces(self, rule):
        finding = await rule.check(_azure(databricks_workspaces=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_workspaces_exist(self, rule):
        # Even with workspaces the rule returns SKIP (diagnostic not collected)
        finding = await rule.check(_azure(databricks_workspaces=[_ws_minimal()]))
        assert finding.status == FindingStatus.SKIPPED


class TestCIS_Az_2_1_8:
    @pytest.fixture
    def rule(self):
        return CIS_2_1_8()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_2_1_9:
    @pytest.fixture
    def rule(self):
        return CIS_2_1_9()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_workspaces(self, rule):
        finding = await rule.check(_azure(databricks_workspaces=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_no_public_ip(self, rule):
        ws = {
            "name": "ws1", "id": "ws1",
            "properties": {"parameters": {"enableNoPublicIp": {"value": True}}}
        }
        finding = await rule.check(_azure(databricks_workspaces=[ws]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_public_ip_enabled(self, rule):
        ws = _ws_minimal()
        finding = await rule.check(_azure(databricks_workspaces=[ws]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_2_1_10:
    @pytest.fixture
    def rule(self):
        return CIS_2_1_10()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_workspaces(self, rule):
        finding = await rule.check(_azure(databricks_workspaces=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_public_access_disabled(self, rule):
        ws = {"name": "ws1", "id": "ws1",
              "properties": {"publicNetworkAccess": "Disabled", "parameters": {}}}
        finding = await rule.check(_azure(databricks_workspaces=[ws]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_public_access_enabled(self, rule):
        ws = {"name": "ws1", "id": "ws1",
              "properties": {"publicNetworkAccess": "Enabled", "parameters": {}}}
        finding = await rule.check(_azure(databricks_workspaces=[ws]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_2_1_11:
    @pytest.fixture
    def rule(self):
        return CIS_2_1_11()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_workspaces(self, rule):
        finding = await rule.check(_azure(databricks_workspaces=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_private_endpoint_exists(self, rule):
        ws = {"name": "ws1", "id": "ws1",
              "properties": {"privateEndpointConnections": [{"id": "pe1"}], "parameters": {}}}
        finding = await rule.check(_azure(databricks_workspaces=[ws]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_private_endpoint(self, rule):
        ws = _ws_minimal()
        finding = await rule.check(_azure(databricks_workspaces=[ws]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_2_1_12:
    @pytest.fixture
    def rule(self):
        return CIS_2_1_12()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


# ============================================================
# SECTION 3 – Compute
# ============================================================

class TestCIS_Az_3_1_1:
    @pytest.fixture
    def rule(self):
        return CIS_3_1_1()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


# ============================================================
# SECTION 5 – Identity
# ============================================================

class TestCIS_Az_5_1_1:
    @pytest.fixture
    def rule(self):
        return CIS_5_1_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_security_defaults_enabled(self, rule):
        finding = await rule.check(_azure(security_defaults={"isEnabled": True}))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_security_defaults_disabled(self, rule):
        finding = await rule.check(_azure(security_defaults={"isEnabled": False}))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_5_1_2:
    @pytest.fixture
    def rule(self):
        return CIS_5_1_2()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_5_1_3:
    @pytest.fixture
    def rule(self):
        return CIS_5_1_3()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_security_defaults_enabled(self, rule):
        finding = await rule.check(_azure(security_defaults={"isEnabled": True}))
        assert finding.status == FindingStatus.PASS

    async def test_skip_when_security_defaults_disabled(self, rule):
        # Rule returns SKIP when defaults disabled (requires CA policy review)
        finding = await rule.check(_azure(security_defaults={"isEnabled": False}))
        assert finding.status == FindingStatus.SKIPPED


class TestCIS_Az_5_1_4:
    @pytest.fixture
    def rule(self):
        return CIS_5_1_4()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_5_3_1:
    @pytest.fixture
    def rule(self):
        return CIS_5_3_1()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_5_3_2:
    @pytest.fixture
    def rule(self):
        return CIS_5_3_2()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_5_3_3:
    @pytest.fixture
    def rule(self):
        return CIS_5_3_3()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_no_uaa_assignments(self, rule):
        finding = await rule.check(_azure(role_assignments=[]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_uaa_exists(self, rule):
        uaa_role_id = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
        finding = await rule.check(_azure(role_assignments=[{
            "properties": {
                "roleDefinitionId": f"/subscriptions/sub/providers/Microsoft.Authorization/roleDefinitions/{uaa_role_id}",
                "principalId": "user1",
            }
        }]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_5_3_4:
    @pytest.fixture
    def rule(self):
        return CIS_5_3_4()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_5_3_5:
    @pytest.fixture
    def rule(self):
        return CIS_5_3_5()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_5_3_6:
    @pytest.fixture
    def rule(self):
        return CIS_5_3_6()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_5_3_7:
    @pytest.fixture
    def rule(self):
        return CIS_5_3_7()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_5_4:
    @pytest.fixture
    def rule(self):
        return CIS_5_4()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_no_wildcard_custom_roles(self, rule):
        finding = await rule.check(_azure(role_definitions=[{
            "properties": {
                "type": "CustomRole",
                "roleName": "limited",
                "permissions": [{"actions": ["Microsoft.Compute/read"]}]
            }
        }]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_wildcard_custom_role(self, rule):
        finding = await rule.check(_azure(role_definitions=[{
            "properties": {
                "type": "CustomRole",
                "roleName": "superadmin",
                "permissions": [{"actions": ["*"]}]
            }
        }]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_5_5:
    @pytest.fixture
    def rule(self):
        return CIS_5_5()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_5_6:
    @pytest.fixture
    def rule(self):
        return CIS_5_6()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_5_7:
    @pytest.fixture
    def rule(self):
        return CIS_5_7()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_2_to_3_owners(self, rule):
        owner_role_id = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
        finding = await rule.check(_azure(role_assignments=[
            {"properties": {"roleDefinitionId": f"/providers/Microsoft.Authorization/roleDefinitions/{owner_role_id}", "principalId": "u1"}},
            {"properties": {"roleDefinitionId": f"/providers/Microsoft.Authorization/roleDefinitions/{owner_role_id}", "principalId": "u2"}},
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_1_owner(self, rule):
        owner_role_id = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
        finding = await rule.check(_azure(role_assignments=[
            {"properties": {"roleDefinitionId": f"/providers/Microsoft.Authorization/roleDefinitions/{owner_role_id}", "principalId": "u1"}},
        ]))
        assert finding.status == FindingStatus.FAIL


# ============================================================
# SECTION 6 – Logging
# ============================================================

class TestCIS_Az_6_1_1_1:
    @pytest.fixture
    def rule(self):
        return CIS_6_1_1_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_settings_exist(self, rule):
        finding = await rule.check(_azure(activity_log_diagnostic_settings=[{"name": "ds1"}]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_settings(self, rule):
        finding = await rule.check(_azure(activity_log_diagnostic_settings=[]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_6_1_1_2:
    @pytest.fixture
    def rule(self):
        return CIS_6_1_1_2()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_all_categories_enabled(self, rule):
        from sspm.providers.azure.rules.section6_logging.cis_6_1_1_2 import _REQUIRED_CATEGORIES
        logs = [{"category": cat, "enabled": True} for cat in _REQUIRED_CATEGORIES]
        finding = await rule.check(_azure(activity_log_diagnostic_settings=[{
            "name": "ds1",
            "properties": {"logs": logs}
        }]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_categories_missing(self, rule):
        finding = await rule.check(_azure(activity_log_diagnostic_settings=[{
            "name": "ds1",
            "properties": {"logs": []}
        }]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_6_1_1_3:
    @pytest.fixture
    def rule(self):
        return CIS_6_1_1_3()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_6_1_1_4:
    @pytest.fixture
    def rule(self):
        return CIS_6_1_1_4()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_key_vaults(self, rule):
        finding = await rule.check(_azure(key_vaults=[], key_vault_diagnostic_settings={}))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_audit_logging_enabled(self, rule):
        vault_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1"
        finding = await rule.check(_azure(
            key_vaults=[{"id": vault_id, "name": "kv1"}],
            key_vault_diagnostic_settings={
                vault_id: [{
                    "properties": {
                        "logs": [{"category": "AuditEvent", "enabled": True}]
                    }
                }]
            },
        ))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_audit_logging(self, rule):
        vault_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1"
        finding = await rule.check(_azure(
            key_vaults=[{"id": vault_id, "name": "kv1"}],
            key_vault_diagnostic_settings={vault_id: []},
        ))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_6_1_1_5:
    @pytest.fixture
    def rule(self):
        return CIS_6_1_1_5()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_6_1_1_6:
    @pytest.fixture
    def rule(self):
        return CIS_6_1_1_6()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_6_1_1_7:
    @pytest.fixture
    def rule(self):
        return CIS_6_1_1_7()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_6_1_1_8:
    @pytest.fixture
    def rule(self):
        return CIS_6_1_1_8()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_6_1_1_9:
    @pytest.fixture
    def rule(self):
        return CIS_6_1_1_9()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


# Activity log alerts (6.1.2.x) – pattern: skip when no data, pass/fail based on matching alert

def _make_alert_classes():
    """Return list of (class, operation_or_category, use_category) for all 6_1_2 rules."""
    return [
        (CIS_6_1_2_1, "microsoft.authorization/policyassignments/write", False),
        (CIS_6_1_2_2, "microsoft.authorization/policyassignments/delete", False),
        (CIS_6_1_2_3, "microsoft.network/networksecuritygroups/write", False),
        (CIS_6_1_2_4, "microsoft.network/networksecuritygroups/delete", False),
        (CIS_6_1_2_5, "microsoft.security/securitysolutions/write", False),
        (CIS_6_1_2_6, "microsoft.security/securitysolutions/delete", False),
        (CIS_6_1_2_7, "microsoft.sql/servers/firewallrules/write", False),
        (CIS_6_1_2_8, "microsoft.sql/servers/firewallrules/delete", False),
        (CIS_6_1_2_9, "microsoft.network/publicipaddresses/write", False),
        (CIS_6_1_2_10, "microsoft.network/publicipaddresses/delete", False),
        (CIS_6_1_2_11, "servicehealth", True),
    ]


class TestCIS_Az_6_1_2_x:
    """Parametrized tests covering all 6.1.2.x alert rules."""

    @pytest.mark.parametrize("cls,value,use_category", _make_alert_classes())
    async def test_skip_when_no_data(self, cls, value, use_category):
        rule = cls()
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.parametrize("cls,value,use_category", _make_alert_classes())
    async def test_pass_when_alert_present(self, cls, value, use_category):
        rule = cls()
        alert = _category_alert(value) if use_category else _alert(value)
        finding = await rule.check(_azure(activity_log_alerts=[alert]))
        assert finding.status == FindingStatus.PASS

    @pytest.mark.parametrize("cls,value,use_category", _make_alert_classes())
    async def test_fail_when_no_alert(self, cls, value, use_category):
        rule = cls()
        finding = await rule.check(_azure(activity_log_alerts=[]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_6_1_3_1:
    @pytest.fixture
    def rule(self):
        return CIS_6_1_3_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_components_exist(self, rule):
        finding = await rule.check(_azure(app_insights_components=[{"name": "ai1"}]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_components(self, rule):
        finding = await rule.check(_azure(app_insights_components=[]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_6_1_4:
    @pytest.fixture
    def rule(self):
        return CIS_6_1_4()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_6_1_5:
    @pytest.fixture
    def rule(self):
        return CIS_6_1_5()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_6_2:
    @pytest.fixture
    def rule(self):
        return CIS_6_2()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


# ============================================================
# SECTION 7 – Networking
# ============================================================

class TestCIS_Az_7_1:
    @pytest.fixture
    def rule(self):
        return CIS_7_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_rdp_not_exposed(self, rule):
        finding = await rule.check(_azure(network_security_groups=[_nsg_deny_all()]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_rdp_open(self, rule):
        finding = await rule.check(_azure(network_security_groups=[_nsg_allow(3389)]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_7_2:
    @pytest.fixture
    def rule(self):
        return CIS_7_2()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_ssh_not_exposed(self, rule):
        finding = await rule.check(_azure(network_security_groups=[_nsg_deny_all()]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_ssh_open(self, rule):
        finding = await rule.check(_azure(network_security_groups=[_nsg_allow(22)]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_7_3:
    @pytest.fixture
    def rule(self):
        return CIS_7_3()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_no_unrestricted_udp(self, rule):
        finding = await rule.check(_azure(network_security_groups=[_nsg_deny_all()]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_unrestricted_udp(self, rule):
        nsg = {
            "name": "open-udp",
            "id": "open-udp-id",
            "properties": {
                "securityRules": [{
                    "name": "allow-all-udp",
                    "properties": {
                        "protocol": "UDP",
                        "access": "Allow",
                        "direction": "Inbound",
                        "destinationPortRange": "*",
                        "sourceAddressPrefix": "*",
                        "destinationAddressPrefix": "*",
                        "priority": 100,
                    }
                }]
            }
        }
        finding = await rule.check(_azure(network_security_groups=[nsg]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_7_4:
    @pytest.fixture
    def rule(self):
        return CIS_7_4()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_http_not_exposed(self, rule):
        finding = await rule.check(_azure(network_security_groups=[_nsg_deny_all()]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_http_open(self, rule):
        finding = await rule.check(_azure(network_security_groups=[_nsg_allow(80)]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_7_5:
    @pytest.fixture
    def rule(self):
        return CIS_7_5()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_retention_ok(self, rule):
        finding = await rule.check(_azure(flow_logs=[{
            "name": "fl1",
            "properties": {"retentionPolicy": {"enabled": True, "days": 90}}
        }]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_flow_logs(self, rule):
        finding = await rule.check(_azure(flow_logs=[]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_7_6:
    @pytest.fixture
    def rule(self):
        return CIS_7_6()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_vnets(self, rule):
        # No VNets → nothing to check, SKIP
        finding = await rule.check(_azure(
            network_watchers=[],
            virtual_networks=[],
        ))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_watcher_covers_all_regions(self, rule):
        finding = await rule.check(_azure(
            network_watchers=[{"location": "eastus"}],
            virtual_networks=[{"location": "eastus"}],
        ))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_missing_watcher(self, rule):
        finding = await rule.check(_azure(
            network_watchers=[{"location": "westus"}],
            virtual_networks=[{"location": "eastus"}],
        ))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_7_7:
    @pytest.fixture
    def rule(self):
        return CIS_7_7()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_7_8:
    @pytest.fixture
    def rule(self):
        return CIS_7_8()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_vnet_flow_logs_ok(self, rule):
        finding = await rule.check(_azure(flow_logs=[{
            "name": "vfl1",
            "properties": {"retentionPolicy": {"enabled": True, "days": 90}}
        }]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_vnet_flow_logs(self, rule):
        finding = await rule.check(_azure(
            flow_logs=[],
            virtual_networks=[{"name": "vnet1"}],
        ))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_7_9:
    @pytest.fixture
    def rule(self):
        return CIS_7_9()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_gateways(self, rule):
        finding = await rule.check(_azure(vpn_gateways=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_aad_auth(self, rule):
        finding = await rule.check(_azure(vpn_gateways=[{
            "name": "gw1",
            "properties": {
                "gatewayType": "Vpn",
                "vpnClientConfiguration": {"vpnAuthenticationTypes": ["AAD"]},
            }
        }]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_cert_auth(self, rule):
        finding = await rule.check(_azure(vpn_gateways=[{
            "name": "gw1",
            "properties": {
                "gatewayType": "Vpn",
                "vpnClientConfiguration": {"vpnAuthenticationTypes": ["Certificate"]},
            }
        }]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_7_10:
    @pytest.fixture
    def rule(self):
        return CIS_7_10()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_gateways(self, rule):
        finding = await rule.check(_azure(application_gateways=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_waf_enabled(self, rule):
        finding = await rule.check(_azure(application_gateways=[{
            "name": "gw1",
            "properties": {"webApplicationFirewallConfiguration": {"enabled": True}}
        }]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_waf_disabled(self, rule):
        finding = await rule.check(_azure(application_gateways=[{
            "name": "gw1",
            "properties": {}
        }]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_7_11:
    @pytest.fixture
    def rule(self):
        return CIS_7_11()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_vnets(self, rule):
        finding = await rule.check(_azure(virtual_networks=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_subnets_have_nsg(self, rule):
        finding = await rule.check(_azure(virtual_networks=[{
            "name": "vnet1",
            "properties": {
                "subnets": [{
                    "name": "default",
                    "properties": {
                        "networkSecurityGroup": {"id": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg1"}
                    }
                }]
            }
        }]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_subnet_lacks_nsg(self, rule):
        finding = await rule.check(_azure(virtual_networks=[{
            "name": "vnet1",
            "properties": {
                "subnets": [{
                    "name": "default",
                    "properties": {"networkSecurityGroup": None}
                }]
            }
        }]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_7_12:
    @pytest.fixture
    def rule(self):
        return CIS_7_12()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_gateways(self, rule):
        finding = await rule.check(_azure(application_gateways=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_tls_12(self, rule):
        finding = await rule.check(_azure(application_gateways=[{
            "name": "gw1",
            "properties": {"sslPolicy": {"minProtocolVersion": "TLSv1_2"}}
        }]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_tls_old(self, rule):
        finding = await rule.check(_azure(application_gateways=[{
            "name": "gw1",
            "properties": {"sslPolicy": {"minProtocolVersion": "TLSv1_0"}}
        }]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_7_13:
    @pytest.fixture
    def rule(self):
        return CIS_7_13()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_gateways(self, rule):
        finding = await rule.check(_azure(application_gateways=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_http2_enabled(self, rule):
        finding = await rule.check(_azure(application_gateways=[{
            "name": "gw1",
            "properties": {"enableHttp2": True}
        }]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_http2_disabled(self, rule):
        finding = await rule.check(_azure(application_gateways=[{
            "name": "gw1",
            "properties": {"enableHttp2": False}
        }]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_7_14:
    @pytest.fixture
    def rule(self):
        return CIS_7_14()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_gateways(self, rule):
        finding = await rule.check(_azure(application_gateways=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_request_body_checked(self, rule):
        finding = await rule.check(_azure(application_gateways=[{
            "name": "gw1",
            "properties": {
                "webApplicationFirewallConfiguration": {
                    "enabled": True,
                    "requestBodyCheck": True,
                }
            }
        }]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_request_body_check(self, rule):
        finding = await rule.check(_azure(application_gateways=[{
            "name": "gw1",
            "properties": {
                "webApplicationFirewallConfiguration": {
                    "enabled": True,
                    "requestBodyCheck": False,
                    "requestBodyEnforcement": False,
                }
            }
        }]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_7_15:
    @pytest.fixture
    def rule(self):
        return CIS_7_15()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_gateways(self, rule):
        finding = await rule.check(_azure(application_gateways=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_waf_policy_attached(self, rule):
        finding = await rule.check(_azure(application_gateways=[{
            "name": "gw1",
            "properties": {
                "webApplicationFirewallConfiguration": {"enabled": True},
                "firewallPolicy": {"id": "/subscriptions/sub/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/pol1"},
            }
        }]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_waf_no_policy(self, rule):
        finding = await rule.check(_azure(application_gateways=[{
            "name": "gw1",
            "properties": {
                "webApplicationFirewallConfiguration": {"enabled": True},
                "firewallPolicy": {},
            }
        }]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_7_16:
    @pytest.fixture
    def rule(self):
        return CIS_7_16()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


# ============================================================
# SECTION 8 – Security Center / Defender
# ============================================================

def _defender_data(plan_name: str, tier: str = "Standard"):
    return _azure(defender_pricings=[_pricing(plan_name, tier)])


class TestCIS_Az_8_1_1_1:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_1_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_cspm_standard(self, rule):
        finding = await rule.check(_defender_data("CloudPosture"))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_cspm_free(self, rule):
        finding = await rule.check(_defender_data("CloudPosture", "Free"))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_8_1_2_1:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_2_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_apis_standard(self, rule):
        finding = await rule.check(_defender_data("Apis"))
        assert finding.status == FindingStatus.PASS


class TestCIS_Az_8_1_3_1:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_3_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_vms_standard(self, rule):
        finding = await rule.check(_defender_data("VirtualMachines"))
        assert finding.status == FindingStatus.PASS


class TestCIS_Az_8_1_3_2:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_3_2()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_8_1_3_3:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_3_3()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_auto_provisioning_on(self, rule):
        finding = await rule.check(_azure(auto_provisioning_settings=[{
            "name": "mma-agent",
            "properties": {"autoProvision": "On"}
        }]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_auto_provisioning_off(self, rule):
        finding = await rule.check(_azure(auto_provisioning_settings=[{
            "name": "mma-agent",
            "properties": {"autoProvision": "Off"}
        }]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_8_1_3_4:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_3_4()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_8_1_3_5:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_3_5()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_8_1_4_1:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_4_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_containers_standard(self, rule):
        finding = await rule.check(_defender_data("Containers"))
        assert finding.status == FindingStatus.PASS


class TestCIS_Az_8_1_5_1:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_5_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_storage_standard(self, rule):
        finding = await rule.check(_defender_data("StorageAccounts"))
        assert finding.status == FindingStatus.PASS


class TestCIS_Az_8_1_5_2:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_5_2()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_8_1_6_1:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_6_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_app_services_standard(self, rule):
        finding = await rule.check(_defender_data("AppServices"))
        assert finding.status == FindingStatus.PASS


class TestCIS_Az_8_1_7_1:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_7_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_cosmos_standard(self, rule):
        finding = await rule.check(_defender_data("CosmosDbs"))
        assert finding.status == FindingStatus.PASS


class TestCIS_Az_8_1_7_2:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_7_2()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED


class TestCIS_Az_8_1_7_3:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_7_3()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_sql_vm_standard(self, rule):
        finding = await rule.check(_defender_data("SqlServerVirtualMachines"))
        assert finding.status == FindingStatus.PASS


class TestCIS_Az_8_1_7_4:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_7_4()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_sql_servers_standard(self, rule):
        finding = await rule.check(_defender_data("SqlServers"))
        assert finding.status == FindingStatus.PASS


class TestCIS_Az_8_1_8_1:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_8_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_keyvaults_standard(self, rule):
        finding = await rule.check(_defender_data("KeyVaults"))
        assert finding.status == FindingStatus.PASS


class TestCIS_Az_8_1_9_1:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_9_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_arm_standard(self, rule):
        finding = await rule.check(_defender_data("Arm"))
        assert finding.status == FindingStatus.PASS


class TestCIS_Az_8_1_10:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_10()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_mma_on(self, rule):
        finding = await rule.check(_azure(auto_provisioning_settings=[{
            "name": "mma-agent",
            "properties": {"autoProvision": "On"}
        }]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_mma_off(self, rule):
        finding = await rule.check(_azure(auto_provisioning_settings=[{
            "name": "mma-agent",
            "properties": {"autoProvision": "Off"}
        }]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_8_1_11:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_11()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_8_1_12:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_12()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_owner_notified(self, rule):
        finding = await rule.check(_azure(security_contacts=[{
            "properties": {"notificationsByRole": {"state": "On", "roles": ["Owner"]}}
        }]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_owner_notification(self, rule):
        finding = await rule.check(_azure(security_contacts=[{
            "properties": {"notificationsByRole": {"state": "Off", "roles": []}}
        }]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_8_1_13:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_13()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_email_set(self, rule):
        finding = await rule.check(_azure(security_contacts=[{
            "properties": {"emails": "sec@example.com"}
        }]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_email(self, rule):
        finding = await rule.check(_azure(security_contacts=[{
            "properties": {"emails": ""}
        }]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_8_1_14:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_14()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_alert_notifications_on(self, rule):
        finding = await rule.check(_azure(security_contacts=[{
            "properties": {"alertNotifications": {"state": "On", "minimalSeverity": "High"}}
        }]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_alerts_off(self, rule):
        finding = await rule.check(_azure(security_contacts=[{
            "properties": {"alertNotifications": {"state": "Off"}}
        }]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_8_1_15:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_15()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_attack_path_notifications_on(self, rule):
        finding = await rule.check(_azure(security_contacts_v2=[{
            "properties": {"notificationsSources": [{"sourceType": "AttackPath", "state": "On"}]}
        }]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_notifications(self, rule):
        finding = await rule.check(_azure(security_contacts_v2=[{
            "properties": {"notificationsSources": []}
        }]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_8_1_16:
    @pytest.fixture
    def rule(self):
        return CIS_8_1_16()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_8_2_1:
    @pytest.fixture
    def rule(self):
        return CIS_8_2_1()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


def _vault(name: str = "kv1", rbac: bool = True, soft_delete: bool = True, purge: bool = True, public: str = "Disabled") -> dict:
    return {
        "id": f"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/{name}",
        "name": name,
        "properties": {
            "enableRbacAuthorization": rbac,
            "enableSoftDelete": soft_delete,
            "enablePurgeProtection": purge,
            "publicNetworkAccess": public,
            "networkAcls": {"defaultAction": "Deny"},
            "privateEndpointConnections": [{"id": "pe1"}],
        }
    }


class TestCIS_Az_8_3_1:
    @pytest.fixture
    def rule(self):
        return CIS_8_3_1()

    async def test_skip_when_no_keys(self, rule):
        finding = await rule.check(_azure(key_vaults=[_vault()]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_keys_have_expiry(self, rule):
        vid = _vault()["id"]
        finding = await rule.check(_azure(
            key_vaults=[_vault()],
            key_vault_keys={vid: [{"name": "k1", "properties": {"attributes": {"enabled": True, "exp": 9999999999}}}]},
        ))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_key_missing_expiry(self, rule):
        vid = _vault()["id"]
        finding = await rule.check(_azure(
            key_vaults=[_vault()],
            key_vault_keys={vid: [{"name": "k1", "properties": {"attributes": {"enabled": True}}}]},
        ))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_8_3_2:
    @pytest.fixture
    def rule(self):
        return CIS_8_3_2()

    async def test_skip_when_no_keys(self, rule):
        finding = await rule.check(_azure(key_vaults=[_vault(rbac=False)]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_access_policy_key_has_expiry(self, rule):
        vid = _vault(rbac=False)["id"]
        finding = await rule.check(_azure(
            key_vaults=[_vault(rbac=False)],
            key_vault_keys={vid: [{"name": "k1", "properties": {"attributes": {"enabled": True, "exp": 9999999999}}}]},
        ))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_key_missing_expiry(self, rule):
        vid = _vault(rbac=False)["id"]
        finding = await rule.check(_azure(
            key_vaults=[_vault(rbac=False)],
            key_vault_keys={vid: [{"name": "k1", "properties": {"attributes": {"enabled": True}}}]},
        ))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_8_3_3:
    @pytest.fixture
    def rule(self):
        return CIS_8_3_3()

    async def test_skip_when_no_secrets(self, rule):
        finding = await rule.check(_azure(key_vaults=[_vault()]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_secrets_have_expiry(self, rule):
        vid = _vault()["id"]
        finding = await rule.check(_azure(
            key_vaults=[_vault()],
            key_vault_secrets={vid: [{"name": "s1", "properties": {"attributes": {"enabled": True, "exp": 9999999999}}}]},
        ))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_secret_missing_expiry(self, rule):
        vid = _vault()["id"]
        finding = await rule.check(_azure(
            key_vaults=[_vault()],
            key_vault_secrets={vid: [{"name": "s1", "properties": {"attributes": {"enabled": True}}}]},
        ))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_8_3_4:
    @pytest.fixture
    def rule(self):
        return CIS_8_3_4()

    async def test_skip_when_no_secrets(self, rule):
        finding = await rule.check(_azure(key_vaults=[_vault(rbac=False)]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_secret_has_expiry(self, rule):
        vid = _vault(rbac=False)["id"]
        finding = await rule.check(_azure(
            key_vaults=[_vault(rbac=False)],
            key_vault_secrets={vid: [{"name": "s1", "properties": {"attributes": {"enabled": True, "exp": 9999999999}}}]},
        ))
        assert finding.status == FindingStatus.PASS


class TestCIS_Az_8_3_5:
    @pytest.fixture
    def rule(self):
        return CIS_8_3_5()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_vaults(self, rule):
        finding = await rule.check(_azure(key_vaults=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_soft_delete_and_purge_enabled(self, rule):
        finding = await rule.check(_azure(key_vaults=[_vault(soft_delete=True, purge=True)]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_purge_disabled(self, rule):
        finding = await rule.check(_azure(key_vaults=[_vault(soft_delete=True, purge=False)]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_8_3_6:
    @pytest.fixture
    def rule(self):
        return CIS_8_3_6()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_vaults(self, rule):
        finding = await rule.check(_azure(key_vaults=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_rbac_enabled(self, rule):
        finding = await rule.check(_azure(key_vaults=[_vault(rbac=True)]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_rbac_disabled(self, rule):
        finding = await rule.check(_azure(key_vaults=[_vault(rbac=False)]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_8_3_7:
    @pytest.fixture
    def rule(self):
        return CIS_8_3_7()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_vaults(self, rule):
        finding = await rule.check(_azure(key_vaults=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_public_disabled(self, rule):
        finding = await rule.check(_azure(key_vaults=[_vault(public="Disabled")]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_public_enabled_default_allow(self, rule):
        v = _vault(public="Enabled")
        v["properties"]["networkAcls"]["defaultAction"] = "Allow"
        finding = await rule.check(_azure(key_vaults=[v]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_8_3_8:
    @pytest.fixture
    def rule(self):
        return CIS_8_3_8()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_vaults(self, rule):
        finding = await rule.check(_azure(key_vaults=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_private_endpoint_exists(self, rule):
        finding = await rule.check(_azure(key_vaults=[_vault()]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_private_endpoint(self, rule):
        v = _vault()
        v["properties"]["privateEndpointConnections"] = []
        finding = await rule.check(_azure(key_vaults=[v]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_8_3_9:
    @pytest.fixture
    def rule(self):
        return CIS_8_3_9()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_rotation_policy_set(self, rule):
        finding = await rule.check(_azure(key_vault_keys={
            "kv1": [{"name": "k1", "properties": {
                "attributes": {"enabled": True},
                "rotationPolicy": {"lifetimeActions": []}
            }}]
        }))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_rotation_policy(self, rule):
        finding = await rule.check(_azure(key_vault_keys={
            "kv1": [{"name": "k1", "properties": {
                "attributes": {"enabled": True},
            }}]
        }))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_8_3_10:
    @pytest.fixture
    def rule(self):
        return CIS_8_3_10()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_8_3_11:
    @pytest.fixture
    def rule(self):
        return CIS_8_3_11()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_cert_validity_ok(self, rule):
        # created=0, exp=90 days (7776000 seconds) — well under the limit
        finding = await rule.check(_azure(key_vault_certificates={
            "kv1": [{"id": "https://kv1.vault.azure.net/certificates/cert1/ver1",
                     "attributes": {"enabled": True, "created": 0, "exp": 7776000}}]
        }))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_cert_too_long(self, rule):
        # 3 years in seconds = 94608000 — likely exceeds the limit
        finding = await rule.check(_azure(key_vault_certificates={
            "kv1": [{"id": "https://kv1.vault.azure.net/certificates/cert1/ver1",
                     "attributes": {"enabled": True, "created": 0, "exp": 94608000}}]
        }))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_8_4_1:
    @pytest.fixture
    def rule(self):
        return CIS_8_4_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_bastion_deployed(self, rule):
        finding = await rule.check(_azure(bastion_hosts=[{"name": "bastion1"}]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_bastion(self, rule):
        finding = await rule.check(_azure(bastion_hosts=[]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_8_5:
    @pytest.fixture
    def rule(self):
        return CIS_8_5()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_vnets(self, rule):
        finding = await rule.check(_azure(virtual_networks=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_ddos_enabled(self, rule):
        finding = await rule.check(_azure(virtual_networks=[{
            "name": "vnet1",
            "properties": {"enableDdosProtection": True}
        }]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_ddos_disabled(self, rule):
        finding = await rule.check(_azure(virtual_networks=[{
            "name": "vnet1",
            "properties": {"enableDdosProtection": False}
        }]))
        assert finding.status == FindingStatus.FAIL


# ============================================================
# SECTION 9 – Storage
# ============================================================

def _sa(name: str = "sa1", **props) -> dict:
    """Create a minimal storage account dict."""
    return {
        "id": f"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/{name}",
        "name": name,
        "properties": props,
    }


class TestCIS_Az_9_1_1:
    @pytest.fixture
    def rule(self):
        return CIS_9_1_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_accounts(self, rule):
        finding = await rule.check(_azure(storage_accounts=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_retention_ok(self, rule):
        sa = _sa()
        acct_id = sa["id"]
        finding = await rule.check(_azure(
            storage_accounts=[sa],
            storage_file_services={acct_id: {
                "properties": {"shareDeleteRetentionPolicy": {"enabled": True, "days": 7}}
            }},
        ))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_retention_disabled(self, rule):
        sa = _sa()
        acct_id = sa["id"]
        finding = await rule.check(_azure(
            storage_accounts=[sa],
            storage_file_services={acct_id: {
                "properties": {"shareDeleteRetentionPolicy": {"enabled": False, "days": 0}}
            }},
        ))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_9_1_2:
    @pytest.fixture
    def rule(self):
        return CIS_9_1_2()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_only_smb31(self, rule):
        sa_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1"
        finding = await rule.check(_azure(storage_file_services={
            sa_id: {"properties": {"protocolSettings": {"smb": {"versions": "SMB3.1.1"}}}}
        }))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_weak_smb_allowed(self, rule):
        sa_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1"
        finding = await rule.check(_azure(storage_file_services={
            sa_id: {"properties": {"protocolSettings": {"smb": {"versions": "SMB2.1;SMB3.0;SMB3.1.1"}}}}
        }))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_9_1_3:
    @pytest.fixture
    def rule(self):
        return CIS_9_1_3()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_channel_encryption_set(self, rule):
        sa_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1"
        finding = await rule.check(_azure(storage_file_services={
            sa_id: {"properties": {"protocolSettings": {"smb": {"channelEncryption": "AES-256-GCM"}}}}
        }))
        assert finding.status == FindingStatus.PASS


class TestCIS_Az_9_2_1:
    @pytest.fixture
    def rule(self):
        return CIS_9_2_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_accounts(self, rule):
        finding = await rule.check(_azure(storage_accounts=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_blob_soft_delete_ok(self, rule):
        sa = _sa()
        acct_id = sa["id"]
        finding = await rule.check(_azure(
            storage_accounts=[sa],
            storage_blob_services={acct_id: {
                "properties": {"deleteRetentionPolicy": {"enabled": True, "days": 7}}
            }},
        ))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_soft_delete_disabled(self, rule):
        sa = _sa()
        acct_id = sa["id"]
        finding = await rule.check(_azure(
            storage_accounts=[sa],
            storage_blob_services={acct_id: {
                "properties": {"deleteRetentionPolicy": {"enabled": False, "days": 0}}
            }},
        ))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_9_2_2:
    @pytest.fixture
    def rule(self):
        return CIS_9_2_2()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_container_retention_enabled(self, rule):
        sa_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1"
        finding = await rule.check(_azure(storage_blob_services={
            sa_id: {"properties": {"containerDeleteRetentionPolicy": {"enabled": True, "days": 7}}}
        }))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_container_retention_disabled(self, rule):
        sa_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1"
        finding = await rule.check(_azure(storage_blob_services={
            sa_id: {"properties": {"containerDeleteRetentionPolicy": {"enabled": False}}}
        }))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_9_2_3:
    @pytest.fixture
    def rule(self):
        return CIS_9_2_3()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_versioning_enabled(self, rule):
        sa_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1"
        finding = await rule.check(_azure(storage_blob_services={
            sa_id: {"properties": {"isVersioningEnabled": True}}
        }))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_versioning_disabled(self, rule):
        sa_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1"
        finding = await rule.check(_azure(storage_blob_services={
            sa_id: {"properties": {"isVersioningEnabled": False}}
        }))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_9_3_1_1:
    @pytest.fixture
    def rule(self):
        return CIS_9_3_1_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_accounts(self, rule):
        finding = await rule.check(_azure(storage_accounts=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_key_expiry_set(self, rule):
        finding = await rule.check(_azure(storage_accounts=[
            _sa(keyPolicy={"keyExpirationPeriodInDays": 90})
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_key_expiry(self, rule):
        finding = await rule.check(_azure(storage_accounts=[_sa()]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_9_3_1_2:
    @pytest.fixture
    def rule(self):
        return CIS_9_3_1_2()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_accounts(self, rule):
        finding = await rule.check(_azure(storage_accounts=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_expiry_set(self, rule):
        finding = await rule.check(_azure(storage_accounts=[
            _sa(keyPolicy={"keyExpirationPeriodInDays": 90})
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_expiry(self, rule):
        finding = await rule.check(_azure(storage_accounts=[_sa()]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_9_3_1_3:
    @pytest.fixture
    def rule(self):
        return CIS_9_3_1_3()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_accounts(self, rule):
        finding = await rule.check(_azure(storage_accounts=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_shared_key_disabled(self, rule):
        finding = await rule.check(_azure(storage_accounts=[
            _sa(allowSharedKeyAccess=False)
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_shared_key_allowed(self, rule):
        finding = await rule.check(_azure(storage_accounts=[_sa(allowSharedKeyAccess=True)]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_9_3_2_1:
    @pytest.fixture
    def rule(self):
        return CIS_9_3_2_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_accounts(self, rule):
        finding = await rule.check(_azure(storage_accounts=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_private_endpoint_exists(self, rule):
        finding = await rule.check(_azure(storage_accounts=[
            _sa(privateEndpointConnections=[{"id": "pe1"}])
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_private_endpoint(self, rule):
        finding = await rule.check(_azure(storage_accounts=[_sa()]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_9_3_2_2:
    @pytest.fixture
    def rule(self):
        return CIS_9_3_2_2()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_accounts(self, rule):
        finding = await rule.check(_azure(storage_accounts=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_public_access_disabled(self, rule):
        finding = await rule.check(_azure(storage_accounts=[
            _sa(publicNetworkAccess="Disabled")
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_public_access_enabled(self, rule):
        finding = await rule.check(_azure(storage_accounts=[
            _sa(publicNetworkAccess="Enabled")
        ]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_9_3_2_3:
    @pytest.fixture
    def rule(self):
        return CIS_9_3_2_3()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_accounts(self, rule):
        finding = await rule.check(_azure(storage_accounts=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_default_deny(self, rule):
        finding = await rule.check(_azure(storage_accounts=[
            _sa(networkAcls={"defaultAction": "Deny"})
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_default_allow(self, rule):
        finding = await rule.check(_azure(storage_accounts=[
            _sa(networkAcls={"defaultAction": "Allow"})
        ]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_9_3_3_1:
    @pytest.fixture
    def rule(self):
        return CIS_9_3_3_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_accounts(self, rule):
        finding = await rule.check(_azure(storage_accounts=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_oauth_default(self, rule):
        finding = await rule.check(_azure(storage_accounts=[
            _sa(defaultToOAuthAuthentication=True)
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_oauth_not_default(self, rule):
        finding = await rule.check(_azure(storage_accounts=[_sa()]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_9_3_4:
    @pytest.fixture
    def rule(self):
        return CIS_9_3_4()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_accounts(self, rule):
        finding = await rule.check(_azure(storage_accounts=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_https_only(self, rule):
        finding = await rule.check(_azure(storage_accounts=[
            _sa(supportsHttpsTrafficOnly=True)
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_http_allowed(self, rule):
        finding = await rule.check(_azure(storage_accounts=[
            _sa(supportsHttpsTrafficOnly=False)
        ]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_9_3_5:
    @pytest.fixture
    def rule(self):
        return CIS_9_3_5()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_accounts(self, rule):
        finding = await rule.check(_azure(storage_accounts=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_azure_services_in_bypass(self, rule):
        finding = await rule.check(_azure(storage_accounts=[
            _sa(networkAcls={"bypass": "AzureServices,Logging"})
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_azure_services_not_in_bypass(self, rule):
        finding = await rule.check(_azure(storage_accounts=[
            _sa(networkAcls={"bypass": "None"})
        ]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_9_3_6:
    @pytest.fixture
    def rule(self):
        return CIS_9_3_6()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_accounts(self, rule):
        finding = await rule.check(_azure(storage_accounts=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_tls12(self, rule):
        finding = await rule.check(_azure(storage_accounts=[
            _sa(minimumTlsVersion="TLS1_2")
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_tls10(self, rule):
        finding = await rule.check(_azure(storage_accounts=[
            _sa(minimumTlsVersion="TLS1_0")
        ]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_9_3_7:
    @pytest.fixture
    def rule(self):
        return CIS_9_3_7()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_accounts(self, rule):
        finding = await rule.check(_azure(storage_accounts=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_cross_tenant_disabled(self, rule):
        finding = await rule.check(_azure(storage_accounts=[
            _sa(allowCrossTenantReplication=False)
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_cross_tenant_enabled(self, rule):
        finding = await rule.check(_azure(storage_accounts=[
            _sa(allowCrossTenantReplication=True)
        ]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_9_3_8:
    @pytest.fixture
    def rule(self):
        return CIS_9_3_8()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_accounts(self, rule):
        finding = await rule.check(_azure(storage_accounts=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_blob_public_access_disabled(self, rule):
        finding = await rule.check(_azure(storage_accounts=[
            _sa(allowBlobPublicAccess=False)
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_blob_public_access_enabled(self, rule):
        finding = await rule.check(_azure(storage_accounts=[
            _sa(allowBlobPublicAccess=True)
        ]))
        assert finding.status == FindingStatus.FAIL


class TestCIS_Az_9_3_9:
    @pytest.fixture
    def rule(self):
        return CIS_9_3_9()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_9_3_10:
    @pytest.fixture
    def rule(self):
        return CIS_9_3_10()

    async def test_always_manual(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_Az_9_3_11:
    @pytest.fixture
    def rule(self):
        return CIS_9_3_11()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_azure())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_accounts(self, rule):
        finding = await rule.check(_azure(storage_accounts=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_geo_redundant(self, rule):
        sa = _sa()
        sa["sku"] = {"name": "Standard_GRS"}
        finding = await rule.check(_azure(storage_accounts=[sa]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_not_geo_redundant(self, rule):
        sa = _sa()
        sa["sku"] = {"name": "Standard_LRS"}
        finding = await rule.check(_azure(storage_accounts=[sa]))
        assert finding.status == FindingStatus.FAIL
