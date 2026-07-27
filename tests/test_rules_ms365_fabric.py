"""Unit tests for the Microsoft Fabric CIS rules (section 9.1)."""

import pytest

from sspm.core.models import FindingStatus
from sspm.providers.base import CollectedData
from sspm.providers.ms365.rules.section9_fabric.cis_9_1_1 import CIS_9_1_1
from sspm.providers.ms365.rules.section9_fabric.cis_9_1_2 import CIS_9_1_2
from sspm.providers.ms365.rules.section9_fabric.cis_9_1_3 import CIS_9_1_3
from sspm.providers.ms365.rules.section9_fabric.cis_9_1_4 import CIS_9_1_4
from sspm.providers.ms365.rules.section9_fabric.cis_9_1_5 import CIS_9_1_5
from sspm.providers.ms365.rules.section9_fabric.cis_9_1_6 import CIS_9_1_6
from sspm.providers.ms365.rules.section9_fabric.cis_9_1_7 import CIS_9_1_7
from sspm.providers.ms365.rules.section9_fabric.cis_9_1_8 import CIS_9_1_8
from sspm.providers.ms365.rules.section9_fabric.cis_9_1_9 import CIS_9_1_9
from sspm.providers.ms365.rules.section9_fabric.cis_9_1_10 import CIS_9_1_10
from sspm.providers.ms365.rules.section9_fabric.cis_9_1_11 import CIS_9_1_11
from sspm.providers.ms365.rules.section9_fabric.cis_9_1_12 import CIS_9_1_12


def _fabric(*settings) -> CollectedData:
    return CollectedData(
        provider="ms365",
        target="test.onmicrosoft.com",
        data={"fabric_tenant_settings": {"tenantSettings": list(settings)}},
    )


def _no_data() -> CollectedData:
    return CollectedData(provider="ms365", target="test.onmicrosoft.com", data={})


# Rules that pass when disabled, or enabled + scoped to security groups.
GROUP_RESTRICT_RULES = [
    (CIS_9_1_1, "AllowGuestUserToAccessSharedContent"),
    (CIS_9_1_2, "ExternalSharingV2"),
    (CIS_9_1_3, "ElevatedGuestsTenant"),
    (CIS_9_1_7, "ShareLinkToEntireOrg"),
    (CIS_9_1_8, "EnableDatasetInPlaceSharing"),
    (CIS_9_1_10, "ServicePrincipalAccessPermissionAPIs"),
    (CIS_9_1_11, "AllowServicePrincipalsCreateAndUseProfiles"),
    (CIS_9_1_12, "ServicePrincipalAccessGlobalAPIs"),
]


class TestGroupRestrictFabricRules:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("rule_cls,setting_name", GROUP_RESTRICT_RULES)
    async def test_pass_when_disabled(self, rule_cls, setting_name):
        data = _fabric({"settingName": setting_name, "enabled": False})
        finding = await rule_cls().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    @pytest.mark.parametrize("rule_cls,setting_name", GROUP_RESTRICT_RULES)
    async def test_pass_when_enabled_with_security_groups(self, rule_cls, setting_name):
        data = _fabric({
            "settingName": setting_name,
            "enabled": True,
            "enabledSecurityGroups": [{"graphId": "g1", "name": "Fabric Admins"}],
        })
        finding = await rule_cls().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    @pytest.mark.parametrize("rule_cls,setting_name", GROUP_RESTRICT_RULES)
    async def test_fail_when_enabled_for_entire_org(self, rule_cls, setting_name):
        data = _fabric({"settingName": setting_name, "enabled": True})
        finding = await rule_cls().check(data)
        assert finding.status == FindingStatus.FAIL

    @pytest.mark.asyncio
    @pytest.mark.parametrize("rule_cls,setting_name", GROUP_RESTRICT_RULES)
    async def test_manual_when_no_fabric_data(self, rule_cls, setting_name):
        finding = await rule_cls().check(_no_data())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_9_1_4:
    """Publish to web: also requires createP2w=false."""

    @pytest.mark.asyncio
    async def test_pass_when_disabled(self):
        data = _fabric({"settingName": "PublishToWebPublishToWeb", "enabled": False})
        finding = await CIS_9_1_4().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_pass_when_restricted_existing_codes_only(self):
        data = _fabric({
            "settingName": "PublishToWebPublishToWeb",
            "enabled": True,
            "enabledSecurityGroups": [{"graphId": "g1"}],
            "properties": [{"name": "createP2w", "value": "false"}],
        })
        finding = await CIS_9_1_4().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_new_codes_allowed(self):
        data = _fabric({
            "settingName": "PublishToWebPublishToWeb",
            "enabled": True,
            "enabledSecurityGroups": [{"graphId": "g1"}],
            "properties": [{"name": "createP2w", "value": "true"}],
        })
        finding = await CIS_9_1_4().check(data)
        assert finding.status == FindingStatus.FAIL


class TestCIS_9_1_5:
    """R and Python visuals: must be disabled, no security-group escape hatch."""

    @pytest.mark.asyncio
    async def test_pass_when_disabled(self):
        data = _fabric({"settingName": "RScriptVisual", "enabled": False})
        finding = await CIS_9_1_5().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_enabled(self):
        data = _fabric({"settingName": "RScriptVisual", "enabled": True})
        finding = await CIS_9_1_5().check(data)
        assert finding.status == FindingStatus.FAIL


class TestCIS_9_1_6:
    """Sensitivity labels: must be enabled (opposite polarity)."""

    @pytest.mark.asyncio
    async def test_pass_when_enabled(self):
        data = _fabric({"settingName": "EimInformationProtectionEdit", "enabled": True})
        finding = await CIS_9_1_6().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_disabled(self):
        data = _fabric({"settingName": "EimInformationProtectionEdit", "enabled": False})
        finding = await CIS_9_1_6().check(data)
        assert finding.status == FindingStatus.FAIL


class TestCIS_9_1_9:
    """Block ResourceKey authentication: must be enabled (opposite polarity)."""

    @pytest.mark.asyncio
    async def test_pass_when_enabled(self):
        data = _fabric({"settingName": "BlockResourceKeyAuthentication", "enabled": True})
        finding = await CIS_9_1_9().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_disabled(self):
        data = _fabric({"settingName": "BlockResourceKeyAuthentication", "enabled": False})
        finding = await CIS_9_1_9().check(data)
        assert finding.status == FindingStatus.FAIL
