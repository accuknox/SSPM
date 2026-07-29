"""Section 7 rules that read Get-SPOTenant properties.

Microsoft Graph's /admin/sharepoint/settings does not expose the link
defaults, guest expiration, email attestation, infected-file download, or
Entra B2B integration properties, so these controls depend on the SharePoint
Online PowerShell bridge (collector key "spo_tenant"). Without a certificate
there is no data, and an Automated control with no data is SKIPPED.
"""

import pytest

from sspm.core.models import FindingStatus
from sspm.providers.base import CollectedData
from sspm.providers.ms365.rules.section7_sharepoint.cis_7_2_2 import CIS_7_2_2
from sspm.providers.ms365.rules.section7_sharepoint.cis_7_2_5 import CIS_7_2_5
from sspm.providers.ms365.rules.section7_sharepoint.cis_7_2_6 import CIS_7_2_6
from sspm.providers.ms365.rules.section7_sharepoint.cis_7_2_7 import CIS_7_2_7
from sspm.providers.ms365.rules.section7_sharepoint.cis_7_2_9 import CIS_7_2_9
from sspm.providers.ms365.rules.section7_sharepoint.cis_7_2_10 import CIS_7_2_10
from sspm.providers.ms365.rules.section7_sharepoint.cis_7_2_11 import CIS_7_2_11
from sspm.providers.ms365.rules.section7_sharepoint.cis_7_3_1 import CIS_7_3_1

SPO_RULES = [CIS_7_2_2, CIS_7_2_7, CIS_7_2_9, CIS_7_2_10, CIS_7_2_11, CIS_7_3_1]


def _spo(**properties) -> CollectedData:
    return CollectedData(
        provider="ms365", target="test.onmicrosoft.com",
        data={"spo_tenant": properties},
    )


def _graph(**properties) -> CollectedData:
    return CollectedData(
        provider="ms365", target="test.onmicrosoft.com",
        data={"sharepoint_settings": properties},
    )


@pytest.mark.parametrize("rule_cls", SPO_RULES)
async def test_skipped_without_the_sharepoint_bridge(rule_cls):
    data = CollectedData(provider="ms365", target="test.onmicrosoft.com", data={})
    finding = await rule_cls().check(data)
    assert finding.status == FindingStatus.SKIPPED
    assert "Get-SPOTenant" in finding.message


@pytest.mark.parametrize("rule_cls", SPO_RULES)
async def test_skipped_on_collection_error(rule_cls):
    data = CollectedData(
        provider="ms365", target="test.onmicrosoft.com",
        data={}, errors={"spo_tenant": "Connect-SPOService failed"},
    )
    finding = await rule_cls().check(data)
    assert finding.status == FindingStatus.SKIPPED
    assert "Connect-SPOService failed" in finding.message


class TestCIS_7_2_2:
    async def test_pass_when_b2b_integration_enabled(self):
        finding = await CIS_7_2_2().check(_spo(EnableAzureADB2BIntegration=True))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_b2b_integration_disabled(self):
        finding = await CIS_7_2_2().check(_spo(EnableAzureADB2BIntegration=False))
        assert finding.status == FindingStatus.FAIL


class TestCIS_7_2_5:
    """Graph exposes the inverse of PreventExternalUsersFromResharing."""

    async def test_pass_from_graph_when_resharing_disabled(self):
        finding = await CIS_7_2_5().check(_graph(isResharingByExternalUsersEnabled=False))
        assert finding.status == FindingStatus.PASS

    async def test_fail_from_graph_when_resharing_enabled(self):
        finding = await CIS_7_2_5().check(_graph(isResharingByExternalUsersEnabled=True))
        assert finding.status == FindingStatus.FAIL

    async def test_spo_property_wins_when_present(self):
        data = _graph(
            isResharingByExternalUsersEnabled=True,
            PreventExternalUsersFromResharing=True,
        )
        finding = await CIS_7_2_5().check(data)
        assert finding.status == FindingStatus.PASS


class TestCIS_7_2_6:
    """CIS audits SharingDomainRestrictionMode + SharingAllowedDomainList."""

    async def test_pass_when_allow_list_has_domains(self):
        finding = await CIS_7_2_6().check(_graph(
            sharingDomainRestrictionMode="allowList",
            sharingAllowedDomainList=["contoso.com"],
        ))
        assert finding.status == FindingStatus.PASS
        assert "contoso.com" in finding.message

    async def test_fail_when_allow_list_is_empty(self):
        finding = await CIS_7_2_6().check(_graph(
            sharingDomainRestrictionMode="allowList", sharingAllowedDomainList=[],
        ))
        assert finding.status == FindingStatus.FAIL

    async def test_fail_when_restriction_mode_is_none(self):
        finding = await CIS_7_2_6().check(_graph(
            sharingDomainRestrictionMode="none", sharingAllowedDomainList=[],
        ))
        assert finding.status == FindingStatus.FAIL

    async def test_fail_when_block_list_is_used(self):
        finding = await CIS_7_2_6().check(_graph(
            sharingDomainRestrictionMode="blockList",
            sharingBlockedDomainList=["bad.com"],
        ))
        assert finding.status == FindingStatus.FAIL

    async def test_accepts_get_spotenant_casing(self):
        finding = await CIS_7_2_6().check(_graph(
            SharingDomainRestrictionMode="AllowList",
            SharingAllowedDomainList="contoso.com fabrikam.com",
        ))
        assert finding.status == FindingStatus.PASS


class TestCIS_7_2_7:
    @pytest.mark.parametrize("value", ["Direct", "Internal", 1, 2])
    async def test_pass_for_restrictive_link_types(self, value):
        finding = await CIS_7_2_7().check(_spo(DefaultSharingLinkType=value))
        assert finding.status == FindingStatus.PASS

    @pytest.mark.parametrize("value", ["AnonymousAccess", 3])
    async def test_fail_for_anonymous_links(self, value):
        finding = await CIS_7_2_7().check(_spo(DefaultSharingLinkType=value))
        assert finding.status == FindingStatus.FAIL

    async def test_fail_for_none(self):
        finding = await CIS_7_2_7().check(_spo(DefaultSharingLinkType="None"))
        assert finding.status == FindingStatus.FAIL


class TestCIS_7_2_9:
    async def test_pass_when_expiry_within_30_days(self):
        finding = await CIS_7_2_9().check(_spo(
            ExternalUserExpirationRequired=True, ExternalUserExpireInDays=30,
        ))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_expiry_exceeds_30_days(self):
        finding = await CIS_7_2_9().check(_spo(
            ExternalUserExpirationRequired=True, ExternalUserExpireInDays=60,
        ))
        assert finding.status == FindingStatus.FAIL

    async def test_fail_when_expiry_not_required(self):
        finding = await CIS_7_2_9().check(_spo(
            ExternalUserExpirationRequired=False, ExternalUserExpireInDays=30,
        ))
        assert finding.status == FindingStatus.FAIL


class TestCIS_7_2_10:
    async def test_pass_when_reauth_within_15_days(self):
        finding = await CIS_7_2_10().check(_spo(
            EmailAttestationRequired=True, EmailAttestationReAuthDays=15,
        ))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_reauth_exceeds_15_days(self):
        finding = await CIS_7_2_10().check(_spo(
            EmailAttestationRequired=True, EmailAttestationReAuthDays=30,
        ))
        assert finding.status == FindingStatus.FAIL

    async def test_fail_when_attestation_not_required(self):
        finding = await CIS_7_2_10().check(_spo(
            EmailAttestationRequired=False, EmailAttestationReAuthDays=15,
        ))
        assert finding.status == FindingStatus.FAIL


class TestCIS_7_2_11:
    @pytest.mark.parametrize("value", ["View", 1])
    async def test_pass_when_default_permission_is_view(self, value):
        finding = await CIS_7_2_11().check(_spo(DefaultLinkPermission=value))
        assert finding.status == FindingStatus.PASS

    @pytest.mark.parametrize("value", ["Edit", 2])
    async def test_fail_when_default_permission_is_edit(self, value):
        finding = await CIS_7_2_11().check(_spo(DefaultLinkPermission=value))
        assert finding.status == FindingStatus.FAIL


class TestCIS_7_3_1:
    async def test_pass_when_infected_downloads_blocked(self):
        finding = await CIS_7_3_1().check(_spo(DisallowInfectedFileDownload=True))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_infected_downloads_allowed(self):
        finding = await CIS_7_3_1().check(_spo(DisallowInfectedFileDownload=False))
        assert finding.status == FindingStatus.FAIL
