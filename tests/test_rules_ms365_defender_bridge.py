"""
Unit tests for the 17 MS365 CIS rules that were upgraded to read real data
from the Exchange Online PowerShell bridge (see
sspm/providers/ms365/powershell_bridge.py and scripts/exchange.ps1).

Every rule below is exercised for:
  1. errors present for its key(s)  -> SKIPPED
  2. key is None (bridge not configured) -> MANUAL
  3. at least one realistic PASS scenario
  4. at least one realistic FAIL scenario
"""

import pytest

from sspm.core.models import FindingStatus
from sspm.providers.base import CollectedData
from sspm.providers.ms365.rules.section1_m365_admin.cis_1_3_3 import CIS_1_3_3
from sspm.providers.ms365.rules.section1_m365_admin.cis_1_3_6 import CIS_1_3_6
from sspm.providers.ms365.rules.section1_m365_admin.cis_1_3_9 import CIS_1_3_9
from sspm.providers.ms365.rules.section2_defender.cis_2_1_1 import CIS_2_1_1
from sspm.providers.ms365.rules.section2_defender.cis_2_1_2 import CIS_2_1_2
from sspm.providers.ms365.rules.section2_defender.cis_2_1_3 import CIS_2_1_3
from sspm.providers.ms365.rules.section2_defender.cis_2_1_4 import CIS_2_1_4
from sspm.providers.ms365.rules.section2_defender.cis_2_1_5 import CIS_2_1_5
from sspm.providers.ms365.rules.section2_defender.cis_2_1_6 import CIS_2_1_6
from sspm.providers.ms365.rules.section2_defender.cis_2_1_7 import CIS_2_1_7
from sspm.providers.ms365.rules.section2_defender.cis_2_1_11 import CIS_2_1_11
from sspm.providers.ms365.rules.section2_defender.cis_2_1_12 import CIS_2_1_12
from sspm.providers.ms365.rules.section2_defender.cis_2_1_13 import CIS_2_1_13
from sspm.providers.ms365.rules.section2_defender.cis_2_1_14 import CIS_2_1_14
from sspm.providers.ms365.rules.section2_defender.cis_2_1_15 import CIS_2_1_15
from sspm.providers.ms365.rules.section2_defender.cis_2_4_4 import CIS_2_4_4
from sspm.providers.ms365.rules.section3_purview.cis_3_1_1 import CIS_3_1_1


def _data(**kv) -> CollectedData:
    return CollectedData(provider="ms365", target="test.onmicrosoft.com", data=kv)


def _errors(key, msg="boom") -> CollectedData:
    return CollectedData(
        provider="ms365",
        target="test.onmicrosoft.com",
        data={},
        errors={key: msg},
    )


def _none(*keys) -> CollectedData:
    return CollectedData(
        provider="ms365",
        target="test.onmicrosoft.com",
        data={k: None for k in keys},
    )


# ---------------------------------------------------------------------------
# 1.3.3 - Calendar external sharing (sharing_policy)
# ---------------------------------------------------------------------------
class TestCIS_1_3_3:
    @pytest.mark.asyncio
    async def test_skip_on_error(self):
        finding = await CIS_1_3_3().check(_errors("sharing_policy"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_none(self):
        finding = await CIS_1_3_3().check(_none("sharing_policy"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_disabled(self):
        data = _data(sharing_policy={"Enabled": False, "Domains": []})
        finding = await CIS_1_3_3().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_pass_when_enabled_freebusy_only(self):
        data = _data(
            sharing_policy={
                "Enabled": True,
                "Domains": ["Anonymous:CalendarSharingFreeBusySimple"],
            }
        )
        finding = await CIS_1_3_3().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_full_detail_shared(self):
        data = _data(
            sharing_policy={
                "Enabled": True,
                "Domains": ["Anonymous:CalendarSharingFreeBusyDetail"],
            }
        )
        finding = await CIS_1_3_3().check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 1.3.6 - Customer Lockbox (organization_config)
# ---------------------------------------------------------------------------
class TestCIS_1_3_6:
    @pytest.mark.asyncio
    async def test_skip_on_error(self):
        finding = await CIS_1_3_6().check(_errors("organization_config"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_none(self):
        finding = await CIS_1_3_6().check(_none("organization_config"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_enabled(self):
        data = _data(organization_config={"CustomerLockBoxEnabled": True})
        finding = await CIS_1_3_6().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_disabled(self):
        data = _data(organization_config={"CustomerLockBoxEnabled": False})
        finding = await CIS_1_3_6().check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 1.3.9 - Shared Bookings restriction (owa_mailbox_policy [+organization_config])
# ---------------------------------------------------------------------------
class TestCIS_1_3_9:
    @pytest.mark.asyncio
    async def test_skip_on_error(self):
        finding = await CIS_1_3_9().check(_errors("owa_mailbox_policy"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_none(self):
        finding = await CIS_1_3_9().check(_none("owa_mailbox_policy"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_bookings_mailbox_creation_disabled(self):
        data = _data(
            owa_mailbox_policy={"BookingsMailboxCreationEnabled": False},
            organization_config=None,
        )
        finding = await CIS_1_3_9().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_pass_when_bookings_disabled_at_org_level(self):
        data = _data(
            owa_mailbox_policy={"BookingsMailboxCreationEnabled": True},
            organization_config={"BookingsEnabled": False},
        )
        finding = await CIS_1_3_9().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_both_enabled(self):
        data = _data(
            owa_mailbox_policy={"BookingsMailboxCreationEnabled": True},
            organization_config={"BookingsEnabled": True},
        )
        finding = await CIS_1_3_9().check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.1.1 - Safe Links for Office Apps (safe_links_policies)
# ---------------------------------------------------------------------------
_COMPLIANT_SAFE_LINKS = {
    "Identity": "Default",
    "EnableSafeLinksForEmail": True,
    "EnableSafeLinksForTeams": True,
    "EnableSafeLinksForOffice": True,
    "TrackClicks": True,
    "AllowClickThrough": False,
    "ScanUrls": True,
    "EnableForInternalSenders": True,
    "DeliverMessageAfterScan": True,
    "DisableUrlRewrite": False,
}


class TestCIS_2_1_1:
    @pytest.mark.asyncio
    async def test_skip_on_error(self):
        finding = await CIS_2_1_1().check(_errors("safe_links_policies"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_none(self):
        finding = await CIS_2_1_1().check(_none("safe_links_policies"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_compliant_policy_exists(self):
        data = _data(safe_links_policies=[_COMPLIANT_SAFE_LINKS])
        finding = await CIS_2_1_1().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_empty(self):
        data = _data(safe_links_policies=[])
        finding = await CIS_2_1_1().check(data)
        assert finding.status == FindingStatus.FAIL

    @pytest.mark.asyncio
    async def test_fail_when_incomplete_policy(self):
        incomplete = dict(_COMPLIANT_SAFE_LINKS, EnableSafeLinksForTeams=False)
        data = _data(safe_links_policies=[incomplete])
        finding = await CIS_2_1_1().check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.1.2 - Common Attachment Types Filter (malware_filter_policy)
# ---------------------------------------------------------------------------
class TestCIS_2_1_2:
    @pytest.mark.asyncio
    async def test_skip_on_error(self):
        finding = await CIS_2_1_2().check(_errors("malware_filter_policy"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_none(self):
        finding = await CIS_2_1_2().check(_none("malware_filter_policy"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_enabled(self):
        data = _data(
            malware_filter_policy=[{"Identity": "Default", "EnableFileFilter": True}]
        )
        finding = await CIS_2_1_2().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_disabled(self):
        data = _data(
            malware_filter_policy=[{"Identity": "Default", "EnableFileFilter": False}]
        )
        finding = await CIS_2_1_2().check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.1.3 - Internal sender malware notifications (malware_filter_policy)
# ---------------------------------------------------------------------------
class TestCIS_2_1_3:
    @pytest.mark.asyncio
    async def test_skip_on_error(self):
        finding = await CIS_2_1_3().check(_errors("malware_filter_policy"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_none(self):
        finding = await CIS_2_1_3().check(_none("malware_filter_policy"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_configured(self):
        data = _data(
            malware_filter_policy=[
                {
                    "Identity": "Default",
                    "EnableInternalSenderAdminNotifications": True,
                    "InternalSenderAdminAddress": "admin@contoso.com",
                }
            ]
        )
        finding = await CIS_2_1_3().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_not_configured(self):
        data = _data(
            malware_filter_policy=[
                {
                    "Identity": "Default",
                    "EnableInternalSenderAdminNotifications": False,
                    "InternalSenderAdminAddress": None,
                }
            ]
        )
        finding = await CIS_2_1_3().check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.1.4 - Safe Attachments policy (safe_attachments_policies)
# ---------------------------------------------------------------------------
class TestCIS_2_1_4:
    @pytest.mark.asyncio
    async def test_skip_on_error(self):
        finding = await CIS_2_1_4().check(_errors("safe_attachments_policies"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_none(self):
        finding = await CIS_2_1_4().check(_none("safe_attachments_policies"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_compliant(self):
        data = _data(
            safe_attachments_policies=[
                {
                    "Identity": "Default",
                    "Enable": True,
                    "Action": "Block",
                    "QuarantineTag": "AdminOnlyAccessPolicy",
                }
            ]
        )
        finding = await CIS_2_1_4().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_not_enabled(self):
        data = _data(
            safe_attachments_policies=[
                {
                    "Identity": "Default",
                    "Enable": False,
                    "Action": "Allow",
                    "QuarantineTag": "",
                }
            ]
        )
        finding = await CIS_2_1_4().check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.1.5 - Safe Attachments for SPO/ODB/Teams (atp_policy_for_o365)
# ---------------------------------------------------------------------------
class TestCIS_2_1_5:
    @pytest.mark.asyncio
    async def test_skip_on_error(self):
        finding = await CIS_2_1_5().check(_errors("atp_policy_for_o365"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_none(self):
        finding = await CIS_2_1_5().check(_none("atp_policy_for_o365"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_compliant(self):
        data = _data(
            atp_policy_for_o365={
                "EnableATPForSPOTeamsODB": True,
                "EnableSafeDocs": True,
                "AllowSafeDocsOpen": False,
            }
        )
        finding = await CIS_2_1_5().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_not_compliant(self):
        data = _data(
            atp_policy_for_o365={
                "EnableATPForSPOTeamsODB": False,
                "EnableSafeDocs": False,
                "AllowSafeDocsOpen": True,
            }
        )
        finding = await CIS_2_1_5().check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.1.6 - Outbound spam admin notifications (hosted_outbound_spam_filter_policy)
# ---------------------------------------------------------------------------
class TestCIS_2_1_6:
    @pytest.mark.asyncio
    async def test_skip_on_error(self):
        finding = await CIS_2_1_6().check(
            _errors("hosted_outbound_spam_filter_policy")
        )
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_none(self):
        finding = await CIS_2_1_6().check(
            _none("hosted_outbound_spam_filter_policy")
        )
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_configured(self):
        data = _data(
            hosted_outbound_spam_filter_policy={
                "BccSuspiciousOutboundMail": True,
                "NotifyOutboundSpam": True,
            }
        )
        finding = await CIS_2_1_6().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_not_configured(self):
        data = _data(
            hosted_outbound_spam_filter_policy={
                "BccSuspiciousOutboundMail": False,
                "NotifyOutboundSpam": False,
            }
        )
        finding = await CIS_2_1_6().check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.1.7 - Anti-phishing policy (anti_phishing_policies)
# ---------------------------------------------------------------------------
_COMPLIANT_ANTIPHISH = {
    "Identity": "Custom Anti-Phish",
    "Enabled": True,
    "PhishThresholdLevel": 3,
    "EnableTargetedUserProtection": True,
    "EnableOrganizationDomainsProtection": True,
    "EnableMailboxIntelligence": True,
    "EnableMailboxIntelligenceProtection": True,
    "EnableSpoofIntelligence": True,
    "TargetedUserProtectionAction": "Quarantine",
    "TargetedDomainProtectionAction": "Quarantine",
    "MailboxIntelligenceProtectionAction": "Quarantine",
    "EnableFirstContactSafetyTips": True,
    "EnableSimilarUsersSafetyTips": True,
    "EnableSimilarDomainsSafetyTips": True,
    "EnableUnusualCharactersSafetyTips": True,
    "HonorDmarcPolicy": True,
}


class TestCIS_2_1_7:
    @pytest.mark.asyncio
    async def test_skip_on_error(self):
        finding = await CIS_2_1_7().check(_errors("anti_phishing_policies"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_none(self):
        finding = await CIS_2_1_7().check(_none("anti_phishing_policies"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_custom_policy_compliant(self):
        data = _data(anti_phishing_policies=[_COMPLIANT_ANTIPHISH])
        finding = await CIS_2_1_7().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_only_default_policy(self):
        default_policy = dict(
            _COMPLIANT_ANTIPHISH,
            Identity="Office365 AntiPhish Default",
            EnableMailboxIntelligence=False,
        )
        data = _data(anti_phishing_policies=[default_policy])
        finding = await CIS_2_1_7().check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.1.11 - Comprehensive attachment filtering (malware_filter_policy)
# ---------------------------------------------------------------------------
class TestCIS_2_1_11:
    @pytest.mark.asyncio
    async def test_skip_on_error(self):
        finding = await CIS_2_1_11().check(_errors("malware_filter_policy"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_none(self):
        finding = await CIS_2_1_11().check(_none("malware_filter_policy"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_comprehensive(self):
        data = _data(
            malware_filter_policy=[
                {
                    "Identity": "Default",
                    "EnableFileFilter": True,
                    "FileTypes": [f"ext{i}" for i in range(150)],
                }
            ]
        )
        finding = await CIS_2_1_11().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_insufficient_types(self):
        data = _data(
            malware_filter_policy=[
                {
                    "Identity": "Default",
                    "EnableFileFilter": True,
                    "FileTypes": ["exe", "js"],
                }
            ]
        )
        finding = await CIS_2_1_11().check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.1.12 - Connection filter IP allow list (hosted_connection_filter_policy)
# ---------------------------------------------------------------------------
class TestCIS_2_1_12:
    @pytest.mark.asyncio
    async def test_skip_on_error(self):
        finding = await CIS_2_1_12().check(
            _errors("hosted_connection_filter_policy")
        )
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_none(self):
        finding = await CIS_2_1_12().check(
            _none("hosted_connection_filter_policy")
        )
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_empty(self):
        data = _data(hosted_connection_filter_policy={"IPAllowList": []})
        finding = await CIS_2_1_12().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_populated(self):
        data = _data(
            hosted_connection_filter_policy={"IPAllowList": ["1.2.3.4"]}
        )
        finding = await CIS_2_1_12().check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.1.13 - Connection filter safe list (hosted_connection_filter_policy)
# ---------------------------------------------------------------------------
class TestCIS_2_1_13:
    @pytest.mark.asyncio
    async def test_skip_on_error(self):
        finding = await CIS_2_1_13().check(
            _errors("hosted_connection_filter_policy")
        )
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_none(self):
        finding = await CIS_2_1_13().check(
            _none("hosted_connection_filter_policy")
        )
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_disabled(self):
        data = _data(hosted_connection_filter_policy={"EnableSafeList": False})
        finding = await CIS_2_1_13().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_enabled(self):
        data = _data(hosted_connection_filter_policy={"EnableSafeList": True})
        finding = await CIS_2_1_13().check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.1.14 - Inbound anti-spam allowed sender domains (hosted_content_filter_policy)
# ---------------------------------------------------------------------------
class TestCIS_2_1_14:
    @pytest.mark.asyncio
    async def test_skip_on_error(self):
        finding = await CIS_2_1_14().check(_errors("hosted_content_filter_policy"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_none(self):
        finding = await CIS_2_1_14().check(_none("hosted_content_filter_policy"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_all_empty(self):
        data = _data(
            hosted_content_filter_policy=[
                {"Identity": "Default", "AllowedSenderDomains": []},
                {"Identity": "Other", "AllowedSenderDomains": None},
            ]
        )
        finding = await CIS_2_1_14().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_one_policy_has_allowed_domains(self):
        data = _data(
            hosted_content_filter_policy=[
                {"Identity": "Default", "AllowedSenderDomains": []},
                {
                    "Identity": "Other",
                    "AllowedSenderDomains": ["trusted.example.com"],
                },
            ]
        )
        finding = await CIS_2_1_14().check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.1.15 - Outbound anti-spam message limits (hosted_outbound_spam_filter_policy)
# ---------------------------------------------------------------------------
class TestCIS_2_1_15:
    @pytest.mark.asyncio
    async def test_skip_on_error(self):
        finding = await CIS_2_1_15().check(
            _errors("hosted_outbound_spam_filter_policy")
        )
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_none(self):
        finding = await CIS_2_1_15().check(
            _none("hosted_outbound_spam_filter_policy")
        )
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_within_limits(self):
        data = _data(
            hosted_outbound_spam_filter_policy={
                "RecipientLimitExternalPerHour": 400,
                "RecipientLimitInternalPerHour": 800,
                "RecipientLimitPerDay": 800,
                "ActionWhenThresholdReached": "BlockUser",
                "NotifyOutboundSpamRecipients": ["admin@contoso.com"],
            }
        )
        finding = await CIS_2_1_15().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_limits_too_high(self):
        data = _data(
            hosted_outbound_spam_filter_policy={
                "RecipientLimitExternalPerHour": 5000,
                "RecipientLimitInternalPerHour": 5000,
                "RecipientLimitPerDay": 5000,
                "ActionWhenThresholdReached": "None",
                "NotifyOutboundSpamRecipients": [],
            }
        )
        finding = await CIS_2_1_15().check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.4.4 - Zero-hour auto purge for Teams (teams_protection_policy)
# ---------------------------------------------------------------------------
class TestCIS_2_4_4:
    @pytest.mark.asyncio
    async def test_skip_on_error(self):
        finding = await CIS_2_4_4().check(_errors("teams_protection_policy"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_none(self):
        finding = await CIS_2_4_4().check(_none("teams_protection_policy"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_enabled(self):
        data = _data(
            teams_protection_policy=[{"Identity": "Default", "ZapEnabled": True}]
        )
        finding = await CIS_2_4_4().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_disabled(self):
        data = _data(
            teams_protection_policy=[{"Identity": "Default", "ZapEnabled": False}]
        )
        finding = await CIS_2_4_4().check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 3.1.1 - Unified audit log search enabled (admin_audit_log_config)
# ---------------------------------------------------------------------------
class TestCIS_3_1_1:
    @pytest.mark.asyncio
    async def test_skip_on_error(self):
        finding = await CIS_3_1_1().check(_errors("admin_audit_log_config"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_none(self):
        finding = await CIS_3_1_1().check(_none("admin_audit_log_config"))
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_enabled(self):
        data = _data(
            admin_audit_log_config={"UnifiedAuditLogIngestionEnabled": True}
        )
        finding = await CIS_3_1_1().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_disabled(self):
        data = _data(
            admin_audit_log_config={"UnifiedAuditLogIngestionEnabled": False}
        )
        finding = await CIS_3_1_1().check(data)
        assert finding.status == FindingStatus.FAIL
