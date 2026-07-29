"""Unit tests for the Exchange Online PowerShell-bridge CIS rules
(section 6, section6_exchange).

Each rule reads a key populated by sspm/providers/ms365/collector.py's
``_collect_exchange_via_powershell`` (backed by scripts/exchange.ps1). These
tests cover: errors present -> SKIPPED, key is None (bridge not configured)
-> MANUAL, a real PASS scenario, and a real FAIL scenario.
"""

import pytest

from sspm.core.models import FindingStatus
from sspm.providers.base import CollectedData
from sspm.providers.ms365.rules.section6_exchange.cis_6_1_1 import CIS_6_1_1
from sspm.providers.ms365.rules.section6_exchange.cis_6_1_2 import CIS_6_1_2
from sspm.providers.ms365.rules.section6_exchange.cis_6_1_3 import CIS_6_1_3
from sspm.providers.ms365.rules.section6_exchange.cis_6_2_1 import CIS_6_2_1
from sspm.providers.ms365.rules.section6_exchange.cis_6_2_2 import CIS_6_2_2
from sspm.providers.ms365.rules.section6_exchange.cis_6_2_3 import CIS_6_2_3
from sspm.providers.ms365.rules.section6_exchange.cis_6_3_1 import CIS_6_3_1
from sspm.providers.ms365.rules.section6_exchange.cis_6_5_1 import CIS_6_5_1
from sspm.providers.ms365.rules.section6_exchange.cis_6_5_2 import CIS_6_5_2
from sspm.providers.ms365.rules.section6_exchange.cis_6_5_3 import CIS_6_5_3
from sspm.providers.ms365.rules.section6_exchange.cis_6_5_4 import CIS_6_5_4
from sspm.providers.ms365.rules.section6_exchange.cis_6_5_5 import CIS_6_5_5


def _data(**kv) -> CollectedData:
    return CollectedData(provider="ms365", target="test.onmicrosoft.com", data=kv)


def _errors(**kv) -> CollectedData:
    return CollectedData(
        provider="ms365", target="test.onmicrosoft.com", data={}, errors=kv
    )


class TestCIS_6_1_1:
    """AuditDisabled organizationally must be False."""

    @pytest.mark.asyncio
    async def test_skipped_on_error(self):
        data = _errors(organization_config="boom")
        finding = await CIS_6_1_1().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_not_configured(self):
        data = _data(organization_config=None)
        finding = await CIS_6_1_1().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_audit_enabled(self):
        data = _data(organization_config={"AuditDisabled": False})
        finding = await CIS_6_1_1().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_audit_disabled(self):
        data = _data(organization_config={"AuditDisabled": True})
        finding = await CIS_6_1_1().check(data)
        assert finding.status == FindingStatus.FAIL


class TestCIS_6_1_2:
    """Mailbox audit actions must include the recommended action sets."""

    ADMIN = [
        "ApplyRecord", "Copy", "Create", "FolderBind", "HardDelete",
        "MailItemsAccessed", "Move", "MoveToDeletedItems", "SendAs",
        "SendOnBehalf", "Send", "SoftDelete", "Update",
        "UpdateCalendarDelegation", "UpdateFolderPermissions",
        "UpdateInboxRules",
    ]
    DELEGATE = [
        "ApplyRecord", "Create", "FolderBind", "HardDelete", "Move",
        "MailItemsAccessed", "MoveToDeletedItems", "SendAs", "SendOnBehalf",
        "SoftDelete", "Update", "UpdateFolderPermissions", "UpdateInboxRules",
    ]
    OWNER = [
        "ApplyRecord", "Create", "HardDelete", "MailboxLogin", "Move",
        "MailItemsAccessed", "MoveToDeletedItems", "Send", "SoftDelete",
        "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions",
        "UpdateInboxRules",
    ]

    def _mailbox(self, **overrides):
        mbx = {
            "DisplayName": "Alice",
            "RecipientTypeDetails": "UserMailbox",
            "AuditEnabled": True,
            "AuditAdmin": list(self.ADMIN),
            "AuditDelegate": list(self.DELEGATE),
            "AuditOwner": list(self.OWNER),
        }
        mbx.update(overrides)
        return mbx

    @pytest.mark.asyncio
    async def test_skipped_on_error(self):
        data = _errors(mailbox_audit_settings="boom")
        finding = await CIS_6_1_2().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_not_configured(self):
        data = _data(mailbox_audit_settings=None)
        finding = await CIS_6_1_2().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_fully_configured(self):
        data = _data(mailbox_audit_settings=[self._mailbox()])
        finding = await CIS_6_1_2().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_audit_disabled_or_missing_actions(self):
        data = _data(
            mailbox_audit_settings=[self._mailbox(AuditEnabled=False, AuditAdmin=[])]
        )
        finding = await CIS_6_1_2().check(data)
        assert finding.status == FindingStatus.FAIL

    @pytest.mark.asyncio
    async def test_non_user_mailboxes_are_ignored(self):
        data = _data(
            mailbox_audit_settings=[
                self._mailbox(RecipientTypeDetails="SharedMailbox", AuditEnabled=False)
            ]
        )
        finding = await CIS_6_1_2().check(data)
        assert finding.status == FindingStatus.PASS


class TestCIS_6_1_3:
    """No mailboxes should have AuditBypassEnabled = True."""

    @pytest.mark.asyncio
    async def test_skipped_on_error(self):
        data = _errors(mailbox_audit_bypass_association="boom")
        finding = await CIS_6_1_3().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_not_configured(self):
        data = _data(mailbox_audit_bypass_association=None)
        finding = await CIS_6_1_3().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_empty(self):
        # scripts/exchange.ps1 pre-filters to only bypass-enabled entries, so
        # an empty list means nothing bypasses auditing.
        data = _data(mailbox_audit_bypass_association=[])
        finding = await CIS_6_1_3().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_accounts_present(self):
        data = _data(
            mailbox_audit_bypass_association=[
                {"Name": "svc-account", "AuditBypassEnabled": True}
            ]
        )
        finding = await CIS_6_1_3().check(data)
        assert finding.status == FindingStatus.FAIL


class TestCIS_6_2_1:
    """AutoForwardingMode must be Off and no transport rule redirects mail."""

    @pytest.mark.asyncio
    async def test_skipped_on_error(self):
        data = _errors(hosted_outbound_spam_filter_policy="boom")
        finding = await CIS_6_2_1().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_not_configured(self):
        data = _data(hosted_outbound_spam_filter_policy=None)
        finding = await CIS_6_2_1().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_off_and_no_forwarding_rules(self):
        data = _data(
            hosted_outbound_spam_filter_policy={"AutoForwardingMode": "Off"},
            transport_rules=[{"Name": "Some Rule", "RedirectMessageTo": None, "BlindCopyTo": None}],
        )
        finding = await CIS_6_2_1().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_automatic_forwarding_allowed(self):
        data = _data(
            hosted_outbound_spam_filter_policy={"AutoForwardingMode": "Automatic"},
            transport_rules=[],
        )
        finding = await CIS_6_2_1().check(data)
        assert finding.status == FindingStatus.FAIL

    @pytest.mark.asyncio
    async def test_fail_when_transport_rule_redirects(self):
        data = _data(
            hosted_outbound_spam_filter_policy={"AutoForwardingMode": "Off"},
            transport_rules=[
                {"Name": "Redirect All", "RedirectMessageTo": ["ext@evil.com"]}
            ],
        )
        finding = await CIS_6_2_1().check(data)
        assert finding.status == FindingStatus.FAIL


class TestCIS_6_2_2:
    """No transport rule may whitelist a domain via SetSCL = -1."""

    @pytest.mark.asyncio
    async def test_skipped_on_error(self):
        data = _errors(transport_rules="boom")
        finding = await CIS_6_2_2().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_not_configured(self):
        data = _data(transport_rules=None)
        finding = await CIS_6_2_2().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_no_whitelist_rules(self):
        data = _data(
            transport_rules=[{"Name": "Normal rule", "SetSCL": None, "SenderDomainIs": None}]
        )
        finding = await CIS_6_2_2().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_whitelist_rule_present(self):
        data = _data(
            transport_rules=[
                {"Name": "Trust Partner", "SetSCL": -1, "SenderDomainIs": ["partner.com"]}
            ]
        )
        finding = await CIS_6_2_2().check(data)
        assert finding.status == FindingStatus.FAIL


class TestCIS_6_2_3:
    """External sender identification must be Enabled for all identities."""

    @pytest.mark.asyncio
    async def test_skipped_on_error(self):
        data = _errors(external_in_outlook="boom")
        finding = await CIS_6_2_3().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_not_configured(self):
        data = _data(external_in_outlook=None)
        finding = await CIS_6_2_3().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_enabled(self):
        data = _data(external_in_outlook=[{"Identity": "Default", "Enabled": True}])
        finding = await CIS_6_2_3().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_disabled(self):
        data = _data(external_in_outlook=[{"Identity": "Default", "Enabled": False}])
        finding = await CIS_6_2_3().check(data)
        assert finding.status == FindingStatus.FAIL


class TestCIS_6_3_1:
    """AssignedRoles must not include the Outlook add-in install roles."""

    @pytest.mark.asyncio
    async def test_skipped_on_error(self):
        data = _errors(role_assignment_policies="boom")
        finding = await CIS_6_3_1().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_not_configured(self):
        data = _data(role_assignment_policies=None)
        finding = await CIS_6_3_1().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_no_addin_roles(self):
        data = _data(
            role_assignment_policies=[
                {"Name": "Default Role Assignment Policy", "AssignedRoles": ["MyBaseOptions"]}
            ]
        )
        finding = await CIS_6_3_1().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_addin_role_present(self):
        data = _data(
            role_assignment_policies=[
                {
                    "Name": "Default Role Assignment Policy",
                    "AssignedRoles": ["MyBaseOptions", "My Custom Apps"],
                }
            ]
        )
        finding = await CIS_6_3_1().check(data)
        assert finding.status == FindingStatus.FAIL


class TestCIS_6_5_1:
    """Modern authentication (OAuth2ClientProfileEnabled) must be enabled."""

    @pytest.mark.asyncio
    async def test_skipped_on_error(self):
        data = _errors(organization_config="boom")
        finding = await CIS_6_5_1().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_not_configured(self):
        data = _data(organization_config=None)
        finding = await CIS_6_5_1().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_modern_auth_enabled(self):
        data = _data(organization_config={"OAuth2ClientProfileEnabled": True})
        finding = await CIS_6_5_1().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_modern_auth_disabled(self):
        data = _data(organization_config={"OAuth2ClientProfileEnabled": False})
        finding = await CIS_6_5_1().check(data)
        assert finding.status == FindingStatus.FAIL


class TestCIS_6_5_2:
    """MailTips must be enabled with an acceptable large-audience threshold."""

    @pytest.mark.asyncio
    async def test_skipped_on_error(self):
        data = _errors(organization_config="boom")
        finding = await CIS_6_5_2().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_not_configured(self):
        data = _data(organization_config=None)
        finding = await CIS_6_5_2().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_all_enabled(self):
        data = _data(
            organization_config={
                "MailTipsAllTipsEnabled": True,
                "MailTipsExternalRecipientsTipsEnabled": True,
                "MailTipsGroupMetricsEnabled": True,
                "MailTipsLargeAudienceThreshold": 25,
            }
        )
        finding = await CIS_6_5_2().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_disabled(self):
        data = _data(
            organization_config={
                "MailTipsAllTipsEnabled": False,
                "MailTipsExternalRecipientsTipsEnabled": True,
                "MailTipsGroupMetricsEnabled": True,
                "MailTipsLargeAudienceThreshold": 25,
            }
        )
        finding = await CIS_6_5_2().check(data)
        assert finding.status == FindingStatus.FAIL


class TestCIS_6_5_3:
    """AdditionalStorageProvidersAvailable must be False."""

    @pytest.mark.asyncio
    async def test_skipped_on_error(self):
        data = _errors(owa_mailbox_policy="boom")
        finding = await CIS_6_5_3().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_not_configured(self):
        data = _data(owa_mailbox_policy=None)
        finding = await CIS_6_5_3().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_false(self):
        data = _data(owa_mailbox_policy={"AdditionalStorageProvidersAvailable": False})
        finding = await CIS_6_5_3().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_true(self):
        data = _data(owa_mailbox_policy={"AdditionalStorageProvidersAvailable": True})
        finding = await CIS_6_5_3().check(data)
        assert finding.status == FindingStatus.FAIL


class TestCIS_6_5_4:
    """SmtpClientAuthenticationDisabled must be True."""

    @pytest.mark.asyncio
    async def test_skipped_on_error(self):
        data = _errors(transport_config="boom")
        finding = await CIS_6_5_4().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_not_configured(self):
        data = _data(transport_config=None)
        finding = await CIS_6_5_4().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_disabled(self):
        data = _data(transport_config={"SmtpClientAuthenticationDisabled": True})
        finding = await CIS_6_5_4().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_enabled(self):
        data = _data(transport_config={"SmtpClientAuthenticationDisabled": False})
        finding = await CIS_6_5_4().check(data)
        assert finding.status == FindingStatus.FAIL


class TestCIS_6_5_5:
    """RejectDirectSend must be True."""

    @pytest.mark.asyncio
    async def test_skipped_on_error(self):
        data = _errors(organization_config="boom")
        finding = await CIS_6_5_5().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_when_not_configured(self):
        data = _data(organization_config=None)
        finding = await CIS_6_5_5().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_true(self):
        data = _data(organization_config={"RejectDirectSend": True})
        finding = await CIS_6_5_5().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_false(self):
        data = _data(organization_config={"RejectDirectSend": False})
        finding = await CIS_6_5_5().check(data)
        assert finding.status == FindingStatus.FAIL
