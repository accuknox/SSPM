"""Unit tests for individual MS365 CIS rules."""

import pytest

from sspm.core.models import FindingStatus
from sspm.providers.base import CollectedData
from sspm.providers.ms365.rules.section1_m365_admin.cis_1_1_1 import CIS_1_1_1
from sspm.providers.ms365.rules.section1_m365_admin.cis_1_1_2 import CIS_1_1_2
from sspm.providers.ms365.rules.section1_m365_admin.cis_1_3_1 import CIS_1_3_1
from sspm.providers.ms365.rules.section1_m365_admin.cis_1_3_3 import CIS_1_3_3
from sspm.providers.ms365.rules.section1_m365_admin.cis_1_3_5 import CIS_1_3_5
from sspm.providers.ms365.rules.section1_m365_admin.cis_1_3_6 import CIS_1_3_6
from sspm.providers.ms365.rules.section1_m365_admin.cis_1_3_7 import CIS_1_3_7
from sspm.providers.ms365.rules.section1_m365_admin.cis_1_3_9 import CIS_1_3_9
from sspm.providers.ms365.rules.section3_purview.cis_3_1_1 import CIS_3_1_1
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
from sspm.providers.ms365.rules.section2_defender.cis_2_4_1 import CIS_2_4_1
from sspm.providers.ms365.rules.section2_defender.cis_2_4_2 import CIS_2_4_2
from sspm.providers.ms365.rules.section2_defender.cis_2_4_4 import CIS_2_4_4
from sspm.providers.ms365.rules.section5_entra.cis_5_1_2_5 import CIS_5_1_2_5
from sspm.providers.ms365.rules.section5_entra.cis_5_1_4_1 import CIS_5_1_4_1
from sspm.providers.ms365.rules.section5_entra.cis_5_1_4_3 import CIS_5_1_4_3
from sspm.providers.ms365.rules.section5_entra.cis_5_1_4_4 import CIS_5_1_4_4
from sspm.providers.ms365.rules.section5_entra.cis_5_1_4_6 import CIS_5_1_4_6
from sspm.providers.ms365.rules.section5_entra.cis_5_1_6_1 import CIS_5_1_6_1
from sspm.providers.ms365.rules.section5_entra.cis_5_2_2_1 import CIS_5_2_2_1
from sspm.providers.ms365.rules.section5_entra.cis_5_2_3_6 import CIS_5_2_3_6
from sspm.providers.ms365.rules.section5_entra.cis_5_2_2_2 import CIS_5_2_2_2
from sspm.providers.ms365.rules.section5_entra.cis_5_2_3_2 import CIS_5_2_3_2
from sspm.providers.ms365.rules.section5_entra.cis_5_2_3_3 import CIS_5_2_3_3
from sspm.providers.ms365.rules.section5_entra.cis_5_2_4_1 import CIS_5_2_4_1
from sspm.providers.ms365.rules.section6_exchange.cis_6_1_1 import CIS_6_1_1
from sspm.providers.ms365.rules.section6_exchange.cis_6_1_2 import CIS_6_1_2
from sspm.providers.ms365.rules.section6_exchange.cis_6_1_3 import CIS_6_1_3
from sspm.providers.ms365.rules.section6_exchange.cis_6_2_2 import CIS_6_2_2
from sspm.providers.ms365.rules.section6_exchange.cis_6_2_3 import CIS_6_2_3
from sspm.providers.ms365.rules.section6_exchange.cis_6_3_1 import CIS_6_3_1
from sspm.providers.ms365.rules.section6_exchange.cis_6_5_2 import CIS_6_5_2
from sspm.providers.ms365.rules.section6_exchange.cis_6_5_3 import CIS_6_5_3
from sspm.providers.ms365.rules.section6_exchange.cis_6_5_4 import CIS_6_5_4
from sspm.providers.ms365.rules.section6_exchange.cis_6_5_5 import CIS_6_5_5
from sspm.providers.ms365.rules.section7_sharepoint.cis_7_2_3 import CIS_7_2_3
from sspm.providers.ms365.rules.section8_teams.cis_8_1_1 import CIS_8_1_1
from sspm.providers.ms365.rules.section8_teams.cis_8_1_2 import CIS_8_1_2
from sspm.providers.ms365.rules.section8_teams.cis_8_2_1 import CIS_8_2_1
from sspm.providers.ms365.rules.section8_teams.cis_8_2_2 import CIS_8_2_2
from sspm.providers.ms365.rules.section8_teams.cis_8_2_3 import CIS_8_2_3
from sspm.providers.ms365.rules.section8_teams.cis_8_2_4 import CIS_8_2_4
from sspm.providers.ms365.rules.section8_teams.cis_8_5_2 import CIS_8_5_2
from sspm.providers.ms365.rules.section8_teams.cis_8_5_3 import CIS_8_5_3
from sspm.providers.ms365.rules.section8_teams.cis_8_5_4 import CIS_8_5_4
from sspm.providers.ms365.rules.section8_teams.cis_8_5_5 import CIS_8_5_5
from sspm.providers.ms365.rules.section8_teams.cis_8_5_6 import CIS_8_5_6
from sspm.providers.ms365.rules.section8_teams.cis_8_5_7 import CIS_8_5_7
from sspm.providers.ms365.rules.section8_teams.cis_8_5_8 import CIS_8_5_8
from sspm.providers.ms365.rules.section8_teams.cis_8_5_9 import CIS_8_5_9
from sspm.providers.ms365.rules.section8_teams.cis_8_6_1 import CIS_8_6_1


def _collected(**kwargs) -> CollectedData:
    return CollectedData(provider="ms365", target="test.onmicrosoft.com", data=kwargs)


# ---------------------------------------------------------------------------
# 1.1.1 – Admin accounts cloud-only
# ---------------------------------------------------------------------------


class TestCIS_1_1_1:
    @pytest.fixture
    def rule(self):
        return CIS_1_1_1()

    @pytest.mark.asyncio
    async def test_pass_when_no_synced_admins(self, rule):
        data = _collected(
            users=[
                {"id": "u1", "userPrincipalName": "admin@test.com", "onPremisesSyncEnabled": False}
            ],
            directory_roles=[{"id": "r1", "displayName": "Global Administrator"}],
            directory_role_members={"r1": ["u1"]},
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_synced_admin_exists(self, rule):
        data = _collected(
            users=[
                {"id": "u1", "userPrincipalName": "hybrid@test.com", "onPremisesSyncEnabled": True}
            ],
            directory_roles=[{"id": "r1", "displayName": "Global Administrator"}],
            directory_role_members={"r1": ["u1"]},
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.FAIL
        assert "hybrid@test.com" in finding.message

    @pytest.mark.asyncio
    async def test_skip_when_no_users_data(self, rule):
        data = _collected()  # no users key
        finding = await rule.check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_pass_when_non_admin_is_synced(self, rule):
        """A synced non-admin user should not cause a failure."""
        data = _collected(
            users=[
                {"id": "u1", "userPrincipalName": "user@test.com", "onPremisesSyncEnabled": True},
                {"id": "u2", "userPrincipalName": "admin@test.com", "onPremisesSyncEnabled": False},
            ],
            directory_roles=[{"id": "r1", "displayName": "Global Administrator"}],
            directory_role_members={"r1": ["u2"]},  # only u2 is admin
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.PASS


# ---------------------------------------------------------------------------
# 1.1.2 – Emergency access accounts (Manual)
# ---------------------------------------------------------------------------


class TestCIS_1_1_2:
    @pytest.fixture
    def rule(self):
        return CIS_1_1_2()

    @pytest.mark.asyncio
    async def test_always_manual(self, rule):
        data = _collected(users=[])
        finding = await rule.check(data)
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_provides_hint_when_candidates_found(self, rule):
        data = _collected(
            users=[
                {
                    "id": "bg1",
                    "userPrincipalName": "breakglass1@tenant.onmicrosoft.com",
                    "assignedLicenses": [],
                }
            ]
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.MANUAL
        assert "onmicrosoft.com" in finding.message


# ---------------------------------------------------------------------------
# 1.3.1 – Password expiration policy
# ---------------------------------------------------------------------------


class TestCIS_1_3_1:
    @pytest.fixture
    def rule(self):
        return CIS_1_3_1()

    @pytest.mark.asyncio
    async def test_pass_when_passwords_never_expire(self, rule):
        data = _collected(
            domains=[
                {"id": "contoso.com", "isVerified": True, "passwordValidityPeriodInDays": 2147483647},
            ]
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_passwords_expire(self, rule):
        data = _collected(
            domains=[
                {"id": "contoso.com", "isVerified": True, "passwordValidityPeriodInDays": 90},
            ]
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.FAIL
        assert "contoso.com" in finding.message

    @pytest.mark.asyncio
    async def test_pass_when_no_expiry_configured(self, rule):
        """None means the field is not set (treat as never expire)."""
        data = _collected(
            domains=[
                {"id": "contoso.com", "isVerified": True, "passwordValidityPeriodInDays": None},
            ]
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.PASS


# ---------------------------------------------------------------------------
# 5.2.2.1 – MFA for admin roles via CA
# ---------------------------------------------------------------------------


class TestCIS_5_2_2_1:
    @pytest.fixture
    def rule(self):
        return CIS_5_2_2_1()

    def _ca_policy(self, include_users=None, include_roles=None, controls=None, state="enabled"):
        return {
            "id": "p1",
            "displayName": "Require MFA for Admins",
            "state": state,
            "conditions": {
                "users": {
                    "includeUsers": include_users or [],
                    "includeRoles": include_roles or [],
                },
                "applications": {"includeApplications": ["All"]},
            },
            "grantControls": {"builtInControls": controls or ["mfa"]},
        }

    @pytest.mark.asyncio
    async def test_pass_when_all_user_mfa_policy_exists(self, rule):
        data = _collected(
            conditional_access_policies=[
                self._ca_policy(include_users=["All"])
            ]
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_no_mfa_policy(self, rule):
        data = _collected(conditional_access_policies=[])
        finding = await rule.check(data)
        assert finding.status == FindingStatus.FAIL

    @pytest.mark.asyncio
    async def test_fail_when_policy_is_report_only(self, rule):
        data = _collected(
            conditional_access_policies=[
                self._ca_policy(include_users=["All"], state="enabledForReportingButNotEnforcing")
            ]
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.FAIL

    @pytest.mark.asyncio
    async def test_skip_when_no_ca_data(self, rule):
        data = _collected()
        finding = await rule.check(data)
        assert finding.status == FindingStatus.SKIPPED


# ---------------------------------------------------------------------------
# 7.2.3 – SharePoint external sharing restricted
# ---------------------------------------------------------------------------


class TestCIS_7_2_3:
    @pytest.fixture
    def rule(self):
        return CIS_7_2_3()

    @pytest.mark.asyncio
    async def test_pass_when_sharing_disabled(self, rule):
        data = _collected(sharepoint_settings={"sharingCapability": 0})
        finding = await rule.check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_pass_when_existing_users_only(self, rule):
        data = _collected(sharepoint_settings={"sharingCapability": 3})
        finding = await rule.check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_anyone_links_allowed(self, rule):
        data = _collected(sharepoint_settings={"sharingCapability": 1})
        finding = await rule.check(data)
        assert finding.status == FindingStatus.FAIL

    @pytest.mark.asyncio
    async def test_skip_when_no_settings(self, rule):
        data = _collected()
        finding = await rule.check(data)
        assert finding.status == FindingStatus.SKIPPED


# ---------------------------------------------------------------------------
# 1.3.5 – Internal phishing protection for Forms
# ---------------------------------------------------------------------------


class TestCIS_1_3_5:
    @pytest.fixture
    def rule(self):
        return CIS_1_3_5()

    @pytest.mark.asyncio
    async def test_pass_when_enabled(self, rule):
        data = _collected(
            forms_settings={"isInOrgFormsPhishingScanEnabled": True}
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_disabled(self, rule):
        data = _collected(
            forms_settings={"isInOrgFormsPhishingScanEnabled": False}
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.FAIL

    @pytest.mark.asyncio
    async def test_manual_when_no_data(self, rule):
        data = _collected()
        finding = await rule.check(data)
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 1.3.7 – Third-party storage services restricted
# ---------------------------------------------------------------------------


class TestCIS_1_3_7:
    @pytest.fixture
    def rule(self):
        return CIS_1_3_7()

    @pytest.mark.asyncio
    async def test_fail_when_no_service_principal(self, rule):
        # Per CIS's own audit script, absence of the SP is itself a FAIL:
        # the integration defaults to enabled until explicitly disabled.
        data = _collected(third_party_storage_service_principal=None)
        finding = await rule.check(data)
        assert finding.status == FindingStatus.FAIL

    @pytest.mark.asyncio
    async def test_pass_when_service_principal_disabled(self, rule):
        data = _collected(
            third_party_storage_service_principal={"accountEnabled": False}
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_service_principal_enabled(self, rule):
        data = _collected(
            third_party_storage_service_principal={"accountEnabled": True}
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 5.1.2.5 – Option to remain signed in hidden (Manual)
# ---------------------------------------------------------------------------


class TestCIS_5_1_2_5:
    @pytest.mark.asyncio
    async def test_always_manual(self):
        finding = await CIS_5_1_2_5().check(_collected())
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 5.2.3.2 – Custom banned passwords lists
# ---------------------------------------------------------------------------


class TestCIS_5_2_3_2:
    @pytest.fixture
    def rule(self):
        return CIS_5_2_3_2()

    @pytest.mark.asyncio
    async def test_pass_when_enforced_and_populated(self, rule):
        data = _collected(
            password_protection_settings={
                "EnableBannedPasswordCheck": "True",
                "BannedPasswordList": "contoso\nwidget",
            }
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_not_enforced(self, rule):
        data = _collected(
            password_protection_settings={
                "EnableBannedPasswordCheck": "False",
                "BannedPasswordList": "",
            }
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.FAIL

    @pytest.mark.asyncio
    async def test_fail_when_no_group_setting_exists(self, rule):
        # Graph collected successfully but no matching groupSetting object
        # exists — the tenant never configured this, which defaults to
        # non-compliant per CIS's own documented default value.
        data = _collected()
        finding = await rule.check(data)
        assert finding.status == FindingStatus.FAIL

    @pytest.mark.asyncio
    async def test_skip_on_collection_error(self, rule):
        data = CollectedData(
            provider="ms365",
            target="test.onmicrosoft.com",
            data={},
            errors={"password_protection_settings": "HTTP 403"},
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.SKIPPED


# ---------------------------------------------------------------------------
# 5.2.3.3 – On-prem AD password protection
# ---------------------------------------------------------------------------


class TestCIS_5_2_3_3:
    @pytest.fixture
    def rule(self):
        return CIS_5_2_3_3()

    @pytest.mark.asyncio
    async def test_pass_when_enforced(self, rule):
        data = _collected(
            password_protection_settings={
                "EnableBannedPasswordCheckOnPremises": "True",
                "BannedPasswordCheckOnPremisesMode": "Enforce",
            }
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_audit_mode(self, rule):
        data = _collected(
            password_protection_settings={
                "EnableBannedPasswordCheckOnPremises": "True",
                "BannedPasswordCheckOnPremisesMode": "Audit",
            }
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.FAIL

    @pytest.mark.asyncio
    async def test_fail_when_no_group_setting_exists(self, rule):
        data = _collected()
        finding = await rule.check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 5.2.4.1 – Self-service password reset set to 'All' (Manual)
# ---------------------------------------------------------------------------


class TestCIS_5_2_4_1:
    @pytest.mark.asyncio
    async def test_always_manual(self):
        finding = await CIS_5_2_4_1().check(_collected())
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# Section 6 – Exchange Online: settings only readable via Exchange Online
# Remote PowerShell (no Graph API equivalent). assessment_status is AUTOMATED
# per CIS, but check() honestly returns MANUAL since this collector only
# authenticates via Microsoft Graph client credentials.
# ---------------------------------------------------------------------------


class TestCIS_6_1_1:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_6_1_1().check(_collected())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_skipped_on_collection_error(self):
        data = CollectedData(
            provider="ms365",
            target="test.onmicrosoft.com",
            data={},
            errors={"organization_config": "insufficient permissions"},
        )
        finding = await CIS_6_1_1().check(data)
        assert finding.status == FindingStatus.SKIPPED


class TestCIS_6_1_2:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_6_1_2().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_6_1_3:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_6_1_3().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_6_2_2:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_6_2_2().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_6_2_3:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_6_2_3().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_6_3_1:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_6_3_1().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_6_5_2:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_6_5_2().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_6_5_3:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_6_5_3().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_6_5_4:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_6_5_4().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_6_5_5:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_6_5_5().check(_collected())
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# Section 1/2 – Exchange/Defender settings only reachable via Exchange Online
# Remote PowerShell (Connect-ExchangeOnline).  CIS classifies these controls
# as AUTOMATED, but this collector only performs Graph client-credentials
# auth, so check() always returns MANUAL with a precise cmdlet citation.
# ---------------------------------------------------------------------------


class TestCIS_1_3_9:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_1_3_9().check(_collected())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_skipped_on_collector_error(self):
        data = CollectedData(
            provider="ms365",
            target="test.onmicrosoft.com",
            data={},
            errors={"owa_mailbox_policy": "boom"},
        )
        finding = await CIS_1_3_9().check(data)
        assert finding.status == FindingStatus.SKIPPED


class TestCIS_2_1_1:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_2_1_1().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_2_1_2:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_2_1_2().check(_collected())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_skipped_on_collector_error(self):
        data = CollectedData(
            provider="ms365",
            target="test.onmicrosoft.com",
            data={},
            errors={"malware_filter_policy": "boom"},
        )
        finding = await CIS_2_1_2().check(data)
        assert finding.status == FindingStatus.SKIPPED


class TestCIS_2_1_3:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_2_1_3().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_2_1_4:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_2_1_4().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_2_1_5:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_2_1_5().check(_collected())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_skipped_on_collector_error(self):
        data = CollectedData(
            provider="ms365",
            target="test.onmicrosoft.com",
            data={},
            errors={"atp_policy_for_o365": "boom"},
        )
        finding = await CIS_2_1_5().check(data)
        assert finding.status == FindingStatus.SKIPPED


class TestCIS_2_1_6:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_2_1_6().check(_collected())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_skipped_on_collector_error(self):
        data = CollectedData(
            provider="ms365",
            target="test.onmicrosoft.com",
            data={},
            errors={"hosted_outbound_spam_filter_policy": "boom"},
        )
        finding = await CIS_2_1_6().check(data)
        assert finding.status == FindingStatus.SKIPPED


class TestCIS_2_1_7:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_2_1_7().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_2_1_11:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_2_1_11().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_2_1_12:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_2_1_12().check(_collected())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_skipped_on_collector_error(self):
        data = CollectedData(
            provider="ms365",
            target="test.onmicrosoft.com",
            data={},
            errors={"hosted_connection_filter_policy": "boom"},
        )
        finding = await CIS_2_1_12().check(data)
        assert finding.status == FindingStatus.SKIPPED


class TestCIS_2_1_13:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_2_1_13().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_2_1_14:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_2_1_14().check(_collected())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_skipped_on_collector_error(self):
        data = CollectedData(
            provider="ms365",
            target="test.onmicrosoft.com",
            data={},
            errors={"hosted_content_filter_policy": "boom"},
        )
        finding = await CIS_2_1_14().check(data)
        assert finding.status == FindingStatus.SKIPPED


class TestCIS_2_1_15:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_2_1_15().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_2_4_1:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_2_4_1().check(_collected())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_skipped_on_collector_error(self):
        data = CollectedData(
            provider="ms365",
            target="test.onmicrosoft.com",
            data={},
            errors={"priority_account_protection": "boom"},
        )
        finding = await CIS_2_4_1().check(data)
        assert finding.status == FindingStatus.SKIPPED


class TestCIS_2_4_2:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_2_4_2().check(_collected())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_skipped_on_collector_error(self):
        data = CollectedData(
            provider="ms365",
            target="test.onmicrosoft.com",
            data={},
            errors={"preset_security_policies": "boom"},
        )
        finding = await CIS_2_4_2().check(data)
        assert finding.status == FindingStatus.SKIPPED


class TestCIS_2_4_4:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_2_4_4().check(_collected())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_skipped_on_collector_error(self):
        data = CollectedData(
            provider="ms365",
            target="test.onmicrosoft.com",
            data={},
            errors={"teams_protection_policy": "boom"},
        )
        finding = await CIS_2_4_4().check(data)
        assert finding.status == FindingStatus.SKIPPED


# ---------------------------------------------------------------------------
# Section 8 – Teams (all MANUAL: MicrosoftTeams/Exchange Remote PowerShell
# settings with no Microsoft Graph equivalent)
# ---------------------------------------------------------------------------


class TestCIS_8_1_1:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_8_1_1().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_8_1_2:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_8_1_2().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_8_2_1:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_8_2_1().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_8_2_2:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_8_2_2().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_8_2_3:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_8_2_3().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_8_2_4:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_8_2_4().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_8_5_2:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_8_5_2().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_8_5_3:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_8_5_3().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_8_5_4:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_8_5_4().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_8_5_5:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_8_5_5().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_8_5_6:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_8_5_6().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_8_5_7:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_8_5_7().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_8_5_8:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_8_5_8().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_8_5_9:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_8_5_9().check(_collected())
        assert finding.status == FindingStatus.MANUAL


class TestCIS_8_6_1:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_8_6_1().check(_collected())
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# Bugs found via live-tenant validation (not part of the original 59-item
# assessment_status audit): fabricated/wrong Graph fields, case-sensitivity
# mismatches, and a missing fail branch in pre-existing rule implementations.
# ---------------------------------------------------------------------------


class TestCIS_1_3_3:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_1_3_3().check(_collected())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_skip_on_collection_error(self):
        data = CollectedData(
            provider="ms365",
            target="test.onmicrosoft.com",
            data={},
            errors={"sharing_policy": "HTTP 403"},
        )
        finding = await CIS_1_3_3().check(data)
        assert finding.status == FindingStatus.SKIPPED


class TestCIS_1_3_6:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_1_3_6().check(_collected())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_skip_on_collection_error(self):
        data = CollectedData(
            provider="ms365",
            target="test.onmicrosoft.com",
            data={},
            errors={"organization_config": "HTTP 403"},
        )
        finding = await CIS_1_3_6().check(data)
        assert finding.status == FindingStatus.SKIPPED


class TestCIS_3_1_1:
    @pytest.mark.asyncio
    async def test_manual_when_no_data(self):
        finding = await CIS_3_1_1().check(_collected())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_skip_on_collection_error(self):
        data = CollectedData(
            provider="ms365",
            target="test.onmicrosoft.com",
            data={},
            errors={"admin_audit_log_config": "HTTP 403"},
        )
        finding = await CIS_3_1_1().check(data)
        assert finding.status == FindingStatus.SKIPPED


class TestCIS_5_1_4_1:
    @pytest.fixture
    def rule(self):
        return CIS_5_1_4_1()

    @pytest.mark.asyncio
    async def test_pass_when_no_users_can_join(self, rule):
        data = _collected(
            device_registration_policy={
                "azureADJoin": {
                    "allowedToJoin": {"@odata.type": "#microsoft.graph.allowedToJoinNoUsers"}
                }
            }
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_field_missing_due_to_wrong_key(self, rule):
        # Regression guard: previously looked up "azureAdJoin" (wrong case)
        # and always fell through to FAIL regardless of real tenant state.
        data = _collected(device_registration_policy={})
        finding = await rule.check(data)
        assert finding.status == FindingStatus.FAIL


class TestCIS_5_1_4_4:
    @pytest.fixture
    def rule(self):
        return CIS_5_1_4_4()

    @pytest.mark.asyncio
    async def test_pass_when_disabled(self, rule):
        data = _collected(
            device_registration_policy={
                "azureADJoin": {
                    "localAdmins": {"registeringUsers": {"localAdminType": "None"}}
                }
            }
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_administrator(self, rule):
        data = _collected(
            device_registration_policy={
                "azureADJoin": {
                    "localAdmins": {
                        "registeringUsers": {"localAdminType": "Administrator"}
                    }
                }
            }
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.FAIL

    @pytest.mark.asyncio
    async def test_fail_when_field_missing(self, rule):
        # Regression guard: previously a missing/unreadable field defaulted
        # to PASS, contradicting this control's documented insecure default.
        data = _collected(device_registration_policy={})
        finding = await rule.check(data)
        assert finding.status == FindingStatus.FAIL


class TestCIS_5_1_4_3:
    @pytest.fixture
    def rule(self):
        return CIS_5_1_4_3()

    @pytest.mark.asyncio
    async def test_pass_when_disabled(self, rule):
        data = _collected(
            device_registration_policy={
                "azureADJoin": {"localAdmins": {"enableGlobalAdmins": False}}
            }
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_enabled(self, rule):
        data = _collected(
            device_registration_policy={
                "azureADJoin": {"localAdmins": {"enableGlobalAdmins": True}}
            }
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.FAIL

    @pytest.mark.asyncio
    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_collected())
        assert finding.status == FindingStatus.SKIPPED


class TestCIS_5_1_4_6:
    @pytest.fixture
    def rule(self):
        return CIS_5_1_4_6()

    @pytest.mark.asyncio
    async def test_pass_when_restricted(self, rule):
        data = _collected(
            authorization_policy={
                "defaultUserRolePermissions": {
                    "allowedToReadBitlockerKeysForOwnedDevice": False
                }
            }
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_not_restricted(self, rule):
        data = _collected(
            authorization_policy={
                "defaultUserRolePermissions": {
                    "allowedToReadBitlockerKeysForOwnedDevice": True
                }
            }
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.FAIL

    @pytest.mark.asyncio
    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_collected())
        assert finding.status == FindingStatus.SKIPPED


class TestCIS_5_1_6_1:
    @pytest.fixture
    def rule(self):
        return CIS_5_1_6_1()

    @pytest.mark.asyncio
    async def test_pass_when_allowed_domains_present(self, rule):
        data = _collected(
            b2b_invitation_domains_policy={
                "AllowedDomains": ["contoso.com", "example.com"]
            }
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_pass_when_allowed_domains_empty(self, rule):
        data = _collected(b2b_invitation_domains_policy={"AllowedDomains": []})
        finding = await rule.check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_blocked_domains_present(self, rule):
        data = _collected(
            b2b_invitation_domains_policy={"BlockedDomains": ["bad.com"]}
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.FAIL

    @pytest.mark.asyncio
    async def test_manual_when_no_policy_configured(self, rule):
        finding = await rule.check(_collected())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_skip_on_collection_error(self, rule):
        data = CollectedData(
            provider="ms365",
            target="test.onmicrosoft.com",
            data={},
            errors={"b2b_invitation_domains_policy": "HTTP 403"},
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.SKIPPED


class TestCIS_5_2_3_6:
    @pytest.fixture
    def rule(self):
        return CIS_5_2_3_6()

    @pytest.mark.asyncio
    async def test_pass_when_enabled_for_all_users(self, rule):
        data = _collected(
            authentication_methods_policy={
                "systemCredentialPreferences": {
                    "state": "enabled",
                    "includeTargets": [{"id": "all_users", "targetType": "group"}],
                }
            }
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_disabled(self, rule):
        data = _collected(
            authentication_methods_policy={
                "systemCredentialPreferences": {"state": "disabled"}
            }
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.FAIL

    @pytest.mark.asyncio
    async def test_fail_when_enabled_but_not_all_users(self, rule):
        data = _collected(
            authentication_methods_policy={
                "systemCredentialPreferences": {
                    "state": "enabled",
                    "includeTargets": [{"id": "some_group", "targetType": "group"}],
                }
            }
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.FAIL

    @pytest.mark.asyncio
    async def test_fail_when_state_default(self, rule):
        # "default" means "Microsoft managed" / never explicitly configured —
        # CIS requires state to literally be 'enabled', so this doesn't
        # satisfy the control.
        data = _collected(
            authentication_methods_policy={
                "systemCredentialPreferences": {"state": "default"}
            }
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.FAIL

    @pytest.mark.asyncio
    async def test_manual_when_state_unrecognized(self, rule):
        data = _collected(
            authentication_methods_policy={
                "systemCredentialPreferences": {"state": "somethingElse"}
            }
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.MANUAL
