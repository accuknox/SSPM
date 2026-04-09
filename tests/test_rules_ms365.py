"""Unit tests for individual MS365 CIS rules."""

import pytest

from sspm.core.models import FindingStatus
from sspm.providers.base import CollectedData
from sspm.providers.ms365.rules.section1_m365_admin.cis_1_1_1 import CIS_1_1_1
from sspm.providers.ms365.rules.section1_m365_admin.cis_1_1_2 import CIS_1_1_2
from sspm.providers.ms365.rules.section1_m365_admin.cis_1_3_1 import CIS_1_3_1
from sspm.providers.ms365.rules.section5_entra.cis_5_2_2_1 import CIS_5_2_2_1
from sspm.providers.ms365.rules.section5_entra.cis_5_2_2_2 import CIS_5_2_2_2
from sspm.providers.ms365.rules.section7_sharepoint.cis_7_2_3 import CIS_7_2_3


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
