"""Unit tests for the Microsoft Teams / EXO PowerShell-bridge CIS rules
(section 8 - Teams)."""

import pytest

from sspm.core.models import FindingStatus
from sspm.providers.base import CollectedData
from sspm.providers.ms365.rules.section8_teams.cis_8_1_1 import CIS_8_1_1
from sspm.providers.ms365.rules.section8_teams.cis_8_1_2 import CIS_8_1_2
from sspm.providers.ms365.rules.section8_teams.cis_8_2_1 import CIS_8_2_1
from sspm.providers.ms365.rules.section8_teams.cis_8_2_2 import CIS_8_2_2
from sspm.providers.ms365.rules.section8_teams.cis_8_2_3 import CIS_8_2_3
from sspm.providers.ms365.rules.section8_teams.cis_8_2_4 import CIS_8_2_4
from sspm.providers.ms365.rules.section8_teams.cis_8_5_1 import CIS_8_5_1
from sspm.providers.ms365.rules.section8_teams.cis_8_5_2 import CIS_8_5_2
from sspm.providers.ms365.rules.section8_teams.cis_8_5_3 import CIS_8_5_3
from sspm.providers.ms365.rules.section8_teams.cis_8_5_4 import CIS_8_5_4
from sspm.providers.ms365.rules.section8_teams.cis_8_5_5 import CIS_8_5_5
from sspm.providers.ms365.rules.section8_teams.cis_8_5_6 import CIS_8_5_6
from sspm.providers.ms365.rules.section8_teams.cis_8_5_7 import CIS_8_5_7
from sspm.providers.ms365.rules.section8_teams.cis_8_5_8 import CIS_8_5_8
from sspm.providers.ms365.rules.section8_teams.cis_8_5_9 import CIS_8_5_9
from sspm.providers.ms365.rules.section8_teams.cis_8_6_1 import CIS_8_6_1


def _data(payload: dict | None = None, errors: dict | None = None) -> CollectedData:
    return CollectedData(
        provider="ms365",
        target="test.onmicrosoft.com",
        data=payload or {},
        errors=errors or {},
    )


# ---------------------------------------------------------------------------
# 8.1.1 - Teams client configuration: approved cloud storage providers
# ---------------------------------------------------------------------------
class TestCIS_8_1_1:
    @pytest.mark.asyncio
    async def test_skipped_on_error(self):
        data = _data(errors={"teams_client_configuration": "boom"})
        finding = await CIS_8_1_1().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_manual_when_none(self):
        finding = await CIS_8_1_1().check(_data())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_pass_when_all_providers_disabled(self):
        data = _data({
            "teams_client_configuration": {
                "AllowDropbox": False,
                "AllowBox": False,
                "AllowGoogleDrive": False,
                "AllowShareFile": False,
                "AllowEgnyte": False,
            }
        })
        finding = await CIS_8_1_1().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_manual_when_some_provider_enabled(self):
        # CIS allows organizationally-approved providers, so this cannot be
        # an automatic FAIL — the rule requires manual review instead.
        data = _data({
            "teams_client_configuration": {
                "AllowDropbox": True,
                "AllowBox": False,
                "AllowGoogleDrive": False,
                "AllowShareFile": False,
                "AllowEgnyte": False,
            }
        })
        finding = await CIS_8_1_1().check(data)
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 8.1.2 - Channel email
# ---------------------------------------------------------------------------
class TestCIS_8_1_2:
    @pytest.mark.asyncio
    async def test_skipped_on_error(self):
        data = _data(errors={"teams_client_configuration": "boom"})
        finding = await CIS_8_1_2().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_manual_when_none(self):
        finding = await CIS_8_1_2().check(_data())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_pass_when_disabled(self):
        data = _data({"teams_client_configuration": {"AllowEmailIntoChannel": False}})
        finding = await CIS_8_1_2().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_enabled(self):
        data = _data({"teams_client_configuration": {"AllowEmailIntoChannel": True}})
        finding = await CIS_8_1_2().check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 8.2.1 - External domains restricted
# ---------------------------------------------------------------------------
class TestCIS_8_2_1:
    @pytest.mark.asyncio
    async def test_skipped_on_error(self):
        data = _data(errors={"teams_external_access_policy": "boom"})
        finding = await CIS_8_2_1().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_on_federation_error(self):
        data = _data(errors={"teams_tenant_federation_configuration": "boom"})
        finding = await CIS_8_2_1().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_manual_when_none(self):
        finding = await CIS_8_2_1().check(_data())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_pass_when_federation_access_disabled(self):
        data = _data({
            "teams_external_access_policy": {"EnableFederationAccess": False},
        })
        finding = await CIS_8_2_1().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_pass_when_allow_federated_users_false(self):
        data = _data({
            "teams_tenant_federation_configuration": {"AllowFederatedUsers": False},
        })
        finding = await CIS_8_2_1().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_federation_access_enabled_and_no_restriction(self):
        data = _data({
            "teams_external_access_policy": {"EnableFederationAccess": True},
        })
        finding = await CIS_8_2_1().check(data)
        assert finding.status == FindingStatus.FAIL

    @pytest.mark.asyncio
    async def test_manual_when_allow_federated_users_true(self):
        # AllowedDomains shape is ambiguous — must not guess.
        data = _data({
            "teams_tenant_federation_configuration": {
                "AllowFederatedUsers": True,
                "AllowedDomains": {"AllowedDomain": ["partner.com"]},
            },
        })
        finding = await CIS_8_2_1().check(data)
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 8.2.2 - Unmanaged Teams users
# ---------------------------------------------------------------------------
class TestCIS_8_2_2:
    @pytest.mark.asyncio
    async def test_skipped_on_error(self):
        data = _data(errors={"teams_external_access_policy": "boom"})
        finding = await CIS_8_2_2().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_manual_when_none(self):
        finding = await CIS_8_2_2().check(_data())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_pass_when_disabled(self):
        data = _data({
            "teams_external_access_policy": {"EnableTeamsConsumerAccess": False},
        })
        finding = await CIS_8_2_2().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_pass_when_federation_config_disabled(self):
        data = _data({
            "teams_tenant_federation_configuration": {"AllowTeamsConsumer": False},
        })
        finding = await CIS_8_2_2().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_enabled(self):
        data = _data({
            "teams_external_access_policy": {"EnableTeamsConsumerAccess": True},
            "teams_tenant_federation_configuration": {"AllowTeamsConsumer": True},
        })
        finding = await CIS_8_2_2().check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 8.2.3 - External users can't initiate conversations
# ---------------------------------------------------------------------------
class TestCIS_8_2_3:
    @pytest.mark.asyncio
    async def test_skipped_on_error(self):
        data = _data(errors={"teams_external_access_policy": "boom"})
        finding = await CIS_8_2_3().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_manual_when_none(self):
        finding = await CIS_8_2_3().check(_data())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_pass_when_disabled(self):
        data = _data({
            "teams_external_access_policy": {"EnableTeamsConsumerInbound": False},
        })
        finding = await CIS_8_2_3().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_enabled(self):
        data = _data({
            "teams_external_access_policy": {"EnableTeamsConsumerInbound": True},
        })
        finding = await CIS_8_2_3().check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 8.2.4 - Trial tenants
# ---------------------------------------------------------------------------
class TestCIS_8_2_4:
    @pytest.mark.asyncio
    async def test_skipped_on_error(self):
        data = _data(errors={"teams_tenant_federation_configuration": "boom"})
        finding = await CIS_8_2_4().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_manual_when_none(self):
        finding = await CIS_8_2_4().check(_data())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_pass_when_blocked(self):
        data = _data({
            "teams_tenant_federation_configuration": {
                "ExternalAccessWithTrialTenants": "Blocked"
            },
        })
        finding = await CIS_8_2_4().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_allowed(self):
        data = _data({
            "teams_tenant_federation_configuration": {
                "ExternalAccessWithTrialTenants": "Allowed"
            },
        })
        finding = await CIS_8_2_4().check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# Simple boolean meeting-policy rules (8.5.2, 8.5.4, 8.5.7, 8.5.8, 8.5.9)
# ---------------------------------------------------------------------------
BOOLEAN_MEETING_POLICY_RULES = [
    (CIS_8_5_1, "AllowAnonymousUsersToJoinMeeting"),
    (CIS_8_5_2, "AllowAnonymousUsersToStartMeeting"),
    (CIS_8_5_4, "AllowPSTNUsersToBypassLobby"),
    (CIS_8_5_7, "AllowExternalParticipantGiveRequestControl"),
    (CIS_8_5_8, "AllowExternalNonTrustedMeetingChat"),
    (CIS_8_5_9, "AllowCloudRecording"),
]


class TestBooleanMeetingPolicyRules:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("rule_cls,prop", BOOLEAN_MEETING_POLICY_RULES)
    async def test_skipped_on_error(self, rule_cls, prop):
        data = _data(errors={"teams_meeting_policy": "boom"})
        finding = await rule_cls().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    @pytest.mark.parametrize("rule_cls,prop", BOOLEAN_MEETING_POLICY_RULES)
    async def test_manual_when_none(self, rule_cls, prop):
        finding = await rule_cls().check(_data())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    @pytest.mark.parametrize("rule_cls,prop", BOOLEAN_MEETING_POLICY_RULES)
    async def test_pass_when_false(self, rule_cls, prop):
        data = _data({"teams_meeting_policy": {prop: False}})
        finding = await rule_cls().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    @pytest.mark.parametrize("rule_cls,prop", BOOLEAN_MEETING_POLICY_RULES)
    async def test_fail_when_true(self, rule_cls, prop):
        data = _data({"teams_meeting_policy": {prop: True}})
        finding = await rule_cls().check(data)
        assert finding.status == FindingStatus.FAIL

    @pytest.mark.asyncio
    @pytest.mark.parametrize("rule_cls,prop", BOOLEAN_MEETING_POLICY_RULES)
    async def test_manual_when_unexpected_value(self, rule_cls, prop):
        data = _data({"teams_meeting_policy": {prop: "Weird"}})
        finding = await rule_cls().check(data)
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 8.5.3 - Lobby bypass (enum)
# ---------------------------------------------------------------------------
class TestCIS_8_5_3:
    @pytest.mark.asyncio
    async def test_skipped_on_error(self):
        data = _data(errors={"teams_meeting_policy": "boom"})
        finding = await CIS_8_5_3().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_manual_when_none(self):
        finding = await CIS_8_5_3().check(_data())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "value",
        ["InvitedUsers", "EveryoneInCompanyExcludingGuests", "OrganizerOnly"],
    )
    async def test_pass_when_compliant(self, value):
        data = _data({"teams_meeting_policy": {"AutoAdmittedUsers": value}})
        finding = await CIS_8_5_3().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_everyone(self):
        data = _data({"teams_meeting_policy": {"AutoAdmittedUsers": "Everyone"}})
        finding = await CIS_8_5_3().check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 8.5.5 - Meeting chat (enum)
# ---------------------------------------------------------------------------
class TestCIS_8_5_5:
    @pytest.mark.asyncio
    async def test_skipped_on_error(self):
        data = _data(errors={"teams_meeting_policy": "boom"})
        finding = await CIS_8_5_5().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_manual_when_none(self):
        finding = await CIS_8_5_5().check(_data())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "value",
        [
            "EnabledExceptAnonymous",
            "EnabledInMeetingOnlyForAllExceptAnonymous",
            "Disabled",
        ],
    )
    async def test_pass_when_compliant(self, value):
        data = _data({"teams_meeting_policy": {"MeetingChatEnabledType": value}})
        finding = await CIS_8_5_5().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_enabled(self):
        data = _data({"teams_meeting_policy": {"MeetingChatEnabledType": "Enabled"}})
        finding = await CIS_8_5_5().check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 8.5.6 - Presenter role (exact string)
# ---------------------------------------------------------------------------
class TestCIS_8_5_6:
    @pytest.mark.asyncio
    async def test_skipped_on_error(self):
        data = _data(errors={"teams_meeting_policy": "boom"})
        finding = await CIS_8_5_6().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_manual_when_none(self):
        finding = await CIS_8_5_6().check(_data())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_pass_when_organizer_only(self):
        data = _data({
            "teams_meeting_policy": {
                "DesignatedPresenterRoleMode": "OrganizerOnlyUserOverride"
            }
        })
        finding = await CIS_8_5_6().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_everyone_can_present(self):
        data = _data({
            "teams_meeting_policy": {
                "DesignatedPresenterRoleMode": "EveryoneUserOverride"
            }
        })
        finding = await CIS_8_5_6().check(data)
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 8.6.1 - Report security concerns (Teams messaging policy + EXO report
# submission policy)
# ---------------------------------------------------------------------------
class TestCIS_8_6_1:
    COMPLIANT_MESSAGING_POLICY = {"AllowSecurityEndUserReporting": True}
    COMPLIANT_REPORT_POLICY = [{
        "ReportJunkToCustomizedAddress": True,
        "ReportNotJunkToCustomizedAddress": True,
        "ReportPhishToCustomizedAddress": True,
        "ReportJunkAddresses": ["soc@contoso.com"],
        "ReportNotJunkAddresses": ["soc@contoso.com"],
        "ReportPhishAddresses": ["soc@contoso.com"],
        "ReportChatMessageEnabled": False,
        "ReportChatMessageToCustomizedAddressEnabled": True,
    }]

    @pytest.mark.asyncio
    async def test_skipped_on_teams_error(self):
        data = _data(errors={"teams_messaging_policy": "boom"})
        finding = await CIS_8_6_1().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_skipped_on_report_error(self):
        data = _data(errors={"report_submission_policy": "boom"})
        finding = await CIS_8_6_1().check(data)
        assert finding.status == FindingStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_manual_when_both_none(self):
        finding = await CIS_8_6_1().check(_data())
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_manual_when_only_teams_present(self):
        data = _data({"teams_messaging_policy": self.COMPLIANT_MESSAGING_POLICY})
        finding = await CIS_8_6_1().check(data)
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_manual_when_only_report_policy_present(self):
        data = _data({"report_submission_policy": self.COMPLIANT_REPORT_POLICY})
        finding = await CIS_8_6_1().check(data)
        assert finding.status == FindingStatus.MANUAL

    @pytest.mark.asyncio
    async def test_pass_when_fully_compliant(self):
        data = _data({
            "teams_messaging_policy": self.COMPLIANT_MESSAGING_POLICY,
            "report_submission_policy": self.COMPLIANT_REPORT_POLICY,
        })
        finding = await CIS_8_6_1().check(data)
        assert finding.status == FindingStatus.PASS

    @pytest.mark.asyncio
    async def test_fail_when_messaging_policy_disabled(self):
        data = _data({
            "teams_messaging_policy": {"AllowSecurityEndUserReporting": False},
            "report_submission_policy": self.COMPLIANT_REPORT_POLICY,
        })
        finding = await CIS_8_6_1().check(data)
        assert finding.status == FindingStatus.FAIL

    @pytest.mark.asyncio
    async def test_fail_when_report_policy_misconfigured(self):
        bad_policy = [dict(self.COMPLIANT_REPORT_POLICY[0], ReportChatMessageEnabled=True)]
        data = _data({
            "teams_messaging_policy": self.COMPLIANT_MESSAGING_POLICY,
            "report_submission_policy": bad_policy,
        })
        finding = await CIS_8_6_1().check(data)
        assert finding.status == FindingStatus.FAIL

    @pytest.mark.asyncio
    async def test_fail_when_report_policy_empty(self):
        data = _data({
            "teams_messaging_policy": self.COMPLIANT_MESSAGING_POLICY,
            "report_submission_policy": [],
        })
        finding = await CIS_8_6_1().check(data)
        assert finding.status == FindingStatus.FAIL
