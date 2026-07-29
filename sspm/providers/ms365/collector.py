"""
MS365 data collector.

Fetches configuration snapshots from Microsoft Graph, and optionally from
Exchange Online / Microsoft Teams / SharePoint Online via a PowerShell
bridge (see ``powershell_bridge.py``) when a certificate or client secret is
configured for it — Exchange and Teams can authenticate app-only with just
an access token acquired from the client secret (no certificate needed);
SharePoint requires a certificate. All data is collected up-front so that
rules can evaluate synchronously against the cached snapshot without
additional API round-trips.

Data keys (used by rules via ``CollectedData.get("<key>")``)
------------------------------------------------------------
Graph API:
    "organization"                  – tenant organisation object
    "domains"                       – verified domains
    "users"                         – all users (with select fields)
    "groups"                        – all M365/security groups
    "directory_roles"               – all activated directory roles
    "directory_role_members"        – {role_id: [user_id, …]}
    "conditional_access_policies"
    "authentication_methods_policy"
    "authorization_policy"          – default user role permissions, SSPR flag
    "admin_consent_request_policy"  – admin consent workflow settings
    "activity_based_timeout_policies"
    "device_registration_policy"    – device join/register settings
    "cross_tenant_access_policy"    – cross-tenant collaboration settings
    "b2b_invitation_domains_policy" – legacy B2B allow/block domain list
                                       (beta/legacy/policies, real Graph API)
    "branding"                      – company branding / sign-in page settings
    "sharepoint_settings"           – tenant-level SharePoint settings
    "audit_log_settings"            – Microsoft Purview audit log probe
    "dlp_policies"                  – Purview sensitivity labels (v2 endpoint)
    "device_compliance_policies"    – Intune device compliance policies
    "intune_enrollment_restrictions"
    "user_mfa_registration"         – per-user MFA capability report
    "pim_role_assignments"          – active + eligible PIM role assignments
    "role_management_policies"      – PIM role management policies
    "access_reviews"                – Identity Governance access review definitions
    "fabric_tenant_settings"        – Microsoft Fabric tenant settings, from
                                       the Fabric admin REST API (not Graph)
    "password_protection_settings"  – Entra Password Protection group setting
                                       (banned password lists, on-prem AD mode)
    "forms_settings"                – Microsoft Forms org settings (beta)
    "third_party_storage_service_principal" – service principal for the
                                       "third-party storage in Office on the
                                       web" integration (CIS 1.3.7)
    "priority_account_protection"   – Defender portal only, permanently None
                                       (no PowerShell/Graph method published)
    "preset_security_policies"      – Defender portal only, permanently None
                                       (no PowerShell/Graph method published)

Exchange Online (scripts/exchange.ps1, via Connect-ExchangeOnline — see
_EXCHANGE_KEYS): "owa_mailbox_policy", "organization_config",
"transport_config", "atp_policy_for_o365", "hosted_outbound_spam_filter_policy",
"hosted_connection_filter_policy", "sharing_policy", "admin_audit_log_config",
"transport_rules", "malware_filter_policy", "hosted_content_filter_policy",
"mailbox_audit_bypass_association", "external_in_outlook",
"role_assignment_policies", "safe_links_policies", "safe_attachments_policies",
"anti_phishing_policies", "mailbox_audit_settings", "teams_protection_policy",
"report_submission_policy".

Microsoft Teams (scripts/teams.ps1, via Connect-MicrosoftTeams — see
_TEAMS_KEYS): "teams_client_configuration", "teams_external_access_policy",
"teams_tenant_federation_configuration", "teams_meeting_policy",
"teams_messaging_policy".

SharePoint Online (scripts/sharepoint.ps1, via Connect-SPOService — see
_SHAREPOINT_KEYS): "spo_tenant" (the Get-SPOTenant properties CIS section 7
audits that /admin/sharepoint/settings does not expose). Requires a
certificate: Connect-SPOService has no access-token auth path.

When no PowerShellBridge/PowerShellConfig is supplied to the collector (the
default), every Exchange/Teams key above is ``None`` — identical to this
collector's behavior before the bridge existed.
"""

from __future__ import annotations

import asyncio
import json
import logging
from importlib import resources
from typing import Any

import httpx

from sspm.providers.base import CollectedData
from sspm.providers.ms365.auth import FABRIC_SCOPE, MS365Auth
from sspm.providers.ms365.powershell_bridge import (
    EXO_TOKEN_SCOPE,
    GRAPH_TOKEN_SCOPE,
    TEAMS_TOKEN_SCOPE,
    PowerShellBridge,
    PowerShellConfig,
    acquire_client_credentials_token,
)

log = logging.getLogger(__name__)

_GRAPH = "https://graph.microsoft.com/v1.0"
_GRAPH_BETA = "https://graph.microsoft.com/beta"
_FABRIC_API = "https://api.fabric.microsoft.com/v1"

# Keys collected by scripts/exchange.ps1 (Connect-ExchangeOnline).
_EXCHANGE_KEYS = [
    "owa_mailbox_policy",
    "organization_config",
    "transport_config",
    "atp_policy_for_o365",
    "hosted_outbound_spam_filter_policy",
    "hosted_connection_filter_policy",
    "sharing_policy",
    "admin_audit_log_config",
    "transport_rules",
    "malware_filter_policy",
    "hosted_content_filter_policy",
    "mailbox_audit_bypass_association",
    "external_in_outlook",
    "role_assignment_policies",
    "safe_links_policies",
    "safe_attachments_policies",
    "anti_phishing_policies",
    "mailbox_audit_settings",
    "teams_protection_policy",
    "report_submission_policy",
]

# Keys collected by scripts/teams.ps1 (Connect-MicrosoftTeams).
_TEAMS_KEYS = [
    "teams_client_configuration",
    "teams_external_access_policy",
    "teams_tenant_federation_configuration",
    "teams_meeting_policy",
    "teams_messaging_policy",
]

# Keys collected by scripts/sharepoint.ps1 (Connect-SPOService).
_SHAREPOINT_KEYS = ["spo_tenant"]


class MS365Collector:
    """
    Fetches MS365 tenant configuration data from Microsoft Graph, and
    optionally from Exchange Online / Teams / SharePoint via a
    :class:`PowerShellBridge` when certificate-based auth is configured.

    Each ``_collect_*`` method fetches one logical data set and stores it
    in ``self._data``.  Errors are stored in ``self._errors`` so that
    individual collection failures do not abort the entire scan.
    """

    def __init__(
        self,
        auth: MS365Auth,
        ps_bridge: PowerShellBridge | None = None,
        ps_config: PowerShellConfig | None = None,
    ) -> None:
        self._auth = auth
        self._ps_bridge = ps_bridge
        self._ps_config = ps_config
        self._data: dict[str, Any] = {}
        self._errors: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def collect(self, tenant_domain: str) -> CollectedData:
        async with httpx.AsyncClient(timeout=60) as client:
            self._client = client
            await asyncio.gather(
                self._collect_all_graph(),
                self._collect_exchange_via_powershell(),
                self._collect_teams_via_powershell(),
                self._collect_sharepoint_via_powershell(),
            )

        return CollectedData(
            provider="ms365",
            target=tenant_domain,
            data=self._data,
            errors=self._errors,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _get(
        self, url: str, params: dict | None = None
    ) -> dict | list | None:
        """GET a Graph endpoint; handle pagination automatically."""
        headers = self._auth.bearer_header
        results: list[dict] = []
        next_url: str | None = url

        while next_url:
            resp = await self._client.get(
                next_url, headers=headers, params=params if next_url == url else None
            )
            resp.raise_for_status()
            body = resp.json()

            # If the response is a collection with pagination
            if "value" in body:
                results.extend(body["value"])
                next_url = body.get("@odata.nextLink")
            else:
                # Single object response
                return body

        return results

    def _store(self, key: str, value: Any) -> None:
        self._data[key] = value

    async def _safe_collect(self, key: str, coro) -> None:
        try:
            result = await coro
            self._store(key, result)
        except httpx.HTTPStatusError as exc:
            msg = f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"
            log.warning("Could not collect %r: %s", key, msg)
            self._errors[key] = msg
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not collect %r: %s", key, exc)
            self._errors[key] = str(exc)

    def _ps_ready(self, module: str) -> bool:
        """True if the PowerShell bridge is configured and enabled for ``module``.

        Requires either a certificate or a client secret to authenticate
        with — a config with neither is treated as not configured, same as
        no config at all.
        """
        if self._ps_bridge is None or self._ps_config is None:
            return False
        if not self._ps_bridge.available:
            return False
        if not (self._ps_config.cert_path or self._ps_config.client_secret):
            return False
        return bool(getattr(self._ps_config, f"enable_{module}", False))

    @staticmethod
    def _script_path(name: str):
        return resources.files("sspm.providers.ms365") / "scripts" / name

    def _cert_env_extra(self) -> dict[str, str]:
        cert_password = self._ps_config.cert_password if self._ps_config else ""
        return {"SSPM_MS365_CERT_PASSWORD": cert_password} if cert_password else {}

    async def _safe_collect_batch(
        self, keys: list[str], script_name: str, args: list[str], env_extra: dict[str, str]
    ) -> None:
        """Run a PowerShell script and distribute its batched result across ``keys``.

        On total script failure (bridge unavailable, timeout, bad JSON), the
        same error string is recorded against every key in the batch so
        rules can distinguish "not configured/failed" from "ran and returned
        nothing" (``None``).
        """
        if not keys:
            return

        result = await self._ps_bridge.run_script(
            self._script_path(script_name), args, env_extra=env_extra
        )

        if not result.ok:
            detail = result.error or "PowerShell script failed"
            if result.stderr:
                detail = f"{detail} | stderr: {result.stderr}"
            log.warning("PowerShell script %s failed: %s", script_name, detail)
            for key in keys:
                self._errors[key] = detail
            return

        payload = result.data or {}
        script_result = payload.get("result") or {}
        script_errors = payload.get("errors") or {}

        for key in keys:
            if key in script_errors:
                self._errors[key] = str(script_errors[key])
            else:
                self._store(key, script_result.get(key))

    async def _collect_exchange_via_powershell(self) -> None:
        if not self._ps_ready("exchange"):
            for key in _EXCHANGE_KEYS:
                self._store(key, None)
            return

        cfg = self._ps_config
        env_extra = self._cert_env_extra()
        args = ["-AppId", cfg.app_id, "-Organization", cfg.organization]

        if cfg.cert_path:
            args += ["-CertificatePath", cfg.cert_path]
        else:
            try:
                token = await acquire_client_credentials_token(
                    cfg.tenant_id, cfg.app_id, cfg.client_secret, EXO_TOKEN_SCOPE
                )
            except RuntimeError as exc:
                log.warning("Could not acquire Exchange Online access token: %s", exc)
                for key in _EXCHANGE_KEYS:
                    self._errors[key] = str(exc)
                return
            env_extra["SSPM_MS365_EXO_ACCESS_TOKEN"] = token

        await self._safe_collect_batch(_EXCHANGE_KEYS, "exchange.ps1", args, env_extra)

    async def _collect_teams_via_powershell(self) -> None:
        if not self._ps_ready("teams"):
            for key in _TEAMS_KEYS:
                self._store(key, None)
            return

        cfg = self._ps_config
        env_extra = self._cert_env_extra()
        args = ["-AppId", cfg.app_id, "-TenantId", cfg.tenant_id]

        if cfg.cert_path:
            args += ["-CertificatePath", cfg.cert_path]
        else:
            try:
                graph_token = await acquire_client_credentials_token(
                    cfg.tenant_id, cfg.app_id, cfg.client_secret, GRAPH_TOKEN_SCOPE
                )
                teams_token = await acquire_client_credentials_token(
                    cfg.tenant_id, cfg.app_id, cfg.client_secret, TEAMS_TOKEN_SCOPE
                )
            except RuntimeError as exc:
                log.warning("Could not acquire Microsoft Teams access token(s): %s", exc)
                for key in _TEAMS_KEYS:
                    self._errors[key] = str(exc)
                return
            env_extra["SSPM_MS365_GRAPH_ACCESS_TOKEN"] = graph_token
            env_extra["SSPM_MS365_TEAMS_ACCESS_TOKEN"] = teams_token

        await self._safe_collect_batch(_TEAMS_KEYS, "teams.ps1", args, env_extra)

    async def _collect_sharepoint_via_powershell(self) -> None:
        # Unlike Exchange and Teams, SharePoint Online Management Shell has no
        # access-token auth path — Connect-SPOService needs the certificate.
        # Without one there is nothing to run, so the keys stay None and the
        # rules SKIP.
        cfg = self._ps_config
        if not self._ps_ready("sharepoint") or not (cfg and cfg.cert_path):
            for key in _SHAREPOINT_KEYS:
                self._store(key, None)
            return

        args = [
            "-AppId", cfg.app_id,
            "-TenantId", cfg.tenant_id,
            "-CertificatePath", cfg.cert_path,
            "-AdminUrl", cfg.sharepoint_admin_url,
        ]
        await self._safe_collect_batch(
            _SHAREPOINT_KEYS, "sharepoint.ps1", args, self._cert_env_extra()
        )

    # ------------------------------------------------------------------
    # Collection methods
    # ------------------------------------------------------------------

    async def _collect_all_graph(self) -> None:
        """Collect all Microsoft Graph data sets sequentially (rate-limit friendly)."""
        # Collect organisation first — subsequent collectors may need its ID.
        await self._safe_collect("organization", self._get_organization())
        await self._safe_collect("domains", self._get_domains())
        await self._safe_collect("users", self._get_users())
        await self._safe_collect("groups", self._get_groups())
        await self._safe_collect("directory_roles", self._get_directory_roles())
        await self._safe_collect(
            "directory_role_members", self._get_directory_role_members()
        )
        await self._safe_collect(
            "conditional_access_policies", self._get_ca_policies()
        )
        await self._safe_collect(
            "authentication_methods_policy", self._get_auth_methods_policy()
        )
        await self._safe_collect(
            "authorization_policy", self._get_authorization_policy()
        )
        await self._safe_collect(
            "admin_consent_request_policy", self._get_admin_consent_request_policy()
        )
        await self._safe_collect(
            "activity_based_timeout_policies",
            self._get_activity_based_timeout_policies(),
        )
        await self._safe_collect(
            "device_registration_policy", self._get_device_registration_policy()
        )
        await self._safe_collect(
            "cross_tenant_access_policy", self._get_cross_tenant_access_policy()
        )
        await self._safe_collect(
            "b2b_invitation_domains_policy",
            self._get_b2b_invitation_domains_policy(),
        )
        await self._safe_collect("branding", self._get_branding())
        # safe_links_policies, safe_attachments_policies, anti_phishing_policies,
        # and transport_rules are collected by the Exchange PowerShell bridge
        # (see _collect_exchange_via_powershell) — no Graph API equivalent.
        await self._safe_collect(
            "sharepoint_settings", self._get_sharepoint_settings()
        )
        await self._safe_collect(
            "audit_log_settings", self._get_audit_log_settings()
        )
        await self._safe_collect("dlp_policies", self._get_dlp_policies())
        await self._safe_collect(
            "device_compliance_policies", self._get_device_compliance_policies()
        )
        await self._safe_collect(
            "intune_enrollment_restrictions",
            self._get_intune_enrollment_restrictions(),
        )
        await self._safe_collect(
            "user_mfa_registration", self._get_user_mfa_registration()
        )
        await self._safe_collect(
            "pim_role_assignments", self._get_pim_role_assignments()
        )
        await self._safe_collect(
            "role_management_policies", self._get_role_management_policies()
        )
        await self._safe_collect("access_reviews", self._get_access_reviews())
        await self._safe_collect(
            "fabric_tenant_settings", self._get_fabric_tenant_settings()
        )
        await self._safe_collect(
            "password_protection_settings",
            self._get_password_protection_settings(),
        )
        await self._safe_collect("forms_settings", self._get_forms_settings())
        await self._safe_collect(
            "third_party_storage_service_principal",
            self._get_third_party_storage_service_principal(),
        )

        # priority_account_protection (CIS 2.4.1) and preset_security_policies
        # (CIS 2.4.2) are Defender-portal-only settings with no published
        # PowerShell or Graph method (per CIS's own audit procedure) — these
        # stay permanently MANUAL regardless of the PowerShell bridge.
        await self._safe_collect(
            "priority_account_protection", self._get_priority_account_protection()
        )
        await self._safe_collect(
            "preset_security_policies", self._get_preset_security_policies()
        )
        # All other Exchange/Teams/SharePoint keys are collected by the
        # PowerShell bridge — see _collect_exchange_via_powershell,
        # _collect_teams_via_powershell, _collect_sharepoint_via_powershell.

    # --- Individual collectors ---

    async def _get_organization(self):
        result = await self._get(f"{_GRAPH}/organization")
        return result[0] if isinstance(result, list) and result else result

    async def _get_domains(self):
        return await self._get(f"{_GRAPH}/domains")

    async def _get_users(self):
        return await self._get(
            f"{_GRAPH}/users",
            params={
                "$select": (
                    "id,displayName,userPrincipalName,onPremisesSyncEnabled,"
                    "assignedLicenses,accountEnabled,userType"
                ),
                "$top": "999",
            },
        )

    async def _get_groups(self):
        return await self._get(
            f"{_GRAPH}/groups",
            params={
                "$select": "id,displayName,groupTypes,securityEnabled,mailEnabled,visibility",
                "$top": "999",
            },
        )

    async def _get_directory_roles(self):
        return await self._get(f"{_GRAPH}/directoryRoles")

    async def _get_directory_role_members(self) -> dict[str, list[str]]:
        roles = self._data.get("directory_roles", [])
        members: dict[str, list[str]] = {}
        for role in roles:
            role_id = role["id"]
            role_members = await self._get(
                f"{_GRAPH}/directoryRoles/{role_id}/members",
                params={"$select": "id"},
            )
            members[role_id] = [m["id"] for m in (role_members or [])]
        return members

    async def _get_ca_policies(self):
        return await self._get(f"{_GRAPH}/identity/conditionalAccess/policies")

    async def _get_auth_methods_policy(self):
        # beta is required: systemCredentialPreferences (CIS 5.2.3.6),
        # reportSuspiciousActivitySettings, and optOutSettings are beta-only
        # fields, absent from the v1.0 representation of this resource. beta
        # is otherwise a strict superset (authenticationMethodConfigurations
        # is present in both), so this is a safe upgrade for the other rules
        # reading this key.
        return await self._get(f"{_GRAPH_BETA}/policies/authenticationMethodsPolicy")

    async def _get_authorization_policy(self):
        # Returns the tenant-wide authorisation policy including
        # defaultUserRolePermissions, guestUserRoleId, allowedToUseSSPR, etc.
        result = await self._get(f"{_GRAPH}/policies/authorizationPolicy")
        # The endpoint returns a collection; take the first (only) item.
        if isinstance(result, list):
            return result[0] if result else None
        return result

    async def _get_admin_consent_request_policy(self):
        return await self._get(f"{_GRAPH}/policies/adminConsentRequestPolicy")

    async def _get_activity_based_timeout_policies(self):
        return await self._get(f"{_GRAPH}/policies/activityBasedTimeoutPolicies")

    async def _get_device_registration_policy(self):
        return await self._get(f"{_GRAPH}/policies/deviceRegistrationPolicy")

    async def _get_cross_tenant_access_policy(self):
        return await self._get(f"{_GRAPH}/policies/crossTenantAccessPolicy")

    async def _get_b2b_invitation_domains_policy(self):
        # Legacy directory policies expose the B2B invitation allow/block
        # domain list (CIS 5.1.6.1), which has no modern Graph API
        # equivalent. Requires Policy.Read.All.
        #   GET /beta/legacy/policies
        #   filter value[].type == 'B2BManagementPolicy'
        #   each matching policy's "definition" is a list of JSON-encoded
        #   strings; parse for B2BManagementPolicy.InvitationsAllowedAndBlockedDomainsPolicy
        result = await self._get(f"{_GRAPH_BETA}/legacy/policies")
        policies = result if isinstance(result, list) else []
        for policy in policies:
            if policy.get("type") != "B2BManagementPolicy":
                continue
            for raw in policy.get("definition") or []:
                try:
                    parsed = json.loads(raw)
                except (TypeError, ValueError):
                    continue
                b2b = parsed.get("B2BManagementPolicy") or {}
                domains_policy = b2b.get("InvitationsAllowedAndBlockedDomainsPolicy")
                if domains_policy is not None:
                    return domains_policy
        return None

    async def _get_branding(self):
        # Requires organisation ID collected earlier.
        org = self._data.get("organization")
        if not org or not org.get("id"):
            return None
        return await self._get(f"{_GRAPH}/organization/{org['id']}/branding")

    async def _get_sharepoint_settings(self):
        # Requires SharePointTenantSettings.Read.All application permission.
        return await self._get(f"{_GRAPH}/admin/sharepoint/settings")

    async def _get_audit_log_settings(self):
        # Use the sign-in logs endpoint as a liveness probe: a successful
        # response confirms AuditLog.Read.All is granted and auditing is on.
        # We deliberately fetch only a single page (no pagination) to avoid
        # expired skip-token errors on tenants with large sign-in volumes.
        # The definitive audit-enabled flag requires Exchange Online PowerShell:
        #   Get-AdminAuditLogConfig | Select UnifiedAuditLogIngestionEnabled
        headers = self._auth.bearer_header
        resp = await self._client.get(
            f"{_GRAPH}/auditLogs/signIns",
            headers=headers,
            params={"$top": "1", "$select": "id"},
        )
        resp.raise_for_status()
        return {"accessible": True}

    async def _get_dlp_policies(self):
        # Sensitivity labels via the beta endpoint with app-only auth.
        # Requires InformationProtectionPolicy.Read.All.
        # A 404 with "policy is empty" means no labels are configured (not an
        # error); treat it as an empty list so rules produce a FAIL rather than SKIP.
        try:
            return await self._get(
                f"{_GRAPH_BETA}/security/informationProtection/sensitivityLabels",
            )
        except Exception as exc:
            if "404" in str(exc) or "itemNotFound" in str(exc) or "notFound" in str(exc):
                return []
            raise

    async def _get_device_compliance_policies(self):
        return await self._get(
            f"{_GRAPH}/deviceManagement/deviceCompliancePolicies"
        )

    async def _get_intune_enrollment_restrictions(self):
        # Requires DeviceManagementServiceConfig.Read.All application permission.
        return await self._get(
            f"{_GRAPH}/deviceManagement/deviceEnrollmentConfigurations"
        )

    async def _get_user_mfa_registration(self):
        # Per-user MFA capability data.
        # Requires Reports.Read.All application permission.
        return await self._get(
            f"{_GRAPH_BETA}/reports/authenticationMethods/userRegistrationDetails",
            params={"$select": "id,userPrincipalName,userType,isMfaCapable,isMfaRegistered"},
        )

    async def _get_pim_role_assignments(self):
        # Collect both active (scheduled) and eligible PIM role assignments.
        # Requires RoleManagement.Read.Directory permission.
        # Returns empty list if PIM is not licensed (gracefully skipped).
        try:
            active = await self._get(
                f"{_GRAPH}/roleManagement/directory/roleAssignmentSchedules"
            ) or []
            eligible = await self._get(
                f"{_GRAPH}/roleManagement/directory/roleEligibilitySchedules"
            ) or []
            for a in active:
                a["assignmentState"] = "active"
            for e in eligible:
                e["assignmentState"] = "eligible"
            return active + eligible
        except Exception:
            # PIM not provisioned / not licensed → return empty list so rules SKIP
            return []

    async def _get_role_management_policies(self):
        # PIM role management policies (activation rules, approval requirements).
        # Requires RoleManagementPolicy.Read.Directory permission *and* a
        # Microsoft Entra ID P2 / Governance licence — without the licence the
        # endpoint answers 400 with an opaque "MissingProvider" body, so
        # translate it into the actual cause for the report.
        try:
            return await self._get(
                f"{_GRAPH}/policies/roleManagementPolicies",
                params={"$filter": "scopeType eq 'directoryRole'"},
            )
        except httpx.HTTPStatusError as exc:
            body = exc.response.text
            if exc.response.status_code == 400 and (
                "MissingProvider" in body or "AadPremiumLicenseRequired" in body
            ):
                raise RuntimeError(
                    "Privileged Identity Management is not provisioned in this "
                    "tenant. It requires a Microsoft Entra ID P2 or Microsoft "
                    "Entra ID Governance licence."
                ) from exc
            raise

    async def _get_access_reviews(self):
        # Identity Governance access review definitions.
        # Requires AccessReview.Read.All permission.
        return await self._get(
            f"{_GRAPH}/identityGovernance/accessReviews/definitions"
        )

    # --- Defender-portal-only settings (no PowerShell or Graph method) ---
    #
    # CIS's own audit procedure for these two is UI-only (Microsoft Defender
    # portal) with no published PowerShell or Graph method — they stay
    # permanently MANUAL, unlike the other Exchange/Teams keys, which are
    # collected by the PowerShell bridge (see _collect_exchange_via_powershell
    # / _collect_teams_via_powershell / scripts/*.ps1).

    async def _get_priority_account_protection(self):
        return None

    async def _get_preset_security_policies(self):
        return None

    async def _get_password_protection_settings(self):
        # Entra Password Protection (banned password lists, on-prem AD proxy
        # mode) is exposed via the tenant-wide "Password Rule Settings"
        # directory setting template (CIS 5.2.3.2 / 5.2.3.3):
        #   GET /groupSettings
        #   filter to templateId == 5cf42378-d67d-4f36-ba46-e8b86229381d
        # Requires Directory.Read.All (or GroupSettings.Read.All).
        template_id = "5cf42378-d67d-4f36-ba46-e8b86229381d"
        settings = await self._get(f"{_GRAPH}/groupSettings") or []
        for setting in settings:
            if setting.get("templateId") == template_id:
                return {v["name"]: v["value"] for v in setting.get("values", [])}
        return None

    async def _get_forms_settings(self):
        # Microsoft Forms org settings (CIS 1.3.5): internal phishing scanning.
        # Requires OrgSettings-Forms.Read.All (beta endpoint only).
        return await self._get(f"{_GRAPH_BETA}/admin/forms/settings")

    async def _get_third_party_storage_service_principal(self):
        # CIS 1.3.7: "third-party storage services in Microsoft 365 on the
        # web" is gated by a first-party service principal. If it does not
        # exist, or exists but is disabled, third-party storage is blocked.
        # Requires Application.Read.All.
        result = await self._get(
            f"{_GRAPH}/servicePrincipals",
            params={
                "$filter": "appId eq 'c1f33bc0-bdb4-4248-ba9b-096807ddb43e'",
            },
        )
        if isinstance(result, list):
            return result[0] if result else None
        return result

    async def _get_fabric_tenant_settings(self):
        # Fabric tenant settings are not available through Microsoft Graph;
        # they are exposed by the dedicated Fabric admin REST API:
        #   GET https://api.fabric.microsoft.com/v1/admin/tenantsettings
        # That resource needs its own token audience, and it only accepts a
        # service principal when the tenant has enabled "Service principals
        # can access read-only admin APIs" and added this app to the allowed
        # security group. Without that it answers 401/403 — recorded as a
        # collection error so the section 9.1 rules SKIP with the reason.
        token = self._auth.get_token_for_scope(FABRIC_SCOPE, "Microsoft Fabric")
        resp = await self._client.get(
            f"{_FABRIC_API}/admin/tenantsettings",
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code in (401, 403):
            raise RuntimeError(
                f"HTTP {resp.status_code} from the Fabric admin API. Enable "
                "'Service principals can access read-only admin APIs' in the "
                "Fabric admin portal (Tenant settings > Developer settings) "
                "and add this app registration to the allowed security group."
            )
        resp.raise_for_status()
        return resp.json()
