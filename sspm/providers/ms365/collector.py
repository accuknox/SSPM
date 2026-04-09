"""
MS365 data collector.

Fetches configuration snapshots from Microsoft Graph and Exchange Online REST
APIs.  All data is collected up-front so that rules can evaluate synchronously
against the cached snapshot without additional API round-trips.

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
    "branding"                      – company branding / sign-in page settings
    "safe_links_policies"           – Defender Safe Links (no Graph API → [])
    "safe_attachments_policies"     – Defender Safe Attachments (no Graph API → [])
    "anti_phishing_policies"        – (no Graph API → [])
    "transport_rules"               – Exchange mail transport rules (no Graph API → None)
    "sharepoint_settings"           – tenant-level SharePoint settings
    "audit_log_settings"            – Microsoft Purview audit log probe
    "dlp_policies"                  – Purview sensitivity labels (v2 endpoint)
    "device_compliance_policies"    – Intune device compliance policies
    "intune_enrollment_restrictions"
    "user_mfa_registration"         – per-user MFA capability report
    "pim_role_assignments"          – active + eligible PIM role assignments
    "role_management_policies"      – PIM role management policies
    "access_reviews"                – Identity Governance access review definitions
    "fabric_tenant_settings"        – Microsoft Fabric (no Graph API → None)
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from sspm.providers.base import CollectedData
from sspm.providers.ms365.auth import MS365Auth

log = logging.getLogger(__name__)

_GRAPH = "https://graph.microsoft.com/v1.0"
_GRAPH_BETA = "https://graph.microsoft.com/beta"


class MS365Collector:
    """
    Fetches MS365 tenant configuration data from Microsoft Graph.

    Each ``_collect_*`` method fetches one logical data set and stores it
    in ``self._data``.  Errors are stored in ``self._errors`` so that
    individual collection failures do not abort the entire scan.
    """

    def __init__(self, auth: MS365Auth) -> None:
        self._auth = auth
        self._data: dict[str, Any] = {}
        self._errors: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def collect(self, tenant_domain: str) -> CollectedData:
        async with httpx.AsyncClient(timeout=60) as client:
            self._client = client
            await self._collect_all()

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

    # ------------------------------------------------------------------
    # Collection methods
    # ------------------------------------------------------------------

    async def _collect_all(self) -> None:
        """Collect all data sets sequentially (rate-limit friendly)."""
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
        await self._safe_collect("branding", self._get_branding())
        await self._safe_collect(
            "safe_links_policies", self._get_safe_links_policies()
        )
        await self._safe_collect(
            "safe_attachments_policies", self._get_safe_attachments_policies()
        )
        await self._safe_collect(
            "anti_phishing_policies", self._get_anti_phishing_policies()
        )
        await self._safe_collect("transport_rules", self._get_transport_rules())
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
        return await self._get(f"{_GRAPH}/policies/authenticationMethodsPolicy")

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

    async def _get_branding(self):
        # Requires organisation ID collected earlier.
        org = self._data.get("organization")
        if not org or not org.get("id"):
            return None
        return await self._get(f"{_GRAPH}/organization/{org['id']}/branding")

    async def _get_safe_links_policies(self):
        # Defender for Office 365 Safe Links policies have no Microsoft Graph
        # equivalent.  Return empty list so rules can distinguish "not collected"
        # (None) from "collected but empty" ([]).
        return []

    async def _get_safe_attachments_policies(self):
        # No Graph API equivalent.
        return []

    async def _get_anti_phishing_policies(self):
        # No Graph API equivalent.
        return []

    async def _get_transport_rules(self):
        # Exchange transport rules have no Graph API equivalent.
        # Full data requires Exchange Online Management PowerShell:
        #   Get-TransportRule | Select-Object Name, State, RedirectMessageTo
        #   Get-HostedOutboundSpamFilterPolicy | Select-Object AutoForwardingMode
        # Return None so rules know data was not collected (vs. an empty list
        # which would falsely indicate "no rules exist").
        return None

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
        # Requires RoleManagementPolicy.Read.Directory permission.
        return await self._get(
            f"{_GRAPH}/policies/roleManagementPolicies",
            params={"$filter": "scopeType eq 'directoryRole'"},
        )

    async def _get_access_reviews(self):
        # Identity Governance access review definitions.
        # Requires AccessReview.Read.All permission.
        return await self._get(
            f"{_GRAPH}/identityGovernance/accessReviews/definitions"
        )

    async def _get_fabric_tenant_settings(self):
        # Fabric tenant settings are not available through Microsoft Graph.
        # They are exposed by the dedicated Fabric REST API:
        #   GET https://api.fabric.microsoft.com/v1/admin/tenantsettings
        # That API requires a delegated token (Fabric.Admin.All scope) which
        # cannot be obtained with client-credentials flow alone.
        # Return None so rules produce a MANUAL finding instead of an error.
        return None
