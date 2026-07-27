"""
Base class for all MS365 rules.

Provides convenience helpers so concrete rules stay concise:
    - ``_pass(data, msg, evidence)``  → PASS Finding
    - ``_fail(data, msg, evidence)``  → FAIL Finding
    - ``_manual(data, msg)``          → MANUAL Finding
    - ``_skip(data, msg)``            → SKIPPED Finding
    - ``_error(data, msg)``           → ERROR Finding
"""

from __future__ import annotations

from typing import Any

from sspm.core.models import Evidence, Finding, FindingStatus
from sspm.providers.base import BaseRule, CollectedData


class MS365Rule(BaseRule):
    """Common base for all MS365 CIS rules."""

    provider = "ms365"

    # ------------------------------------------------------------------
    # Convenience factory methods
    # ------------------------------------------------------------------

    def _pass(
        self,
        message: str,
        resource_id: str = "",
        resource_type: str = "tenant",
        evidence: list[Evidence] | None = None,
    ) -> Finding:
        return Finding(
            rule=self.metadata,
            status=FindingStatus.PASS,
            resource_id=resource_id,
            resource_type=resource_type,
            message=message,
            evidence=evidence or [],
        )

    def _fail(
        self,
        message: str,
        resource_id: str = "",
        resource_type: str = "tenant",
        evidence: list[Evidence] | None = None,
        remediation_guidance: str = "",
    ) -> Finding:
        return Finding(
            rule=self.metadata,
            status=FindingStatus.FAIL,
            resource_id=resource_id,
            resource_type=resource_type,
            message=message,
            evidence=evidence or [],
            remediation_guidance=remediation_guidance or self.metadata.remediation,
        )

    def _manual(
        self,
        message: str = "",
        resource_id: str = "",
        resource_type: str = "tenant",
    ) -> Finding:
        return Finding(
            rule=self.metadata,
            status=FindingStatus.MANUAL,
            resource_id=resource_id,
            resource_type=resource_type,
            message=message,
        )

    def _skip(self, reason: str) -> Finding:
        return Finding(
            rule=self.metadata,
            status=FindingStatus.SKIPPED,
            message=reason,
        )

    def _error(self, message: str) -> Finding:
        return Finding(
            rule=self.metadata,
            status=FindingStatus.ERROR,
            message=message,
        )

    # ------------------------------------------------------------------
    # Shared utilities
    # ------------------------------------------------------------------

    def _get_privileged_role_ids(self, data: CollectedData) -> set[str]:
        """Return IDs of all roles whose display name includes 'Administrator'
        or is 'Global Reader'."""
        roles = data.get("directory_roles") or []
        return {
            r["id"]
            for r in roles
            if "administrator" in r.get("displayName", "").lower()
            or r.get("displayName") == "Global Reader"
        }

    def _get_members_of_privileged_roles(self, data: CollectedData) -> set[str]:
        """Return the union of user IDs assigned to any privileged role."""
        priv_role_ids = self._get_privileged_role_ids(data)
        role_members: dict[str, list[str]] = data.get("directory_role_members") or {}
        members: set[str] = set()
        for role_id, member_ids in role_members.items():
            if role_id in priv_role_ids:
                members.update(member_ids)
        return members

    # ------------------------------------------------------------------
    # Microsoft Fabric tenant settings (Get-CISFabricTenantSettings shape)
    # ------------------------------------------------------------------

    def _get_fabric_setting(
        self, data: CollectedData, setting_name: str
    ) -> dict | None:
        """Return the Fabric tenant setting dict matching ``settingName``, or
        None if Fabric settings were not collected or the setting is absent.

        Shape (Fabric Admin REST API, GET /v1/admin/tenantsettings):
            {"tenantSettings": [
                {"settingName": ..., "enabled": bool,
                 "enabledSecurityGroups": [...], "properties": [...]},
                ...
            ]}
        """
        settings = data.get("fabric_tenant_settings")
        if not settings:
            return None
        items = (
            settings.get("tenantSettings")
            if isinstance(settings, dict)
            else settings
        )
        for item in items or []:
            if item.get("settingName") == setting_name:
                return item
        return None

    def _fabric_property(self, setting: dict, name: str, default: Any = None) -> Any:
        """Look up a nested Fabric setting property by name (a list of
        {"name": ..., "value": ...} entries under "properties")."""
        for prop in setting.get("properties", []) or []:
            if prop.get("name") == name:
                return prop.get("value")
        return default

    def _fabric_restricted_or_disabled(self, setting: dict) -> bool:
        """Common CIS Fabric pass condition: the setting is disabled, or
        enabled but scoped to specific security groups (not the whole org)."""
        if not setting.get("enabled"):
            return True
        return bool(setting.get("enabledSecurityGroups"))
