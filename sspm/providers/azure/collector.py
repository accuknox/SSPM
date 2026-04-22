"""
Azure data collector.

Fetches configuration snapshots from Azure Resource Manager (ARM) and
Microsoft Graph using plain HTTPS requests (``httpx``) + MSAL bearer
tokens.  No ``azure-mgmt-*`` SDK dependencies are required.

Scope
-----
A single Azure subscription is the scan target.  Tenant-level artefacts
(Microsoft Entra ID security defaults, directory role assignments) are
collected via Microsoft Graph alongside subscription-scoped resources.

Data keys (consumed by rules through ``CollectedData.get(...)``)
---------------------------------------------------------------
Identity (Graph / ARM):
    "security_defaults"               – {"isEnabled": bool} or None
    "subscription"                    – subscription display info
    "role_definitions"                – list of role definition dicts
    "role_assignments"                – list of role assignment dicts at /subscriptions/<id>
    "classic_admins"                  – list of classic admin assignments

Storage:
    "storage_accounts"                – list of storage account dicts
    "storage_blob_services"           – {storage_account_id: blob_service_properties}
    "storage_file_services"           – {storage_account_id: file_service_properties}

Key Vault:
    "key_vaults"                      – list of key vault dicts
    "key_vault_diagnostic_settings"   – {vault_id: [diagnostic_setting_dicts]}

Networking:
    "network_security_groups"         – list of NSG dicts (with securityRules expanded)
    "network_watchers"                – list of network watcher dicts
    "flow_logs"                       – list of flow log dicts (across watchers)
    "public_ip_addresses"             – list of public IP dicts
    "bastion_hosts"                   – list of bastion host dicts
    "virtual_networks"                – list of VNet dicts
    "application_gateways"            – list of App Gateway dicts

Monitoring / Defender:
    "activity_log_diagnostic_settings" – list of subscription-level diagnostic settings
    "defender_pricings"                – list of Microsoft.Security/pricings dicts
    "security_contacts"                – list of Microsoft.Security/securityContacts dicts
    "security_auto_provisioning"       – list of auto-provisioning settings dicts
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from sspm.providers.azure.auth import AzureAuth
from sspm.providers.base import CollectedData

log = logging.getLogger(__name__)

ARM_ROOT = "https://management.azure.com"
GRAPH_ROOT = "https://graph.microsoft.com/v1.0"

# API versions. Pinned to stable GA where possible.
API_VERSIONS = {
    "subscription": "2022-12-01",
    "authorization": "2022-04-01",
    "authorization_classic": "2015-06-01",
    "storage": "2023-01-01",
    "keyvault": "2023-07-01",
    "network": "2023-09-01",
    "insights": "2021-05-01-preview",
    "security": "2023-01-01",
    "security_contacts": "2020-01-01-preview",
    "security_pricings": "2024-01-01",
}


class AzureCollector:
    """Fetches Azure configuration data for CIS benchmark evaluation."""

    def __init__(self, auth: AzureAuth, subscription_id: str) -> None:
        self._auth = auth
        self._subscription_id = subscription_id
        self._data: dict[str, Any] = {}
        self._errors: dict[str, str] = {}
        self._client: httpx.Client | None = None

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def collect(self, target: str) -> CollectedData:
        with httpx.Client(timeout=30.0) as client:
            self._client = client
            self._collect_all()
        return CollectedData(
            provider="azure",
            target=target,
            data=self._data,
            errors=self._errors,
        )

    def _collect_all(self) -> None:
        self._safe("security_defaults", self._collect_security_defaults)
        self._safe("subscription", self._collect_subscription)
        self._safe("role_definitions", self._collect_role_definitions)
        self._safe("role_assignments", self._collect_role_assignments)
        self._safe("classic_admins", self._collect_classic_admins)
        self._safe("storage_accounts", self._collect_storage_accounts)
        self._safe("storage_services", self._collect_storage_services)
        self._safe("key_vaults", self._collect_key_vaults)
        self._safe("key_vault_diagnostic_settings", self._collect_keyvault_diagnostics)
        self._safe("network_security_groups", self._collect_nsgs)
        self._safe("network_watchers", self._collect_network_watchers)
        self._safe("flow_logs", self._collect_flow_logs)
        self._safe("bastion_hosts", self._collect_bastion_hosts)
        self._safe("public_ip_addresses", self._collect_public_ips)
        self._safe("virtual_networks", self._collect_vnets)
        self._safe(
            "activity_log_diagnostic_settings",
            self._collect_activity_log_diagnostics,
        )
        self._safe("defender_pricings", self._collect_defender_pricings)
        self._safe("security_contacts", self._collect_security_contacts)

    def _safe(self, key: str, fn) -> None:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            log.warning("Azure collection failed for %s: %s", key, exc)
            self._errors[key] = str(exc)

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _arm_get(self, path: str, api_version: str) -> dict[str, Any]:
        url = f"{ARM_ROOT}{path}"
        params = {"api-version": api_version}
        resp = self._client.get(
            url, headers=self._auth.arm_headers(), params=params
        )
        resp.raise_for_status()
        return resp.json()

    def _arm_list(self, path: str, api_version: str) -> list[dict[str, Any]]:
        """GET *path* and follow ``nextLink`` pagination to return a flat list."""
        url = f"{ARM_ROOT}{path}"
        params: dict[str, Any] | None = {"api-version": api_version}
        items: list[dict[str, Any]] = []
        while url:
            resp = self._client.get(
                url, headers=self._auth.arm_headers(), params=params
            )
            resp.raise_for_status()
            body = resp.json()
            items.extend(body.get("value", []))
            url = body.get("nextLink")
            params = None  # nextLink already has api-version
        return items

    def _graph_get(self, path: str) -> dict[str, Any]:
        resp = self._client.get(
            f"{GRAPH_ROOT}{path}", headers=self._auth.graph_headers()
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Collectors
    # ------------------------------------------------------------------

    def _collect_security_defaults(self) -> None:
        body = self._graph_get("/policies/identitySecurityDefaultsEnforcementPolicy")
        self._data["security_defaults"] = body

    def _collect_subscription(self) -> None:
        body = self._arm_get(
            f"/subscriptions/{self._subscription_id}",
            API_VERSIONS["subscription"],
        )
        self._data["subscription"] = body

    def _collect_role_definitions(self) -> None:
        items = self._arm_list(
            f"/subscriptions/{self._subscription_id}"
            "/providers/Microsoft.Authorization/roleDefinitions",
            API_VERSIONS["authorization"],
        )
        self._data["role_definitions"] = items

    def _collect_role_assignments(self) -> None:
        items = self._arm_list(
            f"/subscriptions/{self._subscription_id}"
            "/providers/Microsoft.Authorization/roleAssignments",
            API_VERSIONS["authorization"],
        )
        self._data["role_assignments"] = items

    def _collect_classic_admins(self) -> None:
        items = self._arm_list(
            f"/subscriptions/{self._subscription_id}"
            "/providers/Microsoft.Authorization/classicAdministrators",
            API_VERSIONS["authorization_classic"],
        )
        self._data["classic_admins"] = items

    def _collect_storage_accounts(self) -> None:
        items = self._arm_list(
            f"/subscriptions/{self._subscription_id}"
            "/providers/Microsoft.Storage/storageAccounts",
            API_VERSIONS["storage"],
        )
        self._data["storage_accounts"] = items

    def _collect_storage_services(self) -> None:
        blob: dict[str, Any] = {}
        files: dict[str, Any] = {}
        for sa in self._data.get("storage_accounts", []):
            acct_id = sa.get("id", "")
            try:
                b = self._arm_get(
                    f"{acct_id}/blobServices/default",
                    API_VERSIONS["storage"],
                )
                blob[acct_id] = b
            except Exception as exc:  # noqa: BLE001
                log.debug("blobServices fetch failed for %s: %s", acct_id, exc)
            try:
                f = self._arm_get(
                    f"{acct_id}/fileServices/default",
                    API_VERSIONS["storage"],
                )
                files[acct_id] = f
            except Exception as exc:  # noqa: BLE001
                log.debug("fileServices fetch failed for %s: %s", acct_id, exc)
        self._data["storage_blob_services"] = blob
        self._data["storage_file_services"] = files

    def _collect_key_vaults(self) -> None:
        items = self._arm_list(
            f"/subscriptions/{self._subscription_id}"
            "/resources",
            API_VERSIONS["subscription"],
        )
        # Filter to just vaults, then re-fetch to get full properties
        vault_ids = [
            r["id"] for r in items
            if r.get("type", "").lower() == "microsoft.keyvault/vaults"
        ]
        vaults: list[dict[str, Any]] = []
        for vid in vault_ids:
            try:
                vaults.append(self._arm_get(vid, API_VERSIONS["keyvault"]))
            except Exception as exc:  # noqa: BLE001
                log.debug("Key Vault fetch failed for %s: %s", vid, exc)
        self._data["key_vaults"] = vaults

    def _collect_keyvault_diagnostics(self) -> None:
        diag: dict[str, list[dict[str, Any]]] = {}
        for vault in self._data.get("key_vaults", []):
            vid = vault.get("id", "")
            try:
                body = self._arm_list(
                    f"{vid}/providers/Microsoft.Insights/diagnosticSettings",
                    API_VERSIONS["insights"],
                )
                diag[vid] = body
            except Exception as exc:  # noqa: BLE001
                log.debug("diagnosticSettings fetch failed for %s: %s", vid, exc)
        self._data["key_vault_diagnostic_settings"] = diag

    def _collect_nsgs(self) -> None:
        items = self._arm_list(
            f"/subscriptions/{self._subscription_id}"
            "/providers/Microsoft.Network/networkSecurityGroups",
            API_VERSIONS["network"],
        )
        self._data["network_security_groups"] = items

    def _collect_network_watchers(self) -> None:
        items = self._arm_list(
            f"/subscriptions/{self._subscription_id}"
            "/providers/Microsoft.Network/networkWatchers",
            API_VERSIONS["network"],
        )
        self._data["network_watchers"] = items

    def _collect_flow_logs(self) -> None:
        all_flow_logs: list[dict[str, Any]] = []
        for watcher in self._data.get("network_watchers", []):
            wid = watcher.get("id", "")
            try:
                logs = self._arm_list(
                    f"{wid}/flowLogs", API_VERSIONS["network"]
                )
                all_flow_logs.extend(logs)
            except Exception as exc:  # noqa: BLE001
                log.debug("flowLogs fetch failed for %s: %s", wid, exc)
        self._data["flow_logs"] = all_flow_logs

    def _collect_bastion_hosts(self) -> None:
        items = self._arm_list(
            f"/subscriptions/{self._subscription_id}"
            "/providers/Microsoft.Network/bastionHosts",
            API_VERSIONS["network"],
        )
        self._data["bastion_hosts"] = items

    def _collect_public_ips(self) -> None:
        items = self._arm_list(
            f"/subscriptions/{self._subscription_id}"
            "/providers/Microsoft.Network/publicIPAddresses",
            API_VERSIONS["network"],
        )
        self._data["public_ip_addresses"] = items

    def _collect_vnets(self) -> None:
        items = self._arm_list(
            f"/subscriptions/{self._subscription_id}"
            "/providers/Microsoft.Network/virtualNetworks",
            API_VERSIONS["network"],
        )
        self._data["virtual_networks"] = items

    def _collect_activity_log_diagnostics(self) -> None:
        # Subscription-scoped diagnostic settings for Activity Logs
        items = self._arm_list(
            f"/subscriptions/{self._subscription_id}"
            "/providers/Microsoft.Insights/diagnosticSettings",
            API_VERSIONS["insights"],
        )
        self._data["activity_log_diagnostic_settings"] = items

    def _collect_defender_pricings(self) -> None:
        items = self._arm_list(
            f"/subscriptions/{self._subscription_id}"
            "/providers/Microsoft.Security/pricings",
            API_VERSIONS["security_pricings"],
        )
        self._data["defender_pricings"] = items

    def _collect_security_contacts(self) -> None:
        items = self._arm_list(
            f"/subscriptions/{self._subscription_id}"
            "/providers/Microsoft.Security/securityContacts",
            API_VERSIONS["security_contacts"],
        )
        self._data["security_contacts"] = items
