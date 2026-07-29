"""
Microsoft 365 authentication via MSAL (app-only / client credentials).

The scanner uses an Entra ID (Azure AD) App Registration with the following
Microsoft Graph application permissions (admin consent required):

    User.Read.All
    RoleManagement.Read.Directory
    Policy.Read.All
    Directory.Read.All
    Reports.Read.All
    SecurityEvents.Read.All
    MailboxSettings.Read
    Organization.Read.All
    Application.Read.All
    AuditLog.Read.All
    IdentityRiskyUser.Read.All
    DeviceManagementConfiguration.Read.All
    TeamSettings.Read.All
    InformationProtectionPolicy.Read.All
    DelegatedPermissionGrant.ReadWrite.All  (read-only equivalent)

Exchange Online / SharePoint Online permissions require separate PowerShell
modules or certificate-based auth (see provider.py for details).
"""

from __future__ import annotations

import logging

import msal

log = logging.getLogger(__name__)

_GRAPH_SCOPE = "https://graph.microsoft.com/.default"

# Microsoft Fabric admin REST API (CIS section 9.1). Separate resource from
# Graph, so it needs its own token — see MS365Collector._get_fabric_tenant_settings.
FABRIC_SCOPE = "https://api.fabric.microsoft.com/.default"


class MS365Auth:
    """Thin wrapper around MSAL ConfidentialClientApplication."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
    ) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._app = msal.ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
        )
        self._token: str | None = None

    def get_token(self) -> str:
        """Return a valid Microsoft Graph access token, acquiring a new one if
        necessary."""
        self._token = self.get_token_for_scope(_GRAPH_SCOPE, "MS Graph")
        return self._token

    def get_token_for_scope(self, scope: str, label: str = "") -> str:
        """Return an app-only access token for an arbitrary resource scope.

        MSAL caches per-scope, so repeated calls are cheap. Used for resources
        outside Microsoft Graph (e.g. the Fabric admin REST API), which need a
        token issued for their own audience.
        """
        result = self._app.acquire_token_for_client(scopes=[scope])
        if "access_token" not in result:
            error = result.get("error_description", result.get("error", "unknown"))
            raise RuntimeError(
                f"Failed to acquire {label or scope} token: {error}"
            )
        return result["access_token"]

    @property
    def bearer_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.get_token()}"}
