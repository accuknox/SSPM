"""
Azure authentication via MSAL (app-only / client credentials).

Produces bearer tokens for two audiences used by the collector:

- ``https://management.azure.com/.default`` – Azure Resource Manager (ARM)
  control-plane APIs (subscriptions, resource groups, storage, key vault,
  network, security, role assignments).
- ``https://graph.microsoft.com/.default`` – Microsoft Graph (security
  defaults policy, directory role assignments).

The app registration requires the following permissions:

- ARM: an RBAC role on the subscription(s) in scope. ``Reader`` plus
  ``Security Reader`` on Microsoft Defender is sufficient for all automated
  Azure CIS checks.
- Graph (application): ``Policy.Read.All``, ``Directory.Read.All``,
  ``RoleManagement.Read.Directory`` (for security defaults + role reviews).
"""

from __future__ import annotations

import logging

import msal

log = logging.getLogger(__name__)

ARM_SCOPE = ["https://management.azure.com/.default"]
GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]


class AzureAuth:
    """Thin wrapper around MSAL ConfidentialClientApplication for Azure."""

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

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    def _acquire(self, scopes: list[str]) -> str:
        result = self._app.acquire_token_for_client(scopes=scopes)
        if "access_token" not in result:
            error = result.get("error_description", result.get("error", "unknown"))
            raise RuntimeError(
                f"Failed to acquire Azure token for {scopes[0]}: {error}"
            )
        return result["access_token"]

    def arm_token(self) -> str:
        return self._acquire(ARM_SCOPE)

    def graph_token(self) -> str:
        return self._acquire(GRAPH_SCOPE)

    def arm_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.arm_token()}"}

    def graph_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.graph_token()}"}
