"""
Microsoft 365 provider.

Wires together authentication, data collection, and rule discovery.
"""

from __future__ import annotations

import logging

from sspm.providers.base import BaseProvider, CollectedData
from sspm.providers.ms365.auth import MS365Auth
from sspm.providers.ms365.collector import MS365Collector

log = logging.getLogger(__name__)

_BENCHMARK = "CIS Microsoft 365 Foundations Benchmark v6.0.1"


class MS365Provider(BaseProvider):
    """
    Provider for Microsoft 365 tenant scanning.

    Parameters
    ----------
    tenant_id:
        Entra ID (Azure AD) tenant identifier (GUID or domain).
    client_id:
        App registration client ID.
    client_secret:
        App registration client secret.
    tenant_domain:
        Human-readable tenant domain, e.g. ``contoso.onmicrosoft.com``.
        Used as the scan target label.
    """

    provider_id = "ms365"
    benchmark = _BENCHMARK

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        tenant_domain: str = "",
    ) -> None:
        self._tenant_domain = tenant_domain or tenant_id
        self._auth = MS365Auth(tenant_id, client_id, client_secret)
        self._collector = MS365Collector(self._auth)

        # Trigger rule auto-discovery on first provider instantiation
        self._autodiscover()

    @property
    def target(self) -> str:
        return self._tenant_domain

    async def collect(self) -> CollectedData:
        return await self._collector.collect(self._tenant_domain)

    @staticmethod
    def _autodiscover() -> None:
        """Import all rule modules so they self-register in the registry."""
        from sspm.core.registry import registry

        registry.autodiscover("sspm.providers.ms365.rules")
