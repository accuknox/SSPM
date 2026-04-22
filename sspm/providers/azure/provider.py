"""
Azure provider.

Wires authentication, data collection, and rule discovery for scans of a
single Azure subscription against CIS Microsoft Azure Foundations
Benchmark v6.0.0.
"""

from __future__ import annotations

import logging

from sspm.providers.azure.auth import AzureAuth
from sspm.providers.azure.collector import AzureCollector
from sspm.providers.base import BaseProvider, CollectedData

log = logging.getLogger(__name__)

_BENCHMARK = "CIS Microsoft Azure Foundations Benchmark v6.0.0"


class AzureProvider(BaseProvider):
    """
    Provider for Azure subscription scanning.

    Parameters
    ----------
    tenant_id:
        Microsoft Entra tenant ID (GUID).
    client_id:
        App registration client ID.
    client_secret:
        App registration client secret.
    subscription_id:
        Azure subscription ID to scan.
    subscription_label:
        Optional human-readable label for reporting; defaults to the
        subscription display name (resolved via ARM) or the subscription ID.
    """

    provider_id = "azure"
    benchmark = _BENCHMARK

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        subscription_id: str,
        subscription_label: str = "",
    ) -> None:
        self._subscription_id = subscription_id
        self._label = subscription_label or subscription_id
        self._auth = AzureAuth(tenant_id, client_id, client_secret)
        self._collector = AzureCollector(self._auth, subscription_id)
        self._autodiscover()

    @property
    def target(self) -> str:
        return self._label

    async def collect(self) -> CollectedData:
        return await self._collector.collect(self._label)

    @staticmethod
    def _autodiscover() -> None:
        from sspm.core.registry import registry
        registry.autodiscover("sspm.providers.azure.rules")
