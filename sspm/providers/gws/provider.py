"""
Google Workspace provider.

Wires together authentication, data collection, and rule discovery.
"""

from __future__ import annotations

import logging
from typing import Any

from sspm.providers.base import BaseProvider, CollectedData
from sspm.providers.gws.auth import GWSAuth
from sspm.providers.gws.collector import GWSCollector

log = logging.getLogger(__name__)

_BENCHMARK = "CIS Google Workspace Foundations Benchmark v1.3.0"


class GWSProvider(BaseProvider):
    """
    Provider for Google Workspace tenant scanning.

    Parameters
    ----------
    service_account_key:
        Path to a Google Cloud service account JSON key file, or the parsed
        key dict.  The service account must have domain-wide delegation enabled
        and be authorised in the Google Workspace Admin Console.
    admin_email:
        Email address of a super administrator to impersonate.
        The service account uses domain-wide delegation to act on behalf of
        this user when calling Admin SDK APIs.
    customer_domain:
        Primary domain of the Google Workspace organisation, e.g.
        ``example.com``.  Used as the scan target label.
    """

    provider_id = "gws"
    benchmark = _BENCHMARK

    def __init__(
        self,
        service_account_key: str | dict[str, Any],
        admin_email: str,
        customer_domain: str = "",
    ) -> None:
        self._admin_email = admin_email
        self._customer_domain = customer_domain or admin_email.split("@")[-1]
        self._auth = GWSAuth(service_account_key, admin_email)
        self._collector = GWSCollector(self._auth)
        self._autodiscover()

    @property
    def target(self) -> str:
        return self._customer_domain

    async def collect(self) -> CollectedData:
        return await self._collector.collect(self._customer_domain)

    @staticmethod
    def _autodiscover() -> None:
        from sspm.core.registry import registry

        registry.autodiscover("sspm.providers.gws.rules")
