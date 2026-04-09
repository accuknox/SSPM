"""
Google Workspace data collector.

Fetches configuration snapshots from the Google Admin SDK Directory API,
Reports API, and Alert Center API.  DNS records (SPF, DKIM, DMARC) are
probed via the dns.google DoH endpoint.

Data keys (used by rules via ``CollectedData.get("<key>")``)
------------------------------------------------------------
Admin Directory API:
    "domains"               – verified domains for the customer
    "users"                 – all user accounts (id, email, isAdmin, 2SV)
    "super_admins"          – users where isAdmin=True
    "org_units"             – organisational units
    "two_sv_enforcement"    – per-OU 2SV enforcement policy (best-effort)

Alert Center API:
    "alert_rules"           – alert policies/rules configured in the tenant

DNS (per domain, keyed by domain name):
    "dns_spf"               – {domain: spf_record_or_None}
    "dns_dkim"              – {domain: dkim_txt_record_or_None}  (google._domainkey)
    "dns_dmarc"             – {domain: dmarc_record_or_None}

Stubs (no API available, rules return MANUAL):
    All Google Workspace Admin Console settings (Calendar, Drive, Gmail, etc.)
    are not accessible via any public API — rules for those controls return
    MANUAL findings pointing auditors to the Admin Console.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from sspm.providers.base import CollectedData
from sspm.providers.gws.auth import GWSAuth

log = logging.getLogger(__name__)

_DIRECTORY = "https://admin.googleapis.com/admin/directory/v1"
_REPORTS = "https://admin.googleapis.com/admin/reports/v1"
_ALERTS = "https://alertcenter.googleapis.com/v1beta1"
_DNS_DOH = "https://dns.google/resolve"


class GWSCollector:
    """
    Fetches Google Workspace tenant configuration data.

    Each ``_collect_*`` method fetches one logical data set and stores it in
    ``self._data``.  Errors are stored in ``self._errors`` so individual
    failures do not abort the entire scan.
    """

    def __init__(self, auth: GWSAuth) -> None:
        self._auth = auth
        self._data: dict[str, Any] = {}
        self._errors: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def collect(self, customer_domain: str) -> CollectedData:
        self._customer_domain = customer_domain
        async with httpx.AsyncClient(timeout=60) as client:
            self._client = client
            await self._collect_all()

        return CollectedData(
            provider="gws",
            target=customer_domain,
            data=self._data,
            errors=self._errors,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _get(self, url: str, params: dict | None = None) -> dict | list | None:
        """GET a paginated API endpoint; follow nextPageToken automatically."""
        headers = await self._auth.bearer_header_async()
        results: list[dict] = []
        page_token: str | None = None

        while True:
            p = dict(params or {})
            if page_token:
                p["pageToken"] = page_token

            resp = await self._client.get(url, headers=headers, params=p if p else None)
            resp.raise_for_status()
            body = resp.json()

            # Collections with a "users", "domains", "alerts" etc. key
            for list_key in ("users", "domains", "orgUnits", "alerts",
                             "items", "usageReports", "activities"):
                if list_key in body:
                    results.extend(body[list_key])
                    break
            else:
                # Single-object response
                return body

            page_token = body.get("nextPageToken")
            if not page_token:
                break

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
    # Collection orchestration
    # ------------------------------------------------------------------

    async def _collect_all(self) -> None:
        await self._safe_collect("domains", self._get_domains())
        await self._safe_collect("users", self._get_users())
        await self._safe_collect("super_admins", self._get_super_admins())
        await self._safe_collect("org_units", self._get_org_units())
        await self._safe_collect("alert_rules", self._get_alert_rules())
        await self._safe_collect("dns_spf", self._get_dns_spf())
        await self._safe_collect("dns_dkim", self._get_dns_dkim())
        await self._safe_collect("dns_dmarc", self._get_dns_dmarc())

    # ------------------------------------------------------------------
    # Individual collectors
    # ------------------------------------------------------------------

    async def _get_domains(self) -> list:
        result = await self._get(
            f"{_DIRECTORY}/customer/my_customer/domains",
            params={"fields": "domains(domainName,verified,isPrimary,creationTime)"},
        )
        return result if isinstance(result, list) else []

    async def _get_users(self) -> list:
        """Fetch all users with fields needed by Section 1 and Section 4 rules."""
        result = await self._get(
            f"{_DIRECTORY}/users",
            params={
                "customer": "my_customer",
                "maxResults": 500,
                "projection": "basic",
                "fields": (
                    "users(id,primaryEmail,name,isAdmin,isDelegatedAdmin,"
                    "isEnrolledIn2Sv,isEnforcedIn2Sv,suspended,archived,"
                    "lastLoginTime,creationTime),"
                    "nextPageToken"
                ),
            },
        )
        return result if isinstance(result, list) else []

    async def _get_super_admins(self) -> list:
        """Fetch users where isAdmin=True."""
        result = await self._get(
            f"{_DIRECTORY}/users",
            params={
                "customer": "my_customer",
                "query": "isAdmin=True",
                "maxResults": 500,
                "projection": "basic",
                "fields": "users(id,primaryEmail,name,isAdmin,lastLoginTime),nextPageToken",
            },
        )
        return result if isinstance(result, list) else []

    async def _get_org_units(self) -> list:
        result = await self._get(
            f"{_DIRECTORY}/customer/my_customer/orgunits",
            params={"type": "all"},
        )
        if isinstance(result, dict):
            return result.get("organizationUnits", [])
        return result if isinstance(result, list) else []

    async def _get_alert_rules(self) -> list:
        """
        Fetch alert rules from the Alert Center API.
        These correspond to the configured alert policies checked by Section 6 rules.
        """
        try:
            result = await self._get(f"{_ALERTS}/alerts", params={"pageSize": 100})
            return result if isinstance(result, list) else []
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (403, 404):
                # Alert Center may not be enabled or scope not granted
                log.warning("Alert Center API unavailable: %s", exc.response.status_code)
                return []
            raise

    # ------------------------------------------------------------------
    # DNS collectors (DoH via dns.google)
    # ------------------------------------------------------------------

    async def _dns_query(self, name: str, rtype: str) -> list[str]:
        """Query dns.google DoH and return TXT record strings."""
        try:
            resp = await self._client.get(
                _DNS_DOH,
                params={"name": name, "type": rtype},
                headers={"Accept": "application/dns-json"},
            )
            if resp.status_code == 200:
                body = resp.json()
                return [
                    ans.get("data", "").strip('"')
                    for ans in body.get("Answer", [])
                    if ans.get("type") == 16  # TXT
                ]
        except Exception as exc:  # noqa: BLE001
            log.debug("DNS query %s %s failed: %s", rtype, name, exc)
        return []

    async def _get_primary_domain(self) -> str:
        """Return the primary verified domain for the customer."""
        domains = self._data.get("domains", [])
        for d in domains:
            if d.get("isPrimary") and d.get("verified"):
                return d["domainName"]
        return self._customer_domain

    async def _get_all_verified_domains(self) -> list[str]:
        """Return all verified domains."""
        domains = self._data.get("domains", [])
        verified = [d["domainName"] for d in domains if d.get("verified")]
        return verified or [self._customer_domain]

    async def _get_dns_spf(self) -> dict[str, str | None]:
        """Check SPF TXT records for all verified domains."""
        result: dict[str, str | None] = {}
        for domain in await self._get_all_verified_domains():
            records = await self._dns_query(domain, "TXT")
            spf = next((r for r in records if r.startswith("v=spf1")), None)
            result[domain] = spf
        return result

    async def _get_dns_dkim(self) -> dict[str, str | None]:
        """
        Check Google DKIM TXT record (google._domainkey.<domain>) for all
        verified domains.
        """
        result: dict[str, str | None] = {}
        for domain in await self._get_all_verified_domains():
            records = await self._dns_query(f"google._domainkey.{domain}", "TXT")
            dkim = next((r for r in records if r.startswith("v=DKIM1")), None)
            result[domain] = dkim
        return result

    async def _get_dns_dmarc(self) -> dict[str, str | None]:
        """Check DMARC TXT records (_dmarc.<domain>) for all verified domains."""
        result: dict[str, str | None] = {}
        for domain in await self._get_all_verified_domains():
            records = await self._dns_query(f"_dmarc.{domain}", "TXT")
            dmarc = next((r for r in records if r.startswith("v=DMARC1")), None)
            result[domain] = dmarc
        return result
