"""Tests for the core scan engine."""

import pytest

from sspm.core.engine import ScanEngine
from sspm.core.models import FindingStatus
from sspm.providers.base import BaseProvider, CollectedData


class FakeProvider(BaseProvider):
    provider_id = "ms365"
    benchmark = "CIS Microsoft 365 Foundations Benchmark v6.0.1"

    def __init__(self, data: dict):
        self._data = data

    @property
    def target(self) -> str:
        return "test.onmicrosoft.com"

    async def collect(self) -> CollectedData:
        return CollectedData(provider="ms365", target=self.target, data=self._data)


@pytest.fixture(autouse=True)
def _autodiscover():
    """Ensure MS365 rules are registered before tests run."""
    from sspm.providers.ms365.provider import MS365Provider
    MS365Provider._autodiscover()


@pytest.mark.asyncio
async def test_scan_returns_result_for_all_rules():
    provider = FakeProvider({})
    engine = ScanEngine(provider=provider)
    result = await engine.scan()

    assert result.target == "test.onmicrosoft.com"
    assert result.provider == "ms365"
    assert len(result.findings) > 0


@pytest.mark.asyncio
async def test_scan_filters_by_rule_id():
    provider = FakeProvider({})
    engine = ScanEngine(provider=provider, rule_ids=["ms365-cis-1.1.1"])
    result = await engine.scan()

    assert len(result.findings) == 1
    assert result.findings[0].rule.id == "ms365-cis-1.1.1"


@pytest.mark.asyncio
async def test_summary_counts():
    provider = FakeProvider({})
    engine = ScanEngine(provider=provider)
    result = await engine.scan()
    summary = result.summary()

    total = (
        summary["passed"]
        + summary["failed"]
        + summary["manual"]
        + summary["errors"]
        + summary["skipped"]
    )
    assert summary["total"] == total
