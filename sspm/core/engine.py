"""
Scan engine.

The engine coordinates data collection and rule evaluation for a single
provider.  It is intentionally thin – all intelligence lives in the
provider's collector and individual rules.

Flow
----
1. ``engine.scan()`` is called with an optional profile filter.
2. The provider's ``collect()`` method is called once; it returns a
   ``CollectedData`` snapshot of the target environment.
3. Each registered rule for the provider is evaluated against that snapshot.
4. A ``ScanResult`` is built from the findings and returned.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sspm.core.models import Evidence, Finding, FindingStatus, ScanResult
from sspm.core.registry import registry

log = logging.getLogger(__name__)


class ScanEngine:
    """
    Provider-agnostic scan orchestrator.

    Parameters
    ----------
    provider:
        An initialised provider instance (e.g. ``MS365Provider``).
    profile_filter:
        When given, only rules that include this profile are evaluated.
        Accepted values: "E3 Level 1", "E3 Level 2", "E5 Level 1", "E5 Level 2".
    rule_ids:
        When given, only the listed rule IDs are evaluated.
    """

    def __init__(
        self,
        provider,
        profile_filter: str | None = None,
        rule_ids: list[str] | None = None,
    ) -> None:
        self.provider = provider
        self.profile_filter = profile_filter
        self.rule_ids = rule_ids

    async def scan(self) -> ScanResult:
        result = ScanResult(
            target=self.provider.target,
            provider=self.provider.provider_id,
            benchmark=self.provider.benchmark,
        )

        # --- Select rules ---
        if self.rule_ids:
            rules = [r for rid in self.rule_ids if (r := registry.get(rid))]
        elif self.profile_filter:
            rules = registry.rules_for_profile(self.profile_filter)
            rules = [r for r in rules if r.provider == self.provider.provider_id]
        else:
            rules = registry.rules_for_provider(self.provider.provider_id)

        if not rules:
            log.warning("No rules matched the selection criteria.")
            result.completed_at = datetime.now(timezone.utc).isoformat()
            return result

        log.info("Collecting data from %s …", self.provider.target)
        collected = await self.provider.collect()

        log.info("Evaluating %d rules …", len(rules))
        for rule in rules:
            try:
                finding = await rule.check(collected)
            except Exception as exc:  # noqa: BLE001
                log.exception("Rule %s raised an error", rule.metadata.id)
                finding = Finding(
                    rule=rule.metadata,
                    status=FindingStatus.ERROR,
                    message=f"Rule evaluation failed: {exc}",
                    evidence=[Evidence(source="engine", data=str(exc))],
                )
            result.findings.append(finding)

        result.completed_at = datetime.now(timezone.utc).isoformat()
        summary = result.summary()
        log.info(
            "Scan complete – pass=%d fail=%d manual=%d error=%d skipped=%d",
            summary["passed"],
            summary["failed"],
            summary["manual"],
            summary["errors"],
            summary["skipped"],
        )
        return result
