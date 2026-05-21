"""
Base class for all Azure CIS rules.

Provides convenience factory helpers (_pass, _fail, _manual, _skip, _error)
so individual rule bodies stay focused on evaluation logic.
"""

from __future__ import annotations

from sspm.core.models import Evidence, Finding, FindingStatus
from sspm.providers.base import BaseRule


class AzureRule(BaseRule):
    """Common base for all Azure CIS rules."""

    provider = "azure"

    # ------------------------------------------------------------------
    # Convenience factory methods
    # ------------------------------------------------------------------

    def _pass(
        self,
        message: str,
        resource_id: str = "",
        resource_type: str = "subscription",
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
        resource_type: str = "subscription",
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
        resource_type: str = "subscription",
    ) -> Finding:
        return Finding(
            rule=self.metadata,
            status=FindingStatus.MANUAL,
            resource_id=resource_id,
            resource_type=resource_type,
            message=message or "Manual review required — see audit procedure.",
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
