"""
Base class for all Google Workspace rules.

Provides convenience helpers identical to the MS365 base so concrete rules
stay concise.
"""

from __future__ import annotations

from sspm.core.models import Evidence, Finding, FindingStatus
from sspm.providers.base import BaseRule, CollectedData


class GWSRule(BaseRule):
    """Common base for all GWS CIS rules."""

    provider = "gws"

    # ------------------------------------------------------------------
    # Convenience factory methods
    # ------------------------------------------------------------------

    def _pass(
        self,
        message: str,
        resource_id: str = "",
        resource_type: str = "tenant",
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
        resource_type: str = "tenant",
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
        resource_type: str = "tenant",
    ) -> Finding:
        return Finding(
            rule=self.metadata,
            status=FindingStatus.MANUAL,
            resource_id=resource_id,
            resource_type=resource_type,
            message=message or self.metadata.audit_procedure,
            remediation_guidance=self.metadata.remediation,
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
