"""
Base class for all AWS CIS rules.

Provides convenience helpers (_pass, _fail, _manual, _skip, _error) and a
shared helper for Section 3 monitoring checks (metric filter + alarm + SNS).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from sspm.core.models import Evidence, Finding, FindingStatus
from sspm.providers.base import BaseRule, CollectedData


class AWSRule(BaseRule):
    """Common base for all AWS CIS rules."""

    provider = "aws"

    # ------------------------------------------------------------------
    # Convenience factory methods
    # ------------------------------------------------------------------

    def _pass(
        self,
        message: str,
        resource_id: str = "",
        resource_type: str = "account",
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
        resource_type: str = "account",
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
        resource_type: str = "account",
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

    # ------------------------------------------------------------------
    # Shared helper for Section 3 monitoring rules
    # ------------------------------------------------------------------

    def _check_monitoring_rule(
        self,
        data: CollectedData,
        filter_pattern_keywords: list[str],
        rule_description: str,
    ) -> Finding:
        """
        Check that:
        1. There is at least one active multi-region CloudTrail with CloudWatch Logs.
        2. The CloudWatch log group has a metric filter containing all *filter_pattern_keywords*.
        3. An alarm exists on the metric defined by that filter.
        4. The alarm's SNS topic has at least one active subscription.

        Returns a PASS/FAIL Finding.
        """
        trails = data.get("cloudtrail_trails", [])
        metric_filters = data.get("cloudwatch_metric_filters", {})
        alarms = data.get("cloudwatch_alarms", [])
        sns_subscriptions = data.get("sns_subscriptions", {})

        # Step 1: find an active multi-region trail with CloudWatch Logs
        qualified_log_group: str | None = None
        for trail in trails:
            if not trail.get("IsMultiRegionTrail"):
                continue
            status = trail.get("_status", {})
            if not status.get("IsLogging"):
                continue
            selectors = trail.get("_event_selectors", [])
            has_mgmt = any(
                s.get("IncludeManagementEvents") and s.get("ReadWriteType") == "All"
                for s in selectors
            )
            if not has_mgmt:
                continue
            log_group_arn = trail.get("CloudWatchLogsLogGroupArn", "")
            if log_group_arn:
                # Extract log group name from ARN
                # arn:aws:logs:<region>:<account>:log-group:<name>:*
                parts = log_group_arn.split(":")
                if len(parts) >= 7:
                    qualified_log_group = parts[6]
                    break

        if not qualified_log_group:
            return self._fail(
                f"No active multi-region CloudTrail with CloudWatch Logs and all management "
                f"events found. Cannot verify {rule_description}.",
            )

        # Step 2: find a metric filter matching all keywords
        matched_metric: str | None = None
        filters_for_group = metric_filters.get(qualified_log_group, [])
        for f in filters_for_group:
            pattern = f.get("filterPattern", "")
            if all(kw.lower() in pattern.lower() for kw in filter_pattern_keywords):
                transformations = f.get("metricTransformations", [])
                if transformations:
                    matched_metric = transformations[0].get("metricName")
                    break

        if not matched_metric:
            return self._fail(
                f"No CloudWatch metric filter matching {rule_description} found on log group "
                f"'{qualified_log_group}'.",
                evidence=[Evidence(
                    source="logs:DescribeMetricFilters",
                    data={"log_group": qualified_log_group, "filters_found": len(filters_for_group)},
                )],
            )

        # Step 3: find an alarm on the metric
        matched_alarm = next(
            (a for a in alarms if a.get("MetricName") == matched_metric), None
        )
        if not matched_alarm:
            return self._fail(
                f"No CloudWatch alarm found for metric '{matched_metric}' "
                f"(filter: {rule_description}).",
            )

        # Step 4: check SNS subscription
        alarm_actions = matched_alarm.get("AlarmActions", [])
        has_active_sub = False
        for action_arn in alarm_actions:
            subs = sns_subscriptions.get(action_arn, [])
            if any(
                s.get("SubscriptionArn", "").startswith("arn:aws:sns:")
                for s in subs
            ):
                has_active_sub = True
                break

        if not has_active_sub:
            return self._fail(
                f"CloudWatch alarm '{matched_alarm.get('AlarmName')}' for {rule_description} "
                f"has no active SNS subscriptions.",
            )

        return self._pass(
            f"Metric filter and alarm with active SNS subscription exist for {rule_description}.",
            evidence=[Evidence(
                source="cloudwatch:DescribeAlarms",
                data={"alarm_name": matched_alarm.get("AlarmName"), "metric": matched_metric},
            )],
        )
