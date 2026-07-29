"""MANUAL is reserved for the controls CIS itself classifies as Manual.

The CIS Microsoft 365 Foundations Benchmark v6.0.1 marks exactly 11 of its 140
recommendations "(Manual)" in the body of the document. (Its Appendix: Summary
Table also marks the twelve Microsoft Fabric controls 9.1.1–9.1.12 Manual, but
each of those controls' own heading and audit procedure says Automated; the
body wins — see the note in cis_9_1_1.py.)

Everything else is Automated and must resolve to PASS or FAIL when its data was
collected, and to SKIPPED when it was not. A rule that answers MANUAL because
its data source was unavailable inflates the manual count and hides the fact
that the control was never actually evaluated.
"""

import inspect

import pytest

from sspm.core.models import AssessmentStatus, FindingStatus
from sspm.core.registry import registry
from sspm.providers.base import CollectedData

registry.autodiscover("sspm.providers.ms365.rules")
MS365_RULES = registry.rules_for_provider("ms365")

# The 11 "(Manual)" recommendations in the benchmark body.
CIS_MANUAL_CONTROLS = {
    "ms365-cis-1.1.2",    # Two emergency access accounts have been defined
    "ms365-cis-1.3.8",    # Sways cannot be shared outside the organization
    "ms365-cis-2.2.1",    # Emergency access account activity is monitored
    "ms365-cis-2.4.3",    # Microsoft Defender for Cloud Apps is enabled
    "ms365-cis-5.1.2.4",  # Access to the Entra admin center is restricted
    "ms365-cis-5.1.2.5",  # The option to remain signed in is hidden
    "ms365-cis-5.1.2.6",  # 'LinkedIn account connections' is disabled
    "ms365-cis-5.1.8.1",  # Password hash sync is enabled for hybrid
    "ms365-cis-5.2.4.1",  # 'Self service password reset enabled' is 'All'
    "ms365-cis-7.2.8",    # External sharing is restricted by security group
    "ms365-cis-8.4.1",    # App permission policies are configured
}


def _rule_source(rule) -> str:
    cls = type(rule) if not isinstance(rule, type) else rule
    return inspect.getsource(cls)


def test_manual_assessment_matches_the_benchmark():
    declared = {
        r.metadata.id
        for r in MS365_RULES
        if r.metadata.assessment_status is AssessmentStatus.MANUAL
    }
    assert declared == CIS_MANUAL_CONTROLS


def test_only_manual_controls_can_return_a_manual_finding():
    """Statically: `_manual()` may only be called by a MANUAL-assessment rule.

    Catches the regression at the call site, including branches that a given
    tenant's data would not happen to reach.
    """
    offenders = sorted(
        r.metadata.id
        for r in MS365_RULES
        if r.metadata.assessment_status is not AssessmentStatus.MANUAL
        and "self._manual(" in _rule_source(r)
    )
    assert offenders == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "snapshot",
    [
        pytest.param({}, id="nothing-collected"),
        pytest.param(None, id="every-key-present-but-none"),
    ],
)
async def test_automated_rules_skip_rather_than_go_manual(snapshot):
    """Behaviourally: with no usable data, an Automated rule must not answer
    MANUAL, and whatever it does answer must carry an explanation."""
    if snapshot is None:
        keys = set()
        for rule in MS365_RULES:
            keys.update(
                m.group(1)
                for m in __import__("re").finditer(
                    r'data\.get\("([^"]+)"\)', _rule_source(rule)
                )
            )
        snapshot = dict.fromkeys(keys)

    data = CollectedData(
        provider="ms365", target="test.onmicrosoft.com", data=snapshot, errors={}
    )

    for rule in MS365_RULES:
        finding = await rule.check(data)
        if rule.metadata.assessment_status is AssessmentStatus.MANUAL:
            continue
        assert finding.status is not FindingStatus.MANUAL, (
            f"{rule.metadata.id} answered MANUAL with no data available; "
            "an Automated control that could not be evaluated is SKIPPED"
        )
        assert finding.message, f"{rule.metadata.id} gave no reason for its verdict"
