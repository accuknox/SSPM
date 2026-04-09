"""
Abstract base classes for providers and rules.

A *provider* connects to a SaaS platform, collects configuration data, and
exposes it as a ``CollectedData`` snapshot.  Rules consume that snapshot.

To add a new SaaS target (Salesforce, GitHub, etc.):
1. Subclass ``BaseProvider`` and implement ``collect()``.
2. Subclass ``BaseRule`` and implement ``check()``.
3. Call ``registry.register(rule_instance)`` or use ``@registry.rule``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from sspm.core.models import Finding, RuleMetadata


# ---------------------------------------------------------------------------
# Collected data
# ---------------------------------------------------------------------------


@dataclass
class CollectedData:
    """
    A provider-specific snapshot of the target's configuration state.

    The ``data`` dict is keyed by logical data-source names
    (e.g. ``"users"``, ``"conditional_access_policies"``).  Rules access
    exactly the keys they need; missing keys mean the data was not collected
    (e.g. insufficient permissions) and a rule should return SKIPPED.
    """

    provider: str
    target: str
    data: dict[str, Any] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)  # key → error message

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def has(self, key: str) -> bool:
        return key in self.data


# ---------------------------------------------------------------------------
# Base provider
# ---------------------------------------------------------------------------


class BaseProvider(ABC):
    """
    Abstract SaaS provider.

    Implementations handle authentication and data collection.
    """

    #: Short identifier used to filter rules, e.g. ``"ms365"``.
    provider_id: str = ""

    #: Human-readable name of the benchmark this provider maps to.
    benchmark: str = ""

    @property
    @abstractmethod
    def target(self) -> str:
        """Human-readable identifier of the scanned organisation/tenant."""

    @abstractmethod
    async def collect(self) -> CollectedData:
        """
        Connect to the SaaS platform, fetch all configuration data needed by
        the registered rules, and return a ``CollectedData`` snapshot.

        This method is called exactly once per scan.  Implementations should
        collect data eagerly (all at once) to minimise API round-trips.
        """


# ---------------------------------------------------------------------------
# Base rule
# ---------------------------------------------------------------------------


class BaseRule(ABC):
    """
    Abstract security rule.

    Subclasses must:
    * Set the ``metadata`` class attribute with a ``RuleMetadata`` instance.
    * Set the ``provider`` class attribute to match the provider ID.
    * Implement ``async def check(self, data: CollectedData) -> Finding``.
    """

    #: Must match ``BaseProvider.provider_id`` of the target provider.
    provider: str = ""

    #: Populated by the concrete rule class.
    metadata: RuleMetadata

    @abstractmethod
    async def check(self, data: CollectedData) -> Finding:
        """
        Evaluate this rule against the collected data snapshot.

        Always returns a ``Finding``; never raises (the engine wraps calls in
        a try/except and produces an ERROR finding on unexpected exceptions).
        """
