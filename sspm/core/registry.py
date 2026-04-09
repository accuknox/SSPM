"""
Rule registry.

Rules self-register by calling ``registry.register(rule_instance)`` or
by using the ``@registry.rule`` class decorator.  The engine resolves
all rules for a given provider at scan time.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sspm.providers.base import BaseRule


class RuleRegistry:
    """Central catalogue of all loaded rules, keyed by rule ID."""

    def __init__(self) -> None:
        self._rules: dict[str, "BaseRule"] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, rule: "BaseRule") -> None:
        rid = rule.metadata.id
        if rid in self._rules:
            raise ValueError(f"Duplicate rule ID: {rid!r}")
        self._rules[rid] = rule

    def rule(self, cls: type) -> type:
        """Class decorator that instantiates and registers a rule."""
        self.register(cls())
        return cls

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get(self, rule_id: str) -> "BaseRule | None":
        return self._rules.get(rule_id)

    def all_rules(self) -> list["BaseRule"]:
        return list(self._rules.values())

    def rules_for_provider(self, provider: str) -> list["BaseRule"]:
        return [r for r in self._rules.values() if r.provider == provider]

    def rules_for_profile(self, profile: str) -> list["BaseRule"]:
        from sspm.core.models import CISProfile

        target = CISProfile(profile)
        return [r for r in self._rules.values() if target in r.metadata.profiles]

    # ------------------------------------------------------------------
    # Auto-discovery
    # ------------------------------------------------------------------

    def autodiscover(self, package: str) -> None:
        """
        Recursively import every module under *package* so that rule classes
        decorated with ``@registry.rule`` get registered automatically.

        Usage::

            registry.autodiscover("sspm.providers.ms365.rules")
        """
        pkg = importlib.import_module(package)
        if not hasattr(pkg, "__path__"):
            return  # not a package

        for _finder, name, _ispkg in pkgutil.walk_packages(
            pkg.__path__, prefix=package + "."
        ):
            importlib.import_module(name)


# Singleton used across the application
registry = RuleRegistry()
