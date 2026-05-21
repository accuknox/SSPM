"""Shared helpers for NSG inbound-rule evaluation (Sections 7.1–7.4)."""
from __future__ import annotations

from typing import Iterable


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


_INTERNET_SOURCES = {"*", "0.0.0.0/0", "internet", "any"}


def _ports_include(port_value: str, target_port: int) -> bool:
    """Return True if *port_value* (may be ``*``, a single port, or ``a-b``) covers *target_port*."""
    if not port_value:
        return False
    port_value = str(port_value).strip()
    if port_value in ("*", ""):
        return True
    if "-" in port_value:
        try:
            lo, hi = port_value.split("-", 1)
            return int(lo) <= target_port <= int(hi)
        except ValueError:
            return False
    try:
        return int(port_value) == target_port
    except ValueError:
        return False


def find_offending_nsgs(
    nsgs: Iterable[dict],
    target_port: int,
    protocols: tuple[str, ...] = ("tcp", "*"),
) -> list[str]:
    """Return names of NSGs whose inbound rules allow the Internet to reach *target_port*."""
    offenders: list[str] = []
    for nsg in nsgs:
        name = nsg.get("name") or nsg.get("id", "")
        rules = nsg.get("properties", {}).get("securityRules", []) or []
        for rule in rules:
            p = rule.get("properties", rule)
            if (p.get("access") or "").lower() != "allow":
                continue
            if (p.get("direction") or "").lower() != "inbound":
                continue
            proto = (p.get("protocol") or "").lower()
            if proto not in protocols:
                continue
            # Source must cover the Internet
            sources: list[str] = []
            sources += _as_list(p.get("sourceAddressPrefix"))
            sources += _as_list(p.get("sourceAddressPrefixes"))
            if not any((s or "").lower() in _INTERNET_SOURCES for s in sources):
                continue
            # Port must cover target_port
            port_values: list[str] = []
            port_values += _as_list(p.get("destinationPortRange"))
            port_values += _as_list(p.get("destinationPortRanges"))
            if any(_ports_include(pv, target_port) for pv in port_values):
                offenders.append(name)
                break
    return offenders
