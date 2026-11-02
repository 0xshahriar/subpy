"""Shared data model for discovered hosts.

One :class:`Host` travels through the whole pipeline: passive sources create
them, the resolver enriches them, the wildcard manager may veto them, and
the writers serialise them. Keeping enrichment on the object (rather than in
parallel dicts) is what keeps the reporters simple.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

__all__ = ["Host", "ScanSummary", "SOURCE_PASSIVE", "SOURCE_ACTIVE", "SOURCE_PERMUTATION"]

SOURCE_PASSIVE = "passive"
SOURCE_ACTIVE = "active"
SOURCE_PERMUTATION = "permutation"


@dataclass
class Host:
    """A single discovered hostname and everything learned about it."""

    name: str
    sources: set[str] = field(default_factory=set)

    # Resolution state. ``None`` means "not attempted", ``False`` means
    # "definitively does not resolve".
    resolved: bool | None = None
    addresses: list[str] = field(default_factory=list)
    addresses_v6: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    ttl: int = 0
    rcode: str = ""
    error: str = ""

    # Bookkeeping
    first_seen: float = field(default_factory=time.time)
    latency_ms: float = 0.0
    wildcard: bool = False
    wildcard_reason: str = ""

    # A name that resolves to a CNAME whose target does not resolve is a
    # subdomain-takeover candidate: whoever registers that target inherits
    # this hostname. We report it, because it is the single most actionable
    # thing a subdomain scan can surface.
    dangling: bool = False
    takeover_hint: str = ""

    # Annotations produced by optional enrichers
    http_status: int | None = None
    http_title: str = ""
    server: str = ""
    tech: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return self.name.split(".", 1)[0]

    @property
    def depth(self) -> int:
        return self.name.count(".") + 1

    @property
    def ip(self) -> str:
        """Primary address, for display in a single column."""
        if self.addresses:
            return self.addresses[0]
        if self.addresses_v6:
            return self.addresses_v6[0]
        return ""

    @property
    def all_addresses(self) -> list[str]:
        return list(self.addresses) + list(self.addresses_v6)

    def add_source(self, source: str) -> None:
        if source:
            self.sources.add(source)

    def add_address(self, value: str) -> None:
        if not value:
            return
        bucket = self.addresses_v6 if ":" in value else self.addresses
        if value not in bucket:
            bucket.append(value)

    def add_cname(self, value: str) -> None:
        value = (value or "").lower().rstrip(".")
        if value and value not in self.cnames:
            self.cnames.append(value)

    def to_dict(self) -> dict:
        """JSON-friendly representation (stable key order)."""
        return {
            "host": self.name,
            "sources": sorted(self.sources),
            "resolved": self.resolved,
            "alive": self.resolved is True,
            "ip": self.addresses,
            "ipv6": self.addresses_v6,
            "cname": self.cnames,
            "ttl": self.ttl,
            "rcode": self.rcode,
            "latency_ms": round(self.latency_ms, 2),
            "wildcard": self.wildcard,
            "dangling": self.dangling,
            "takeover_hint": self.takeover_hint,
            "http_status": self.http_status,
            "http_title": self.http_title,
            "server": self.server,
            "tech": self.tech,
            "error": self.error,
        }


@dataclass
class ScanSummary:
    """Aggregate statistics for the end-of-run report."""

    domain: str = ""
    started: float = field(default_factory=time.time)
    finished: float = 0.0
    candidates: int = 0
    resolved: int = 0
    wildcard_filtered: int = 0
    passive_found: int = 0
    active_found: int = 0
    permutation_found: int = 0
    queries: int = 0
    dns_seconds: float = 0.0
    source_errors: list[str] = field(default_factory=list)
    skipped_sources: list[str] = field(default_factory=list)
    resolver_stats: dict[str, int] = field(default_factory=dict)
    wildcard_levels: int = 0
    interrupted: bool = False

    @property
    def elapsed(self) -> float:
        end = self.finished or time.time()
        return max(0.0, end - self.started)

    @property
    def qps(self) -> float:
        """Resolver throughput.

        Measured against time actually spent querying, not wall-clock: a scan
        that waits 13s on a slow HTTP source is not a 20 qps scan.
        """
        seconds = self.dns_seconds or self.elapsed
        return (self.queries / seconds) if seconds > 0.2 else 0.0

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "elapsed_seconds": round(self.elapsed, 2),
            "candidates": self.candidates,
            "resolved": self.resolved,
            "wildcard_filtered": self.wildcard_filtered,
            "passive_found": self.passive_found,
            "active_found": self.active_found,
            "permutation_found": self.permutation_found,
            "queries": self.queries,
            "queries_per_second": round(self.qps, 1),
            "dns_seconds": round(self.dns_seconds, 2),
            "wildcard_levels": self.wildcard_levels,
            "source_errors": self.source_errors,
            "skipped_sources": self.skipped_sources,
            "resolver": self.resolver_stats,
            "interrupted": self.interrupted,
        }
