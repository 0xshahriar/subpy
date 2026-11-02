"""Identify authoritative nameservers so they are not reported as subdomains.

A domain's own nameservers usually live *inside* the domain: hackerone.com is
served by ``a.ns.hackerone.com`` and ``b.ns.hackerone.com``. Those names
resolve, so every enumeration technique finds them, and reporting them as
discovered subdomains is noise: they are the delegation itself, not hosts the
owner put on the internet.

Two sources feed the index:

* the delegation -- the **NS RRset** of the target (and of any subzone met
  during the scan), which is authoritative and cheap (one query); and
* the **SOA MNAME**, which names the primary server and occasionally differs
  from the NS set.

The test is exact set membership, never a pattern. A host is excluded only
when the domain's own delegation names it. ``ns1.example.com`` that is *not*
in the NS RRset is a legitimate host and is kept -- guessing from the label
would delete real infrastructure.
"""

from __future__ import annotations

from collections.abc import Iterable

__all__ = ["NameserverIndex"]


class NameserverIndex:
    """The set of names that serve DNS for the scanned domain."""

    def __init__(self, domain: str, *, enabled: bool = True) -> None:
        self.domain = domain
        self.enabled = enabled
        self._names: set[str] = set()
        self.skipped: list[str] = []

    # -- population -------------------------------------------------------
    def add(self, name: str | None) -> bool:
        """Record one nameserver name. Returns True when it was new."""
        if not name or not self.enabled:
            return False
        name = name.strip().lower().rstrip(".")
        if not name or "." not in name:
            return False
        if name in self._names:
            return False
        # Only names inside the scanned domain can collide with a reported
        # subdomain, but out-of-zone servers are recorded too: they are still
        # part of the delegation and cost nothing to hold.
        self._names.add(name)
        return True

    def extend(self, names: Iterable[str | None]) -> None:
        for name in names:
            self.add(name)

    def add_from_message(self, msg) -> None:  # noqa: ANN001 - DNSMessage
        """Harvest NS and SOA records from any section of a response.

        Authority sections carry the parent's delegation, which is exactly
        how a subzone's nameservers reveal themselves during a scan.
        """
        if msg is None or not self.enabled:
            return
        for section in (msg.answers, msg.authority, msg.additional):
            for rr in section:
                if rr.rtype == 2 and rr.target or rr.rtype == 6 and rr.target:  # NS
                    self.add(rr.target)

    # -- queries ----------------------------------------------------------
    def __contains__(self, name: str) -> bool:
        if not self.enabled or not self._names:
            return False
        return name.strip().lower().rstrip(".") in self._names

    def __len__(self) -> int:
        return len(self._names)

    @property
    def names(self) -> set[str]:
        return set(self._names)

    def is_nameserver(self, name: str) -> bool:
        return name in self

    def note_skipped(self, name: str) -> None:
        """Remember a name that was excluded, for reporting."""
        if name not in self.skipped:
            self.skipped.append(name)

    def describe(self) -> str:
        if not self._names:
            return "no nameservers found"
        return ", ".join(sorted(self._names))
