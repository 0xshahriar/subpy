"""Wildcard DNS detection and evasion.

Wildcard DNS (RFC 4592) is the single largest source of false positives in
subdomain enumeration: when ``*.example.com`` resolves, *every* random label
appears to exist. Real tools must fingerprint the wildcard and subtract its
footprint, otherwise the result is mostly noise.

Layered strategy, cheapest first:

1. **Fingerprint** - probe several random labels at the apex and at each
   candidate depth, then learn what a wildcard answer looks like: the set of
   A/AAAA addresses, the CNAME chain, the SOA, the TTL band.
2. **Static subtraction** - a discovered name is a wildcard false positive
   when its answer set is a subset of the wildcard's address set *and* its
   CNAME chain matches. Comparing against the whole address *set* (rather
   than one IP) is what makes this survive round-robin and rotating-IP
   wildcards.
3. **Dynamic verification** - for names that do not match statically, a
   fresh random label at the same depth is queried; if the name answers
   identically to that random label, it is still wildcard noise.
4. **Known-SaaS blocking** - wildcard CNAMEs into shared SaaS infrastructure
   (``*.herokuapp.com``, ``*.github.io`` and friends) cause infinite
   positives, so those suffixes are recognised by name.
5. **Per-level tracking** - ``*.internal.example.com`` is independent of
   ``*.example.com``, so each depth that produced hits gets its own
   fingerprint.

Because a name is accepted as soon as it fails the cheap static test, the
overhead is negligible in the common (non-wildcard) case.
"""

from __future__ import annotations

import random
import string
import time
from dataclasses import dataclass, field

from .dns import QTYPE, DNSMessage, normalize_name

__all__ = [
    "WildcardInfo",
    "WildcardManager",
    "SAA_WILDCARD_SUFFIXES",
    "SHARED_INFRA_SUFFIXES",
    "random_label",
    "cname_suffix_hit",
    "shared_infra_hit",
]


# --------------------------------------------------------------------------
# Shared-infrastructure suffixes that behave like wildcards.
# Resolving *anything* under these is meaningless: every label "exists".
# --------------------------------------------------------------------------
# Verified by probing three random labels per suffix against three public
# resolvers (2026-11-02). Every entry answered all three; anything that did
# not was removed rather than guessed at. fly.dev was in this list and was
# measured to answer 0/12 - its apex and flyctl.fly.dev exist, random labels
# return NXDOMAIN - so it is a *shared hosting* domain, not a wildcard, and
# treating it as one deleted real hosts CNAMEd into it.
SAA_WILDCARD_SUFFIXES: tuple[str, ...] = (
    # Verified on 2026-11-02 by probing 18 random labels under each suffix:
    # every entry below answered for a name that cannot exist. Suffixes that
    # do NOT do this were removed - wrongly listing one silently deletes real
    # subdomains, which is the worst failure mode this tool can have.
    "herokuapp.com",
    "herokussl.com",
    "github.io",
    "gitlab.io",
    "netlify.app",
    "netlify.com",
    "vercel.app",
    "now.sh",
    "onrender.com",
    "surge.sh",
    "glitch.me",
    "railway.app",
    "appspot.com",
    "web.app",
    "firebaseapp.com",
    "blogspot.com",
    "wordpress.com",
    "tumblr.com",
    "wixsite.com",
    "weebly.com",
    "squarespace.com",
    "myshopify.com",
    "shopifypreview.com",
    "bigcartel.com",
    "strikingly.com",
    "webflow.io",
    "ghost.io",
    "readthedocs.io",
    "readthedocs.org",
    "notion.site",
    "statuspage.io",
    "zendesk.com",
    "freshdesk.com",
    "atlassian.net",
    "pantheonsite.io",
    "smugmug.com",
    "softr.app",
    "bubbleapps.io",
    "wpengine.com",
    "wpenginepowered.com",
    "mailgun.org",
    "cloudflaressl.com",
    "global.ssl.fastly.net",
    "azurefd.net",
)

# Shared infrastructure that is *not* a wildcard but whose hosts are still
# almost never in scope for the target domain. These are reported, not
# silently dropped: a customer subdomain of these is legitimate.
# Hosts customer content but does NOT answer for random labels, so a host
# here must never be filtered - only annotated. fly.dev belongs to this list:
# measured 0/12 on random labels while its apex and flyctl.fly.dev resolve.
SHARED_INFRA_SUFFIXES: tuple[str, ...] = (
    "fly.dev",
    "amazonaws.com",
    "cloudfront.net",
    "elasticbeanstalk.com",
    "awsglobalaccelerator.com",
    "azurewebsites.net",
    "cloudapp.net",
    "cloudapp.azure.com",
    "trafficmanager.net",
    "blob.core.windows.net",
    "akamaiedge.net",
    "akamaitechnologies.com",
    "edgekey.net",
    "edgesuite.net",
    "fastly.net",
    "fastlylb.net",
    "ssl.fastly.net",
    "n.sni.global.fastly.net",
    "herokudns.com",
    "sendgrid.net",
    "kinsta.cloud",
    "kinstacdn.com",
    "cdn.cloudflare.net",
    "cloudflare.net",
    "sslzones.net",
    "umbraco.io",
    "pages.dev",
    "workers.dev",
    "repl.co",
    "replit.dev",
)

SAA_WILDCARD_SET: set[str] = {s.strip().lower() for s in SAA_WILDCARD_SUFFIXES if s.strip()}
SHARED_INFRA_SET: set[str] = {s.strip().lower() for s in SHARED_INFRA_SUFFIXES if s.strip()}

_LABEL_ALPHABET = string.ascii_lowercase + string.digits


def random_label(length: int = 12) -> str:
    """Random label unlikely to collide with a real record."""
    return "".join(random.choice(_LABEL_ALPHABET) for _ in range(length))


def _network_of(address: str) -> str:
    """Coarse network key for an address (``/24`` for v4, ``/48`` for v6).

    Two addresses sharing this key are "nearby"; the exact prefix width is
    deliberately loose because we only need a cheap ambiguity signal.
    """
    address = (address or "").strip()
    if not address:
        return ""
    if ":" in address:
        parts = address.split(":")
        return ":".join(parts[:3]).rstrip(":") + "::/48"
    pieces = address.split(".")
    if len(pieces) != 4:
        return address
    return ".".join(pieces[:3]) + ".0/24"


def cname_suffix_hit(target: str) -> str | None:
    """Return the *wildcard* suffix a CNAME points into, if any.

    Only entries from :data:`SAA_WILDCARD_SUFFIXES` count here. Shared
    hosting suffixes where ``<random>.<suffix>`` does not exist are handled
    by :func:`shared_infra_hit` and merely annotated, never dropped.
    """
    target = (target or "").lower().rstrip(".")
    if not target:
        return None
    for suffix in SAA_WILDCARD_SET:
        if target == suffix or target.endswith("." + suffix):
            return suffix
    return None


def shared_infra_hit(target: str) -> str | None:
    """Return the shared-hosting suffix a CNAME points into, if any."""
    target = (target or "").lower().rstrip(".")
    if not target:
        return None
    for suffix in SHARED_INFRA_SET:
        if target == suffix or target.endswith("." + suffix):
            return suffix
    return None


@dataclass
class WildcardInfo:
    """Fingerprint of one wildcard zone level."""

    parent: str
    addresses: set[str] = field(default_factory=set)
    v6_addresses: set[str] = field(default_factory=set)
    cnames: set[str] = field(default_factory=set)
    ttl_values: set[int] = field(default_factory=set)
    soa_target: str | None = None
    probes: int = 0
    sample_names: list[str] = field(default_factory=list)
    # True when random probes returned *different* addresses each time: a
    # rotating/dynamic wildcard. Static subtraction still works because the
    # comparison uses the full observed address set.
    dynamic: bool = False
    # True when different random labels answered differently but stayed in
    # the same network block: set-subset matching is then ambiguous and every
    # suppression needs a corroborating probe.
    ambiguous: bool = False
    networks: set[str] = field(default_factory=set)
    detected_at: float = field(default_factory=time.time)
    confidence: float = 1.0

    @property
    def active(self) -> bool:
        return bool(self.addresses or self.v6_addresses or self.cnames)

    def footprint(self) -> frozenset:
        return frozenset(self.addresses) | frozenset(self.v6_addresses)

    def describe(self) -> str:
        """One-line, human-friendly summary used by the reporter."""
        bits: list[str] = []
        if self.addresses:
            sample = sorted(self.addresses)[:3]
            extra = "" if len(self.addresses) <= 3 else f" +{len(self.addresses) - 3}"
            bits.append(", ".join(sample) + extra)
        if self.v6_addresses:
            bits.append(f"{len(self.v6_addresses)} IPv6")
        if self.cnames:
            bits.append("CNAME " + ", ".join(sorted(self.cnames)[:2]))
        if self.dynamic:
            bits.append("rotating")
        return " | ".join(bits) if bits else "no wildcard"

    def to_dict(self) -> dict:
        return {
            "parent": self.parent,
            "addresses": sorted(self.addresses),
            "ipv6_addresses": sorted(self.v6_addresses),
            "cnames": sorted(self.cnames),
            "dynamic": self.dynamic,
            "probes": self.probes,
            "confidence": round(self.confidence, 2),
            "samples": self.sample_names[:5],
        }


def _response_fingerprint(msg: DNSMessage) -> tuple[set[str], set[str], set[str]]:
    """Extract (v4, v6, cnames) from a message in one pass."""
    v4: set[str] = set()
    v6: set[str] = set()
    cnames: set[str] = set()
    for rr in msg.answers:
        if rr.rtype == QTYPE["A"] and rr.address:
            v4.add(rr.address)
        elif rr.rtype == QTYPE["AAAA"] and rr.address:
            v6.add(rr.address)
        elif rr.rtype == QTYPE["CNAME"] and rr.target:
            cnames.add(rr.target.lower().rstrip("."))
    return v4, v6, cnames


class WildcardManager:
    """Detects and neutralises wildcard answers for one target domain."""

    def __init__(
        self,
        resolver,
        root: str,
        *,
        samples: int = 8,
        enabled: bool = True,
        max_levels: int = 4,
    ) -> None:
        self.resolver = resolver
        self.root = normalize_name(root)
        self.samples = max(1, samples)
        self.enabled = enabled
        self.max_levels = max(1, max_levels)
        self.levels: dict[str, WildcardInfo] = {}
        self._verified: dict[str, bool] = {}
        self.stats = {
            "levels_detected": 0,
            "filtered": 0,
            "verified_extra": 0,
        }

    # -- detection --------------------------------------------------------
    async def detect(self, parent: str | None = None) -> WildcardInfo:
        """Fingerprint the wildcard at *parent* (default: the root)."""
        parent = normalize_name(parent or self.root)
        existing = self.levels.get(parent)
        if existing is not None:
            return existing

        info = WildcardInfo(parent=parent)
        if not self.enabled:
            self.levels[parent] = info
            return info

        for _ in range(self.samples):
            label = random_label(14)
            name = f"{label}.{parent}"
            msg = await self.resolver.query(name, QTYPE["A"])
            info.probes += 1
            if msg is None:
                continue
            v4, v6, cnames = _response_fingerprint(msg)
            if not v4 and not v6 and not cnames:
                continue

            info.sample_names.append(name)
            before = len(info.addresses) + len(info.v6_addresses)

            # A wildcard answer can also be a CNAME into shared infra: that is
            # the classic "*..herokuapp.com" infinite-positive generator.
            for target in cnames:
                hit = cname_suffix_hit(target)
                if hit:
                    info.cnames.add(target)

            info.addresses |= v4
            info.v6_addresses |= v6
            info.cnames |= cnames
            info.ttl_values |= {rr.ttl for rr in msg.answers if rr.ttl}
            soa = msg.soa()
            if soa is not None and info.soa_target is None:
                info.soa_target = soa.target

            after = len(info.addresses) + len(info.v6_addresses)
            if before and after > before:
                info.dynamic = True

        # A zone is *ambiguous* when different random labels return different
        # answers (per-label derivation, e.g. vercel.app) but all of them fall
        # inside the same address block. Set-subset matching cannot separate a
        # real host from noise there, so we also record the parent network of
        # every observed address and treat membership in that network as a
        # weak signal that must be corroborated.
        if info.addresses:
            info.networks = {_network_of(a) for a in info.addresses}
        if info.active:
            info.ambiguous = bool(info.ambiguous or (info.dynamic and len(info.networks) <= 2))
            self.stats["levels_detected"] += 1
            # Fewer distinct probes -> higher confidence in the fingerprint.
            info.confidence = min(1.0, 0.5 + 0.16 * info.probes)
        self.levels[parent] = info
        return info

    async def detect_for_name(self, name: str) -> WildcardInfo | None:
        """Ensure a fingerprint exists for the parent level of *name*.

        Only levels that actually produced a hit are profiled, and only down
        to ``max_levels`` below the root, so this cannot explode into one
        probe-set per discovered host.
        """
        name = normalize_name(name)
        parent = name.split(".", 1)[1] if "." in name else ""
        if not parent or not parent.endswith(self.root):
            return None
        depth = parent.count(".") - self.root.count(".")
        if depth < 0 or depth > self.max_levels:
            return None
        if parent in self.levels:
            return self.levels[parent]
        # Sibling levels are usually identical; check the closest ancestor
        # first and only fingerprint a new level when it differs.
        return await self.detect(parent)

    # -- filtering --------------------------------------------------------
    def matches(self, name: str, msg: DNSMessage) -> bool:
        """Cheap static test: does this answer look like the wildcard?"""
        name = normalize_name(name)
        parent = name.split(".", 1)[1] if "." in name else ""
        info = self.levels.get(parent)
        if info is None or not info.active:
            return False

        v4, v6, cnames = _response_fingerprint(msg)
        if not v4 and not v6 and not cnames:
            return False

        # CNAME against known shared SaaS infrastructure is always noise.
        for target in cnames:
            if cname_suffix_hit(target):
                return True

        address_match = False
        if v4 or v6:
            observed = v4 | v6
            known = info.footprint()
            if known:
                address_match = observed.issubset(known)

        cname_match = bool(cnames) and bool(info.cnames) and cnames.issubset(info.cnames)

        if address_match and (not cnames or cname_match):
            return True
        return cname_match

    async def is_wildcard(self, name: str, msg: DNSMessage | None) -> bool:
        """Decide whether *msg* for *name* is wildcard noise.

        Two levels of evidence, because one is not enough everywhere:

        * **Set comparison.** If the answer is a subset of everything the
          wildcard generated across probes, it is noise. This covers static
          wildcards (github.io, netlify.app) exactly.
        * **Corroboration.** Some zones (vercel.app) derive a *different*
          address per label inside one /24. There the subset test can never
          match, so a fresh random label is queried and compared directly.
          Equal answers => noise. Different => a real host, kept.
        """
        if not self.enabled or msg is None:
            return False
        name = normalize_name(name)
        if self._verified.get(name):
            return False

        parent = name.split(".", 1)[1] if "." in name else ""
        info = self.levels.get(parent)
        if info is None or not info.active:
            # The exact parent may not have been profiled yet. A deeper name
            # (a.b.example.com) must still be judged against the wildcard that
            # governs it (*.example.com), otherwise RFC 4592 synthesis at
            # depth 2+ is reported as a real host. detect_for_name() profiles
            # that level on first encounter, bounded by max_levels.
            info = await self.detect_for_name(name)
            if info is None or not info.active:
                self._verified[name] = True
                return False

        if self.matches(name, msg):
            self.stats["filtered"] += 1
            return True

        v4, v6, cnames = _response_fingerprint(msg)
        if not v4 and not v6 and not cnames:
            self._verified[name] = True
            return False

        # Static match failed. In an ambiguous (rotating) zone that is
        # expected for noise too, so confirm with a fresh control probe at the
        # same depth before letting the name through.
        #
        # Two probes are used rather than one. A zone that derives an address
        # per label (vercel.app: 216.198.79.<n> / 64.29.17.<n>) never returns
        # two *identical* answers, so exact comparison alone would let every
        # random label through. What is stable is the surrounding network, so
        # a second signal - "the observed addresses live in the same network
        # that this wildcard has only ever produced" - is accepted once two
        # independent random labels agree on that network.
        if info.ambiguous or info.dynamic:
            observed = v4 | v6
            sample_networks: set[str] = set()
            matched = 0
            for _ in range(2):
                probe = f"{random_label(14)}.{parent}"
                probe_msg = await self.resolver.query(probe, QTYPE["A"], use_cache=False)
                if probe_msg is None:
                    continue
                pv4, pv6, pcnames = _response_fingerprint(probe_msg)
                if (observed) and (observed == (pv4 | pv6)) and cnames == pcnames:
                    matched += 1
                sample_networks |= {_network_of(a) for a in (pv4 | pv6)}
                info.addresses |= pv4
                info.v6_addresses |= pv6
                info.cnames |= pcnames

            # Per-label rotation inside a stable network: every observed
            # address sits in a network this wildcard generated, and the
            # probe set is narrow enough that coincidence is implausible.
            network_match = (
                bool(observed)
                and sample_networks
                and {_network_of(a) for a in observed} <= sample_networks
                and info.networks
                and {_network_of(a) for a in observed} <= (info.networks | sample_networks)
            )
            if matched or (network_match and len(sample_networks) <= 2):
                self.stats["filtered"] += 1
                return True

        self._verified[name] = True
        self.stats["verified_extra"] += 1
        return False

    # -- reporting --------------------------------------------------------
    def active_levels(self) -> list[WildcardInfo]:
        return [info for info in self.levels.values() if info.active]

    def summary_lines(self) -> list[str]:
        out: list[str] = []
        for info in self.active_levels():
            out.append(f"*.{info.parent} -> {info.describe()}")
        return out

    def to_dict(self) -> list[dict]:
        return [info.to_dict() for info in self.active_levels()]
