"""Passive source registry and base classes.

A *passive* source returns subdomains other people already observed: certificate
transparency logs, public DNS datasets, search-engine indexes, threat-intel
APIs. A *passive* source never touches the target, so it is safe, quiet, and
much more complete than brute force alone.

Every source is a small class with a uniform contract:

    name            short identifier shown in output
    category        "ct" | "dns" | "crawl" | "intel" | "search"
    requires_key    True when an API key is mandatory
    key_env         environment variable that supplies the key
    free            False for commercial-only sources
    reliability     0..1 prior used to rank and weight results
    async def fetch(domain, ctx) -> iterable of hostnames

A source may fail in dozens of ways; the runner isolates failures so one dead
API never sinks the scan. Sources are also *deduplicated by name*, so the
same hostname found by six CT logs counts once while its provenance is kept
(this is how we can report confidence later).
"""

from __future__ import annotations

import asyncio
import os
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from .http import HttpClient, HttpError

__all__ = [
    "SourceContext",
    "PassiveSource",
    "SourceResult",
    "SOURCE_REGISTRY",
    "get_sources",
    "list_sources",
]

# A hostname must look like a DNS name; this rejects the junk that HTML
# scrapes and certificate SANs love to emit (wildcards, IPs, emails, URLs).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(\*\.)?([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$"
)
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def clean_hostname(value: str) -> str | None:
    """Normalise one candidate hostname, or return ``None`` if unusable.

    Handles the usual mess: wildcards, trailing dots, URL prefixes, ports,
    uppercase, punycode, embedded whitespace, email addresses in SANs.
    """
    if not value:
        return None
    value = value.strip().strip("\"'`").strip()
    if not value:
        return None
    # Drop anything that is obviously not a hostname.
    if any(ch in value for ch in " <>()[]{}\\\"',;\t\r\n"):
        return None
    if "://" in value:
        value = value.split("://", 1)[1]
    if "/" in value:
        value = value.split("/", 1)[0]
    if "@" in value:
        return None
    if ":" in value:
        # IPv6 or host:port
        if value.count(":") > 1:
            return None
        value = value.split(":", 1)[0]
    value = value.strip().rstrip(".").lower()
    if not value or len(value) > 253:
        return None
    if _IPV4_RE.match(value):
        return None
    # A wildcard SAN ("*.example.com") covers the parent's children, not the
    # parent itself. Returning the stripped apex would invent a host that was
    # never in the certificate, so drop wildcards entirely; real children are
    # found by the brute-force stage.
    if "*" in value:
        return None
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        try:
            value = value.encode("idna").decode("ascii").lower()
        except (UnicodeError, ValueError):
            return None
    if not _HOSTNAME_RE.match(value):
        return None
    if value.startswith("-") or ".." in value:
        return None
    return value


def belongs_to(host: str, domain: str) -> bool:
    """True when *host* is *domain* itself or a subdomain of it."""
    host = host.rstrip(".").lower()
    domain = domain.rstrip(".").lower()
    return host == domain or host.endswith("." + domain)


@dataclass
class SourceContext:
    """Shared state handed to every source during one scan."""

    domain: str
    http: HttpClient
    keys: dict[str, str] = field(default_factory=dict)
    timeout: float = 20.0
    verbose: bool = False
    extras: dict[str, str] = field(default_factory=dict)

    def key(self, env_name: str) -> str | None:
        if env_name in self.keys:
            return self.keys[env_name] or None
        value = os.environ.get(env_name, "").strip()
        self.keys[env_name] = value
        return value or None


@dataclass
class SourceResult:
    """Outcome of one source, including its failures."""

    name: str
    hosts: set[str] = field(default_factory=set)
    elapsed: float = 0.0
    error: str | None = None
    skipped: str | None = None
    count: int = 0

    @property
    def ok(self) -> bool:
        return self.error is None and self.skipped is None


class PassiveSource:
    """Base class for all passive sources."""

    name: str = "base"
    category: str = "misc"
    description: str = ""
    requires_key: bool = False
    key_env: str = ""
    free: bool = True
    reliability: float = 0.5
    # Passive sources saturate quickly; this caps concurrent in-flight
    # requests *within* a source.
    concurrency: int = 1
    # Soft rate in requests per second for this host.
    rate: float = 4.0
    enabled_by_default: bool = True

    # -- key handling -----------------------------------------------------
    def has_key(self, ctx: SourceContext) -> bool:
        if not self.requires_key:
            return True
        return bool(ctx.key(self.key_env))

    # -- main entry -------------------------------------------------------
    async def fetch(self, ctx: SourceContext) -> Iterable[str]:
        raise NotImplementedError

    async def collect(self, ctx: SourceContext) -> SourceResult:
        """Run :meth:`fetch`, cleaning and territory-filtering results."""
        result = SourceResult(name=self.name)
        loop = asyncio.get_running_loop()
        started = loop.time()

        if self.requires_key and not self.has_key(ctx):
            result.skipped = f"missing {self.key_env}"
            return result

        try:
            raw = await self.fetch(ctx)
        except asyncio.CancelledError:
            raise
        except (HttpError, asyncio.TimeoutError, ValueError, OSError) as exc:
            result.error = f"{type(exc).__name__}: {exc}"[:200]
            result.elapsed = loop.time() - started
            return result
        except Exception as exc:  # a source bug must never kill the scan
            result.error = f"{type(exc).__name__}: {exc}"[:200]
            result.elapsed = loop.time() - started
            return result

        for item in raw or ():
            host = clean_hostname(item)
            if host and belongs_to(host, ctx.domain):
                result.hosts.add(host)

        result.count = len(result.hosts)
        result.elapsed = loop.time() - started
        return result

    # -- helpers ----------------------------------------------------------
    def _headers(self, ctx: SourceContext, extra: dict[str, str] | None = None) -> dict[str, str]:
        hdrs = {"Accept": "application/json, text/html;q=0.9, */*;q=0.8"}
        if extra:
            hdrs.update(extra)
        return hdrs


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------
SOURCE_REGISTRY: dict[str, type] = {}


def register(cls: type) -> type:
    """Class decorator adding a source to the registry."""
    instance = cls()
    SOURCE_REGISTRY[instance.name] = cls
    return cls


def get_sources(
    names: Sequence[str] | None = None,
    *,
    include_keyed: bool = True,
) -> list[PassiveSource]:
    """Instantiate the requested sources, in registry (priority) order."""
    if names:
        wanted = {n.strip().lower() for n in names if n.strip()}
        missing = wanted - set(SOURCE_REGISTRY)
        if missing:
            raise KeyError(f"unknown source(s): {', '.join(sorted(missing))}")
        chosen = [cls() for name, cls in SOURCE_REGISTRY.items() if name in wanted]
    else:
        chosen = [cls() for cls in SOURCE_REGISTRY.values()]

    if not include_keyed:
        chosen = [s for s in chosen if not s.requires_key]
    return chosen


def list_sources() -> list[dict]:
    """Metadata for ``--list-sources``, sorted for stable output.

    Sorting matters: registration order depends on import order, which an
    import sorter can legitimately change. Users diff this output.
    """
    out = []
    for cls in sorted(SOURCE_REGISTRY.values(), key=lambda c: getattr(c, "name", "")):
        inst = cls()
        out.append(
            {
                "name": inst.name,
                "category": inst.category,
                "requires_key": inst.requires_key,
                "key_env": inst.key_env,
                "free": inst.free,
                "reliability": inst.reliability,
                "description": inst.description,
            }
        )
    return out
