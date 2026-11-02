"""Public DNS dataset sources.

These services have already walked the DNS and published the results:
reverse-DNS databases, passive-DNS aggregators, and payload archives. They
cost one HTTP request and often return names that no certificate ever
exposed (internal-looking hosts, legacy records, wildcard victims).
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Iterable

from .base import PassiveSource, SourceContext, register

__all__ = [
    "HackerTargetSource",
    "AnubisSource",
    "RapidDNSSource",
    "SubdomainCenterSource",
    "ThreatCrowdSource",
    "DNSDumpsterSource",
    "NetlasSource",
    "FullHuntSource",
]

_HOST_TOKEN = re.compile(r"[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_\-]{1,63})+", re.I)


@register
class HackerTargetSource(PassiveSource):
    """hackertarget.com hostsearch - free, no key, ~50 queries/day."""

    name = "hackertarget"
    category = "dns"
    description = "HackerTarget host search (free tier)"
    reliability = 0.7
    rate = 0.5

    BASE = "https://api.hackertarget.com/hostsearch/"

    async def fetch(self, ctx: SourceContext) -> Iterable[str]:
        loop = asyncio.get_running_loop()

        def _run() -> list[str]:
            text = ctx.http.get_text(
                self.BASE,
                params={"q": ctx.domain},
                timeout=20.0,
                retries=1,
                rate=self.rate,
                rate_key="hackertarget",
            )
            # Either "host,ip" lines or a plain-text error message.
            if not text or "error" in text.lower()[:80] and "," not in text:
                return []
            out = []
            for line in text.splitlines():
                line = line.strip()
                if not line or "," not in line:
                    continue
                out.append(line.split(",", 1)[0])
            return out

        return await loop.run_in_executor(None, _run)


@register
class AnubisSource(PassiveSource):
    """Anubis-DB (jldc.me) - long-running passive DNS JSON API."""

    name = "anubis"
    category = "dns"
    description = "Anubis passive DNS database"
    reliability = 0.6
    rate = 1.0
    # Frequently rate-limits or serves a JS challenge; kept opt-in-safe.
    enabled_by_default = True

    # jldc.me and jonlu.ca both redirect (301/403) as of 2026-11-02;
    # anubisdb.com is the live host. It answers with a huge JSON array that
    # includes numeric and single-character junk labels, so every candidate
    # must still be validated by DNS (which the scanner does unconditionally).
    BASE = "https://anubisdb.com/anubis/subdomains/"

    async def fetch(self, ctx: SourceContext) -> Iterable[str]:
        loop = asyncio.get_running_loop()
        url = f"{self.BASE}{ctx.domain}"
        data = await loop.run_in_executor(
            None,
            lambda: ctx.http.get_json(
                url,
                timeout=20.0,
                retries=1,
                rate=self.rate,
                rate_key="anubis",
            ),
        )
        if isinstance(data, list):
            return [str(x) for x in data]
        return []


@register
class RapidDNSSource(PassiveSource):
    """rapiddns.io - HTML table of DNS records, no API key."""

    name = "rapiddns"
    category = "dns"
    description = "RapidDNS subdomain records"
    reliability = 0.65
    rate = 0.7

    BASE = "https://rapiddns.io/subdomain/{domain}"

    async def fetch(self, ctx: SourceContext) -> Iterable[str]:
        loop = asyncio.get_running_loop()

        def _run() -> list[str]:
            text = ctx.http.get_text(
                self.BASE.format(domain=ctx.domain),
                params={"full": "1"},
                headers={"Accept": "text/html"},
                timeout=20.0,
                retries=1,
                rate=self.rate,
                rate_key="rapiddns",
            )
            found: set[str] = set()
            for token in _HOST_TOKEN.findall(text or ""):
                token = token.lower()
                if token.endswith("." + ctx.domain) or token == ctx.domain:
                    found.add(token)
            return list(found)

        return await loop.run_in_executor(None, _run)


@register
class SubdomainCenterSource(PassiveSource):
    """subdomain.center - large pre-computed index, returns a JSON array."""

    name = "subdomain-center"
    category = "dns"
    description = "subdomain.center aggregated index"
    reliability = 0.6
    rate = 0.5

    BASE = "https://api.subdomain.center/"

    async def fetch(self, ctx: SourceContext) -> Iterable[str]:
        loop = asyncio.get_running_loop()
        data = await loop.run_in_executor(
            None,
            lambda: ctx.http.get_json(
                self.BASE,
                params={"domain": ctx.domain},
                timeout=40.0,
                retries=1,
                rate=self.rate,
                rate_key="subdomain.center",
            ),
        )
        if isinstance(data, list):
            return [str(x) for x in data]
        return []


@register
class ThreatCrowdSource(PassiveSource):
    """ThreatCrowd passive DNS (community threat intel)."""

    name = "threatcrowd"
    category = "intel"
    description = "ThreatCrowd domain report"
    reliability = 0.45
    rate = 0.5
    # Service has been unreliable for years: opt-in.
    enabled_by_default = False

    BASE = "https://www.threatcrowd.org/searchApi/v2/domain/report/"

    async def fetch(self, ctx: SourceContext) -> Iterable[str]:
        loop = asyncio.get_running_loop()
        data = await loop.run_in_executor(
            None,
            lambda: ctx.http.get_json(
                self.BASE,
                params={"domain": ctx.domain},
                timeout=15.0,
                retries=0,
                rate=self.rate,
                rate_key="threatcrowd",
            ),
        )
        if isinstance(data, dict):
            return [str(x) for x in data.get("subdomains") or []]
        return []


@register
class DNSDumpsterSource(PassiveSource):
    """dnsdumpster.com - requires a CSRF token, so we do the two-step flow."""

    name = "dnsdumpster"
    category = "dns"
    description = "DNSDumpster host search (CSRF flow)"
    reliability = 0.5
    rate = 0.4
    enabled_by_default = False

    BASE = "https://dnsdumpster.com/"

    async def fetch(self, ctx: SourceContext) -> Iterable[str]:
        loop = asyncio.get_running_loop()

        def _run() -> list[str]:
            status, body, _ = ctx.http.request(
                self.BASE,
                headers={"Accept": "text/html"},
                timeout=20.0,
                retries=1,
                rate=self.rate,
                rate_key="dnsdumpster",
            )
            text = body.decode("utf-8", "replace")
            match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', text)
            if not match:
                return []
            token = match.group(1)
            import urllib.parse as _u

            payload = _u.urlencode(
                {"csrfmiddlewaretoken": token, "targetip": ctx.domain, "user": "free"}
            ).encode()
            _, body2, _ = ctx.http.request(
                self.BASE,
                method="POST",
                data=payload,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": self.BASE,
                    "Cookie": _cookie_from(ctx, "dnsdumpster"),
                },
                timeout=25.0,
                retries=1,
                rate=self.rate,
                rate_key="dnsdumpster",
            )
            text2 = body2.decode("utf-8", "replace")
            found: set[str] = set()
            for token_match in _HOST_TOKEN.findall(text2):
                token_match = token_match.lower()
                if token_match.endswith("." + ctx.domain):
                    found.add(token_match)
            return list(found)

        return await loop.run_in_executor(None, _run)


def _cookie_from(ctx: SourceContext, key: str) -> str:
    return str(ctx.extras.get(f"cookie:{key}", "") or "")


@register
class NetlasSource(PassiveSource):
    """Netlas.io - large DNS/certificate index (free key available)."""

    name = "netlas"
    category = "dns"
    description = "Netlas.io domain WHOIS/DNS index"
    requires_key = True
    key_env = "NETLAS_API_KEY"
    reliability = 0.7
    rate = 1.0
    enabled_by_default = True

    BASE = "https://app.netlas.io/api/domains/"

    async def fetch(self, ctx: SourceContext) -> Iterable[str]:
        key = ctx.key(self.key_env)
        if not key:
            raise RuntimeError("missing NETLAS_API_KEY")
        loop = asyncio.get_running_loop()
        data = await loop.run_in_executor(
            None,
            lambda: ctx.http.get_json(
                self.BASE,
                params={"q": f"domain:*.{ctx.domain}", "fields": "domain", "size": "1000"},
                headers={"X-API-Key": key, "Accept": "application/json"},
                timeout=25.0,
                retries=1,
                rate=self.rate,
                rate_key="netlas",
            ),
        )
        out: list[str] = []
        for item in (data or {}).get("items") or []:
            if isinstance(item, dict):
                dom = item.get("data", {}).get("domain") or item.get("domain")
                if dom:
                    out.append(str(dom))
        return out


@register
class FullHuntSource(PassiveSource):
    """FullHunt.io asset search API."""

    name = "fullhunt"
    category = "intel"
    description = "FullHunt attack-surface API"
    requires_key = True
    key_env = "FULLHUNT_API_KEY"
    reliability = 0.7
    rate = 1.0
    enabled_by_default = True

    BASE = "https://fullhunt.io/api/v1/domain/{domain}/subdomains"

    async def fetch(self, ctx: SourceContext) -> Iterable[str]:
        key = ctx.key(self.key_env)
        if not key:
            raise RuntimeError("missing FULLHUNT_API_KEY")
        loop = asyncio.get_running_loop()
        data = await loop.run_in_executor(
            None,
            lambda: ctx.http.get_json(
                self.BASE.format(domain=ctx.domain),
                headers={"X-API-KEY": key, "Accept": "application/json"},
                timeout=25.0,
                retries=1,
                rate=self.rate,
                rate_key="fullhunt",
            ),
        )
        if isinstance(data, dict):
            return [str(x) for x in data.get("hosts") or []]
        return []
