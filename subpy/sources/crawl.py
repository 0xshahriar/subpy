"""Web-archive and crawler derived sources.

Search engines and web archives remember hostnames that no certificate ever
covered: subdomains that only ever served HTTP, staging boxes behind a
private CA, hosts that died years ago. They are slower and noisier than CT
logs, but they fill exactly the gaps CT cannot reach.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Iterable

from .base import PassiveSource, SourceContext, register

__all__ = [
    "WaybackSource",
    "CommonCrawlSource",
    "UrlscanSource",
    "VirusTotalSource",
    "ShodanSource",
    "SecurityTrailsSource",
    "ChaosSource",
    "OtxSource",
    "BinaryEdgeSource",
]

_HOST_RE = re.compile(r"[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_\-]{1,63}){1,}", re.I)


def _hosts_from_text(text: str, domain: str, limit: int = 200000) -> set[str]:
    """Pull every plausible hostname belonging to *domain* out of a blob."""
    found: set[str] = set()
    if not text:
        return found
    suffix = "." + domain.lower()
    for match in _HOST_RE.finditer(text[:limit]):
        token = match.group(0).lower()
        if token.endswith(suffix):
            found.add(token)
    return found


@register
class WaybackSource(PassiveSource):
    """Internet Archive CDX API - historical URL index."""

    name = "wayback"
    category = "crawl"
    description = "Wayback Machine CDX index"
    reliability = 0.6
    rate = 0.5
    concurrency = 1

    BASE = "https://web.archive.org/cdx/search/cdx"

    async def fetch(self, ctx: SourceContext) -> Iterable[str]:
        loop = asyncio.get_running_loop()

        def _run() -> set[str]:
            text = ctx.http.get_text(
                self.BASE,
                params={
                    "url": f"*.{ctx.domain}/*",
                    "output": "text",
                    "fl": "original",
                    "collapse": "urlkey",
                    "limit": "100000",
                    "filter": "statuscode:200",
                },
                timeout=60.0,
                retries=1,
                rate=self.rate,
                rate_key="web.archive.org",
            )
            return _hosts_from_text(text, ctx.domain)

        return await loop.run_in_executor(None, _run)


@register
class CommonCrawlSource(PassiveSource):
    """Common Crawl index - the largest public web crawl."""

    name = "commoncrawl"
    category = "crawl"
    description = "Common Crawl URL index"
    reliability = 0.55
    rate = 0.5
    concurrency = 1

    COLLINFO = "https://index.commoncrawl.org/collinfo.json"
    _cached_index: str = ""

    async def _latest_index(self, ctx: SourceContext) -> str:
        loop = asyncio.get_running_loop()
        try:
            data = await loop.run_in_executor(
                None,
                lambda: ctx.http.get_json(
                    self.COLLINFO,
                    timeout=20.0,
                    retries=1,
                    rate=1.0,
                    rate_key="commoncrawl",
                ),
            )
            if isinstance(data, list) and data:
                return str(data[0].get("cdx-api") or "")
        except Exception:
            pass
        return ""

    async def fetch(self, ctx: SourceContext) -> Iterable[str]:
        loop = asyncio.get_running_loop()
        index = await self._latest_index(ctx)
        if not index:
            return set()

        def _run() -> set[str]:
            text = ctx.http.get_text(
                index,
                params={"url": f"*.{ctx.domain}", "output": "json", "limit": "50000"},
                timeout=60.0,
                retries=1,
                rate=self.rate,
                rate_key="index.commoncrawl.org",
            )
            hosts: set[str] = set()
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                url = record.get("url") or ""
                if "://" in url:
                    host = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
                    if host.lower().endswith("." + ctx.domain):
                        hosts.add(host.lower())
            return hosts

        return await loop.run_in_executor(None, _run)


@register
class UrlscanSource(PassiveSource):
    """urlscan.io - public scan corpus, searchable by domain."""

    name = "urlscan"
    category = "crawl"
    description = "urlscan.io public scan index"
    reliability = 0.65
    rate = 30.0  # generous for anonymous use; key raises it
    key_env = "URLSCAN_API_KEY"

    SEARCH = "https://urlscan.io/api/v1/search/"

    async def fetch(self, ctx: SourceContext) -> Iterable[str]:
        loop = asyncio.get_running_loop()
        headers = {"Accept": "application/json"}
        key = ctx.key(self.key_env)
        if key:
            headers["api-key"] = key

        hosts: set[str] = set()
        search_after: str = ""
        for _ in range(5):  # 5 * 100 results: deeper pages are rarely useful
            # "page.domain:" restricts to results whose *page* is in the
            # target domain. Plain "domain:example.com" returned 100 results
            # of which 34 pointed at unrelated sites (apnews.com, ...): it
            # matches any request URL mentioning the domain, so the results
            # are mostly third-party pages that embed it.
            params = {"q": f"page.domain:{ctx.domain}", "size": "100"}
            if search_after:
                params["search_after"] = search_after

            def _run(p=params) -> dict:
                return (
                    ctx.http.get_json(
                        self.SEARCH,
                        params=p,
                        headers=headers,
                        timeout=25.0,
                        retries=1,
                        rate=self.rate,
                        rate_key="urlscan",
                    )
                    or {}
                )

            try:
                data = await loop.run_in_executor(None, _run)
            except Exception:
                break
            results = data.get("results") or []
            if not results:
                break
            for item in results:
                page = item.get("page") or {}
                for candidate in (page.get("domain"), page.get("apexDomain")):
                    if candidate:
                        hosts.add(str(candidate))
                task = item.get("task") or {}
                if task.get("url"):
                    url = str(task["url"])
                    if "://" in url:
                        hosts.add(url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0])
            if len(results) < 100:
                break
            search_after = str(results[-1].get("sort") or "")
            if not search_after:
                break
        return hosts


@register
class VirusTotalSource(PassiveSource):
    """VirusTotal domain/subdomains API v3 (free key, 4 req/min)."""

    name = "virustotal"
    category = "intel"
    description = "VirusTotal subdomain relationships"
    requires_key = True
    key_env = "VIRUSTOTAL_API_KEY"
    reliability = 0.8
    rate = 4.0 / 60.0

    BASE = "https://www.virustotal.com/api/v3/domains/{domain}/subdomains"

    async def fetch(self, ctx: SourceContext) -> Iterable[str]:
        key = ctx.key(self.key_env)
        if not key:
            raise RuntimeError("missing VIRUSTOTAL_API_KEY")
        loop = asyncio.get_running_loop()
        hosts: set[str] = set()
        cursor: str = ""
        for _ in range(4):
            params: dict[str, str] = {"limit": "40"}
            if cursor:
                params["cursor"] = cursor

            def _run(p=params) -> dict:
                return (
                    ctx.http.get_json(
                        self.BASE.format(domain=ctx.domain),
                        params=p,
                        headers={"x-apikey": key, "Accept": "application/json"},
                        timeout=25.0,
                        retries=1,
                        rate=self.rate,
                        rate_key="virustotal",
                    )
                    or {}
                )

            try:
                data = await loop.run_in_executor(None, _run)
            except Exception:
                break
            for item in data.get("data") or []:
                attrs = item.get("attributes") or {}
                if attrs.get("id"):
                    hosts.add(str(attrs["id"]))
                if item.get("id"):
                    hosts.add(str(item["id"]))
            cursor = str((data.get("links") or {}).get("next") or "")
            if not cursor or "cursor=" not in cursor:
                break
            cursor = cursor.split("cursor=", 1)[1].split("&", 1)[0]
        return hosts


@register
class ShodanSource(PassiveSource):
    """Shodan DNS domain info (paid key for full results)."""

    name = "shodan"
    category = "intel"
    description = "Shodan DNS domain listing"
    requires_key = True
    key_env = "SHODAN_API_KEY"
    reliability = 0.7
    rate = 1.0

    BASE = "https://api.shodan.io/dns/domain/{domain}"

    async def fetch(self, ctx: SourceContext) -> Iterable[str]:
        key = ctx.key(self.key_env)
        if not key:
            raise RuntimeError("missing SHODAN_API_KEY")
        loop = asyncio.get_running_loop()
        data = await loop.run_in_executor(
            None,
            lambda: ctx.http.get_json(
                self.BASE.format(domain=ctx.domain),
                params={"key": key},
                timeout=25.0,
                retries=1,
                rate=self.rate,
                rate_key="shodan",
            ),
        )
        out: list[str] = []
        for record in (data or {}).get("data") or []:
            sub = record.get("subdomain")
            if sub:
                out.append(f"{sub}.{ctx.domain}" if sub else ctx.domain)
            for value in record.get("value") or []:
                out.append(str(value))
        return out


@register
class SecurityTrailsSource(PassiveSource):
    """SecurityTrails subdomain listing (free tier, key required)."""

    name = "securitytrails"
    category = "intel"
    description = "SecurityTrails subdomain enumeration"
    requires_key = True
    key_env = "SECURITYTRAILS_API_KEY"
    reliability = 0.85
    rate = 4.0 / 60.0

    BASE = "https://api.securitytrails.com/v1/domain/{domain}/subdomains"

    async def fetch(self, ctx: SourceContext) -> Iterable[str]:
        key = ctx.key(self.key_env)
        if not key:
            raise RuntimeError("missing SECURITYTRAILS_API_KEY")
        loop = asyncio.get_running_loop()
        hosts: set[str] = set()
        for page in range(1, 4):
            data = await loop.run_in_executor(
                None,
                lambda p=page: ctx.http.get_json(
                    self.BASE.format(domain=ctx.domain),
                    params={"page": str(p)},
                    headers={"APIKEY": key, "Accept": "application/json"},
                    timeout=25.0,
                    retries=1,
                    rate=self.rate,
                    rate_key="securitytrails",
                ),
            )
            subs = (data or {}).get("subdomains") or []
            if not subs:
                break
            for sub in subs:
                hosts.add(f"{sub}.{ctx.domain}")
            if len(subs) < 100:
                break
        return hosts


@register
class ChaosSource(PassiveSource):
    """ProjectDiscovery Chaos - free public bug-bounty DNS dataset."""

    name = "chaos"
    category = "dns"
    description = "ProjectDiscovery Chaos dataset"
    requires_key = True
    key_env = "CHAOS_KEY"
    reliability = 0.85
    rate = 1.0

    BASE = "https://dns.projectdiscovery.io/dns/{domain}/subdomains"

    async def fetch(self, ctx: SourceContext) -> Iterable[str]:
        key = ctx.key(self.key_env)
        if not key:
            raise RuntimeError("missing CHAOS_KEY")
        loop = asyncio.get_running_loop()
        data = await loop.run_in_executor(
            None,
            lambda: ctx.http.get_json(
                self.BASE.format(domain=ctx.domain),
                headers={"Authorization": key, "Accept": "application/json"},
                timeout=25.0,
                retries=1,
                rate=self.rate,
                rate_key="chaos",
            ),
        )
        out: list[str] = []
        for sub in (data or {}).get("subdomains") or []:
            out.append(f"{sub}.{ctx.domain}")
        return out


@register
class OtxSource(PassiveSource):
    """AlienVault OTX passive DNS (key raises the anonymous quota)."""

    name = "otx"
    category = "intel"
    # As of 2026-11-02 this endpoint rejects anonymous callers outright:
    #   {"detail": "Anonymous access to this endpoint is limited. Please
    #    authenticate."}  (HTTP 429)
    # Every Sublist3r-era recipe that calls it unkeyed is therefore broken.
    description = "AlienVault OTX passive DNS (requires a free API key)"
    requires_key = True
    key_env = "OTX_API_KEY"
    reliability = 0.7
    rate = 0.5

    BASE = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"

    async def fetch(self, ctx: SourceContext) -> Iterable[str]:
        loop = asyncio.get_running_loop()
        headers = {"Accept": "application/json"}
        key = ctx.key(self.key_env)
        if key:
            headers["X-OTX-API-KEY"] = key

        def _run() -> set[str]:
            data = ctx.http.get_json(
                self.BASE.format(domain=ctx.domain),
                headers=headers,
                timeout=30.0,
                retries=1,
                rate=self.rate,
                rate_key="otx",
            )
            hosts: set[str] = set()
            for record in (data or {}).get("passive_dns") or []:
                hostname = record.get("hostname")
                if hostname:
                    hosts.add(str(hostname).lower())
            return hosts

        return await loop.run_in_executor(None, _run)


@register
class BinaryEdgeSource(PassiveSource):
    """BinaryEdge domain/subdomain search (key required)."""

    name = "binaryedge"
    category = "intel"
    description = "BinaryEdge subdomain index"
    requires_key = True
    key_env = "BINARYEDGE_API_KEY"
    reliability = 0.7
    rate = 1.0

    BASE = "https://api.binaryedge.io/v2/query/domains/subdomain/{domain}"

    async def fetch(self, ctx: SourceContext) -> Iterable[str]:
        key = ctx.key(self.key_env)
        if not key:
            raise RuntimeError("missing BINARYEDGE_API_KEY")
        loop = asyncio.get_running_loop()
        data = await loop.run_in_executor(
            None,
            lambda: ctx.http.get_json(
                self.BASE.format(domain=ctx.domain),
                headers={"X-Key": key, "Accept": "application/json"},
                timeout=25.0,
                retries=1,
                rate=self.rate,
                rate_key="binaryedge",
            ),
        )
        if isinstance(data, dict):
            return [str(x) for x in data.get("events") or []]
        return []
