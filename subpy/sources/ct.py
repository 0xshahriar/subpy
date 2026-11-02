"""Certificate Transparency log sources.

CT logs are the single richest passive source: every publicly trusted TLS
certificate is published, and the Subject Alternative Names on those
certificates are exactly the hostnames organisations expose. Coverage is
excellent for 2016+ and the data is free and permanent.

crt.sh is the friendliest front-end but is often overloaded (502s are
routine), so several independent CT aggregators are used. They index the
same logs, which is redundancy rather than duplication.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Iterable

from .base import PassiveSource, SourceContext, register

__all__ = ["CrtShSource", "CertSpotterSource", "FacebookCTSource", "CensysCTSource"]


def _split_names(blob: str) -> list[str]:
    """Split the multi-value blobs CT APIs return into individual names."""
    if not blob:
        return []
    out: list[str] = []
    for chunk in re.split(r"[\s,;]+", blob):
        chunk = chunk.strip()
        if chunk:
            out.append(chunk)
    return out


@register
class CrtShSource(PassiveSource):
    """crt.sh - the canonical free CT search engine."""

    name = "crtsh"
    category = "ct"
    description = "Certificate Transparency search (crt.sh)"
    reliability = 0.85
    rate = 2.0
    concurrency = 1

    BASE = "https://crt.sh/"

    async def fetch(self, ctx: SourceContext) -> Iterable[str]:
        loop = asyncio.get_running_loop()
        params_variants = [
            {"q": f"%.{ctx.domain}", "output": "json", "exclude": "expired", "deduplicate": "Y"},
            # Some deployments reject the deduplicate flag; retry bare.
            {"q": f"%.{ctx.domain}", "output": "json"},
            # Narrower query as a last resort: sometimes the recursive form
            # times out while the direct one succeeds.
            {"q": ctx.domain, "output": "json"},
        ]

        last_error: Exception | None = None
        for params in params_variants:
            try:
                data = await loop.run_in_executor(
                    None,
                    lambda p=params: ctx.http.get_json(
                        self.BASE,
                        params=p,
                        headers={"Accept": "application/json"},
                        timeout=45.0,
                        retries=1,
                        rate=self.rate,
                        rate_key="crt.sh",
                    ),
                )
            except Exception as exc:
                last_error = exc
                continue

            if data is None:
                continue
            if isinstance(data, dict):
                # crt.sh returns an error object on overload.
                if data.get("error"):
                    last_error = RuntimeError(str(data.get("error")))
                    continue
                data = [data]
            if not isinstance(data, list):
                continue

            hosts: set[str] = set()
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                for field in ("name_value", "common_name"):
                    for raw in _split_names(str(entry.get(field) or "")):
                        # Drop wildcards; the wildcard manager handles them.
                        raw = raw.lstrip("*.")
                        if raw:
                            hosts.add(raw)
            if hosts:
                return hosts
        if last_error is not None:
            raise RuntimeError(f"crt.sh unavailable: {last_error}")
        return set()


@register
class CertSpotterSource(PassiveSource):
    """SSLMate Cert Spotter - stable, quota-friendly CT API."""

    name = "certspotter"
    category = "ct"
    description = "SSLMate Cert Spotter issuances API"
    reliability = 0.9
    rate = 1.0
    requires_key = False  # anonymous access works with lower quotas
    key_env = "CERTSPOTTER_API_KEY"

    BASE = "https://api.certspotter.com/v1/issuances"

    async def fetch(self, ctx: SourceContext) -> Iterable[str]:
        loop = asyncio.get_running_loop()
        headers = {"Accept": "application/json"}
        key = ctx.key(self.key_env)
        if key:
            headers["Authorization"] = f"Bearer {key}"

        hosts: set[str] = set()
        after: str | None = None
        # Cap pagination: certificates issued under a huge domain can run to
        # thousands of pages and we already have depth from other sources.
        for _ in range(6):
            params = {
                "domain": ctx.domain,
                "include_subdomains": "true",
                "expand": "dns_names",
            }
            if after:
                params["after"] = after
            try:
                data = await loop.run_in_executor(
                    None,
                    lambda p=params: ctx.http.get_json(
                        self.BASE,
                        params=p,
                        headers=headers,
                        timeout=25.0,
                        retries=1,
                        rate=self.rate,
                        rate_key="certspotter",
                    ),
                )
            except Exception:
                break
            if not data:
                break
            if isinstance(data, dict):
                break
            last_id = None
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                last_id = entry.get("id", last_id)
                for raw in entry.get("dns_names") or []:
                    hosts.add(str(raw))
            if not last_id or len(data) < 2:
                break
            after = str(last_id)
        return hosts


@register
class FacebookCTSource(PassiveSource):
    """Meta/Facebook CT monitoring API (anonymous, generous)."""

    name = "facebookct"
    category = "ct"
    description = "Meta certificate transparency monitor"
    reliability = 0.8
    rate = 3.0
    enabled_by_default = True

    BASE = "https://developers.facebook.com/tools/ct/search/"

    async def fetch(self, ctx: SourceContext) -> Iterable[str]:
        loop = asyncio.get_running_loop()

        def _run() -> Iterable[str]:
            text = ctx.http.get_text(
                self.BASE,
                params={"query": ctx.domain, "limit": "3000"},
                headers={"User-Agent": "subpy/1.0 (+ct-monitor)"},
                timeout=25.0,
                retries=1,
                rate=self.rate,
                rate_key="facebookct",
            )
            # The endpoint answers either JSON or plain text lines.
            text = text.strip()
            if text.startswith("[") or text.startswith("{"):
                import json as _json

                try:
                    payload = _json.loads(text)
                except ValueError:
                    payload = None
                if isinstance(payload, dict):
                    names = payload.get("data") or payload.get("names") or []
                    if isinstance(names, list):
                        return [str(n) for n in names if isinstance(n, str)]
                elif isinstance(payload, list):
                    return [str(n) for n in payload if isinstance(n, str)]
            return [ln.strip() for ln in text.splitlines() if ln.strip()]

        return await loop.run_in_executor(None, _run)


@register
class CensysCTSource(PassiveSource):
    """Censys certificate search (optional: needs API credentials)."""

    name = "censys"
    category = "ct"
    description = "Censys certificate search API"
    requires_key = True
    key_env = "CENSYS_API_ID"
    free = True
    reliability = 0.75
    rate = 1.0
    enabled_by_default = False

    # The legacy v2 endpoint was decommissioned on 2026-09-30 and now
    # returns 403 with an explicit "decommissioned" body. The replacement is
    # the platform API, which uses a different auth scheme (a personal access
    # token rather than id/secret) and a different query dialect.
    BASE = "https://api.platform.censys.io/v3/global/search/query"

    async def fetch(self, ctx: SourceContext) -> Iterable[str]:
        # Accept either the new personal access token or the legacy id/secret
        # pair, so existing setups keep working against the new base URL.
        token = ctx.key("CENSYS_API_TOKEN")
        if not token:
            api_id = ctx.key("CENSYS_API_ID")
            api_secret = ctx.key("CENSYS_API_SECRET")
            if api_id and api_secret:
                import base64

                token = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        if not token:
            raise RuntimeError("missing CENSYS_API_TOKEN or CENSYS_API_ID/_SECRET")

        loop = asyncio.get_running_loop()
        data = await loop.run_in_executor(
            None,
            lambda: ctx.http.get_json(
                self.BASE,
                params={"q": f"names:*.{ctx.domain}", "page_size": "100"},
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
                timeout=25.0,
                retries=1,
                rate=self.rate,
                rate_key="censys",
            ),
        )
        hosts: set[str] = set()
        # The v3 envelope nests hits under result.hits, same as v2.
        result = (data or {}).get("result") or {}
        for hit in result.get("hits") or []:
            for raw in hit.get("names") or ():
                hosts.add(str(raw))
        return hosts
