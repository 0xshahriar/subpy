"""Small, dependency-free HTTP client used by all passive sources.

Every passive source must behave well under pressure: aggressive rate
limiting, transient 5xx responses, cloudflare challenges, timeouts and
outright outages are normal. This module centralises that pain so each
source stays a few lines of code:

* per-host token-bucket rate limiting,
* exponential backoff with jitter on 429/5xx,
* hard timeouts that never leak a hung connection,
* automatic gzip decoding,
* proxy support from the standard environment variables,
* a shared retry budget so one sick source cannot stall a scan.
"""

from __future__ import annotations

import gzip
import http.client
import json
import random
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

__all__ = ["HttpError", "RateLimiter", "HttpClient", "DEFAULT_USER_AGENT"]

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0 Safari/537.36 subpy/1.0"
)


class HttpError(RuntimeError):
    """Raised for non-retryable or exhausted HTTP failures."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class RateLimiter:
    """Thread-safe token bucket, one bucket per key."""

    def __init__(self, rate: float = 5.0, burst: float | None = None) -> None:
        self.rate = max(0.01, float(rate))
        self.burst = float(burst if burst is not None else max(1.0, self.rate))
        self._tokens: dict[str, float] = {}
        self._stamps: dict[str, float] = {}
        self._lock = threading.Lock()

    def acquire(self, key: str = "default", blocking: bool = True) -> float:
        """Take one token; returns seconds actually waited."""
        waited = 0.0
        while True:
            with self._lock:
                now = time.monotonic()
                last = self._stamps.get(key, now)
                tokens = self._tokens.get(key, self.burst)
                tokens = min(self.burst, tokens + (now - last) * self.rate)
                self._stamps[key] = now
                if tokens >= 1.0:
                    self._tokens[key] = tokens - 1.0
                    return waited
                self._tokens[key] = tokens
                deficit = (1.0 - tokens) / self.rate
            if not blocking:
                return -1.0
            time.sleep(min(deficit, 1.0))
            waited += deficit


@dataclass
class _HostState:
    failures: int = 0
    blocked_until: float = 0.0
    last_status: int = 0

    @property
    def blocked(self) -> bool:
        return time.monotonic() < self.blocked_until

    def penalise(self, seconds: float) -> None:
        self.failures += 1
        self.blocked_until = time.monotonic() + seconds


class HttpClient:
    """Thread-safe pooled-ish HTTP client with retries and rate limiting."""

    def __init__(
        self,
        *,
        timeout: float = 20.0,
        retries: int = 2,
        rate: float = 6.0,
        user_agent: str = DEFAULT_USER_AGENT,
        proxy: str | None = None,
        max_bytes: int = 32 << 20,
    ) -> None:
        self.timeout = timeout
        self.retries = max(0, retries)
        self.limiter = RateLimiter(rate=rate)
        self.user_agent = user_agent
        self.max_bytes = max_bytes
        self._hosts: dict[str, _HostState] = {}
        self._lock = threading.Lock()

        handlers: list = []
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        else:
            handlers.append(urllib.request.ProxyHandler())  # env-based proxies
        self._opener = urllib.request.build_opener(*handlers)
        self.stats = {"requests": 0, "failures": 0, "retries": 0}

    # -- internals --------------------------------------------------------
    def _host_state(self, host: str) -> _HostState:
        with self._lock:
            st = self._hosts.get(host)
            if st is None:
                st = _HostState()
                self._hosts[host] = st
            return st

    def host_blocked(self, url: str) -> bool:
        host = urllib.parse.urlsplit(url).netloc.lower()
        return self._host_state(host).blocked

    def _decode(self, raw: bytes, encoding: str) -> bytes:
        encoding = (encoding or "").lower()
        try:
            if "gzip" in encoding:
                return gzip.decompress(raw)
            if "deflate" in encoding:
                try:
                    return zlib.decompress(raw)
                except zlib.error:
                    return zlib.decompress(raw, -zlib.MAX_WBITS)
        except (OSError, zlib.error):
            pass
        return raw

    # -- public -----------------------------------------------------------
    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        data: bytes | None = None,
        json_body: Any | None = None,
        timeout: float | None = None,
        retries: int | None = None,
        rate_key: str | None = None,
        rate: float | None = None,
        accept_status: Iterable[int] = (200,),
    ) -> tuple[int, bytes, dict[str, str]]:
        """Perform a request, returning ``(status, body, headers)``."""
        if params:
            sep = "&" if urllib.parse.urlsplit(url).query else "?"
            url = url + sep + urllib.parse.urlencode(params, doseq=True)

        host = urllib.parse.urlsplit(url).netloc.lower()
        state = self._host_state(host)
        if state.blocked:
            raise HttpError(f"{host} temporarily blocked", state.last_status)

        hdrs = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
        if headers:
            hdrs.update({k: v for k, v in headers.items() if v is not None})
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")

        attempts = self.retries if retries is None else max(0, retries)
        accepted = set(accept_status)
        last_error: Exception | None = None

        for attempt in range(attempts + 1):
            # Apply a per-source rate limit when one is given, otherwise the
            # client-wide default keyed by host.
            if rate is not None:
                self.limiter.acquire(rate_key or host)
            else:
                self.limiter.acquire(host)

            self.stats["requests"] += 1
            req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
            try:
                with self._opener.open(req, timeout=timeout or self.timeout) as resp:
                    raw = resp.read(self.max_bytes)
                    body = self._decode(raw, resp.headers.get("Content-Encoding", ""))
                    status = resp.status
                    if status in accepted or not accepted:
                        state.failures = 0
                        return status, body, dict(resp.headers)
                    last_error = HttpError(f"unexpected status {status}", status)
                    if status in (403, 404, 410):
                        # Not worth retrying: the resource simply is not there.
                        raise last_error
            except urllib.error.HTTPError as exc:
                status = exc.code
                state.last_status = status
                try:
                    raw = exc.read(self.max_bytes)
                    body = self._decode(raw, exc.headers.get("Content-Encoding", ""))
                except Exception:
                    body = b""
                if status in accepted:
                    return status, body, dict(exc.headers or {})
                last_error = HttpError(f"HTTP {status} for {host}", status)
                if status == 429:
                    retry_after = 0.0
                    try:
                        retry_after = float((exc.headers or {}).get("Retry-After", 0) or 0)
                    except (TypeError, ValueError):
                        retry_after = 0.0
                    state.penalise(max(retry_after, min(60.0, 2.0 * (attempt + 1))))
                    break
                if status in (401, 403, 404, 410, 451):
                    # Auth problems and missing endpoints: give up on this host
                    # for a while instead of hammering it.
                    state.penalise(60.0)
                    raise last_error from None
                if status < 500:
                    raise last_error from None
            except (
                urllib.error.URLError,
                http.client.HTTPException,
                socket.timeout,
                OSError,
            ) as exc:
                last_error = HttpError(f"{type(exc).__name__}: {exc}")
                self.stats["failures"] += 1
            except ValueError as exc:  # bad URL / TLS problems surface oddly
                last_error = HttpError(str(exc))

            if attempt < attempts:
                self.stats["retries"] += 1
                # Jittered exponential backoff keeps retries from synchronising.
                delay = (0.4 * (2**attempt)) + random.uniform(0, 0.35)
                time.sleep(min(delay, 6.0))

        if state.failures >= 3:
            state.penalise(120.0)
        raise last_error or HttpError("request failed")

    # -- conveniences -----------------------------------------------------
    def get_text(self, url: str, *, headers: Mapping[str, str] | None = None, **kw) -> str:
        _, body, _ = self.request(url, headers=headers, **kw)
        return body.decode("utf-8", "replace")

    def get_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
        **kw,
    ) -> Any:
        hdrs = {"Accept": "application/json"}
        if headers:
            hdrs.update(headers)
        _, body, _ = self.request(url, headers=hdrs, params=params, **kw)
        text = body.decode("utf-8", "replace").strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise HttpError(f"invalid JSON: {exc.msg}") from exc
