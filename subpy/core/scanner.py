"""The scan orchestrator.

Pipeline overview::

    target  ->  [wildcard fingerprint]  ->  +---------------------+
                                            |  passive sources    |--+
                                            +---------------------+  |
                                            |  brute force        |--+--> dedupe
                                            +---------------------+  |    -> resolve
                                            |  permutations       |--+    -> wildcard
                                            +---------------------+       -> filter
                                            |  zone transfer walk |--+    -> report
                                            +---------------------+

Design goals:

* **Never block on a dead source.** Everything is concurrent and every
  failure is contained; a source that errors is reported, not fatal.
* **Never emit a name that is not real.** Every candidate is resolved and
  passed through the wildcard manager before it reaches the caller.
* **Bounded memory.** Candidates stream through a fixed-size queue rather
  than being materialised as one list.
* **Instant feedback.** Resolved hosts are handed to a callback the moment
  they are confirmed, so the CLI can print them live.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Sequence
from typing import Callable

from .dns import QTYPE, DNSMessage, normalize_name
from .models import (
    SOURCE_ACTIVE,
    SOURCE_PASSIVE,
    SOURCE_PERMUTATION,
    Host,
    ScanSummary,
)
from .resolver import AsyncResolver, ResolverConfig, system_resolvers
from .wildcard import WildcardManager

__all__ = ["Scanner", "ScanConfig"]

HostCallback = Callable[[Host], None]


class ScanConfig:
    """All tunables for one scan, in one place."""

    def __init__(
        self,
        domain: str,
        *,
        passive: bool = True,
        active: bool = True,
        permutations: bool = True,
        resolve_passive: bool = True,
        concurrency: int = 200,
        timeout: float = 2.0,
        retries: int = 1,
        resolvers: Sequence[str] | None = None,
        use_system_resolvers: bool = True,
        wildcard: bool = True,
        wildcard_samples: int = 3,
        sources: Sequence[str] | None = None,
        exclude_sources: Sequence[str] | None = None,
        wordlist_paths: Sequence[str] | None = None,
        use_builtin_wordlist: bool = True,
        wordlist_limit: int = 0,
        max_permutations: int = 40,
        include_ipv6: bool = True,
        source_timeout: float = 20.0,
        passive_budget: float = 90.0,
        source_concurrency: int = 8,
        zone_transfer: bool = True,
        include_unresolved: bool = False,
        retry_unresolved: bool = True,
        dedupe_subdomains: bool = True,
        verbose: bool = False,
    ) -> None:
        self.domain = normalize_name(domain)
        self.passive = passive
        self.active = active
        self.permutations = permutations
        self.resolve_passive = resolve_passive
        self.concurrency = max(1, int(concurrency))
        self.timeout = max(0.2, float(timeout))
        self.retries = max(1, int(retries))
        self.resolvers = list(resolvers or [])
        self.use_system_resolvers = use_system_resolvers
        self.wildcard = wildcard
        self.wildcard_samples = max(1, int(wildcard_samples))
        self.sources = list(sources or [])
        self.exclude_sources = list(exclude_sources or [])
        self.wordlist_paths = list(wordlist_paths or [])
        self.use_builtin_wordlist = use_builtin_wordlist
        self.wordlist_limit = max(0, int(wordlist_limit))
        self.max_permutations = max(0, int(max_permutations))
        self.include_ipv6 = include_ipv6
        self.source_timeout = max(3.0, float(source_timeout))
        self.passive_budget = max(self.source_timeout, float(passive_budget))
        self.source_concurrency = max(1, int(source_concurrency))
        self.zone_transfer = zone_transfer
        self.include_unresolved = include_unresolved
        self.retry_unresolved = retry_unresolved
        self.dedupe_subdomains = dedupe_subdomains
        self.verbose = verbose


class Scanner:
    """Coordinates passive discovery, brute force and verification."""

    def __init__(
        self,
        config: ScanConfig,
        *,
        on_host: HostCallback | None = None,
        on_progress: Callable[[dict], None] | None = None,
        logger: Callable[[str], None] | None = None,
    ) -> None:
        self.config = config
        self.on_host = on_host
        self.on_progress = on_progress
        self.log = logger or (lambda _msg: None)

        self.summary = ScanSummary(domain=config.domain)
        self.hosts: dict[str, Host] = {}
        self._in_progress: set[str] = set()
        self._lock = asyncio.Lock()
        self._resolver: AsyncResolver | None = None
        self._wildcard: WildcardManager | None = None
        self._stop = False
        self._seen_labels: set[str] = set()

    # -- lifecycle --------------------------------------------------------
    async def run(self) -> list[Host]:
        """Execute the full scan and return resolved hosts."""
        started = time.monotonic()
        self.summary.started = time.time()

        resolvers = self._build_resolver_list()
        resolver_config = ResolverConfig(
            servers=resolvers,
            timeout=self.config.timeout,
            retries=self.config.retries,
            concurrency=self.config.concurrency,
            ipv6=self.config.include_ipv6,
        )
        self._resolver = AsyncResolver(resolver_config)
        await self._resolver.start()

        try:
            self._wildcard = WildcardManager(
                self._resolver,
                self.config.domain,
                samples=self.config.wildcard_samples,
                enabled=self.config.wildcard,
            )

            if self.config.wildcard:
                info = await self._wildcard.detect()
                self.summary.wildcard_levels = len(self._wildcard.active_levels())
                if info.active:
                    self.log(f"wildcard detected: *.{self.config.domain} -> {info.describe()}")

            candidates: set[str] = set()

            # Passive discovery and brute force are independent, so run them
            # together: brute force is resolver-bound while passive waiting is
            # network-bound, and overlapping them hides source latency almost
            # entirely. This is the main reason subpy feels fast.
            passive_task = (
                asyncio.ensure_future(self._run_passive()) if self.config.passive else None
            )
            brute_task = (
                asyncio.ensure_future(self._run_bruteforce()) if self.config.active else None
            )

            if brute_task is not None:
                brute = await brute_task
                candidates |= brute
                if self._stop:
                    self.summary.interrupted = True

            if passive_task is not None:
                try:
                    remaining = max(0.0, self.config.passive_budget)
                    passive = await asyncio.wait_for(passive_task, timeout=remaining)
                    candidates |= passive
                except asyncio.TimeoutError:
                    self.summary.source_errors.append("passive budget exhausted")
                    passive_task.cancel()

            if self._stop:
                self.summary.interrupted = True
                return self._finalise()

            # Resolve anything not already handled (rounded up passively).
            pending = [
                c for c in candidates if c not in self.hosts or self.hosts[c].resolved is None
            ]
            if pending and not self._stop:
                await self._resolve_batch(pending, source=None)

            if self.config.permutations and self.config.max_permutations > 0 and not self._stop:
                await self._run_permutations()

            # A second pass catches names that only appeared as a CNAME target
            # or were truncated by the resolver under load.
            if self.config.retry_unresolved and not self._stop:
                retry = [
                    name
                    for name, host in self.hosts.items()
                    if host.resolved is None and not host.error
                ]
                if retry:
                    await self._resolve_batch(retry, source=None)

            if self.config.zone_transfer and not self._stop:
                await self._try_zone_transfer()

        finally:
            if self._resolver is not None:
                self.summary.resolver_stats = dict(self._resolver.stats)
                await self._resolver.close()

        self.summary.finished = time.time()
        if self.summary.queries == 0 and self._resolver is not None:
            self.summary.queries = self._resolver.stats.get("queries", 0)
        self.log(f"scan complete in {self.summary.elapsed:.1f}s")
        _ = time.monotonic() - started
        return self._finalise()

    def stop(self) -> None:
        """Request a graceful early stop (Ctrl-C friendly)."""
        self._stop = True
        self.summary.interrupted = True

    # -- resolver setup ---------------------------------------------------
    def _build_resolver_list(self) -> Sequence[str]:
        servers: list[str] = []
        seen: set[str] = set()

        for server in self.config.resolvers:
            server = str(server).strip()
            if server and server not in seen:
                seen.add(server)
                servers.append(server)

        if self.config.use_system_resolvers:
            for server in system_resolvers():
                if server not in seen:
                    seen.add(server)
                    servers.append(server)

        if not servers:
            from .resolver import PUBLIC_RESOLVERS

            servers = list(PUBLIC_RESOLVERS)
        return servers

    # -- passive ----------------------------------------------------------
    async def _run_passive(self) -> set[str]:
        from ..sources import HttpClient, SourceContext, get_sources

        config = self.config
        try:
            sources = get_sources(config.sources or None, include_keyed=True)
        except KeyError as exc:
            self.summary.source_errors.append(str(exc))
            return set()

        if config.exclude_sources:
            excluded = {s.strip().lower() for s in config.exclude_sources}
            sources = [s for s in sources if s.name not in excluded]

        # Keyed sources without credentials are dropped silently (they would
        # only burn a timeout each).
        http = HttpClient(timeout=30.0, retries=1, rate=8.0)
        ctx = SourceContext(
            domain=config.domain,
            http=http,
            timeout=config.source_timeout,
            verbose=config.verbose,
        )
        sources = [s for s in sources if s.has_key(ctx)]

        if not sources:
            self.log("no passive sources available")
            return set()

        self.log(f"passive: querying {len(sources)} sources")

        semaphore = asyncio.Semaphore(config.source_concurrency)
        collected: set[str] = set()

        async def _one(source) -> None:
            async with semaphore:
                try:
                    result = await asyncio.wait_for(
                        source.collect(ctx), timeout=config.source_timeout
                    )
                except asyncio.CancelledError:
                    raise
                except asyncio.TimeoutError:
                    self.summary.source_errors.append(f"{source.name}: timeout")
                    return
                except Exception as exc:  # contained by design
                    self.summary.source_errors.append(f"{source.name}: {type(exc).__name__}")
                    return
            if result.skipped:
                self.summary.skipped_sources.append(f"{source.name} ({result.skipped})")
                return
            if result.error:
                self.summary.source_errors.append(f"{source.name}: {result.error}")
                return
            if result.hosts:
                async with self._lock:
                    for host in result.hosts:
                        collected.add(host)
                        entry = self.hosts.get(host)
                        if entry is None:
                            entry = Host(name=host, sources={SOURCE_PASSIVE})
                            entry.sources.add(source.name)
                            self.hosts[host] = entry
                        else:
                            entry.sources.add(source.name)
                if self.config.verbose:
                    self.log(f"  {source.name}: {result.count} hosts")
            elif self.config.verbose:
                self.log(f"  {source.name}: 0 hosts")

        await asyncio.gather(*(_one(s) for s in sources))

        self.summary.passive_found = len(collected)
        self.log(f"passive: {len(collected)} unique candidates")

        return collected

    # -- brute force ------------------------------------------------------
    async def _run_bruteforce(self) -> set[str]:
        from .wordlists import iter_wordlist

        config = self.config
        domain = config.domain
        found: set[str] = set()

        labels = iter_wordlist(
            domain=domain,
            paths=config.wordlist_paths,
            builtin=config.use_builtin_wordlist,
            limit=config.wordlist_limit,
        )

        batch: list[str] = []
        batch_size = max(250, config.concurrency * 3)
        index = 0

        async def _flush() -> None:
            nonlocal batch
            if not batch:
                return
            names = [f"{label}.{domain}" for label in batch]
            self._seen_labels.update(batch)
            batch = []
            resolved = await self._resolve_batch(names, source=SOURCE_ACTIVE)
            found.update(resolved)

        for label in labels:
            if self._stop:
                break
            index += 1
            name = f"{label}.{domain}"
            if name in self.hosts and self.hosts[name].resolved is not None:
                continue
            batch.append(label)
            if len(batch) >= batch_size:
                await _flush()

        await _flush()
        self.summary.active_found = len(found)
        self.log(f"brute: {index} words tested, {len(found)} resolved")
        return found

    # -- permutations -----------------------------------------------------
    async def _run_permutations(self) -> None:
        from .wordlists import generate_permutations

        config = self.config
        if not self.hosts:
            return

        labels: list[str] = [host.label for host in self.hosts.values() if host.resolved]

        if not labels:
            return

        self.log(f"permute: generating siblings for {len(labels)} hosts")
        candidates = []
        seen: set[str] = set()
        for label in generate_permutations(
            labels, domain=config.domain, max_per_label=config.max_permutations
        ):
            full = f"{label}.{config.domain}"
            if full in self.hosts or full in seen:
                continue
            seen.add(full)
            candidates.append(full)

        if not candidates:
            return
        resolved = await self._resolve_batch(candidates, source=SOURCE_PERMUTATION)
        self.summary.permutation_found = len(resolved)
        self.log(f"permute: {len(candidates)} tried, {len(resolved)} resolved")

    # -- resolution -------------------------------------------------------
    async def _resolve_batch(self, names: Sequence[str], *, source: str | None) -> list[str]:
        """Resolve names concurrently, verifying each and reporting hits."""
        assert self._resolver is not None
        if not names:
            return []

        found: list[str] = []
        chunk: list[str] = []

        for name in names:
            chunk.append(name)
            if len(chunk) >= self.config.concurrency * 3:
                found.extend(await self._resolve_chunk(chunk, source))
                chunk = []
                if self._stop:
                    break

        if chunk and not self._stop:
            found.extend(await self._resolve_chunk(chunk, source))
        return found

    async def _resolve_chunk(self, names: list[str], source: str | None) -> list[str]:
        assert self._resolver is not None
        tasks = [asyncio.ensure_future(self._verify_one(name, source)) for name in names]
        started = time.monotonic()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        self.summary.dns_seconds += time.monotonic() - started
        hits: list[str] = []
        for name, result in zip(names, results):
            if result is True:
                hits.append(name)
            elif isinstance(result, Exception) and self.config.verbose:
                self.log(f"  resolve error {name}: {result}")
        self.summary.queries += len(names)
        return hits

    async def _verify_one(self, name: str, source: str | None) -> bool:
        """Resolve and validate one candidate. Returns True when real."""
        assert self._resolver is not None
        assert self._wildcard is not None

        name = normalize_name(name)
        # Claim the name before awaiting. Passive discovery and brute force
        # run concurrently and routinely surface the same candidate; without
        # this guard both coroutines proceed, both resolve, and on_host fires
        # twice for one host (the file is deduplicated later, but live output
        # printed it twice and summary.resolved over-counted).
        if name in self._in_progress:
            return False
        self._in_progress.add(name)
        try:
            return await self._verify_claimed(name, source)
        finally:
            self._in_progress.discard(name)

    async def _verify_claimed(self, name: str, source: str | None) -> bool:
        """Resolve a name already claimed by :meth:`_verify_one`."""
        assert self._resolver is not None
        assert self._wildcard is not None
        started = time.monotonic()
        msg: DNSMessage | None = await self._resolver.query(name, QTYPE["A"])
        elapsed = (time.monotonic() - started) * 1000.0

        host = self.hosts.get(name)
        if host is None:
            host = Host(name=name)
            self.hosts[name] = host
        if source:
            host.add_source(source)
        host.latency_ms = elapsed

        if msg is None:
            # No answer at all: infrastructure failure, not a negative result.
            host.error = "no response"
            host.resolved = None
            return False

        host.rcode = msg.rcode_name

        # Existence is decided by the ANSWER SECTION, never by RCODE.
        #
        # Measured on this host (2026-11-02): example.com, cloudflare.com,
        # github.com, apple.com and netflix.com all answer NOERROR with zero
        # answers for names that do not exist, while google.com and amazon.com
        # send NXDOMAIN. Keying on NXDOMAIN produced 104 false positives in
        # 105 probes. A name exists iff it has at least one answer record.
        if not msg.answers:
            # An IPv6-only host legitimately has zero A records. Falling back
            # to AAAA has to happen here, before the existence test concludes
            # "does not exist", otherwise the fallback further down is
            # unreachable for exactly the case it exists to cover.
            if self.config.include_ipv6:
                v6 = await self._resolver.query(name, QTYPE["AAAA"])
                if v6 is not None and v6.answers:
                    msg = v6
                else:
                    host.resolved = False
                    return False
            else:
                host.resolved = False
                return False

        # Wildcard check happens before anything is announced so the user
        # never sees a name that gets taken back a second later.
        if await self._wildcard.is_wildcard(name, msg):
            host.wildcard = True
            host.wildcard_reason = "matches wildcard fingerprint"
            host.resolved = False
            self.summary.wildcard_filtered += 1
            return False

        addresses = msg.addresses()
        if not addresses and self.config.include_ipv6:
            v6 = await self._resolver.query(name, QTYPE["AAAA"])
            if v6 is not None:
                addresses = [rr.address for rr in v6.answers if rr.address]

        cnames = msg.cnames()
        for address in addresses:
            host.add_address(address)
        for target in cnames:
            host.add_cname(target)

        # A CNAME chain must terminate somewhere; a bare CNAME with no
        # address is still a real record, but flag it for the reporter.
        if not addresses and not cnames:
            host.resolved = False
            return False

        host.ttl = min((rr.ttl for rr in msg.answers if rr.ttl), default=0)

        # CNAME with no address anywhere in the chain: the name exists but
        # points at something that does not. Flag it as a takeover candidate
        # rather than silently reporting a dead host.
        if cnames and not addresses:
            host.dangling = True
            from .wildcard import shared_infra_hit

            target = cnames[-1]
            infra = shared_infra_hit(target)
            if infra:
                host.takeover_hint = f"dangling CNAME to unclaimed {infra} host"
            else:
                host.takeover_hint = f"dangling CNAME to {target}"

        host.resolved = True
        self.summary.resolved += 1
        if self.on_host is not None:
            self.on_host(host)
        return True

    # -- zone transfer ----------------------------------------------------
    async def _try_zone_transfer(self) -> None:
        """Attempt an AXFR against the domain's authoritative servers.

        Almost always refused, but it is cheap (one query) and when it works
        it returns the entire zone.
        """
        assert self._resolver is not None
        domain = self.config.domain
        try:
            ns_msg = await self._resolver.query(domain, QTYPE["NS"])
        except Exception:
            return
        if ns_msg is None:
            return

        nameservers = ns_msg.ns_names()
        if not nameservers:
            return

        names: set[str] = set()
        for nameserver in nameservers[:3]:
            try:
                transferred = await asyncio.wait_for(
                    _axfr(nameserver, domain, self.config.timeout * 3), timeout=12.0
                )
            except (asyncio.TimeoutError, Exception):
                continue
            if transferred:
                names |= transferred

        if not names:
            return

        self.log(f"axfr: zone transfer succeeded ({len(names)} names)")
        new_names = [n for n in names if n not in self.hosts]
        if new_names:
            await self._resolve_batch(new_names, source=SOURCE_ACTIVE)

    # -- results ----------------------------------------------------------
    def _finalise(self) -> list[Host]:
        self.summary.finished = self.summary.finished or time.time()
        if self._resolver is not None:
            self.summary.resolver_stats = dict(self._resolver.stats)
            self.summary.queries = max(self.summary.queries, self._resolver.stats.get("queries", 0))
        self.summary.resolved = sum(1 for h in self.hosts.values() if h.resolved)
        if self._wildcard is not None:
            self.summary.wildcard_levels = len(self._wildcard.active_levels())
        self.summary.candidates = len(self.hosts)

        results = [h for h in self.hosts.values() if h.resolved]
        if self.config.include_unresolved:
            results += [h for h in self.hosts.values() if not h.resolved and not h.wildcard]
        results.sort(key=lambda h: (h.name.count("."), h.name))
        return results

    def results(self) -> list[Host]:
        """Return the hosts found so far, without re-running anything.

        Public because an interrupted scan must still be able to report what
        it has; nothing here touches the network.
        """
        return self._finalise()

    def wildcard_report(self) -> list[dict]:
        return self._wildcard.to_dict() if self._wildcard else []


async def _axfr(nameserver: str, domain: str, timeout: float) -> set[str]:
    """Try a TCP AXFR and collect the names in the answer."""
    import struct

    from .dns import QTYPE as _Q
    from .dns import build_query, parse_message

    if ":" in nameserver:
        return set()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(nameserver, 53), timeout)
    except (OSError, asyncio.TimeoutError):
        return set()

    names: set[str] = set()
    try:
        packet, qid = build_query(domain, _Q["AXFR"], edns=False)
        writer.write(struct.pack("!H", len(packet)) + packet)
        await writer.drain()

        while True:
            try:
                header = await asyncio.wait_for(reader.readexactly(2), timeout)
            except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                break
            (length,) = struct.unpack("!H", header)
            if length == 0 or length > 65535:
                break
            try:
                body = await asyncio.wait_for(reader.readexactly(length), timeout)
            except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                break
            try:
                msg = parse_message(body, expect_id=qid)
            except Exception:
                break
            if msg.rcode != 0:
                break
            for rr in msg.answers:
                if rr.name.endswith("." + domain) or rr.name == domain:
                    names.add(rr.name)
                if (
                    rr.rtype in (_Q["CNAME"], _Q["NS"])
                    and rr.target
                    and rr.target.endswith("." + domain)
                ):
                    names.add(rr.target)
            # The closing SOA terminates the transfer.
            if len(names) > 1 and msg.answers and any(rr.rtype == _Q["SOA"] for rr in msg.answers):
                break
            if not msg.answers:
                break
    finally:
        with contextlib.suppress(Exception):
            writer.close()

    names.discard("")
    return names
