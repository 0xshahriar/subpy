# Architecture

subpy is deliberately small. This document explains how the pieces fit, and
why each one exists, so a contributor can change behaviour without breaking
an invariant somewhere else.

## Layers

```
subpy/
├── cli.py            argument parsing, signals, exit codes
├── update.py         GitHub release check (cached, opt-out)
├── core/
│   ├── dns.py        DNS wire format: encode query, decode response
│   ├── resolver.py   async UDP/TCP/DoH client, health, caching
│   ├── wildcard.py   wildcard detection and filtering
│   ├── wordlists.py  built-in list, loading, permutations
│   ├── models.py     Host and ScanSummary
│   └── scanner.py    orchestration
├── sources/          passive discovery (HTTP)
│   ├── http.py       urllib client, rate limiting, retries
│   ├── base.py       source contract and registry
│   ├── ct.py         certificate transparency
│   ├── datasets.py   aggregated DNS datasets
│   └── crawl.py      web archives and scan corpora
└── output/
    ├── theme.py      colour, width, Unicode detection
    ├── console.py    live reporter and progress
    └── writers.py    txt / json / csv / md / html
```

The dependency rule is one-directional: `output` may import `core`, `core`
may import nothing above it, and `sources` may import `core` but never
`output`. That is what lets the library be used without a terminal.

## The pipeline

```
target
  │
  ├─ wildcard fingerprint (K random probes per level)
  │
  ├─ passive sources ─┐
  ├─ brute force ─────┼─→ deduplicate ─→ resolve ─→ wildcard filter ─→ report
  ├─ permutations ────┤
  └─ zone transfer ───┘
```

Passive and active run **concurrently**. Passive work is network-bound
(HTTP), brute force is resolver-bound (UDP). Overlapping them hides source
latency almost completely, which is the single biggest contributor to the
tool feeling fast.

## Invariants

These are not style preferences. Breaking one produces silently wrong output.

### 1. Existence is decided by the answer section, never by RCODE

Measured on 2026-11-02 against public resolvers: `example.com`,
`cloudflare.com`, `github.com`, `apple.com` and `netflix.com` all reply
`NOERROR` with zero answers for names that do not exist. Only `google.com`
and `amazon.com` replied `NXDOMAIN`. Keying on `NXDOMAIN` produced 104 false
positives in 105 probes.

```python
if not msg.answers:      # correct
    return False
```

### 2. The OPT pseudo-record is never an answer

EDNS0 adds an OPT record (type 41) to the additional section — including on
`NXDOMAIN` responses. `parse_message` drops it while reading sections, so
`msg.answers` never contains one. `tests/test_dns.py` guards this.

### 3. Wildcards are per-level, not per-zone

`*.herokuapp.com` and `*.foo.herokuapp.com` can both resolve to different
address sets. Fingerprints are therefore keyed by the full parent name, and
a new level is profiled on first encounter, bounded by `max_levels`.

### 4. Filtering compares address *sets*, and corroborates when ambiguous

A static wildcard is caught by a subset test against every address seen
during probing. Some zones (measured: `vercel.app`) derive a different
address per label inside one `/24`; subset matching can never fire there, so
a fresh control probe is issued and the answers compared directly. Equal
answers mean noise.

### 5. A suffix is only treated as a wildcard if it was verified to be one

`SAA_WILDCARD_SUFFIXES` contains 44 suffixes confirmed to answer for random
labels, each probed three times against three public resolvers.
`SHARED_INFRA_SUFFIXES` lists 30 that host customer content but return
`NXDOMAIN` for random labels — treating those as wildcards would silently
delete real subdomains, so they are annotated and never dropped.

`fly.dev` sits in the second list for exactly this reason: it answered 0/12
on random labels while its apex and `flyctl.fly.dev` resolve. It was
originally in the first list, and that single wrong entry deleted every real
host CNAMEd into Fly.io.

Deeper names are profiled on first encounter by `detect_for_name`, bounded by
`max_levels`. Without that, `a.b.example.com` is judged against
`b.example.com` only and RFC 4592 synthesis at depth 2+ leaks through as a
real host.

### 6. Resolver loss is silent, so the window is small

Public resolvers shed load by dropping packets rather than sending
`SERVFAIL`. Measured with 800 queries per configuration:

| in-flight per server | throughput | loss |
| --- | --- | --- |
| 8 | 267 qps | 0.1% |
| **16** | **328 qps** | **0%** |
| 32 | 262 qps | 0% |
| 64 | 230 qps | 2.5% |

Hence `window_per_server = 16` and `concurrency = 100`. Ranking resolvers
purely by RTT is also wrong for bulk work: it sends every query to the
fastest server until it throttles. Selection is least-in-flight first, RTT
as tie-break, round-robin on ties.

### 7. Anything that fails must fail quietly

Sources time out, hosts get rate limited, archives go offline. No single
failure aborts a scan; it is recorded in `summary.source_errors` and the
scan continues. The update check never raises.

## Adding a passive source

```python
from .base import PassiveSource, SourceContext, register

@register
class MySource(PassiveSource):
    name = "mysource"
    category = "dns"            # ct | dns | intel | crawl
    description = "What it returns"
    requires_key = False        # True if an API key is mandatory
    key_env = ""                # e.g. "MYSOURCE_API_KEY"
    reliability = 0.7           # 0..1, used to rank/annotate
    rate = 2.0                  # requests per second

    async def fetch(self, ctx: SourceContext):
        loop = asyncio.get_running_loop()
        data = await loop.run_in_executor(
            None,
            lambda: ctx.http.get_json("https://api.example/subdomains",
                                      params={"domain": ctx.domain}),
        )
        return [f"{x}.{ctx.domain}" for x in (data or {}).get("subdomains", [])]
```

`collect()` wraps `fetch()`, isolates exceptions, normalises every candidate
through `clean_hostname()`, and rejects anything outside the target domain.
A source only needs to return strings.

## Testing

```
python -m unittest discover -s tests   # 94 tests, no network
ruff check subpy tests
ruff format --check subpy tests
```

`tests/test_compat.py` enforces the claims that CI cannot otherwise verify on
a single interpreter: no 3.10+ syntax, no third-party imports, optional
accelerators imported lazily, ASCII fallback, and `NO_COLOR` semantics.
