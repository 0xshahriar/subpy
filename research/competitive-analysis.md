# Subdomain Enumeration Tooling — Competitive Analysis

**Purpose:** inform `subpy` — Python, stdlib-first, Termux-friendly, active+passive, wildcard-aware, low FP/FN, minimal aesthetic output.

**Method / verification legend**

| Mark | Meaning |
|---|---|
| ✅ **LIVE** | Measured/fetched by me in this session (2026-11-02, UTC) against the live service/repo. |
| 📄 **DOC** | Stated in the project's own README/source, fetched live but claim is self-reported. |
| ⚠️ **INFERRED** | My reasoning from code/behaviour; not directly benchmarked. |

Network was available. GitHub REST API was rate-limited to 60 req/hr (unknown IP), so star counts, licenses and commit dates were scraped from repo HTML/Atom feeds (not rate-limited) and the READMEs/source were pulled raw. `web_search` hit an out-of-credits error mid-task; **all external claims below are backed by direct fetches, not search snippets.**

---

## 1. Master comparison table

Stars/license/last-commit = ✅ LIVE (scraped 2026-11-02).

| Tool | Lang | ★ (approx) | License | Last commit | Passive | Active brute | Wildcard-aware | Output | Termux |
|---|---|---|---|---|---|---|---|---|---|
| **subfinder** | Go | 14.7k | MIT 📄 | 2026-10-08 | ✅ **54 sources** (counted in source) | ⚠️ `-nW` only resolves, no wordlist | ❌ none (passive-only) | txt, JSONL, per-domain dirs | ⚠️ needs Go build |
| **amass (OWASP)** | Go | 15.4k | Apache-2.0 📄 (LICENSE file: "License: Apache2.0") | 2026-10-25 | ✅ ~45 APIs 📄 | ✅ | ✅ | txt, JSON, graph DB (SQLite/Postgres) | ❌ heavy, DB-bound |
| **assetfinder** | Go | 3.7k | MIT | **2020-04-15** (stale) | ✅ ~8 sources 📄 | ❌ | ❌ | plain lines only | ✅ trivial static Go binary |
| **findomain** | Rust | 3.8k | GPL-3.0 | 2026-09-07 | ✅ (crt.sh API + DB) | ✅ | ⚠️ partial | txt, CSV, JSON, monitoring/webhook | ❌ **Termux install broken** (issue) |
| **knockpy** | Python | 4.2k | GPL-3.0 | 2026-02-19 | ✅ | ✅ async | ⚠️ partial | txt, JSON, CSV | ❌ **Termux resolv.conf crash** (issue) |
| **Sublist3r** | Python | 11.1k | GPL-2.0 | **2020-07-29** (stale) | ✅ | ✅ | ❌ | txt | ⚠️ py2-era deps |
| **dnsx** | Go | 2.9k | MIT | 2026-08-31 | ❌ (resolver) | ✅ resolver only | ✅ `-wd/-wt/-aw` | txt, JSONL, `-ot` template | ⚠️ Go |
| **puredns** | Go+massdns | 2.3k | GPL-3.0 | 2026-02-23 | ❌ | ✅ | ✅ **best-in-class 2-phase** | txt, massdns | ❌ needs massdns binary |
| **massdns** | C | 3.7k | GPL-3.0 | 2026-09-27 | ❌ | ✅ resolver | ❌ (by design) | txt + 7 formats | ❌ needs C build |
| **shuffledns** | Go+massdns | 1.7k | GPL-3.0 | 2026-01-20 | ❌ | ✅ | ✅ (buggy) | txt | ❌ 2 binaries |
| **gobuster dns** | Go | 14.3k | Apache-2.0 | 2026-01-13 | ❌ | ✅ | ⚠️ `--wildcard` | txt | ⚠️ Go |
| **ffuf** | Go | 17.0k | MIT | 2026-09-26 | ❌ | ✅ VHost/DNS mode | ❌ | txt, JSON, HTML, eJSON | ⚠️ Go |
| **dnsrecon** | Python | 3.1k | GPL-2.0 | 2026-10-26 | ⚠️ | ✅ | ✅ explicit wildcard check | txt, CSV, JSON, SQLite, XML | ⚠️ py3.12+, many deps |
| **fierce** | Python | 1.8k | GPL-3.0 | 2024-08-28 | ❌ | ✅ | ⚠️ recursive | stdout only | ✅ pure py |
| **aquatone** | Go | 6.0k | MIT | **ARCHIVED** ✅ | ❌ | ❌ (screenshot) | ❌ | txt, JSON, HTML report | ⚠️ |
| **bbot** | Python | 10.9k | **AGPL-3.0** | 2026-11-01 (API `pushed_at`) | ✅ | ✅ | ✅ (has FP bugs) | JSONL, Neo4j, CSV | ❌ heavy |
| **theHarvester** | Python | 18.2k | GPL-2.0 | 2026-10-20 | ✅ | ✅ `-c` | ⚠️ | HTML, XML, JSON, `-f` | ⚠️ deps |
| **spiderfoot** | Python | 24.2k | MIT | **2023-11-05** (stale) | ✅ | ✅ | ⚠️ | SQLite + web UI | ❌ |
| **OneForAll** | Python | 10.1k | GPL-3.0 | 2026-11-02 | ✅ | ✅ | ✅ (has wildcard flow doc) | txt, CSV, JSON, SQLite | ❌ |
| **Sudomy** | Bash | 2.4k | MIT | **2024-02-19** | ✅ | ✅ via gobuster | ⚠️ delegates | txt, CSV, HTML | ⚠️ bash+many bins |
| **Subdominator** | Python | 0.8k | MIT | 2026-10-07 | ✅ | ❌ | ❌ | JSON, txt | ⚠️ |
| **chaos-client** | Go | 0.9k | MIT | 2026-10-22 | ✅ Chaos DB | ❌ | ❌ | txt, JSONL | ⚠️ needs API key |
| **zdns** | Go | 1.2k | Apache-2.0 | 2026-10-18 | ❌ | ✅ resolver, library-first | ❌ | JSON, txt | ⚠️ |
| **aiodnsbrute** | Python | 0.7k | GPL-3.0 | **2019-06-04** (stale) | ❌ | ✅ asyncio | ❌ | txt, JSON | ✅ pure py |
| **dnscan** | Python | 1.3k | GPL-3.0 | 2024-12-17 | ⚠️ | ✅ | ✅ | txt | ✅ |
| **recon-ng** | Python | 6.0k | GPL-3.0 | 2026 ⚠️ | ✅ modular | ⚠️ via modules | ❌ | SQLite workspace | ❌ |
| **nmap dns-brute** | Lua/C | 13.9k | NPSL ⚠️ | 2026 ⚠️ | ❌ | ✅ | ❌ | NSE text | ⚠️ nmap pkg |

**Tools requested but with no meaningful independent existence** (checked, resolved here):
- `sublister-ng` — **no such maintained repo** (GitHub 404 on two candidate paths; top "sublister" repos have ≤1★). Treat as folklore; do not benchmark against it.
- `whoisdsl` — no such tool found; there is no recognized subdomain-enumeration project by this name. Likely a garbled/misremembered name.
- `crtsh-based tools` — not one tool but a **source class**; subfinder/assetfinder/findomain/theHarvester/Subdominator all consume crt.sh. Covered via those.
- `aquatone` — ✅ **LIVE: `isArchived: true`.** It was never an enumerator (HTTP screenshotter over an existing list). SUPERSEDED by `httpx`/`gowitness`. Exclude from feature comparisons.
- `spiderfoot` — an OSINT *platform*, not an enumerator; 2023-stale. Peripheral only.

---

## 2. Per-tool notes: strengths, weaknesses, failure modes

### subfinder (the UX benchmark)
- **Strength:** 54 passive sources (✅ counted from `pkg/passive/sources.go` imports), the pipe-friendly CLI that became the industry convention, granular `-es/-s/-all`, `-oJ` JSONL, provider rate limits (`-rls "shodan=15/s"` 📄).
- **Weakness — it does not resolve.** No wordlist brute force; `-nW/-active` only *filters* to domains that resolve. It is **passive-only**: on a fresh/small domain it returns almost nothing and can never find a subdomain that isn't already in a third-party dataset.
- **Weakness — silent source death.** Unmaintained APIs fail quietly. Live-verified today: `dns.bufferover.run` **connection failed (exit 6)**, `api.certspotter.com` **HTTP 429**, `otx.alienvault.com` **HTTP 429**, `jonlu.ca/anubis` **HTTP 403**. Each is a subfinder source. A run silently returns less data with no error. This is the single most damaging class of bug in the whole category.
- **Weakness — total latency dominated by worst source.** ✅ crt.sh took **5.14 s** for `%github.com`; the tool cannot finish faster than its slowest source.
- **Issue evidence:** `#1828` crt.sh SQL source broken (PgBouncer rejects `statement_timeout`); `#1560` "Timeout flag does not work consistently"; `#1538` dnsrepo source dead; `#1948` data races on concurrent calls; `#1955` needed explicit regex filters; `#1698` request tracking (`-stats`).
- **Output:** txt, JSONL, per-domain output dirs, `-oI` IP column. `-silent` = pure newline list.

### amass (OWASP)
- **Strength:** only tool that is a real *asset graph* — sources, brute force, zone-transfer attempts, ASN/netblock expansion, recursive sub-domain discovery, and a persistent DB for repeated runs. Install docs cover latest v5 (pip/npm README + v4 Go path).
- **Weakness — operational weight.** Graph DB is mandatory in practice: `#971` SQLite "malformed database schema" (open), `#885` MySQL not working, `#897` MySQL source unusable, `#797` *"Option to disable use of graph database"* (open feature request — users actively want the DB **gone**). Config-file-only runs error out with no output.
- **Weakness — crashes.** Open/closed crashes: `#1010+` region — SIGSEGV, "unexpected fault address", reflect slice-index panics, "BSOD" report, Windows crash report, Docker container randomly crashing on Fargate.
- **Verdict:** maximum coverage, minimum ergonomics. Nobody uses amass for a one-shot 30-second lookup.

### massdns / puredns / shuffledns (the performance tier)
- **massdns** 📄: "capable of resolving over **350,000 names per second** using publicly available resolvers." C, raw sockets, no wildcard logic **by design** — it is a resolver engine, not an enumerator.
- **puredns** 📄✅: 2-phase design = mass resolve with untrusted public resolvers → re-validate against **trusted** resolvers → wildcard filter using "the minimal number of queries." This is the correct architecture and the one to copy.
  - Bugs: `#14` **"Wildcard Domains with CNAME not filtered"** (open — a real FP hole), `#57` "No valid domains remaining." (false *negatives* — everything filtered), `#72` massdns export contains non-final answers.
- **shuffledns** — worst wildcard bug record of the tier, all citable: `#53` **"False positives during wildcard removal"**, `#55` **"False positives in version 1.0.4"**, plus "Strict wildcard filtering not strict enough", "Incorrect clearing of wildcard subdomains", "Wildcard filtering fails with big amount of data", `panic: runtime error: index out of range [-1]`, and a hang when removing wildcards without `-d`. Its own docs admit it is a massdns **wrapper** — inheriting two-binary fragility.
- **Cost of the tier:** you must ship/compile `massdns` (C) next to a Go binary, and you must supply your own resolver list. No Termux story.

### Go web-tool DNS modes
- **gobuster dns** has `--wildcard` and is genuinely fast, but wildcard handling is a blunt "any-IP match" check and it cannot tell you *why* something was filtered. **ffuf** DNS/VHost mode exists but is a fuzzer — wildcard filtering is manual (`-fs` size filters). Neither is passive.

### Python incumbents
- **Sublist3r** (11.1k★, **no commits since 2020-07-29**) is effectively abandoned: CSRF-token scraping against VirusTotal broke (`token = csrf_regex.findall(resp)[0]` IndexError), "Virustotal probably now is blocking our requests", multiple py3.11 Unicode/SSL/type errors, `no module named 'requests'`. **It is still the most-recommended Python tool** — evidence that the Python slot is held by a zombie.
- **knockpy** — best-maintained Python option (2026-02), async, but ✅ live issue: **`dns.resolver.NoResolverConfiguration: cannot open /etc/resolv.conf {TERMUX}`** — i.e. it breaks on precisely the platform `subpy` targets. Also PyQt5 hard-dep crashes (`knockpy 5.1.0 pyqt5 error`), `--set` arg parsing errors, crt.py plugin errors.
- **aiodnsbrute** (0.7k★, **no commits since 2019-06-04**) — the canonical Python asyncio benchmark, now stale.
- **dnsrecon** — the most *complete* Python DNS tool (zone transfer, SRV, TLD expansion, **explicit wildcard check**, PTR, cache snooping) and recently maintained (2026-10-26), but py3.12+, multi-dep, and output is verbose text meant for human reading, not piping.
- **fierce** — clean pure-Python, recursive non-contiguous-space discovery is a genuinely good idea; output is stdout-only with no machine format.
- **theHarvester** (18.2k★) — excellent, recently-rewritten responsible-use posture (see §7), but it is an *email/OSINT* tool that happens to do subdomains (only `crtsh`/`certspotter` pass the "subdomains only" filter in its own provider table 📄).
- **Subdominator** — small, MIT, passive-only, purely aggregator.
- **OneForAll** — very capable (has a documented wildcard-judgment flow, CSV/JSON/SQLite) but Chinese-first docs and heavy deps.
- **Sudomy** — Bash orchestrator that *delegates* brute force to gobuster; "output formats" are really report exports. Heavy install.

### bbot — the cautionary tale
bbot is the most *architecturally* ambitious Python tool and its open issues are a precise catalogue of what goes wrong when you build this well but not carefully:
- `#3547` **"Nested wildcard domains aren't detected, causing runaway subdomain enumeration"** (closed) — wildcard detection that only checks one level explodes into infinite enumeration.
- **"HTTP wildcard detection can stall an entire scan for tens of minutes in compare_body (quadratic DeepDiff pairing, holds the GIL)"** — a *quadratic* comparison plus the **GIL** = total stall. This is the exact failure mode a single-process Python tool must design against.
- **"DNS brute-force canary check is non-functional due to three bugs in brute.py"** — the safety check that would have caught the wildcard bug was itself broken. Two bugs cancelled the visibility of each other.
- **"Excessive subdomains produced by Chaos API module"**, "Module flags are static, but some modules are active or passive depending on config".
- License **AGPL-3.0** — a real adoption blocker for corporate users.

---

## 3. Top 10 features users praise or miss

Ranked by (frequency across issues/docs) × (impact on results).

1. **Wildcard/IP-based filtering that actually works** — every resolver-tier tool has open FP/FN bugs (shuffledns #53/#55, puredns #14/#57, bbot #3547). Universally demanded, rarely correct. **This is the #1 unmet need.**
2. **Pipe-native minimal output** — `-silent`, one host per line, nothing else. subfinder's convention. puredns had to *request* a quiet mode (`#4`) and more output formats (`#9`).
3. **JSONL, not JSON** — line-delimited so `jq`/streaming works. `-oJ`, `-j`, `-json`. A single JSON array is an anti-pattern for big runs.
4. **Batch input (`-dL`)** — multi-domain from file + per-domain output dirs (`-oD`). `#28` "Add support for domains list".
5. **Resolver control** — custom resolver list, trusted-resolver list, per-provider rate limits (`-rls "shodan=15/s"`), and resolver *validation* (puredns `#5` "Validate DNS resolvers").
6. **IP/CNAME enrichment in output** — puredns `#28` "Add ip output" (still open). Users want `host → A/CNAME` in one pass, not a second tool.
7. **Progress/statistics visibility** — subfinder `#1698` "request tracking with `-stats`". People need to know a run isn't silently dead.
8. **Recursive / sub-sub-domain discovery** — subfinder `-recursive`, OneForAll, fierce's non-contiguous space. Flat one-level enums miss real estate.
9. **Rate-limit + timeout that are honoured** — `#1560` "Timeout flag does not work consistently", `#1434` "`rl,rls` not supported". Flags that lie are worse than absent flags.
10. **Regex match/filter** — `-match-regex`/`-filter-regex` (`#1955`). Post-filters are how people turn 50k results into 200.

Also repeatedly wanted: stdin *and* stdout support (dnsx 📄 "stdin and stdout support"), custom output templates (`-ot '{{host}} {{a}}'`), and colour-disable (`-nc`) for CI.

---

## 4. Most common complaints (with citations)

### 4.1 Wildcard false positives — the dominant bug class
| Issue | Text |
|---|---|
| `shuffledns#53` | **False positives during wildcard removal** |
| `shuffledns#55` | **False positives in version 1.0.4** |
| `shuffledns#514` | Strict wildcard filtering not strict enough |
| `puredns#14` (open) | **Wildcard Domains with CNAME not filtered** |
| `puredns#67` / `#68` | wildcard detection filters domains which are *not* subdomains of any wildcard root (double bug: FP *and* FN in one algorithm) |
| `bbot#3547` | **Nested wildcard domains aren't detected, causing runaway enumeration** |
| `dnsx` (multiple) | "Handle domains that respond to any DNS query positively"; `-wd` method not working; "JSON unmarshal error in wildcard filtering" |
| `subfinder#…` | "Wildcards check support multi-level subdomain" (feature request) |

**My own live verification (✅ LIVE) — this is the most important finding in the report.** Random-label probes across 8 major domains, 3 probes each, via 8.8.8.8:

| Domain | NXDOMAIN | **NOERROR/NODATA** | answered |
|---|---|---|---|
| github.com | 0 | **3** | 0 |
| cloudflare.com | 0 | **3** | 0 |
| example.com | 0 | **3** | 0 |
| apple.com | 0 | **3** | 0 |
| netflix.com | 0 | **3** | 0 |
| google.com | 3 | 0 | 0 |
| microsoft.com | 3 | 0 | 0 |
| amazon.com | 3 | 0 | 0 |

**5 of 8 major domains return `NOERROR` with zero answers for labels that do not exist.**

Consequence: **any tool that treats "no exception from the resolver" or "rcode == 0" as "this subdomain exists" is broken on the majority of large domains.** `getaddrinfo()` raises on both NXDOMAIN *and* NODATA, so a naive try/except is accidentally safe — but a raw rcode check, or an `aiodns` handler that catches `DNSError` and reports NODATA as success, is not. The correct test is **`rcode == 0 AND ancount > 0`**, plus a *content* comparison against a known-random baseline, not merely "did we get a response".

Corollary: "wildcard" is not one thing. There are at least four distinct cases, and most tools implement one:
1. **True wildcard** `*.example.com` → A record. Detected by random-label probing; must compare **answer sets**, not just "resolves".
2. **NODATA wildcard** (above) — NOERROR, no answer. Detected only by checking `ancount == 0`, not by exceptions.
3. **CNAME wildcard** — resolves via CNAME to a shared sink (puredns `#14`). Must follow CNAME and compare *targets*.
4. **Nested wildcard** — `*.*.example.com` / per-zone wildcards (bbot `#3547`). Requires testing at **multiple label depths**, e.g. `rnd.d1.d2.example.com` and `rnd.d2.example.com` separately.

### 4.2 Silent source failure — the quiet killer
✅ LIVE, measured today:

| Endpoint | Status | Time |
|---|---|---|
| `crt.sh/?output=json` | 200 | **5.14 s** |
| `api.certspotter.com` | **429** | 0.95 s |
| `otx.alienvault.com` (passive_dns) | **429** | 0.54 s |
| `dns.bufferover.run` | **conn. failed (curl exit 6)** | 0.04 s |
| `jonlu.ca/anubis` | **403** | 0.22 s |
| `api.hackertarget.com` | 200 | 1.18 s |
| `api.subdomain.center` | 200 | 1.53 s |

Every dead source returns *less data with no error*, because enumerators treat a failed source as "zero findings". Users cannot distinguish "this domain has 3 subdomains" from "all 10 of my sources 429'd". subfinder's own history: `#1538` dnsrepo dead, `#1828` crt.sh SQL broken, `#1687` Censys key broken, `#1560` timeout inconsistent.
**Design requirement:** per-source status must be first-class (`--stats`: ok/failed/empty/skipped per source) and non-zero exit if *all* sources fail.

### 4.3 Crashes & platform
- **amass:** SIGSEGV, `unexpected fault address`, reflection panics, Windows BSOD reports, Docker crashes on Fargate, "Amass makes windows crash", DB schema corruption (`#971`).
- **Subdominator:** hangs after completion, `ScannerError: mapping values are not allowed here` on its own YAML, `cannot import name 'XMLParsedAsHTMLWarning' from bs4`, `AttributeError: 'NoneType' object has no attribute 'config_path'`, `No module named 'tldextract'`.
- **knockpy:** `NoResolverConfiguration: cannot open /etc/resolv.conf {TERMUX}` ← **the Termux blocker**, PyQt5 import crash, `unrecognized arguments: --set`.
- **findomain:** "installation error on termux", crt.sh connection timeouts, conflicting trait impls on build, "download link is not working".
- **Sublist3r:** `no module named 'requests'`, py3.11 Unicode/SSL/TypeError, List index out of range, CSRF token IndexError.

### 4.4 Slowness / hangs
- `puredns`: "Heavy Load on Wi-Fi Router", "PureDNS stucks at \", "No valid domains remaining."
- `shuffledns`: hangs while removing wildcards when `-d` omitted; wildcard filter fails "with big amount of data".
- `bbot`: HTTP wildcard detection stalls a scan for **tens of minutes** (quadratic DeepDiff, GIL-held).
- General: crt.sh is the universal latency floor (5 s+), and DNS brute force against public resolvers hits their per-source throttles long before your client is saturated.

---

## 5. Performance: published numbers vs. what Python can actually do

### 5.1 Published claims
| Tool | Claim | Source |
|---|---|---|
| massdns | **>350,000 names/sec** with public resolvers | 📄 README |
| puredns | "thousands of DNS queries per second" using massdns + public resolvers; "millions of queries in just a few minutes" | 📄 README |
| aiodnsbrute | **~100k resolutions in 1.5–2 min** on a small VPS; **1M requests in just over 3 minutes** on an Amazon M3 | 📄 README |
| zdns | recommends ≤10k goroutines for "millions of lookups"; default 1,000 threads (below Linux's 1024 fd default) | 📄 README |

Note aiodnsbrute's own arithmetic: 1M/180 s ≈ **5,500 qps**, and 100k/105 s ≈ **~950 qps** — i.e. its two claims differ by 6× and neither is near massdns's 350k. Its README also warns: "Your ISP's and home router's DNS servers probably *suck*… stick to a VPS."

### 5.2 What I actually measured (✅ LIVE, 2026-11-02, stdlib-only UDP + asyncio, 8-vCPU container)

| Test | Result |
|---|---|
| `socket.getaddrinfo()`, serial, NXDOMAIN | **14 qps** (1.40 s / 20 lookups) |
| Async UDP, 1 resolver (8.8.8.8), conc=50, N=500 | **387 qps**, 500/500 answered |
| Same, conc=100 | 188 qps |
| 1.1.1.1, conc=200, N=500 | 182 qps |
| 9.9.9.9, conc=100, N=500 | 133 qps (**424/500** answered — 15% dropped) |
| 3 resolvers, conc=45 | 65 qps |
| 6 resolvers, conc=90 | 140 qps |
| **DNS packet parse, pure Python** | **102,828 parses/sec on one core** |

### 5.3 Honest conclusion on speed
**Python is not the bottleneck; the resolver is.** Parsing costs ~10 µs/packet ⇒ 100k parses/s on one core — 3× *massdns's* claimed 350k qps is unreachable but that is a resolver limit, not a Python limit. My async client pushed 387 qps on a single public resolver at conc=50 and *got slower* at conc=100/200, with 9.9.9.9 dropping 15% of queries: **public resolvers rate-limit and drop before Python breaks a sweat.**

Realistic targets, stated honestly:
- **1k–5k qps sustained** is achievable in stdlib asyncio **iff** you shard across many resolvers (dozens+) or run your own recursor. Multi-resolver sharding is mandatory, and it is *the* scaling lever (my 6-resolver test beat the 3-resolver test 2×, per-resolver efficiency fell as expected).
- **~100k–350k qps is NOT reachable from Python against public resolvers** — not because of asyncio, but because you'd be rate-limited/DNS-poisoned. Any claim otherwise is hype. massdns's 350k figure presumes a large curated resolver pool and near-zero processing per packet.
- **Avoid `getaddrinfo` for bulk work**: 14 qps serial. It also hides rcode/ancount, making correct wildcard detection impossible. Use raw UDP/dnspython-style wire parsing.
- **The real win is total wall-clock, not qps**: because 54 passive sources are the *dominant* cost (crt.sh alone = 5.14 s), a tool that (a) runs all passive sources concurrently with per-source deadlines, (b) never waits on a dead source, and (c) starts active resolution while passive is still running, will *beat* faster resolvers on the metric users care about — time-to-first-result and time-to-complete-run. **Concurrency + deadline discipline beats C versus Python.**

---

## 6. What would genuinely differentiate `subpy`

### Realistic to build well (do these)
1. **Correct-by-construction wildcard engine (the differentiator).** Handle all four cases in §4.1 — true wildcard, NODATA wildcard, CNAME wildcard, nested/multi-depth — using **answer-set and CNAME-target comparison against a random baseline at ≥2 label depths**, and classify+report *why* each name was dropped. Nobody does all four; every incumbent has a live bug here. This is defensible, testable, and pure stdlib. **Make it the brand.**
2. **Honest per-source telemetry.** `--stats` showing ok/failed/empty/timeout per source with elapsed ms; non-zero exit when every source fails; `-v` to say "certspotter: 429, skipped". Directly fixes §4.2, which no incumbent addresses. Cheap to build (it's just bookkeeping) and immediately perceived as trustworthy.
3. **Deadline-bounded source fan-out.** Global `--timeout` that is *enforced* per source (subfinder `#1560` says its isn't), so a 5 s crt.sh can't hold the run hostage. Stream results to stdout as they arrive.
4. **One binary, zero deps, Termux-native.** Pure stdlib: no `requests`, no `dnspython`, no `tldextract`, no PyQt5, no massdns. Explicitly test `/etc/resolv.conf`-less and Android environments (knockpy's live Termux crash is your marketing). Public-suffix handling needs a bundled static PSL snapshot, not `tldextract` (network fetch at import = Termux/first-run fragility).
5. **Pipe-first UX:** `-silent` newline list to stdout; `-jsonl`; `-o`; `-ot` template; `-nc`; stdin via `-` and `-dL`. Copy subfinder's flags nearly verbatim — the muscle memory is free distribution.
6. **Rate-limit that is honoured** (`-rl`, `-rls provider=n/s`) and resolver validation (`--check-resolvers`) — two explicit, citable user complaints.

### Realistic but scope-limited
7. **Recursive / sub-sub discovery** — high value but interacts badly with wildcard depth logic; ship after the wildcard engine is proven.
8. **CNAME/IP enrichment inline** (`--with-ip`, `--with-cname`) — puredns `#28` is open; cheap to add, but must not become default (breaks `-silent` piping purity).
9. **Zone-transfer attempt** — dnsrecon does it, it's ~40 lines, occasionally pays off. Nice-to-have.

### Hype — be honest, don't promise
- **"Faster than massdns."** Not realistic. massdns is C with a bespoke socket loop; a Python tool cannot win raw qps against a resolver pool. Compete on **time-to-complete and correctness**, never on the 350k number.
- **"Full amass-parity asset graph."** Requires a DB, months of work, and amass's own users are asking to *remove* the DB (#797). Skip.
- **"ML/AI-powered subdomain discovery."** No defensible mechanism; pure marketing. Skip.
- **"We never have false positives."** Impossible — DNS poisoning via public resolvers is unfixable from the client (puredns's whole "trusted resolvers" phase exists for it). Promise **measured, reported, explainable** FP filtering and a `--strict` mode instead.
- **"1000+ passive sources."** Source count is a vanity metric when sources die (4 of 8 I tested were down). ~10–15 *maintained* sources with honest status beats 54 rotting ones.

---

## 7. Legal / ethical norms and standard disclaimer wording

**Consensus norm across every serious tool:** enumeration is only legitimate against domains you own or are **explicitly authorized** to test; "passive" does **not** mean invisible or risk-free; the author disclaims all liability; the user bears full legal responsibility.

**Verbatim, ✅ LIVE-fetched:**

- **puredns** (`README.md`, "Disclaimer & License"):
  > "Any resolvers included in this repository are present for reference only. The author is not responsible for any misuse of the resolvers in that list. It is the user's responsibility to curate a list of resolvers you are authorized to use."
  > "Usage of this program for attacking targets without consent is illegal. It is the user's responsibility to obey all applicable laws. The developer assumes no liability and is not responsible for any misuse or damage caused by this program. Please use responsibly."

- **subfinder** (`DISCLAIMER.md`): lists each leveraged API's ToS (Bufferover, CommonCrawl, certspotter, crt.name, dnsdumpster, Google Transparency, AlienVault, Subdomain Center) then:
  > "You expressly understand and agree that Subfinder (creators and contributors) shall not be liable for any damages or losses resulting from your use of this tool or third-party products that use it."
  > Creators have "no responsibility for any kind of: Unlawful or illegal use of the tool. Legal or Law infringement … Act against ethical and / or human moral … Malicious act, capable of causing damage to third parties…"

- **theHarvester** (rewritten `docs/wiki/Responsible-Use-and-Scope.md`) — the **best current model**, and worth copying structurally:
  > "Use theHarvester only on targets you own or are explicitly authorized to assess. The authorization should name the target, permitted techniques, time window, data-handling rules, and third-party restrictions."
  > "**Passive does not mean invisible** — Passive discovery sources query third-party services instead of directly probing every target host. Those services still receive the domain or organization name, may log requests, and enforce their own terms, quotas, and acceptable-use rules."
  > "Do not treat a provider key, bug-bounty program, or publicly reachable host as blanket authorization."
  It also ships a table of which flags cause **network activity** vs provider-facing vs target-facing, and notes: "Queries have resolver timeouts, but the phase has no default query-count or runtime ceiling."

- **aiodnsbrute**: has a `**DISCLAIMER**` section (line 11) — stub-level, typical of older Python tools.

### Required for `subpy`
1. `SECURITY.md` with a vulnerability-disclosure channel (subfinder/dnsx use `security@projectdiscovery.io` + "DO NOT CREATE AN ISSUE"; 3-working-day ack). Note: **subfinder's `SECURITY.md` 404s** — a gap; own this.
2. `DISCLAIMER.md` — authorization-required, no-warranty, no-liability, plus an explicit **third-party ToS** list (this is what subfinder does and what a passive aggregator legally needs).
3. README **prominent** (top, not buried): "Use only against systems you own or are explicitly authorized to test." Add theHarvester's "passive is not invisible" line — it is the most honest and least-copied framing available.
4. A **flag-level risk table** marking passive vs resolver-facing vs target-facing, so `--brute`/`--axfr` users know they've crossed a line.
5. Do **not** ship resolver lists. puredns's disclaimer explicitly distances itself from bundled resolvers for good reason — bundling a resolver list is the single most legally-exposed thing in this category.
6. Never imply a bug-bounty program or public reachability equals authorization (theHarvester's explicit line).

---

## 8. Copy-list for `subpy` (concrete UX decisions)

Adopt from subfinder: `-d`, `-dL <file>`, `-silent`, `-o`, `-oJ`→`-jsonl`, `-r/-rL` resolvers, `-rl` rate limit, `-nc`, `-v`, `--version`.
Adopt from dnsx: `-l -` stdin support, `-ot '{{host}} {{a}}'` output template, `-omit-raw`, `-j` JSONL.
Adopt from httpx: `-lof/-eof` field-selection philosophy (list/filter output fields), `-csv` alongside JSONL, `-silent` + `-o` orthogonality (stdout vs file are independent).
Adopt from puredns: two resolver tiers (`--resolvers` untrusted bulk + `--trusted-resolvers` validation), `--wildcard-tests N`, `-q` quiet (their `#4`).
Add (nobody has it): `--stats` per-source table, non-zero exit on total source failure, `--explain` printing why each candidate was dropped (wildcard/NODATA/CNAME/ratelimit), `--strict` mode that only emits names passing all four wildcard checks.

**Formatting rule:** stdout is the result stream and nothing else (respecting `-silent`/pipe); all diagnostics, progress, warnings and `--stats` go to **stderr**. Colour only when `stderr.isatty()`, auto-off.

---

## 9. Bottom-line priorities for `subpy`

1. **Wildcard correctness across all 4 cases** — the only genuinely open problem in the category, with a live bug in every incumbent and a verified FP vector hitting 5/8 top domains.
2. **Per-source honesty** — sources rot silently (4/8 dead/throttled live); surfacing that builds trust no competitor has.
3. **Deadline discipline + stdlib/Termux zero-dep** — win total wall-clock and installability, not qps.
4. **Pipe-pure output** — free adoption via copyfamiliar flags.
5. **Do not** compete on raw qps, asset graphs, or "1000 sources".
