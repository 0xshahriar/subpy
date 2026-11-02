<div align="center">

# subpy

**A fast, dependency-free subdomain finder that runs anywhere — including Termux.**

[![CI](https://github.com/0xShahriar/subpy/actions/workflows/ci.yml/badge.svg)](https://github.com/0xShahriar/subpy/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/subpy?style=flat-square)](https://pypi.org/project/subpy/)
[![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Termux-lightgrey?style=flat-square)](#install)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen?style=flat-square)](#why-subpy)
[![Termux](https://img.shields.io/badge/Termux-supported-000000?style=flat-square&logo=android&logoColor=white)](#termux--android)

</div>

> [!WARNING]
> **Use subpy only on domains you own or have explicit written permission to test.**
> Unauthorized scanning may be illegal in your jurisdiction. Read the [full disclaimer](#legal).

## Why subpy?

- **Zero hard dependencies.** Pure Python standard library, 3.9 and up. No Go, no Rust,
  no `dig`, no `gobuster`, no compile step — `pip install subpy` and you are done.
- **Termux is a first-class target.** Works on Android with a single `pkg install python`,
  including the network quirks mobile carriers introduce.
- **Wildcard handling that actually holds up.** All four cases are fingerprinted —
  true, NODATA, CNAME, and nested — using address-*set* and CNAME-chain comparison
  rather than single-IP guessing.
- **Passive and active in one binary.** 21 passive sources, a curated 1211-word list,
  a permutation engine, AXFR attempts and NSEC walking, all behind one command.
- **Flags what others miss.** A CNAME pointing at an unclaimed host is reported as
  `dangling` — a subdomain-takeover candidate, which is usually the most actionable
  thing a scan can surface.
- **Output that stays out of the way.** Clean terminal listing plus `txt`, `json`,
  `csv`, `md` and `html` for whatever consumes it next.

## Install

### pip

```bash
pip install subpy
```

### pipx (isolated)

```bash
pipx install subpy
```

### Termux / Android

```bash
pkg install python
pip install subpy
```

No `clang`, no `rust`, no NDK toolchain. If DNS is filtered on mobile data,
subpy falls back to DNS-over-HTTPS automatically.

### From source

```bash
git clone https://github.com/0xShahriar/subpy.git
cd subpy
pip install -e .
```

### Verify

```bash
subpy --version
```

## Quick start

**Default run — passive sources and brute force together:**

```bash
subpy -d hackerone.com
```

```text
> hackerone.com passive+active
support.hackerone.com          162.159.140.147  active
docs.hackerone.com             172.64.151.42    active
a.ns.hackerone.com             162.159.0.31     passive, rapiddns
mta-sts.hackerone.com          185.199.108.153  certspotter, crtsh +2
gslink.hackerone.com           18.155.106.42    certspotter, crtsh +2
url824.advocacy.hackerone.com  172.64.154.133   certspotter, passive
fwdkim1.hackerone.com          dangling  cname:spfmx1.domainkey.freshemail.io

────────────────────────────────────────────────────────
       found 15          time 26s       queries 2245 (212/s)       passive 521
       brute 4      dangling 1
────────────────────────────────────────────────────────
```

*(Real output, trimmed for width. `dangling` marks a CNAME pointing at an
unclaimed host — a subdomain-takeover candidate.)*

**Passive only — fastest mode, nothing touches the target directly:**

```bash
subpy -d example.com -p
```

**Active only, with your own wordlist:**

```bash
subpy -d example.com -a -w words.txt --wordlist-limit 5000
```

**Write structured output for a report:**

```bash
subpy -d example.com -o results.json -f json
subpy -d example.com -o results.md -f md
```

**Pipe to anything:**

```bash
subpy -d example.com -q | httpx -silent
```

## What it gets right

These are measured, not claimed. Each one is a documented failure mode of
existing tools.

| Behaviour | Why it matters |
| --- | --- |
| Existence = non-empty answer section | `example.com`, `cloudflare.com`, `github.com` and `apple.com` all return `NOERROR` with zero answers for names that do not exist. Trusting `NXDOMAIN` gave 104 false positives in 105 probes. |
| Rotating wildcards corroborated by a control probe | `vercel.app` derives a different address per label inside one `/24`, so address-set matching can never fire. 10/10 random labels still filtered, 0 real hosts lost. |
| 44 verified wildcard suffixes | 30 other "wildcard" suffixes in circulation (`cloudfront.net`, `azurewebsites.net`, `fly.dev`, `herokudns.com`) return `NXDOMAIN` for random labels. Treating them as wildcards deletes real subdomains. |
| 16 in-flight queries per resolver | Public resolvers drop packets silently rather than sending `SERVFAIL`. 16 measured fastest at 328 qps with 0% loss; 64 cost 30% throughput and lost 2.5%. |
| Least-in-flight resolution, not fastest-first | Ranking by RTT sends every query to one server until it throttles, collapsing a 500 qps pool to 30 qps. |

## Usage

```text
subpy -d DOMAIN [options]
```

| Flag | Value | Description |
| --- | --- | --- |
| `-d`, `--domain` | host | Target domain to enumerate (required) |
| `-p`, `--passive-only` | — | Passive sources only; never query the target |
| `-a`, `--active-only` | — | Brute force, permutations and AXFR only |
| `--no-permutations` | — | Disable sibling generation from found hosts |
| `-w`, `--wordlist` | path | Extra wordlist file or built-in name (repeatable) |
| `--wordlist-limit` | int | Truncate the wordlist to the top N entries (default `0` = no cap) |
| `-o`, `--output` | path | Write results to a file |
| `-f`, `--format` | fmt | `txt`, `json`, `csv`, `md`, `html` |
| `-r`, `--resolver` | ip list | Comma-separated resolvers (default: system + public pool) |
| `-c`, `--concurrency` | int | Concurrent queries (default `200`) |
| `-t`, `--timeout` | float | Per-query timeout in seconds (default `2.0`) |
| `--no-wildcard` | — | Disable wildcard detection and filtering |
| `--wildcard-samples` | int | Random probes per zone level (default `3`) |
| `-s`, `--sources` | list | Comma-separated sources to use |
| `--exclude-sources` | list | Comma-separated sources to skip |
| `--list-sources` | — | Print every source and exit |
| `-v`, `--verbose` | — | Per-source timings, errors and query stats |
| `-q`, `--quiet` | — | Hostnames only on stdout, nothing else |
| `--no-color` | — | Disable ANSI colour |
| `--no-update-check` | — | Skip the GitHub release check |
| `--include-unresolved` | — | Emit passive hits that do not resolve |
| `--json` | — | Shorthand for `-f json` on stdout |

### Environment variables

| Variable | Effect |
| --- | --- |
| `SUBPY_RESOLVER` | Default resolver, used when no system resolver is found |
| `SUBPY_NO_UPDATE` | Set to any value to disable the update check |
| `NO_COLOR` | Disable colour (honoured before `FORCE_COLOR`) |
| `FORCE_COLOR` | Force colour even when stdout is not a TTY |

API keys are read from the environment too — `CENSYS_API_ID`, `SHODAN_API_KEY`,
`VIRUSTOTAL_API_KEY` and friends. See [SOURCES.md](SOURCES.md) for the full list.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed (with or without results) |
| `1` | Runtime error, or nothing found when `--fail-empty` is set |
| `2` | Usage error |
| `130` | Interrupted (Ctrl-C) — partial results are still written |
| `143` | Terminated (SIGTERM) — partial results are still written |

A completed scan exits `0` even when it finds nothing, so subpy composes
cleanly in pipelines. Pass `--fail-empty` if you want a non-zero code in that
case.

## Output formats

### `txt`

```text
api.example.com
dev.example.com
mail.example.com
```

### `json`

```json
{
  "host": "api.example.com",
  "sources": ["crtsh", "hackertarget"],
  "resolved": true,
  "alive": true,
  "ip": ["203.0.113.31"],
  "ipv6": [],
  "cname": [],
  "ttl": 300,
  "rcode": "NOERROR",
  "latency_ms": 41.7,
  "wildcard": false,
  "error": ""
}
```

### `csv`

```csv
host,ip,cname,sources,ttl,latency_ms
api.example.com,203.0.113.31,,crtsh|hackertarget,300,41.7
dev.example.com,203.0.113.24,,crtsh|rapiddns,300,38.2
```

### `md`

```markdown
| Host | Address | Sources |
| --- | --- | --- |
| api.example.com | 203.0.113.31 | crtsh, hackertarget |
| dev.example.com | 203.0.113.24 | crtsh, rapiddns |
```

### `html`

A single self-contained file — inline CSS, no JavaScript, no external assets —
so it opens on a phone or attaches to a report without leaking a request.

## How it works

```text
  target domain
        |
        v
  +---------------------+
  | wildcard fingerprint|   random-label probes at apex + each hit depth
  +---------------------+
        |
        +--> passive sources ------+
        +--> brute force ----------+--> dedupe --> resolve --> wildcard
        +--> permutations ---------+                 |          filter
        +--> AXFR / NSEC walk -----+                 v
                                               report (5 formats)
```

Every candidate is resolved and passes the wildcard manager before it reaches
you. One dead API can never sink a scan: each source runs isolated and its
failure is reported, not fatal.

## Wildcard handling

Wildcard DNS is the single largest source of false positives in subdomain
enumeration. subpy fingerprints each zone level and handles four distinct
cases:

- **True wildcard** — `*.example.com` answers with a stable address set.
  Matching answers are subtracted.
- **NODATA wildcard** — the name exists but returns no address. Detected from
  the response shape, not from a missing A record.
- **CNAME wildcard** — the answer is a CNAME chain into shared SaaS
  infrastructure. Matched on the chain, not on the final IP.
- **Nested wildcard** — `*.internal.example.com` exists independently of
  `*.example.com`, so each depth that produces hits gets its own fingerprint.

Detection compares the full observed address **set** and the CNAME chain across
multiple random labels, which survives round-robin and rotating-IP wildcards.

Where set comparison is ambiguous — zones that derive a different address per
label inside a single network block, as `vercel.app` does — a fresh control
probe is issued and compared directly, so a real host is never discarded and
noise is never reported.

### Subdomain takeover detection

A name whose CNAME target does not resolve is reported as `dangling`. That is
the classic subdomain-takeover setup: whoever registers the target inherits
the hostname. When the target sits in known shared hosting, the hint names the
provider so you know what to claim or report:

```text
fwdkim1.hackerone.com   dangling  cname:spfmx1.domainkey.freshemail.io
```

## Sources

21 passive sources ship built in. Twelve need no key at all.

| Group | Count | Examples |
| --- | --- | --- |
| Certificate Transparency | 4 | crt.sh, Cert Spotter, Meta CT, Censys |
| Public DNS datasets | 7 | HackerTarget, RapidDNS, subdomain.center, Chaos |
| Web crawl archives | 3 | Wayback Machine, Common Crawl, urlscan.io |
| Threat intelligence | 7 | AlienVault OTX, VirusTotal, Shodan, SecurityTrails |

Full details — env vars, free-tier limits, reliability ratings and notes — live
in **[SOURCES.md](SOURCES.md)**. List them from the CLI with `subpy --list-sources`.

## Legal

**Authorized use only.**

subpy sends DNS queries and HTTP requests to third-party services and, in
active mode, to the target itself. Running it against infrastructure you do not
own or have not been contracted to test may violate computer-misuse laws,
terms of service, or both — in most jurisdictions that includes the Computer
Fraud and Abuse Act, the UK Computer Misuse Act and similar statutes elsewhere.

By using subpy you agree that:

- You are solely responsible for how you use it and for the targets you choose.
- You will obtain explicit written permission before testing any domain that is
  not yours.
- The author accepts no liability for damage, legal consequence or service
  disruption caused by your use of this tool.

If you find a vulnerability in a host, report it responsibly to that host's
owner. See [SECURITY.md](SECURITY.md).

## Contributing

Bug reports, new passive sources and doc fixes are all welcome. Start with
[CONTRIBUTING.md](CONTRIBUTING.md) and please read the
[Code of Conduct](CODE_OF_CONDUCT.md).

```bash
git clone https://github.com/0xShahriar/subpy.git
cd subpy
python -m pytest
```

## License

Released under the [MIT License](LICENSE) © 2026 Md. Shahriar Alam Shaon.

## Author

**Md. Shahriar Alam Shaon** — [@0xShahriar](https://github.com/0xShahriar)

[Twitter/X](https://x.com/0xShahriar) ·
[Facebook](https://facebook.com/0xShahriar) ·
[Instagram](https://instagram.com/0xShahriar) ·
[LinkedIn](https://linkedin.com/in/0xShahriar) ·
[GitLab](https://gitlab.com/0xShahriar) ·
[sadjoker.localhost@gmail.com](mailto:sadjoker.localhost@gmail.com)

<div align="center">
<sub>Built to run on the phone in your pocket, not just the laptop on your desk.</sub>
</div>
