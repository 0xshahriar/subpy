# Passive Sources

`subpy` ships with 21 passive sources. A passive source only reads data that
other parties already published — certificate transparency logs, public DNS
datasets, web archives and threat-intel APIs — so it never sends traffic to the
target itself.

Ten of them work with no key at all. The rest activate automatically the moment
their environment variable is set.

List the live registry from the CLI:

```bash
subpy --list-sources
```

---

## No key required

These run out of the box. The two with an optional key get a higher quota when
you provide one.

| Source | Category | Auth | Free tier | Reliability | Notes |
| --- | --- | --- | --- | --- | --- |
| `crtsh` | CT | none | Free, unmetered | 0.85 | crt.sh certificate search. The workhorse source |
| `certspotter` | CT | optional `CERTSPOTTER_API_KEY` | Free, key optional | 0.90 | SSLMate Cert Spotter. Highest-confidence CT feed |
| `facebookct` | CT | none | Free, unmetered | 0.80 | Meta certificate transparency monitor |
| `hackertarget` | DNS | none | Free, ~50 queries/day | 0.70 | Host search API; the tightest daily cap here |
| `rapiddns` | DNS | none | Free, unmetered | 0.65 | RapidDNS record index, HTML scrape |
| `subdomain-center` | DNS | none | Free, unmetered | 0.60 | Aggregated third-party index |
| `wayback` | crawl | none | Free, unmetered | 0.60 | Wayback CDX index; needs patience |
| `commoncrawl` | crawl | none | Free, unmetered | 0.55 | Common Crawl URL index; slowest, widest |
| `urlscan` | crawl | optional `URLSCAN_API_KEY` | Free, key raises quota | 0.65 | urlscan.io public scan index |
| `otx` | intel | optional `OTX_API_KEY` | Free, key raises quota | 0.70 | AlienVault OTX passive DNS |

## Key gated

A source stays silent until its environment variable is present. `subpy` reports
it as *skipped: missing KEY* in `-v` output rather than failing the scan.

| Source | Category | Environment variable | Free tier | Reliability | Notes |
| --- | --- | --- | --- | --- | --- |
| `virustotal` | intel | `VIRUSTOTAL_API_KEY` | Free account | 0.80 | Subdomain relationships endpoint |
| `shodan` | intel | `SHODAN_API_KEY` | Free account | 0.70 | DNS domain listing |
| `securitytrails` | intel | `SECURITYTRAILS_API_KEY` | Free account | 0.85 | Strong historical DNS, low quota |
| `chaos` | DNS | `CHAOS_KEY` | Free with signup | 0.85 | ProjectDiscovery Chaos dataset |
| `binaryedge` | intel | `BINARYEDGE_API_KEY` | Free account | 0.70 | Subdomain index |
| `censys` | CT | `CENSYS_API_ID` | Free account | 0.75 | Certificate search API |
| `netlas` | DNS | `NETLAS_API_KEY` | Free account | 0.70 | Domain WHOIS and DNS index |
| `fullhunt` | intel | `FULLHUNT_API_KEY` | Free account | 0.70 | Attack-surface API |

## Opt-in and unreliable

These three are excluded from a default run because the upstream services have
been broken, rate-limited into uselessness, or shut down. They are kept so that
existing habits still work when the service recovers, and can be requested
explicitly with `-s anubis,threatcrowd,dnsdumpster`.

| Source | Category | Auth | Status | Reliability | Notes |
| --- | --- | --- | --- | --- | --- |
| `anubis` | DNS | none | Opt-in | 0.60 | Intermittent availability |
| `threatcrowd` | intel | none | Opt-in | 0.45 | Service frequently offline |
| `dnsdumpster` | DNS | none | Opt-in | 0.50 | CSRF flow; breaks whenever the page changes |

---

## Rate limiting

Every source declares a soft rate — a request-per-second budget — and `subpy`
enforces it with a per-host token bucket before any request leaves the process.
That is why a scan looks slow in the first second and then settles: the
throttle is deliberate, not a stall.

Rate limits exist to protect three different things:

1. **Your account.** Key-gated APIs suspend keys that burst. A scan that trips
   a quota costs you the source for the whole day.
2. **The service.** Free CT logs and DNS datasets absorb enormous public load
   on donated infrastructure.
3. **The scan itself.** Aggressive concurrency against a rate-limited endpoint
   produces `429` responses, which cost more wall-clock time than pacing does.

Retries use exponential backoff with jitter on `429` and `5xx` responses. A
source that cannot complete inside its timeout is reported and abandoned; it
never blocks the rest of the scan.

## Why some sources are opt-in

A default run should be boring. Three sources break that promise often enough
to be excluded:

- **ThreatCrowd** has been intermittently offline for extended periods.
- **DNSDumpster** requires a CSRF token dance that breaks whenever the page
  markup changes.
- **Anubis** responds inconsistently, so it contributes latency without
  contributing many hosts.

Each one still appears in `--list-sources`, and each still works when the
upstream service does. Enabling them is one flag away.

## Supplying API keys

Keys are read from the environment at scan time — never written to disk, never
sent anywhere except the provider that owns them.

**Shell, current session:**

```bash
export SHODAN_API_KEY="your-key-here"
subpy -d example.com
```

**Shell, permanent:**

```bash
echo 'export SHODAN_API_KEY="your-key-here"' >> ~/.bashrc
```

**One command only:**

```bash
SHODAN_API_KEY="your-key-here" subpy -d example.com
```

**Termux:** identical — the same `export` works in the Termux shell.

**Windows PowerShell:**

```powershell
$env:SHODAN_API_KEY = "your-key-here"
```

On a shared machine, prefer the one-command form so the key never lands in your
shell history or in the environment of unrelated processes.

## Selecting sources

```bash
subpy -d example.com -s crtsh,certspotter,chaos    # exactly these
subpy -d example.com --exclude-sources wayback      # everything but these
subpy -d example.com -p                             # passive only, never touch the target
```

Source names are the identifiers in the first column of the tables above.
