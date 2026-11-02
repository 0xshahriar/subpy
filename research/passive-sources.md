# Passive Subdomain Enumeration Sources — Implementation Reference

**Target:** Python subdomain finder, stdlib-first, Termux/Android friendly (no `requests`, no compilers).
**Verification session:** 2026-11-02 (02:59–04:15 UTC and 09:20–09:45 UTC), via `curl` 8.18.0 + CPython 3.14 against live endpoints from a single IPv4 egress.
**Legend for `VERIFIED`:** `✅ 200` = endpoint answered with real payload this session · `⚠️` = answered but degraded/unusable as-is · `🔑` = reachable, auth required · `💀` = dead/DNS-dead/decommissioned.

> All response snippets below are trimmed real output captured in this session. Nothing here is from memory alone.

---

## 1. Master table

| # | Source | Auth | Endpoint | Format | VERIFIED | Rating |
|---|--------|------|----------|--------|----------|--------|
| 1 | crt.sh HTTP | none | `https://crt.sh/?q=%25.{dom}&output=json&exclude=expired` | JSON array | ✅ 200 (flaky) | **A** |
| 1b | crt.sh Postgres | none (`guest`/`certwatch`) | `crt.sh:5432` TLS | SQL | ✅ 200 (conn-capped) | B |
| 2 | Cert Spotter v1 | none (anon tier) | `https://api.certspotter.com/v1/issuances` | JSON array | ✅ 200 | **A−** |
| 3 | HackerTarget hostsearch | none | `https://api.hackertarget.com/hostsearch/?q={dom}` | text CSV | ✅ 200 | C |
| 4 | RapidDNS | none (HTML) | `https://rapiddns.io/subdomain/{dom}?full=1` | HTML | ⚠️ 200, paging dead | B− |
| 5 | AlienVault OTX passive_dns | **API key now** | `https://otx.alienvault.com/api/v1/indicators/domain/{dom}/passive_dns` | JSON | ⚠️ 429 anon | D (anon) |
| 6 | urlscan.io search | none | `https://urlscan.io/api/v1/search/?q=page.domain:{dom}` | JSON | ✅ 200 | B |
| 7 | VirusTotal v3 | `x-apikey` | `https://www.virustotal.com/api/v3/domains/{dom}/subdomains` | JSON | 🔑 401 | B (with key) |
| 8a | SecurityTrails | `APIKEY` | `https://api.securitytrails.com/v1/domain/{dom}/subdomains` | JSON | 🔑 401 | B (paid) |
| 8b | Shodan `dns/domain` | key (anon = cache-hits only) | `https://api.shodan.io/dns/domain/{dom}` | JSON | ⚠️ inconsistent | C |
| 8c | Censys | yes | `api.platform.censys.io/v3/...` | JSON | 💀 legacy dead | D |
| 9 | Chaos dataset | none for zips | `https://chaos-data.projectdiscovery.io/index.json` | JSON + zip | ✅ 200 | B (scoped) |
| 10 | Facebook CT API | — | `graph.facebook.com/certificates` | JSON | 💀 400 | D |
| 11 | AnubisDB (new host) | none | `https://anubisdb.com/anubis/subdomains/{dom}` | JSON array | ✅ 200 (noisy) | C+ |
| 11b | AnubisDB (old hosts) | — | `jldc.me` / `jonlu.ca` | — | 💀 403 / 301 | D |
| 12 | ThreatMiner | none | `https://api.threatminer.org/v2/domain.php` | JSON | 💀 522 | D |
| 13 | Search engines (Baidu/Bing/Google/DDG) | — | — | HTML | 💀 blocked/empty | D |
| 13b | Mojeek | none | `https://www.mojeek.com/search?q=site:{dom}` | HTML | ⚠️ 200, ~0 yield | D+ |
| 14 | Common Crawl index | none | `https://index.commoncrawl.org/{coll}-index?url=*.{dom}` | JSONL | ⚠️ 504-heavy | D+ |
| 15 | Wayback CDX | none | `https://web.archive.org/cdx/search/cdx?url=*.{dom}` | JSON | ⚠️ 503-heavy | D+ |
| 16 | (dup of 5) | — | — | — | — | — |
| 17 | DNSDumpster | none (no CSRF!) | `POST https://dnsdumpster.com/htmld/` | HTML frag | ✅ 200 | B− |
| 18 | Netcraft | — | `api.netcraft.com/search/api/json/` | JSON | 💀 404/403 | D |
| 19 | bufferover.run | — | `dns.bufferover.run` | — | 💀 NXDOMAIN | D |
| 20 | Riddler | — | `riddler.io` | — | 💀 NXDOMAIN | D |
| 21 | Rapid7 Sonar FDNS | gated | `sonardata.rapid7.com/sonar.fdns_v2/` | .gz | ⚠️ 302→gate | D |
| 22 | CertStream | none | `wss://certstream.calidog.io` | WSS | ⚠️ 101, no frames | C |
| 23 | subdomain.center | none | `https://api.subdomain.center/?domain={dom}` | JSON | ✅ 200 | B− |
| 24 | HackerTarget reverse IP | none | `https://api.hackertarget.com/reverseiplookup/?q={ip}` | text | ✅ 200 | C |
| 25 | DNSRepo | — | `dnsrepo.nixway.com` | — | 💀 NXDOMAIN | D |
| — | ct.fr-par.scw.cloud | — | — | — | 💀 NXDOMAIN | D |
| — | ctsearch.entrust.com | — | — | — | 💀 NXDOMAIN | D |
| — | ui.ctstream.me | — | — | — | 💀 NXDOMAIN | D |
| — | merkle.town | — | — | — | 💀 NXDOMAIN | D |
| — | sonar.omnisint.io | — | — | — | 💀 404 | D |

---

## 2. crt.sh

### 2.1 HTTP JSON endpoint (primary)

```
GET https://crt.sh/?q=%25.{domain}&output=json&exclude=expired
```
`%25` is the URL-encoded `%` wildcard, i.e. `q=%.example.com`. Also accepts `identity=%25.{domain}` (lowercase `identity` returned 200; capitalised `Identity=` returned 502 in one sample — treat as flaky, not semantic).

**Auth:** none. No key, no cookie, no UA requirement (tested `-A 'subpy/1.0'` → 200).

**Response (verified, `q=%25.github.com&exclude=expired`, 84 rows / 28 KB):**

```json
[{"issuer_ca_id":204406,
  "issuer_name":"C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV R36",
  "common_name":"github.com",
  "name_value":"garage.github.com\ngist.github.com\ngithub.com\nwww.github.com",
  "id":29824981846,
  "not_before":"2026-10-14T00:00:00",
  "not_after":"2027-01-11T23:59:59",
  "serial_number":"628ce509d633e3e4de237be5e4e0e4f5",
  "result_count":5}]
```

**Extraction:** `name_value` is a **newline-separated** list of SANs (not one name per row). Union `name_value` and `common_name`; split on `\n`; strip; lowercase.

**Parameters that matter:**

| Param | Verified behaviour |
|---|---|
| `output=json` | array of cert objects |
| `output=csv` | `crt.sh ID,Not Before,Not After,Common Name, Matching Identities, Issuer Name` — verified 200 |
| `output=json3` | **not supported**: returns `<BR><BR>Unsupported output type: json3</BODY>` (HTTP 200, non-JSON) |
| `exclude=expired` | ✅ works. In-scope names drop 143 → 45 for `github.com`; 0 rows with `not_after < now` |
| `exclude=none` | same as omitting (1238 rows) |
| `deduplicate=Y` | ⚠️ works when it 200s (84 → 48 rows, same 45 unique names) but 404/502 intermittently. Do not depend on it |
| `limit=N` | ⚠️ mostly ignored: `limit=5`/`limit=20` → 502; `limit=100` → 200 with all 84 rows |
| `offset=N` | ⚠️ ignored (identical first row and row count for `offset=0` and `offset=100`) |

**Pagination:** none usable. The endpoint returns the full result set; you cannot page. This is the main scaling limit — a high-fan-out apex can return megabytes in one shot (`amazon.com`: 821 KB / 1767 rows / 800 unique names / 23 s).

**Rate limits:** undocumented. Observed: no `Retry-After`, no rate-limit headers. **502s are the rate limit.**

Measured reliability this session:

| Test | Result |
|---|---|
| 12 sequential requests, 1 s apart (unique domains) | 11×200, 1×502 |
| 5 parallel requests | 4×200, 1×502 |
| 10 requests on unrelated throwaway domains | 4×200, 6×502 (after long session) |
| 10 domains × up to 3 retries | **10/10 succeed** |
| Latency when successful | 0.85 s – 14 s (typical 1–6 s); `amazon.com` 23 s |
| Failure latency | 0.8–1.1 s (fast 502) or 60 s+ hang |

**Quirks:**
- Returns `*.` wildcard entries verbatim (`*.github.com`, `*.registry.github.com`) — 18 of 800 names for `amazon.com`. Must be stripped *and* the wildcard's children treated as wildcard-resolved (see §7).
- Returns the **apex** (`github.com`) in the set.
- Returns **non-hostname junk** in `name_value`: verified real junk `https://github.com/LeviMarvin/OFCA` (a URL SAN) and `support@github.com` (an **email SAN**). Regex-filter to `^(\*\.)?([a-z0-9_-]+\.)+[a-z]{2,}$`.
- **IDN:** input must be **punycode**. `q=%25.xn--mnchen-3ya.de` → 200 with `xn--mnchen-3ya.de`. `q=%25.münchen.de` (unicode) → `[]` (empty, not an error).
- **Case:** output already lowercase (0 uppercase names observed). No trailing dots observed.
- Cross-domain contamination: `q=%.github.com` can return `*.github.io`-style names only via the Cert Spotter route, not crt.sh — but `name_value` can still carry unrelated SANs from a shared cert; always filter to `== apex or endswith('.'+apex)`.

### 2.2 crt.sh Postgres interface

**Verified live** — this is the most under-documented part and it does work:

```
host=crt.sh port=5432
SSLRequest  -> 'S'   (TLSv1.2 negotiated)
StartupMessage user=guest database=certwatch -> AuthenticationOk (code 0, trust)
server_version: PostgreSQL 12.14 on x86_64-pc-linux-gnu (Gentoo Hardened 9.3.0)
```

39 tables in `public`. Relevant objects:

| Object | Notes |
|---|---|
| `certificate(id, issuer_ca_id, certificate)` | the raw cert row |
| `certificate_identity` | ⚠️ **superseded**; any query raises `P0001: Sorry, the "certificate_identity" table has been superseded by a Full Text Search index on the "certificate" table.` |
| `certificate_and_identities(certificate_id, certificate, name_type, name_value, issuer_ca_id)` | the usable view |
| `identities(certificate)` | FTS helper function |

`name_type` real values: `san:dNSName`, `2.5.4.3` (CN), `2.5.4.10` (O), `2.5.4.11` (OU). You must filter on `name_type='san:dNSName'` (or `'2.5.4.3'` for CN).

Documented query shape:

```sql
SELECT ci.NAME_VALUE
FROM certificate_and_identities ci
WHERE plainto_tsquery('certwatch', 'example.com') @@ identities(ci.certificate)
  AND ci.NAME_TYPE = 'san:dNSName'
GROUP BY ci.NAME_VALUE;
```

**Observed behaviour, honestly:**
- `plainto_tsquery('certwatch','example.com')` and `...('github.com')` both returned **0 rows** in my tests.
- `NAME_VALUE ILIKE '%.example.com'` timed out: `57014 canceling statement due to statement timeout`.
- Connection cap is brutal and is the real blocker: `08P01 no more connections allowed (max_client_conn)` after only ~3–4 rapid connects; recovery took 40–90 s. Egress to `crt.sh:5432` also intermittently failed with `Errno 101 Network is unreachable` (2 of 5 attempts).

**Verdict:** the PG route is real and needs no credentials, but with a connection cap of a handful and a statement timeout, it is **worse than the HTTP endpoint** for a per-domain CLI tool. Keep it as an optional "expert mode" only, single connection, `SET statement_timeout` yourself, and never in a thread pool. On Termux, `psql` is not installed by default — you would need a raw-socket PG client in pure Python (feasible: I implemented startup + SSLRequest + simple Query protocol in ~60 lines of stdlib `socket`/`ssl`/`struct` to produce the facts above).

**Alternative mirrors:** none survive. `ct.fr-par.scw.cloud`, `ctsearch.entrust.com`, `ui.ctstream.me`, `merkle.town` all NXDOMAIN. crt.sh is the only free HTTP CT aggregator left.

---

## 3. Cert Spotter (SSLMate) v1

```
GET https://api.certspotter.com/v1/issuances
    ?domain={dom}&include_subdomains=true&expand=dns_names
```

**Auth:** none for the anonymous tier (`vary: Authorization` present; adding a key lifts limits).

**Response (verified, trimmed):**

```json
[{"id":"13962517288",
  "tbs_sha256":"41b88ef9...",
  "cert_sha256":"4cd176fa...",
  "dns_names":["f.cloud.github.com"],
  "pubkey_sha256":"83fe170a...",
  "not_before":"2026-02-27T20:05:17Z",
  "not_after":"2027-03-31T20:05:16Z",
  "revoked":false}]
```

**Extraction:** flatten `dns_names[]` from every issuance. Note the top-level object has **no** `name_value`; the `expand=dns_names` param is mandatory or you get only `tbs_sha256`/`cert_sha256`.

**Pagination:** cursor in the `Link` header — verified live:
```
link: <https://api.certspotter.com/issuances?after=18080134161&domain=github.com&expand=dns_names&include_subdomains=true>; rel="next"
```
Follow `after=<last id>` until no `Link`. Observed 69 issuances on page 1 for `github.com`.

**Rate limits (verified via headers + the official pricing page, which is `sslmate.com/ct_search_api/` — `sslmate.com/certspotter/api` is a 308 redirect):**

| Tier | single-hostname q/h | full-domain q/h | per-min | per-sec | query timeout |
|---|---|---|---|---|---|
| **Small $0** | 100 | **10** | 75 | 5 | 15 s |

Headers seen: `x-ratelimit-limit: 10, x-ratelimit-remaining: 9` for `include_subdomains=true`; `x-ratelimit-limit: 100` for `include_subdomains=false`. Because `include_subdomains=true` is exactly what you need, your real budget is **10 domains/hour, 5 requests/second burst**.

**429 body (verified):**
```json
{"code":"rate_limited","message":"You have exceeded your domain search quota for the SSLMate CT Search API. Please try again later, or authenticate with an API key, ..."}
```
with `retry-after: 208`. Respect it — the window is hourly, so a hard 429 means a ~1 h stall.

**Quirks:**
- **v0 is dead:** `https://certspotter.com/api/v0/certs?domain=...` → **410** `This API endpoint has been discontinued`.
- Returns `*.` wildcards heavily (13 of 59 names for `github.com` — more wildcard-dense than crt.sh).
- Returns apex.
- **Cross-domain SANs:** a `github.com` query returned `*.github.io` and `*.githubusercontent.com`. These are legitimately on the cert but **out of scope** — filter by apex suffix.
- `match_wildcards=false` exists but did **not** remove wildcards in testing (40 names still had 6 `*`). Don't rely on it; strip client-side.
- **Coverage is much narrower than crt.sh.** For `github.com` scope: crt.sh (no expiry filter) = 141 unique names, Cert Spotter = 52; Cert-Spotter-only = 2. It is a *supplementary* source, not a replacement.

---

## 4. HackerTarget hostsearch

```
GET https://api.hackertarget.com/hostsearch/?q={dom}
```

**Auth:** none.

**Response:** `text/plain`, one `hostname,ip` per line, **no header row**.

```
github.com,140.82.112.3
accelerator.github.com,185.199.110.153
accessibility.github.com,185.199.111.153
alive-staging.github.com,143.55.70.2
```

**Extraction:** `line.split(',')[0]`. Includes apex.

**Quota (verified empirically):**

```
x-api-quota: 21      <- total budget still available
x-api-count: 15      <- monotonically increasing per call
x-api-boost: 0
```
I drove `x-api-count` from 11 → 21 with repeated calls; call #22+ returned HTTP **200** with body:
```
API count exceeded - Increase Quota with Membership
```
It did **not** recover within the same hour (still exhausted ~50 min later, and `q=example.net` / `q=wikipedia.org` both still blocked). Quota is **per egress IP**, not per UA (a bogus UA inherited the same exhausted counter).

Published free tier (from `https://hackertarget.com/find-dns-host-records/`, verified 200): **Free User: 20 queries/day, max 50 results**; Member: 500 000 results, hourly updates.

**Result cap verified:** `q=github.com` returned **51 lines** (apex + 50 subdomains) — hard 50-subdomain cap.

**Quirks:**
- **Errors are HTTP 200.** `?q=this-domain-should-not-exist-9z8x.com` → `200` with body `error invalid host`. Missing `q` → same. **Never trust the status code; parse the body.** Any body that doesn't contain a comma is an error.
- No wildcards. No trailing dots. Apex included.
- `reverseiplookup/?q={ip}` → plain text hostname list (no IP column), costs 1 quota unit, returns **unrelated shared-hosting hostnames** (e.g. `1.1.1.1` → `inech.ru`, `patrixweb.net`).

**Verdict C:** 20 domains/day and 50 results each make this a side channel only. Cheap to add (parse = `split(',')`), but it will be the first thing to fail in any batch run.

---

## 5. RapidDNS

```
GET https://rapiddns.io/subdomain/{dom}?full=1
```

**Auth:** none. `server: cloudflare`, but **no JS challenge and no UA requirement** — 10 consecutive requests all returned 200 with `curl`'s default UA and an empty UA. `cf-cache-status: DYNAMIC`, no `cf-mitigated` header.

**Response:** HTML, one table:

```html
<p>Found 92148 subdomains for github.com on RapidDNS</p>
<table class="table table-striped table-bordered " id="table">
  <tr><th scope="row ">1</th>
      <td>live.github.com</td>
      <td><a href="/sameip/64:ff9b::8c52:7219#result">64:ff9b::8c52:7219</a></td>
      <td>AAAA</td>
      <td>2026-10-29</td></tr>
```
101 `<tr>` = 1 header + **100 data rows**. Record types present: `A`, `AAAA`, `CNAME`, `MX` (so the same host appears multiple times).

**Extraction (stdlib):**
```python
import re
rows = re.findall(r'<tr>(.*?)</tr>', html, re.S)[1:]
for r in rows:
    cells = re.findall(r'<td[^>]*>(.*?)</td>', r, re.S)
    if len(cells) >= 3:
        host = re.sub(r'<[^>]+>', '', cells[0]).strip()
```
The apex count comes from `Found ([\d,]+) subdomains`.

**⚠️ Pagination is inert for anonymous users.** This is the big finding. Verified on three domains:

| Domain | `page=1` unique hosts | `page=2` | `page=5` | `page=50` | `page=900` | Overlap |
|---|---|---|---|---|---|---|
| `github.com` | 54 | 54 | 54 | 54 | 54 | **100 %** |
| `iana.org` | 51 | — | 51 | — | — | **100 %** |
| `example.com` | 3 | 3 | 3 | — | — | **100 %** |

`?p=2`, `?offset=100`, `?full=1&page=2`, `/subdomain/{dom}/2` (404) — none change the page. Adding a session cookie + `Referer` doesn't help. So **you only ever get the first 100 rows (~50 unique hosts)** of a "92,148 subdomains" dataset. Also note 100 rows yield only 54 unique hosts — 46 rows are the same host on different record types.

There is a JSON API (`/api/search/{kw}?page=1&pagesize=100`, `X-API-KEY: rdns_...`) documented at `https://rapiddns.io/help/api` — verified **Pro/Max only**:
- no key → `401 {"error":"Authentication required (API Key or JWT)"}`
- dummy key → `401 {"error":"Invalid API Key"}`

**Quirks:** apex included; no wildcards; no trailing dots. Reverse-IP page `/sameip/{ip}?full=1` works and is also capped at 100 rows.

**Verdict B−:** trivially parseable, no auth, fast — but capped at ~50 hosts/domain, so it is a top-up source, not a backbone.

---

## 6. AlienVault OTX

```
GET https://otx.alienvault.com/api/v1/indicators/domain/{dom}/passive_dns
```

**Auth: REQUIRED as of 2026-11.** Anonymous access is refused. Verified repeatedly over 45 minutes, with and without a UA:

```
HTTP/1.1 429 Too Many Requests
{"detail": "Anonymous access to this endpoint is limited. Please authenticate."}
```

Sending a header named `X-OTX-API-KEY` with junk still gives 429 (the endpoint appears gated before key validation, so a *valid* key is the only way through). This **contradicts the widely-copied Sublist3r/OWASP-amass behaviour** where `passive_dns` was free — plan for a key or drop the source.

Still anonymous-friendly (verified 200): `/general` and `/url_list`. `/general` is useful for a cheap existence/pulse check:

```json
{"sections":["general","geo","url_list","passive_dns","malware","whois","http_scans"],
 "indicator":"example.com","type":"domain","type_title":"Domain",
 "pulse_info":{"count":50,...},"validation":[{"source":"akamai","message":"Akamai rank: #1608",...}]}
```

**For reference, the shape you get *with* a key** (stable across OTX versions): `{"passive_dns":[{"address":"1.2.3.4","first":"...","last":"...","hostname":"sub.dom","record_type":"A",...}],"pagination":{"next":"...","limit":500,"page":1}}` — extract `hostname`. Paginated via `?page=N&limit=500`. `api/v1/pdns/domain/{dom}` → **404** (does not exist). `indicators/hostname/{h}/passive_dns` timed out (000).

---

## 7. urlscan.io

```
GET https://urlscan.io/api/v1/search/?q=page.domain:{dom}&size=100
```

**Auth:** none for search (`x-rate-limit-scope: ip-address`). A bogus `API-Key` header returns 400, so **don't send the header unless you have a key**.

**Response (verified):**

```json
{"results":[{"task":{"visibility":"public","method":"api","domain":"api.github.com",
   "apexDomain":"github.com","time":"2026-11-02T03:00:18.428Z",
   "uuid":"01a19a33-339b-7585-bc0e-3f58e2709fd7",
   "url":"https://api.github.com/repos/..."},
  "page":{"url":"api.github.com/repos/..."},"stats":{...},"submitter":{}}],
 "total":10000,"has_more":true,"took":...,"search_date_limit_days":30}
```

**Extraction:** `r['page']['domain']` (or `r['task']['domain']`), then filter to apex scope.

**Query semantics — the important part.** `q=domain:{dom}` is a **loose full-text match** against every hostname appearing in the scan (resources, links, redirects). For `q=domain:github.com`, 100 results → only **71** were `*.github.com`; **29 were unrelated** (`pages.dev`, `docs.atlasos.net`, `caliberhomeloans.com`, `d.sssysy.top`, …). Use **`q=page.domain:{dom}`** for the scanned host itself — that returned exactly 3 hosts (`github.com`, `api.github.com`, `codeload.github.com`).

**Rate limits (headers, verified):**
```
x-rate-limit-limit: 30        x-rate-limit-window: minute
x-rate-limit-concurrency-limit: 10   x-rate-limit-scope: ip-address
```
30 searches/minute/IP, 10 concurrent.

**Pagination:** `size` is **capped at 100** (`size=1000` → 100 results). Cursor is `search_after={13-digit-ms},{uuid}` — the regex is enforced:
```
ValidationError: "search_after" with value "1700000000000" fails to match the required pattern:
  /^\d{13},[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i  -> 400
```
`has_more: true` is reported but a well-formed cursor still returned 0 results in my sample; and `total` is capped at **10000** regardless of reality. **Search window is 30 days** (`search_date_limit_days: 30`) — you cannot reach older scans.

**Quirks:** no wildcards in output; apex included; only surfaces hosts that someone actually scanned → heavily skewed to popular targets; near-zero yield for obscure domains.

---

## 8. Paid / keyed APIs

### 8.1 VirusTotal v3
```
GET https://www.virustotal.com/api/v3/domains/{dom}/subdomains?limit=40
Header: x-apikey: <key>
```
Verified `401 {"error":{"code":"AuthenticationRequiredError","message":"X-Apikey header is missing"}}` with no key; `{"code":"WrongCredentialsError","message":"Wrong API key"}` with a junk key. Response shape: `{"data":[{"id":"sub.dom","type":"domain","attributes":{...}}],"links":{"next":"...?cursor=..."}}` — extract `id`, paginate on `links.next` cursor. Public free tier is 4 req/min & 500 req/day (documented; the docs URLs I tried (`/docs/api-limits`) returned 404, so treat the exact numbers as **not verified this session**).

### 8.2 SecurityTrails
`GET https://api.securitytrails.com/v1/domain/{dom}/subdomains?children_only=false&include_inactive=true`, header `APIKEY`. Verified `401 Please check user credentials` (plain text, not JSON). Free tier no longer covers subdomains; response is `{"subdomains":["a","b"],"endpoint":"...","subdomain_count":N}` in one shot.

### 8.3 Shodan
```
GET https://api.shodan.io/dns/domain/{dom}
```
**Surprise:** this answers **anonymously, but only for a cached subset.** Verified:

| Domain | Anon result |
|---|---|
| `github.com` | ✅ 200, 303 subdomains, `cf-cache-status: HIT`, `age: 12976` |
| `example.com` | ✅ 200, 3 subdomains |
| `tesla.com` | ✅ 200, 852 |
| `openai.com` | ✅ 200, 481 |
| `microsoft.com`, `apple.com` | ✅ 200 |
| `iana.org`, `wikipedia.org`, `netflix.com`, `randomdomainxyz123.com` | ❌ **401** HTML, `cf-cache-status: BYPASS` |
| `?page=2`, `?key=`, `/dns/reverse`, `/shodan/host/search` | ❌ 401 |

So the anonymous path is serving a Cloudflare-cached copy of previously-computed popular-domain results. You cannot predict which domains hit cache, and you cannot page. **Not usable as a reliable source without a key.**

Shape: `{"domain":"github.com","tags":["dmarc","spf"],"subdomains":["52.wiki","_dmarc","accelerator","api.mcp"],"data":[{"subdomain":"","type":"A","value":"140.82.112.3","last_seen":"2026-10-22T04:31:31"}],"more":false}` — note `subdomains` are **relative labels** (`accelerator`, `api.mcp`), you must append `.{dom}`. `more` signals more pages (with key).

### 8.4 Censys — **decommissioned**
```
GET https://search.censys.io/api/v2/hosts/search  ->  403
{"error":"Censys Legacy Search was decommissioned on September 30, 2026.","status":"error","error_type":"decommissioned"}
GET https://api.platform.censys.io/v3/global/search/query -> 401 Access credentials are invalid
```
Update any code that still calls `search.censys.io/api/v2`.

---

## 9. Chaos (ProjectDiscovery)

Two things, only one of which is free:

| Endpoint | Verified |
|---|---|
| `GET https://chaos-data.projectdiscovery.io/index.json` | ✅ 200, 286 KB, **795 programs** (763 with `count > 0`, ~11.4 M subdomains total) |
| `GET https://chaos-data.projectdiscovery.io/{slug}.zip` | ✅ 200 — **no key needed** |
| `GET https://api.projectdiscovery.io/chaos/program` | ❌ `404 fault filter abort` with or without `X-API-Key` |

Index entry:
```json
{"name":"Airtable","program_url":"https://hackenproof.com/airtable/...",
 "URL":"https://chaos-data.projectdiscovery.io/airtable.zip",
 "count":611,"change":0,"is_new":false,"platform":"hackenproof",
 "bounty":true,"last_updated":"2026-11-02T00:12:19Z"}
```

Zip contents (verified, `airtable.zip` = 3 933 B):
```
['airtable.com.txt', 'staging-airtableblocks.com.txt']
brand.airtable.com
meet.airtable.com
static.fs.airtable.com
email-69-72-44-244.airtable.com
```
One hostname per line, split per apex into `<apex>.txt`. Membership gating is by *program*, not by domain — this is a **dataset, not a per-domain API**. Useful only when the target is a listed bug-bounty program.

**Quirk:** use the `URL` field verbatim. `chaos-data…/Acorns%20Grow.zip` and `…/Acorns Grow.zip` both returned `403 AccessDenied` (S3 XML); the index gives the correct slug `acorns_grow.zip`.

---

## 10. AnubisDB

| Host | Verified |
|---|---|
| `https://jldc.me/anubis/subdomains/{dom}` | 301 → `jonlu.ca` |
| `https://jonlu.ca/anubis/subdomains/{dom}` | **403** (Cloudflare HTML block, also with a browser UA) |
| `https://anubisdb.com/anubis/subdomains/{dom}` | ✅ **200**, JSON array |

```
GET https://anubisdb.com/anubis/subdomains/{dom}
["*.branch.github.com","*.codespaces-dev.github.com","api.security.github.com","camo.github.com",...]
```
No auth, no headers, case-insensitive input, trailing dot accepted.

**Quality is the problem.** `example.com` returned **22 253** entries, of which 950 are bare numeric labels and 180 are single-character labels — this is brute-force/AXFR-derived data, not observed DNS. Sample:

```
["0.example.com","001.example.com","02.example.com","04.example.com","05.example.com", ...
 ...,"zzzzzzzzzzzz.example.com","www.example.com"]
```

For `github.com` (85 entries) it was a **pure subset of crt.sh** (0 Anubis-only). For `iana.org` it had 34 entries of which 12 overlapped crt.sh and it knew live names crt.sh's *unexpired* window missed (`blackhole-1.iana.org`, `ns.iana.org`, `maintenance.iana.org`). So: real value, but **every name must be DNS-validated**; do not emit AnubisDB results unvalidated.

---

## 11. DNSDumpster — **no CSRF token anymore**

The classic "scrape the CSRF token then POST" flow is obsolete. As of 2026-11 it is an htmx form:

```html
<form data-form-id="mainform" hx-post="/htmld/" hx-target="#results"
      hx-headers='{"Authorization": ""}'>
  <input type="text" id="target" name="target" placeholder="example.com">
```

**Working flow (verified end-to-end, 200 + 214 KB HTML fragment):**

```bash
curl -X POST 'https://dnsdumpster.com/htmld/' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'target=github.com&user=free'
```
No cookie jar, no CSRF token, no `HX-Request` header, no `Referer` needed. `GET` on the same path → **405 Method Not Allowed**. `GET /` does **not** contain any `csrfmiddlewaretoken` (verified: 0 matches).

**Parsing:** tables are `<table id="a_rec_table">` and friends; rows are `hostname | ip | ptr-name`:
```html
<tr><td>accelerator.github.com</td><td>185.199.110.153</td>
    <td>cdn-185-199-110-153.github.com</td></tr>
```
⚠️ The third cell is a **PTR-derived name**; it looks like a subdomain and often is one, but it is not an A-record owner. Drop it if you only want forward names.

**Cap:** free tier is hard-limited — banner: *"Free users are limited to 50 results for a single domain."* Verified 50–59 hosts returned per domain.

**Quirk:** `target=example.com` → `Error: Invalid domain, check input and try again.` (200 status, HTML error fragment). It rejects reserved/example domains but works fine for `github.com`, `cloudflare.com`, `wikipedia.org`, `tesla.com`, `iana.org`. Apex is **not** included in results.

---

## 12. Common Crawl index

```
GET https://index.commoncrawl.org/{collection}-index?url=*.{dom}&output=json&fl=url
```
Collections: `GET https://index.commoncrawl.org/collinfo.json` → ✅ 200, **129** collections, newest `CC-MAIN-2026-43`.

**Response is JSONL, not a JSON array** — one object per line:
```json
{"urlkey":"com,example)/","timestamp":"20261005112841","url":"https://example.com/",
 "mime":"text/html","mime-detected":"text/html","status":"200","digest":"7R2CIN...",
 "length":"996","offset":"204233603","filename":"crawl-data/CC-MAIN-2026-43/segments/..."}
```
Keys: `urlkey, timestamp, url, mime, mime-detected, status, digest, length, offset, filename, languages, recordid, encoding`.

**Two fatal problems, both verified:**

1. **504 Gateway Time-out is the norm.** `nginx/1.31.8`, fails at ~10.8 s. Roughly **2 of 3 requests 504**; you need a retry loop. Failing calls: `*.example.com`, `*.github.com`, `*.iana.org`, `*.kubernetes.io` (0/3 success), `*.portswigger.net`, `matchType=domain`, `matchType=host`, `page=1/2/3`.
2. **Wildcard queries return almost no subdomains.** The index is sorted by SURT urlkey, and `com,example)/…` (the apex) sorts *before* `com,example,sub)/…`. So the head of the result set is entirely apex paths:

| Query | Rows returned | Distinct hosts |
|---|---|---|
| `url=*.iana.org&limit=1000` | 1000 | **2** (`www.iana.org`, `iana.org`) |
| `url=*.wikipedia.org&limit=2000` | 2000 | **2** |
| `url=*.wikipedia.org&limit=5000` | 5000 | **2** |
| `url=*.github.com&limit=3000` | 3000 | **2** |
| `url=wikipedia.org&matchType=domain&limit=500` | 500 | **2** |
| `url=example.com` (exact) | 1 | 1 |
| `url=*.github.com&filter=urlkey:.*,github.com,.*` | 504 ×3 | — |

To actually reach subdomains you must page deeply (`page`, `pageSize` exist; `page=0` works, `page=1/2` mostly 504'd) — i.e. hundreds of retried requests to mine one domain. On Termux over mobile data this is not viable.

The columnar (parquet) index that would fix this is not at the public URL I probed (`data.commoncrawl.org/cc-index/table/cc-main/warc/crawl=CC-MAIN-2026-43/...` → 404).

---

## 13. Wayback Machine CDX

```
GET https://web.archive.org/cdx/search/cdx?url=*.{dom}&output=json&fl=original&collapse=urlkey&limit=N
```

**Response with `output=json`:** array of arrays, first element is the header row:
```json
[["original"],["http://github.com/"],["https://github.com/!!!"]]
```
Without `output=json` it is plain text, one URL per line.

**Availability (verified) — this is the headline:** the Internet Archive now serves a full-page **503 "Internet Archive: Temporarily Offline"** (11 832 B HTML with embedded base64 logos) and **504** timeouts very frequently.

| Test | Result |
|---|---|
| 4 domains × up to 3 retries (`*.iana.org`, `*.example.com`, `*.mozilla.org`, `*.wikipedia.org`) | needed retries on **all**; sequence seen `503, 000(timeout), 503` |
| `*.iana.org&limit=300` | 504 at 60 s, then 200 on retry (9 s) |
| `*.mozilla.org&limit=300` | 504 ×2, 200 on 3rd attempt |
| `*.bbc.co.uk&limit=1000` | 503 |
| `page=1/4/6/8` | 503 |
| `filter=!original:...` (any regex form) | 503 or 504 every time |
| `web/timemap/link/example.com` | 200 but **95.9 MB**, timed out at 60 s |

**Same SURT crowding problem as Common Crawl:**

| Query | Rows | Distinct hosts |
|---|---|---|
| `url=*.iana.org&limit=200` | 200 | 2 |
| `url=*.iana.org&limit=1000` | 1000 | 2 |
| `url=*.iana.org&limit=5000` | 5000 | 2 |
| `url=*.mozilla.org&limit=3000` | 3000 | 2 |
| `url=github.com&matchType=domain&limit=1500` | 1500 | 2 (`github.com`, `www.github.com`) |
| `url=*.iana.org&page=2&limit=100` | 1 | 1 |

**Pagination:** `page=N` + `limit=N` works when the server cooperates. `showResumeKey=true` exists (timed out in test). `collapse=urlkey` reduces volume but not host diversity.

`https://archive.org/wayback/available?url={dom}` → ✅ 200 in <1 s, but returns only the *closest single snapshot*, useless for enumeration.

**Verdict D+:** keep it as an optional deep-tail source for 2–3 high-value apexes with a 3-attempt retry and a hard timeout; it is not worth wiring into the default path.

---

## 14. Search-engine scraping (the Sublist3r approach) — **dead**

| Engine | URL | Verified |
|---|---|---|
| Baidu | `baidu.com/s?wd=site:{dom}` | 302 → `wappass.baidu.com/static/captcha/tuxing_v2.html` — **CAPTCHA wall** |
| Bing | `bing.com/search?q=site:{dom}&count=50` | 200, 94 KB, but **0** `b_algo` result blocks, **0** domain matches |
| Bing RSS | `...&format=rss` | 200, 1 756 B, 0 results (localised empty channel) |
| Google | `google.com/search?q=site:{dom}&num=100` | 200, 93 KB JS shell (`enablejs`), 1 match total — JS-gated |
| DuckDuckGo HTML | `html.duckduckgo.com/html/?q=site:{dom}` | **202** challenge, 0 results |
| Yahoo | `search.yahoo.com/search?p=site:{dom}` | `000`, `SSL_read: unexpected eof` |
| Brave | `search.brave.com/search?q=site:{dom}` | 200, 152 KB, **0** domain matches (client-rendered) |
| Mojeek | `mojeek.com/search?q=site:{dom}` | 200 but 5.5 KB; **0** hosts for `github.com`/`tesla.com`/`cloudflare.com`, 5 for `example.com` (`site1.`, `test1.`, `webmail.`, `ww.`, `www.`) |

**All eight are non-viable in 2026.** Even the one that returns HTML (Mojeek) yields nothing for real targets. Do not ship these scrapers; they add latency, ban risk, and zero results.

---

## 15. Certificate Transparency streaming (CertStream)

```
wss://certstream.calidog.io
```
Handshake verified: `HTTP/1.1 101 Switching Protocols` over TLS, `server: cloudflare`. I opened the socket twice, sent `Upgrade: websocket` with a valid `Sec-WebSocket-Key`, and **received 0 bytes of frames** within 10–20 s (only a 99-byte trailing frame). CertStream requires the `certstream` WebSocket sub-protocol and a JSON `{"action":"subscribe",...}`; the raw handshake alone does not stream.

**Verdict:** architecturally wrong for a "fast, stdlib-first, offline-friendly" CLI — it is an unbounded global firehose (~millions of certs/day) that you must filter client-side, and it only helps if the tool runs continuously. Pure-stdlib WebSocket framing is implementable but adds a whole protocol layer. **Skip for v1.**

---

## 16. subdomain.center

```
GET https://api.subdomain.center/?domain={dom}
```
No auth. Returns a **JSON array of hostnames**, exactly **500** entries (cap verified: `google.com`, `amazon.com`, `github.com` all → 500). No wildcards. Apex excluded.

**Two quirks, both verified:**

1. **Rate/queue errors as HTTP 200** with a JSON *object* instead of an array:
   `{"error": "server busy (64 queries in flight)"}` — 1 of 3 sequential calls; burst of 5 → `200, 503, 200, 200, 200`. Always type-check the top-level JSON.
2. **Results are non-deterministic samples.** Three sequential calls for `example.com` returned two disjoint 500-item lists: **overlap between call 2 and call 3 = 1 item**, union = 998. So a single call is a random ~50 % slice; **call it 3–5× and union**.
3. `?d=example.com` → `400 {"error":"missing required parameter: domain"}`. Only `domain=` works.

---

## 17. Rapid7 Sonar FDNS — **now gated**

```
GET https://opendata.rapid7.com/sonar.fdns_v2/   ->  301 -> https://sonardata.rapid7.com/sonar.fdns_v2/
```
✅ 200, 33 KB listing. Every file row carries `class="gated"` and a lock icon:

| File | Size |
|---|---|
| `2026-10-31-…-fdns_cname.json.gz` | **5.3 GB** |
| `2026-10-31-…-fdns_mx.json.gz` | 8.6 GB |
| `2026-10-31-…-fdns_caa.json.gz` | 7.5 GB |
| `2026-11-01-…-fdns_txt_mx_dmarc.json.gz` | 96.8 MB |

Direct fetch of a gated file → **302 → back to `/sonar.fdns_v2/`** (no download). A guessed non-gated filename → 404. So **FDNS requires a Rapid7 account now**; the old "just `wget` the 20 GB daily file" workflow is gone. Even if ungated it would be unusable on Termux (multi-GB gzip, needs full scan). Note the filename pattern changed too: `YYYY-MM-DD-<epoch>-fdns_<type>.json.gz` with hyphens, not underscores.

---

## 18. Dead / unavailable (confirmed this session)

| Source | Evidence |
|---|---|
| bufferover.run | `Could not resolve host: dns.bufferover.run` |
| Riddler | `Could not resolve host: riddler.io` |
| DNSRepo | `Could not resolve host: dnsrepo.nixway.com` |
| merkle.town | `Could not resolve host: api.merkle.town` |
| ct.fr-par.scw.cloud | `Could not resolve host` |
| ctsearch.entrust.com | `Could not resolve host` |
| ui.ctstream.me | `Could not resolve host` |
| ThreatMiner | HTTP **522** (Cloudflare origin down); host resolves |
| Netcraft | `api.netcraft.com/search/api/json/` → 404 `{"message":"no Route matched with those values"}`; `searchdns.netcraft.com` → 403 |
| sonar.omnisint.io | 404 |
| Facebook CT API | `graph.facebook.com/certificates` → **400** `GraphMethodException: Object with ID 'certificates' does not exist, cannot be loaded due to missing permissions, or does not support this operation` |
| Cert Spotter v0 | 410 discontinued (see §3) |
| Censys legacy | decommissioned 2026-09-30 (see §8.4) |
| Google CT report | `transparencyreport.google.com/https/certificates?domain=` → 200 but a JS-application shell, no API |
| crt.sh json3 | `Unsupported output type: json3` |

---

## 19. Normalisation & dedup

Run every candidate through this pipeline **before** dedup; it eliminates the majority of false positives for ~2 ms/name.

```python
import re, unicodedata

LABEL = re.compile(r'^(?!-)[a-z0-9-]{1,63}(?<!-)$')

def normalise(name: str, apex: str) -> str | None:
    if not name: return None
    s = name.strip().strip('.').lower()          # strip trailing dot, lowercase
    s = s.split()[0] if s.split() else s         # crt.sh csv/odd whitespace
    if '@' in s or '/' in s or ':' in s: return None   # email SANs, URLs (crt.sh junk)
    if s.startswith('*.'):  s = s[2:]            # wildcard -> base
    elif '*' in s: return None                   # mid-label wildcard: drop
    if s.startswith('_'):
        # _dmarc / _domainkey are DNS records, not hosts — keep only if you want them
        pass
    # IDN: crt.sh/CertSpotter return A-labels already; if you ever see U-labels:
    try:
        s.encode('ascii')
    except UnicodeEncodeError:
        s = s.encode('idna').decode('ascii')     # -> xn--...
    if not (s == apex or s.endswith('.' + apex)): return None   # apex scope
    labels = s.split('.')
    if not all(LABEL.match(l) for l in labels): return None
    if len(s) > 253: return None
    return s
```

Rules worth stating explicitly:

| Rule | Why (observed) |
|---|---|
| **Lowercase** | Case-insensitive DNS; shodan/rapiddns mixed forms otherwise duplicate |
| **Strip trailing dot** | AnubisDB accepts `example.com.` queries and may echo FQDN form |
| **Strip leading `*.`; drop mid-string `*`** | crt.sh 18/800, Cert Spotter 13/59 wildcards; mid-label wildcards are unverifiable |
| **Punycode-normalise IDN** | crt.sh returns `xn--mnchen-3ya.de`; unicode queries return `[]` — always query with A-labels |
| **Reject `@`, `/`, `:`** | crt.sh emits email SANs (`support@github.com`) and URL SANs (`https://github.com/LeviMarvin/OFCA`) |
| **Enforce apex suffix** | Cert Spotter returns `*.github.io` for a `github.com` query; urlscan `domain:` returns 29 % unrelated hosts |
| **Strip a trailing `.<apex>` duplicate** | `foo.github.com.github.com` appears when a source already returns FQDN and you append apex |
| **Drop `cdn-<ip>.<apex>` PTR artefacts (optional)** | DNSDumpster's third column is reverse DNS, not a forward record |

**Dedup** is then a plain `set`. Per-source dedup is *essential* before dedup-across-sources: RapidDNS returned 100 rows → 54 unique hosts (46 dupes from A/AAAA/CNAME/MX); crt.sh 1238 rows → 143 unique names (473 duplicate serial numbers, each cert appearing twice by CA-id).

**Wildcard handling** (this is where false positives come from):

1. Collect every `*.X` seen in any source into a candidate wildcard set.
2. For each apex, probe a random nonexistent label (`r = ''.join(random.choices(string.ascii_lowercase, k=10))`). If `r.{dom}` resolves to the same A/AAAA/CNAME set as another random label, the apex has a **wildcard DNS record**.
3. When a wildcard is present, a name matching `*.X` is only evidence of the *wildcard*, not of that specific host. Either mark those results "wildcard-only / unverified" or drop them; otherwise a single `*.example.com` cert yields an unbounded family of phantom hosts.

---

## 20. False positives by source

| Rank | Source | FP mode | Observed rate |
|---|---|---|---|
| 1 | **AnubisDB** | Brute-force/AXFR-derived; emits `0.dom`, `001.dom`, `zzzzzzzzzzzz.dom` | 950 numeric + 180 single-char labels in 22 253 entries for `example.com` |
| 2 | **urlscan `domain:`** | Loose full-text: matches any hostname referenced *in* a scan | 29/100 results unrelated |
| 3 | **crt.sh / Cert Spotter wildcards** | `*.dom` implies infinite children | 18/800 (crt.sh), 13/59 (CS) |
| 4 | **Cert Spotter cross-domain SANs** | Shared certs carry other apexes | `*.github.io`, `*.githubusercontent.com` |
| 5 | **crt.sh email/URL SANs** | `name_value` is a raw SAN blob | 2/143 for `github.com` |
| 6 | **HackerTarget reverse IP** | Shared hosting / CDN co-tenancy | 2 of 3 results unrelated for `1.1.1.1` |
| 7 | **RapidDNS** | Low; dedup issue not FP | 46/100 duplicate rows |
| 8 | **crt.sh (generally)** | **Very low** — certs are ground truth for *existence at issuance time* | ~0 |

Best precision ranking: **crt.sh > Cert Spotter > Chaos > VT > RapidDNS > DNSDumpster > subdomain.center > Shodan > AnubisDB**.

---

## 21. Reliability ranking, 2025–2026

| Rank | Source | Why |
|---|---|---|
| 1 | **crt.sh** | Only free CT aggregator left; broadest coverage (141 vs 52 names for `github.com`); no auth; but needs 3 retries + 30 s timeout |
| 2 | **Cert Spotter v1** | Clean schema, real cursor pagination, honest rate-limit headers; capped at 10 full-domain queries/hour |
| 3 | **Chaos** | Curated, high-signal, no key for zips; but only for listed bounty programs |
| 4 | **urlscan.io** | Free, 30 req/min; needs `page.domain:`; 30-day window |
| 5 | **VirusTotal v3** | Good data, free key, tight quota (4/min) |
| 6 | **RapidDNS** | No auth, fast, trivial parse — but hard-capped at ~50 hosts/domain |
| 7 | **subdomain.center** | Broad, no auth; random 500-item samples, must union repeats |
| 8 | **DNSDumpster** | 50-host cap, no CSRF needed, rejects `example.com` |
| 9 | **Shodan anon** | Cache-dependent lottery |
| 10 | **AnubisDB** | Works but needs DNS validation on everything |

**What actually changed vs. common wisdom:**

- OTX `passive_dns` is **no longer anonymous** (429) — the unit of most `sublist3r`-era recipes.
- **Censys legacy API is gone** (2026-09-30).
- **Rapid7 FDNS is gated** behind a login; no more direct `wget`.
- **DNSDumpster has no CSRF token**; it is a bare `POST /htmld/`.
- **Shodan's `dns/domain` answers anonymously for cached domains** — a fact almost nobody documents, and yet not dependable.
- **Common Crawl and Wayback are near-useless for subdomain enumeration** because SURT ordering puts the apex first; the "just query `*.domain`" recipe yields ~2 hosts per 1000–5000 records.
- **Search-engine scraping is fully dead** — all 8 engines tested returned zero usable results.
- **AnubisDB survives at `anubisdb.com`** (the `jldc.me`/`jonlu.ca` hosts in every tool are 403/301).

---

## 22. Free wordlists (brute-force)

All sizes below measured live on 2026-11-02 (line counts via `wc -l` over HTTPS).

### SecLists — MIT (`danielmiessler/SecLists`, `Discovery/DNS/`)

| File | Bytes | Lines | Use |
|---|---|---|---|
| `subdomains-top1million-5000.txt` | 30 075 | 5 000 | **Termux default** — best speed/coverage tradeoff |
| `subdomains-top1million-20000.txt` | 135 562 | 20 000 | step up |
| `subdomains-top1million-110000.txt` | 1 311 067 | 110 000 | deep pass |
| `bitquark-subdomains-top100000.txt` | 1 426 217 | 100 000 | popularity-ranked, good precision |
| `fierce-hostlist.txt` | 14 683 | ~2 200 | tiny, legacy |
| `namelist.txt` | 1 585 853 | — | broad |
| `shubs-subdomains.txt` | 5 984 338 | 484 699 | large |
| `dns-Jhaddix.txt` | 26 502 200 | 2 171 687 | very large |
| `n0kovo_subdomains.txt` | 51 558 245 | 3 000 001 | largest |
| `combined_subdomains.txt` | 8 285 473 | 653 920 | union of bitquark+shubs+110000 |

Base URL: `https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/<file>`

Quirk worth knowing: the SecLists README says `subdomains-top1million-*` were **zone-transferred from Cloudflare in January 2026** — i.e. real observed labels, not generated combos. Good precision.

### Assetnote — Apache-2.0

| File | Bytes | Lines |
|---|---|---|
| `https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt` | 140 842 282 | **9 544 235** |
| `https://wordlists-cdn.assetnote.io/data/manual/2m-subdomains.txt` | 29 395 757 | 2 167 059 |

⚠️ The CDN copy of `best-dns-wordlist.txt` reports `last-modified: Fri, 28 Apr 2023` — stale despite `wordlists.assetnote.io` claiming monthly regeneration.

### commonspeak2 — Apache-2.0

`https://raw.githubusercontent.com/assetnote/commonspeak2-wordlists/master/subdomains/subdomains.txt` — 5 984 344 B, 484 701 lines. **Frozen since 2018**; superseded by the Assetnote CDN lists. Include only for provenance/compat.

### Licensing summary

| Corpus | Licence | Redistributable |
|---|---|---|
| SecLists | MIT | ✅ yes, with notice |
| Assetnote wordlists | Apache-2.0 | ✅ yes, with NOTICE |
| commonspeak2 | Apache-2.0 | ✅ yes |

Ship only `subdomains-top1million-5000.txt` (30 KB) in-repo and download the rest on demand — 140 MB is not a Termux install.

---

## 23. Recommended default source set

**Tier 1 — always on, no credentials, ordered by yield/cost.** Run concurrently with a shared 3-retry/30 s policy; expect Tier 1 alone to recover the large majority of what a 7-source Sublist3r-class tool would find.

| Order | Source | Timeout | Retries | Notes |
|---|---|---|---|---|
| 1 | **crt.sh** `output=json&exclude=expired` | 30 s | 3 (backoff 2 s, 5 s) | treat 502/504 as retryable; parse `name_value.split('\n')`; no paging |
| 2 | **Cert Spotter** v1 `include_subdomains=true` | 20 s | 2; honour `retry-after` | follow `Link: rel="next"`, cap 3 pages; 10 domains/h budget |
| 3 | **RapidDNS** HTML | 15 s | 2 | first page only — paging is inert; expect ~50 hosts |
| 4 | **subdomain.center** | 25 s | 3 | call **3×** and union; check for `{"error":...}` object |
| 5 | **urlscan.io** `q=page.domain:` | 20 s | 2 | `size=100`, `q=page.domain:` **not** `domain:` |
| 6 | **AnubisDB** `anubisdb.com` | 15 s | 2 | results are candidates only — must be DNS-validated |

**Tier 2 — opt-in, key required.** `--with-key`: VirusTotal v3 (`x-apikey`), AlienVault OTX (`X-OTX-API-KEY`, now mandatory), SecurityTrails (`APIKEY`), Shodan (skip unless keyed). Chaos: only when the apex is a listed program — match `index.json` once, cache 24 h, then unzip `{slug}.zip`.

**Tier 3 — deliberately excluded.** Wayback CDX and Common Crawl (SURT ordering makes them return ~2 hosts per 1000 records, plus ~60 % 5xx), all search-engine scrapers (dead), CertStream (firehose, wrong shape for a CLI), AnubisDB old hosts, Sonar FDNS (gated), DNSDumpster (50-host cap is dominated by Tier-1 sources at the same cost) — expose the first two behind `--deep` only.

**Execution policy for a stdlib-only client:**

```
per-source:  ThreadPoolExecutor(max_workers=6)   # crt.sh tolerates 5 parallel, 1 in 5 fails
retry:       on 429/502/503/504/timeout, backoff 2s → 5s → 12s, max 3
hard cap:    total wall clock 90 s; abandon a source, keep partial results
gzip:        Accept-Encoding: gzip  (stdlib gzip + io.BytesIO)
identity:    always query with A-labels (punycode); never send U-labels to crt.sh
output:      normalise (§19) → set-dedup → wildcard-filter → optional DNS resolve
```

**Minimum viable source for a Termux build:** crt.sh + Cert Spotter + RapidDNS. That trio covers CT plus live-ish passive DNS with zero keys, three independent failure domains, and ~250 KB of transfer for a mid-size apex.

---

*Verification date: 2026-11-02. Endpoint behaviour in this space changes quarterly; re-run §2, §3, §6 and §8.4 before a release.*
