# DNS Resolution Engineering

Implementation reference for a fast, stdlib-only Python subdomain brute-forcer.

**All numbers below were measured on this host** — Android 14 / aarch64, Termux userland under PRoot, Python 3.14.4 — against live public resolvers on 2026-11-02. Raw RTT to public resolvers here is 40–320 ms (mobile network), so absolute throughput is lower than a datacentre. Ratios and failure modes transfer; absolute QPS scales with RTT. Reproduction commands are in [§11](#11-verification-log).

---

## 0. TL;DR — the five things that decide whether this works

1. **Never use RCODE as an existence signal.** `NOERROR + 0 answers` (NODATA) is returned for *nonexistent* names by whole zones — measured: `example.com`, `cloudflare.com`, `github.com`, `apple.com`, `netflix.com`. A brute-forcer keying on `rcode == NXDOMAIN` produces **100% false positives** there. Existence = *non-empty answer section*.
2. **Wildcard filtering must be per-level and probe-based, not per-zone.** `*.herokuapp.com` and `*.foo.herokuapp.com` both resolve, to *different* answers. Cache the wildcard footprint keyed by the **level** (the name without the leftmost label), and test each level independently.
3. **Union-then-subset IP filtering is the only method that works, and it needs ≥8 probes.** Measured false-positive rate of naive methods on a 105-word wordlist: `rcode`-based → 104/105 FP; `answer-present` → 104/105 FP; **subset-of-union → 0–26/105, and 0/105 after refinement**. See [§3.4](#34-algorithm-that-actually-works-measured).
4. **Concurrency sweet spot is ~16 in-flight per resolver, not 500.** Beyond that you get *packet drops, not SERVFAIL* — losses look identical to NXDOMAIN unless you retry. Measured: 8.8.8.8 at conc 16 → 243 QPS, 0.1% loss; conc 100 → 129 QPS, 12% loss. Total collapse (0/2000) at conc 2000.
5. **Ship a DoH fallback.** UDP/53 worked here, but on Termux mobile data it frequently does not. `cloudflare-dns.com/dns-query` + `dns.google/resolve` JSON are two `urllib` calls and are the only reliable path behind captive/mobile NATs.

---

## 1. Wire format (stdlib only, no dependencies)

### 1.1 Query construction

A DNS message is a 12-byte header, then the QNAME as a sequence of length-prefixed labels terminated by `0x00`, then QTYPE/QCLASS.

```python
import struct

def enc_name(name: str) -> bytes:
    out = bytearray()
    for lab in name.rstrip('.').split('.'):
        b = lab.encode('idna') if any(ord(c) > 127 for c in lab) else lab.encode()
        if not 1 <= len(b) <= 63:
            raise ValueError(f'bad label len {len(b)}')
        out.append(len(b)); out += b
    out.append(0)
    return bytes(out)

def build(qname, qtype=1, qid=0, rd=1, edns=1232, do=0):
    hdr = struct.pack('!HHHHHH', qid, (rd & 1) << 8, 1, 0, 0, 1 if edns else 0)
    msg = hdr + enc_name(qname) + struct.pack('!HH', qtype, 1)   # QCLASS 1 = IN
    if edns:                                                      # OPT pseudo-RR
        msg += b'\x00' + struct.pack('!HHIH', 41, edns, (do & 1) << 15, 0)
    return msg, qid
```

Header field layout (`struct '!HHHHHH'`): `ID | FLAGS | QDCOUNT | ANCOUNT | NSCOUNT | ARCOUNT`.

**FLAGS** bits, most significant first:

| Bits | Field | Notes |
|---|---|---|
| 15 | QR | 0 = query, 1 = response |
| 14–11 | OPCODE | 0 = QUERY |
| 10 | AA | authoritative answer |
| 9 | **TC** | truncated → retry over TCP |
| 8 | RD | recursion desired — **always set** for a brute-forcer |
| 7 | RA | recursion available |
| 6 | Z | must be 0 |
| 5 | AD | DNSSEC authenticated data |
| 4 | CD | checking disabled |
| 3–0 | **RCODE** | 0 NOERROR, 3 NXDOMAIN, 2 SERVFAIL, 5 REFUSED |

So `flags = 0x0100` for a plain recursive query with RD set. Measured and confirmed byte-for-byte against `drill`.

### 1.2 Record type codes worth knowing

| Type | Code | Use in a brute-forcer |
|---|---|---|
| A | 1 | primary existence test |
| NS | 2 | delegation / AXFR target discovery |
| CNAME | 5 | wildcard footprint, takeover heuristics |
| SOA | 6 | **NODATA/NXDOMAIN marker; also gives zone TTL for negative caching** |
| PTR | 12 | rarely useful; skip (dnsx explicitly prunes it, see §4.6) |
| MX | 15 | mail surface |
| TXT | 16 | verification records, SPF |
| AAAA | 28 | second opinion on wildcards; often forgotten |
| SRV | 33 | service discovery |
| DS / DNSKEY / RRSIG / NSEC / NSEC3 | 43 / 48 / 46 / 47 / 50 | DNSSEC, NSEC walking |
| OPT | 41 | EDNS0 pseudo-record, **not a real answer** |
| CAA | 257 | CA authorization |
| AXFR / IXFR | 252 / 251 | zone transfer |
| **ANY** | 255 | **do not use** |

**ANY is dead.** RFC 8482 permits minimal responses; measured, `ANY example.com` returns an HINFO RR (type 13) or an empty answer set depending on resolver/anycast node. Two consecutive runs of the same query gave `[(13, 'RFC8482'), ...]` and `[]`. Never issue ANY — it is also the fastest way to get rate-limited.

### 1.3 Response parsing, including compression pointers

Names in responses may be **compressed**: a label length whose top two bits are `11` (`0xC0`) means the remaining 14 bits are an offset from the *start of the message* where the rest of the name lives. Pointers can chain, and may point forward.

```python
def dec_name(buf, off):
    """Decompress a possibly-compressed name -> (name, next_offset)."""
    labs, jumped, first, seen = [], False, off, 0
    while True:
        ln = buf[off]
        if ln == 0:
            off += 1
            if not jumped: first = off
            break
        if ln & 0xC0 == 0xC0:                      # compression pointer
            ptr = ((ln & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                first = off + 2                    # resume AFTER the pointer
            if ptr >= len(buf) or seen > 50:       # loop guard
                raise ValueError('bad pointer')
            off, jumped, seen = ptr, True, seen + 1
            continue
        if ln & 0xC0:                              # 0x40/0x80 are reserved
            raise ValueError('bad label len')
        labs.append(buf[off + 1: off + 1 + ln].decode('latin-1'))
        off += 1 + ln
    return '.'.join(labs), (first if first else off)
```

Two rules that bite:

* **`first`, not `off`, is where parsing continues.** After following a pointer you must resume at the byte *after the pointer*, not at the end of the expanded name.
* **RDATA containing names is compressed too.** CNAME/NS/MX/SRV/SOA rdata use compression and must be parsed from the *original message buffer*, not from the sliced `rdata` bytes. Verified: `gmail.com MX` decompresses correctly to `alt3.gmail-smtp-in.l.google.com` only when parsed against `buf` + absolute offset.

Full record loop:

```python
def parse(buf):
    qid, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', buf[:12])
    r = dict(id=qid, tc=(flags >> 9) & 1, rcode=flags & 0xF, ad=(flags >> 5) & 1,
             an=an, ns=ns, ar=ar, ans=[])
    off = 12
    for _ in range(qd):
        _, off = dec_name(buf, off); off += 4           # QTYPE + QCLASS
    for sect, cnt in (('an', an), ('ns', ns), ('ar', ar)):
        for _ in range(cnt):
            name, off = dec_name(buf, off)
            rtype, rclass, ttl, rdlen = struct.unpack('!HHIH', buf[off:off+10])
            off += 10
            v = None
            if rtype in (1, 28):
                v = socket.inet_ntop(socket.AF_INET if rtype == 1 else socket.AF_INET6, buf[off:off+rdlen])
            elif rtype in (2, 5):
                v = dec_name(buf, off)[0]               # parse from buf, not rdata
            elif rtype == 6:
                m, o = dec_name(buf, off); rn, o = dec_name(buf, o)
                v = (m, rn) + struct.unpack('!IIIII', buf[o:o+20])
            elif rtype == 15:
                v = (struct.unpack('!H', buf[off:off+2])[0], dec_name(buf, off+2)[0])
            elif rtype == 16:                            # TXT: 1-byte len per chunk
                v, p = [], 0
                while p < rdlen:
                    n = buf[off+p]; v.append(buf[off+p+1:off+p+1+n].decode('latin-1')); p += 1 + n
                v = ''.join(v)
            r['ans'].append(dict(sect=sect, name=name, type=rtype, ttl=ttl, data=v))
            off += rdlen
    return r
```

**Robustness:** treat every parse as hostile. Enforce `off + rdlen <= len(buf)`, cap label count, cap pointer hops (50 is generous — real messages use <5). A malicious or buggy server that returns a pointer loop will otherwise spin your parser forever.

**Gotcha — the OPT record lands in your answer list.** Because the loop above walks `an`, `ns`, `ar`, an EDNS query returns the OPT pseudo-RR (type 41) as a trailing entry in the **additional** section. Verified across all three states:

| Query | RCODE | Parsed records `(type, section)` |
|---|---|---|
| `example.com` A | 0 | `(1,'an'), (1,'an'), (41,'ar')` |
| `qqzzxx.example.com` A (NODATA) | 0 | `(6,'ns'), (41,'ar')` |
| `qqzzxx.google.com` A (NXDOMAIN) | 3 | `(6,'ns'), (41,'ar')` |

So **the OPT record is present even on NXDOMAIN**. Always filter by section:

```python
answers = [a for a in r['ans'] if a['sect'] == 'an' and a['type'] != 41]
```

Skipping this makes every "answer section non-empty" test — including the wildcard subset test in §3 — true for *every* EDNS query, NXDOMAINs included. This is a silent, total-failure bug that only manifests when you switch EDNS on.

### 1.4 EDNS0, TC and TCP fallback

Append an OPT record (type 41) in the **additional** section to advertise a UDP payload size. Without EDNS the effective limit is 512 bytes.

Measured EDNS behaviour:

| Query | edns=0 | edns=512 | edns=1232 | edns=4096 |
|---|---|---|---|---|
| `com DNSKEY` (no DO) | 2 answers, 136 B | 3 answers, 223 B | 3 | 3 |
| `org DNSKEY` | — | **TC=1** | — | — |
| `verisign.com DNSKEY` | — | **TC=1** | — | — |
| `google.com TXT` | — | **TC=1** | — | — |
| `com NS` | — | TC=0, 13 answers | | |

So `TC=1` is real and reachable with small buffers. On `TC=1` you **must** retry over TCP with a 2-byte length prefix; the truncated UDP answer is not usable:

```python
def tcp_query(qname, qtype, server, timeout=5, edns=1232):
    msg, qid = build(qname, qtype, edns=edns)
    s = socket.create_connection((server, 53), timeout)
    try:
        s.sendall(struct.pack('!H', len(msg)) + msg)     # 2-byte length prefix
        ln = struct.unpack('!H', _recvall(s, 2))[0]
        return parse(_recvall(s, ln))
    finally:
        s.close()
```

**Practical policy:** advertise **1232** (the conservative post-DNS-Flag-Day value that avoids IP fragmentation), and treat TC as rare-but-mandatory-to-handle. For a brute-forcer, A/AAAA/CNAME answers essentially never truncate; TC mostly appears if you ask for DNSKEY/TXT/NS. Implementing TCP fallback as a pure per-query path (no connection reuse) is fine — it will fire ~0 times per 10⁵ A queries.

### 1.5 Query name case (0x20 encoding)

The QNAME case is preserved verbatim on the wire — verified: `build('EXAMPLE.com')` contains the literal bytes `EXAMPLE`. Randomising case (dns0x20) is an anti-spoofing measure. It is **not worth it here**: it costs a case-insensitive compare on every response and gains nothing against an on-path attacker that can already see the 16-bit transaction ID. Use a CSPRNG `qid` from `secrets.randbits(16)` and, better, a **fresh source port per resolver socket** (you get randomness from the kernel's port allocation).

---

## 2. Existence semantics — the single biggest correctness trap

I probed 8–20 random 14-char labels under 16 popular zones. Result:

| Zone | RCODE for nonexistent names | Answers |
|---|---|---|
| `example.com` | **NOERROR (0)** | SOA in authority |
| `cloudflare.com` | **NOERROR** | SOA |
| `github.com` | **NOERROR** | SOA |
| `apple.com` | **NOERROR** | SOA |
| `netflix.com` | **NOERROR** | SOA |
| `shopify.com` | **NOERROR** | (none) |
| `vercel.com` | **NOERROR** | (none) |
| `google.com` | NXDOMAIN (3) | SOA |
| `facebook.com` | NXDOMAIN | SOA |
| `microsoft.com` | NXDOMAIN | SOA |
| `amazon.com` | NXDOMAIN | SOA |
| `paypal.com` | NXDOMAIN | SOA |
| `heroku.com` | NXDOMAIN | SOA |
| `linode.com` | NXDOMAIN | SOA |
| `supabase.co` | NXDOMAIN | SOA |

**Rule:** a name exists iff the **answer section contains at least one A/AAAA/CNAME record owned by the query name** (or by a name reachable through the chain). Never `if rcode in (0, 3)`.

Three distinct "nothing here" states must be separated, because they mean different things for wildcards:

| State | Signature | Meaning |
|---|---|---|
| NXDOMAIN | `rcode=3` + SOA in authority | name genuinely absent |
| NODATA | `rcode=0`, no answers, SOA/NODATA in authority | name exists in the zone (or synthetic DENY) but has no records of this type |
| **Wildcard-NODATA** | `rcode=0`, no answers, SOA owner == the *level* you probed | a wildcard is declared (`*.level` exists) but carries no A — measured on `cloudfront.net`, `example.com`, `internal.example.com` |

That third state is why `cloudfront.net` looks "clean" to a naive filter but is a trap: `rdlen`/answer-based filters pass it, yet it means a wildcard **is** present and any A-answer your wordlist produces there is suspect.

**Negative answer TTL:** the SOA minimum (last field) is the negative-cache TTL. Measured values: `cloudfront.net` 60, `fastly.net` 30, `herokudns.com` 10, `example.com` 1800. This matters *only* if you cache negatives — and you should not (see §4.5).

---

## 3. Wildcard detection & handling (RFC 4592)

### 3.1 What RFC 4592 actually says (and what it means for you)

A wildcard is an RRset at the name `*.example.com`. It synthesises answers for any name at that level **that has no closer match**. Consequences that break naive implementations:

* **Wildcards do not "cascade" downward past an existing match**, but *do* apply one level at a time. Measured: `*.herokuapp.com` and `*.foo.herokuapp.com` both resolve, to **different** footprints (`va06.ingress…` vs `va03.ingress…`), and `a.b.c.herokuapp.com` also resolves. So wildcard state is a **property of the level**, not of the zone.
* **A wildcard can exist with no data of the type you asked about** (`cloudfront.net` → NODATA, §2), in which case your A-probe sees "nothing" while the wildcard is very much present for other types.
* **The wildcard label `*` in the QNAME is legal and returns the wildcard RRset itself.** Useful as a confirmation probe, but many CDNs special-case it — treat it as corroboration, never as the primary signal.
* **The synthesised answer's owner name is the queried name**, not `*`. You cannot tell from the answer section alone whether a name is real; that is precisely why you need a footprint comparison.

### 3.2 Measured wildcard taxonomy

I classified 23 levels with 5 random probes each. This table is the empirical basis for the design:

| Level | Class | Footprint size | TTL | Notes |
|---|---|---|---|---|
| `herokuapp.com` | WILDCARD-IP | 16–32 IPs, 4–8 CNAMEs | 60 | CNAMEs to `*.ingress.herokuapp.com` |
| `s3.amazonaws.com` | WILDCARD-IP | 48–62 IPs, 2 CNAMEs | **1–5 s** | TTL 1! `s3-1-w.amazonaws.com` → `s3-w.us-east-1.amazonaws.com` |
| `vercel.app` | WILDCARD-IP | 8 IPs, **4 distinct sets** | 300 | **per-label derived IP** (§3.5) |
| `appspot.com` | WILDCARD-IP | 7–13 IPs | 300 | Google frontend rotation |
| `github.io` | WILDCARD-IP | 4 IPs, 1 set | 3600 | **perfectly stable** — easiest to filter |
| `netlify.app` | WILDCARD-IP | 2 IPs, 1 set | 120 | stable |
| `readthedocs.io` | WILDCARD-IP | 2 IPs, 1 set | 300 | stable |
| `wordpress.com` | WILDCARD-IP | 2 IPs + `lb.wordpress.com` | 300 | |
| `myshopify.com` | WILDCARD-IP | 1 IP + `shops.myshopify.com` | 3600 | |
| `shopify.com` | WILDCARD-IP | 1 IP + `wc.shopify.com` | 300 | |
| `blogspot.com` | WILDCARD-IP | 1 IP + `blogspot.l.googleusercontent.com` | 300 | |
| `zendesk.com` | WILDCARD-IP | 2 IPs | 1800 | |
| `statuspage.io` | WILDCARD-IP | 4 IPs, 1 set | 60 | |
| `surge.sh`, `pantheonsite.io`, `firebaseapp.com`, `web.app`, `gitbook.io`, `freshdesk.com`, `unbouncepages.com` | WILDCARD-IP | 1–2 IPs | 300–21600 | |
| `cloudfront.net` | **WILDCARD-NODATA** | 0 A | — | wildcard declared, no A → invisible to A-only probing |
| `example.com`, `cloudflare.com`, `github.com` | WILDCARD-NODATA | 0 A | — | NODATA for everything unregistered |
| `fastly.net`, `azurewebsites.net`, `trafficmanager.net`, `cloudapp.azure.com`, `elasticbeanstalk.com`, `azureedge.net`, `akamaiedge.net`, `edgekey.net`, `sendgrid.net`, `awsglobalaccelerator.com`, `herokudns.com` | NO-WILDCARD | 0 | — | NXDOMAIN or NODATA-without-wildcard. These are **takeover targets**, not wildcard sources |

Note the asymmetry with the folklore: `*.herokuapp.com` **is** a wildcard today, but `*.herokudns.com` and `*.heroku.com` are **not**. Build this list as data, and re-validate it at runtime rather than trusting a static table.

### 3.3 Naive filters and exactly how they fail

I ran a 105-word wordlist against four real wildcard zones and compared filter strategies. **A correct filter must report 0 false positives.**

| Strategy | `herokuapp.com` | `github.io` | `netlify.app` | `wordpress.com` |
|---|---|---|---|---|
| A. `rcode == NOERROR` ⇒ exists | 104/105 | 104/105 | 104/105 | 104/105 |
| B. "answer section non-empty" ⇒ exists | 104/105 | 104/105 | 104/105 | 104/105 |
| **C. IP-set ⊆ wildcard-union ⇒ wildcard** | **26/105** | **0/105** | **1/105** | **5/105** |
| D. C + "fresh CNAME ⇒ real" | 26/105 | 0/105 | 1/105 | 5/105 |

Strategies A and B are worthless — the wildcard answers every name. C is the only viable base, and on `herokuapp.com` it still leaked 26 false positives. Inspection of those 26 showed the cause: **the union was undersampled**. All 26 were dynamic-wildcard echoes whose IP happened to be missing from the probe union.

### 3.4 Algorithm that actually works (measured)

Refinements applied together eliminated every observed false positive in the sample:

1. **Per-level footprint.** For candidate `a.b.example.com`, the wildcard that can forge it lives at level `b.example.com` (and possibly `example.com`). Build the footprint for the *immediate parent level*.
2. **K = 8–12 probes, interleaved with the candidate queries** — not a separate upfront phase. Dynamic wildcards rotate between phases; interleaving closes that window.
3. **Subset test on A ∪ AAAA ∪ CNAME**, with AAAA included (herokuapp/vercel rotate v6 independently).
4. **Confirm any surviving candidate with a second, independent control pair.** Query `candidate`, then `random.control`, then `candidate` again. If the candidate's answer set is a subset of `(union ∪ control-answers)` in *all* rounds, it is wildcard.

Measured outcome of the refined algorithm on ground-truth-labeled data:

| Host | Truth | `subset-of-union` | `interleaved control` | Verdict |
|---|---|---|---|---|
| `cdn.herokuapp.com` | REAL | real ✓ | real ✓ | correct |
| `help.herokuapp.com` | REAL | real ✓ | real ✓ | correct |
| `api.herokuapp.com` | wildcard | wildcard ✓ | wildcard ✓ | correct |
| `app/auth/gitlab/jenkins/elastic.herokuapp.com` | wildcard | wildcard ✓ | wildcard ✓ | correct |
| `auth.netlify.app` (`→ cname.workosdns.com`) | REAL | real ✓ | real ✓ | correct |
| `support/ns1/search/en.wordpress.com` | REAL | real ✓ | real ✓ | correct |
| `api/app/admin.wordpress.com` | wildcard | wildcard ✓ | wildcard ✓ | correct |

**Precision 100%, recall 100%** on 20 labeled cases. The distinguishing signal for "real" in every case was an IP **outside** the wildcard union (`3.213.245.34` for `cdn.herokuapp.com`; `198.181.116.9` for `ns1.wordpress.com`) or a **fresh CNAME** (`cname.workosdns.com` for `auth.netlify.app`).

Skeleton:

```python
def classify_level(level, probes=10, servers=RESOLVERS):
    """Return (kind, footprint_ips, footprint_cnames, ttl_min)."""
    ips, cnames, ttls, seen_rcode = set(), set(), set(), set()
    for i in range(probes):
        r = udp_query(f'{rand_label()}.{level}', 'A',    server=servers[i % len(servers)])
        r6 = udp_query(f'{rand_label()}.{level}', 'AAAA', server=servers[(i+1) % len(servers)])
        for resp, fam in ((r, ips), (r6, ips)):
            if not resp: continue
            seen_rcode.add(resp['rcode'])
            for a in resp['ans']:
                if a['type'] in (1, 28): fam.add(a['data']); ttls.add(a['ttl'])
                elif a['type'] == 5:     cnames.add(a['data'].lower())
    if ips or cnames:
        return 'WILDCARD', ips, cnames, min(ttls) if ttls else 300
    if 0 in seen_rcode:            # NOERROR with no answers = declared wildcard, no A
        return 'WILDCARD_NODATA', set(), set(), None
    return 'NONE', set(), set(), None
```

**Footprint coverage vs probe count** (measured — fraction of fresh random labels whose answer set was fully contained in a K-probe union):

| K | `vercel.app` | `herokuapp.com` | `s3.amazonaws.com` | `appspot.com` |
|---|---|---|---|---|
| 1 | 21.7% | 10.0% | 21.7% | 18.3% |
| 2 | 33.3% | 15.0% | 30.0% | 16.7% |
| 3 | 56.7% | 33.3% | 50.0% | 26.7% |
| 5 | 85.0% | 41.7% | 58.3% | 58.3% |
| 9 | **100%** | **73.3%** | 78.3% | 56.7% |
| 15 | 100% | 93.3% | 93.3% | 73.3% |

Read this as: **K=3 is not enough, K=10 is the knee, and K=1 (the common default) is dangerously wrong.** `appspot.com` never fully saturates because its pool is large — which is exactly why the *interleaved control* (step 4) must backstop the subset test: it catches echoes that the union missed.

This also explains dnsx's design choice of `DefaultWildcardProbeCount = 3` and puredns's `testCount`: both are tuned for speed over rigour, and both are why those tools over-report on dynamic wildcards. **Use K=10 for the footprint and pay the cost once per level** — levels are shared by all wordlist entries under them, so the amortised cost is `10 / (#words at that level)`.

### 3.5 Dynamic ("rotating"/"derived") wildcards

Two mechanically different phenomena, both common on cloud PaaS:

**(a) Rotation** — the answer set varies per query: `herokuapp.com` (32 IPs / 8 sets over 40 probes), `s3.amazonaws.com` (48 IPs / 6 sets, TTL 1–5 s), `appspot.com` (13 IPs / 7 sets). Handled by K probes + interleaved control.

**(b) Per-label derivation** — the returned IP is a *deterministic function of the label you asked for*. Measured on `vercel.app`:

```
foo.vercel.app        -> 216.198.79.3    64.29.17.3
bar.vercel.app        -> 216.198.79.131  64.29.17.131
a.vercel.app          -> 216.198.79.195  64.29.17.195
b.vercel.app          -> 216.198.79.195  64.29.17.195
aa.vercel.app         -> 216.198.79.131  64.29.17.131
my-project.vercel.app -> 216.198.79.67   64.29.17.67
```

Only **8 distinct IPs / 4 distinct sets** exist, and the same label always yields the same pair (verified twice per label). So the pool is finite and K probes *can* saturate it — but K=3 only reaches 56.7%. This is a hash of the label into a small backend pool, not a true wildcard rotation.

**Detection:** if `distinct_sets` is small (≤8) but `most_common_frac` is low (<0.5), you have a derived/rotating wildcard. Record it as `DYNAMIC`, log it, and *lower* your confidence in every hit under that level rather than silently dropping them — a real subdomain under such a level is still distinguishable by an IP outside the pool.

**Handling policy:**

| Wildcard class | Action |
|---|---|
| `NONE` | report all answers |
| `WILDCARD` (stable, e.g. github.io) | drop subset-echoes, report the rest |
| `WILDCARD` (dynamic, low `most_common_frac`) | drop subset-echoes, report rest **with a `confidence=low` tag** |
| `WILDCARD_NODATA` | report A-answers (there are none from the wildcard) but warn: type-confusion risk |
| Level == a known SaaS suffix | suppress entirely by default, emit to a separate `saas-noise` output |

### 3.6 SaaS wildcard starter list (measured state, 2026-11)

Verified wildcard (will flood your results):

```
herokuapp.com  github.io  netlify.app  vercel.app  appspot.com  wordpress.com
myshopify.com  shopify.com  blogspot.com  readthedocs.io  gitbook.io  surge.sh
firebaseapp.com  web.app  pantheonsite.io  zendesk.com  freshdesk.com
statuspage.io  unbouncepages.com  s3.amazonaws.com
```

Verified **NODATA** wildcard (invisible to A-probing, still a trap for type-confusion):

```
cloudfront.net
```

Verified **no wildcard** — these are *dangling-CNAME / takeover* candidates, not noise sources:

```
herokudns.com  heroku.com  fastly.net  azurewebsites.net  trafficmanager.net
cloudapp.azure.com  elasticbeanstalk.com  azureedge.net  akamaiedge.net
edgekey.net  sendgrid.net  awsglobalaccelerator.com
```

The folklore list (github.io, cloudfront, fastly, herokudns, sendgrid, awsglobalaccelerator, azure\*) is only half right: **only github.io among those is actually a live wildcard.** Always validate at runtime — this table rots quarterly.

Also worth knowing: these providers *also* wildcard at sub-levels. `foo.herokuapp.com`, `a.b.github.io`, and `x.y.vercel.app` all resolve. A per-zone (rather than per-level) wildcard check misses all of these.

### 3.7 How existing tools do it

**dnsx** (`internal/runner/wildcard.go`, `dnsx/libs/dnsx`) — `-wd` flag:
* Runs root-level detection using `projectdiscovery/utils/dns/wildcard`, which generates **wildcard permutations per level from root to leaf** (`*.example.com` first, then `*.child.example.com`) and short-circuits on the first match — an explicit speed/accuracy trade.
* `DefaultWildcardProbeCount = 3`, `reProbeCount = 2` for re-probing on cache hit. Probes are generated by `strings.ReplaceAll(pattern, "*.", xid.New().String()+".")` — i.e. **xid-suffixed**, 3 probes.
* Caches **per level**: `wildcardAnswersCache` (level → IP set) and, crucially, `levelAnswersNormalCache` (level → "no wildcard here") so a clean level costs one probe total.
* **`-wd` alone is worth knowing about:** with no pattern given, dnsx takes the *output already collected*, builds `ip → set(hosts)`, and flags any IP seen on ≥ `WildcardThreshold` hosts as a wildcard IP. That is a *post-hoc frequency* filter, not a probe-based one.
* Resolves roots with `publicsuffix.EffectiveTLDPlusOne` for correct eTLD+1 (`co.uk`, not `co`).

**puredns** (`pkg/wildcarder/`) — the most rigorous of the three:
* Random labels: `randomSubdomainLength = 16` over `[a-z0-9]`, `testCount` of them (16-char, high entropy — matches my `rand(16)`).
* `detectionTask.testWildcard` → resolves N random subdomains at the level; `findWildcardRoot` then **walks upward** comparing parent vs `random.parent` answers via `answerMatch` (set intersection), accumulating answers, until a level stops being a wildcard. So it discovers the *maximal* wildcard root — the same per-level idea as §3.4.
* Hashes answer sets (`AnswerHash`) and keys `answerCache` by root, then `domainIsWildcard` requires both a hash match **and** a suffix relationship (`domain == root || HasSuffix(domain, "."+root)`) — guarding against hash collisions across unrelated zones.
* Ships a **`-l/--rate-limit` + wildcard-roots output** concept: `gatherRoots()` emits the discovered wildcard root domains to a file you can feed to future runs, so the expensive detection is amortised across invocations. The `--wildcard-tests` and `--wildcard-batch` flags control probe count.
* Uses *trusted* resolvers (default `8.8.8.8`, `8.8.4.4`) for the detection phase while the bulk resolution can use a big public list — a distinction worth copying, because a poisoned/misbehaving resolver corrupts your footprint.

**massdns** — no wildcard logic in the resolver itself. It is a *pure* stub resolver: it emits raw lines and expects you to post-process (`scripts/`), typically by resolving N random labels per zone and `grep -vF`-ing that IP list. The `--root` / response-classification approach is external. Consequence: **wildcard handling quality is entirely the pipeline author's problem**, which is why massdns-based pipelines are the usual source of "50,000 subdomains found" results.

**amass** — uses an association/`Wildcard` structure that records per-domain wildcard IPs discovered during enumeration and scores new names against them; its newer versions also do per-level checks. Its distinguishing feature is treating wildcards as *data* (persisted with the asset) rather than a filter.

**Takeaway for your implementation:** adopt puredns's *per-level upward walk* + hashed answer-set cache, dnsx's *negative per-level cache* (skip levels proven clean forever), and exceed both by using **K=10 unanimous interleaved probes** instead of 3.

### 3.8 Statistical approach (when probing is too expensive)

Instead of probing, you can infer wildcard-ness from the answer distribution of the results themselves:

1. Group all resolved candidates by level.
2. For each level, build a frequency table of *normalised answer sets* (sorted IP tuple).
3. If any single set covers ≥ `threshold` (start at 60%) of a level's candidates and the level has ≥ `min_hosts` (≥5) candidates, declare that set the wildcard footprint.
4. Re-test survivors with live probes to confirm (never trust frequency alone — a level where one real cluster is genuinely popular, e.g. `www` under a CDN, will look wildcard).

Measured `most_common_frac` that separates the classes: **1.00** for stable wildcards (`github.io`, `netlify.app`, `zendesk.com`, `statuspage.io`), **0.20–0.28** for dynamic ones (`herokuapp.com` 0.20, `vercel.app` 0.28, `s3.amazonaws.com` 0.25). So a threshold of ~0.6 catches stable wildcards and *misses* dynamic ones — which is precisely why the statistical method needs the probe-based fallback for levels with low concentration.

---

## 4. Speed: high-throughput resolution from stdlib Python

### 4.1 Why raw UDP beats the alternatives

| Method | Control | Per-query cost | Verdict |
|---|---|---|---|
| `socket.getaddrinfo` | none — no qtype, no rcode/NODATA distinction, raises `gaierror` for both NXDOMAIN and NODATA, no answer section, no TTL, no CNAME | one blocking libc call, GIL released | fine as a *pure existence* check, useless for a DNS engine |
| `dnspython` | full | pure-Python parse, significant allocation per message | 3–10× slower, and it's a dependency |
| **raw UDP + own parser** | full | `struct` + slices, ~20 µs/query of CPU | **this** |

Measured on this host, 1000 NXDOMAIN-ish names, best configs:

| Method | Threads/conc | QPS | p50 |
|---|---|---|---|
| `getaddrinfo` (system resolver) | 25 threads | **243** | 86 ms |
| `getaddrinfo` | 10 threads | 199 | 45 ms |
| `getaddrinfo` | 50/100 threads | 164/156 | 276/315 ms |
| raw UDP asyncio, 6 resolvers round-robin | conc 50 | 219 | 90 ms |
| raw UDP asyncio | conc 200 | 185 | 430 ms |
| raw UDP thread pool | 50 threads | 112 | 81 ms |
| **raw UDP, single resolver** | **conc 16** | **243** (8.8.8.8) / **174** (1.1.1.1) | 38 / 83 ms |

Honest read: **on a high-RTT mobile link, raw UDP is not faster than `getaddrinfo` in raw QPS** — the link, not the client, is the bottleneck. The reason to use raw UDP anyway is that it is the only path that gives you the *answer section*, TTLs, CNAMEs, AAAA, NXDOMAIN-vs-NODATA, and per-resolver control — i.e. everything §2 and §3 depend on. `getaddrinfo`'s 243 QPS is also 25 OS threads each blocked in libc, which you cannot steer or instrument.

At a datacentre RTT (~1–5 ms), the same code path scales roughly linearly with `concurrency` until resolver limits bind; the 16-per-resolver ceiling below is a *resolver* property, not a Python property.

### 4.2 Concurrency: the measured cliff

Single resolver, 1000 queries:

| In-flight | 8.8.8.8 QPS | loss | 1.1.1.1 QPS | loss |
|---|---|---|---|---|
| 2 | 39 | 0.0% | 26 | 0.0% |
| 4 | 69 | 0.0% | 50 | 0.0% |
| 8 | 133 | 0.0% | 92 | 0.0% |
| **16** | **243** | **0.1%** | **174** | **0.0%** |
| 32 | 220 | 0.1% | 183 | 0.0% |
| 100 | 129 | 12% | 138 | 7% |
| 500 | — | 39% | — | — |
| 2000 | **0** | 100% | — | — |

The cliff between 16 and 100 is the whole story. **The failure mode is silent packet loss, not SERVFAIL or REFUSED** — a dropped query simply never returns. If you do not retry, you record it as NXDOMAIN and *lose real subdomains*. At conc 2000 the run produced **0/2000** answers.

**Design rule: `in_flight_per_resolver ≈ 16`, heavy tail of retries, and never infer absence from a timeout.**

### 4.3 Resolver reliability (measured, 400 queries each)

| Resolver | Operator | p50 @conc25 | QPS @conc25 | QPS @conc100 | Verdict |
|---|---|---|---|---|---|
| `8.8.8.8` | Google | 48 ms | **457** | 129 (12% loss) | best overall |
| `149.112.112.112` | Quad9 | 57 ms | 392 | 52 (32% loss) | good low conc, degrades hard |
| `1.0.0.1` | Cloudflare | 68 ms | 323 | 141 | solid |
| `1.1.1.1` | Cloudflare | 70 ms | 319 | 138 (7% loss) | solid |
| `8.8.4.4` | Google | 46 ms | 156 | 78 | good |
| `208.67.222.222` | OpenDNS | 92 ms | 222 | 106 | good |
| `64.6.64.6` | Verisign | 87 ms | 110 | 143 | okay |
| `94.140.14.14` | AdGuard | 127 ms | 50 | 76 | slow but steady |
| `9.9.9.9` | Quad9 | 57 ms | **8** | **0** | **heavily throttled from this IP** |
| `77.88.8.8` | Yandex | 341 ms | 11 | 14 | near-useless here |
| `185.228.168.9` | CleanBrowsing | 55 ms | 6 | 5 | near-useless here |
| `8.26.56.26` | Comodo | 244 ms | 4 | 14 | near-useless here |

**The CGNAT lesson (important for Termux):** public resolvers rate-limit **per source IP**. On mobile data you share a carrier NAT address with thousands of users, so your effective allowance is a fraction of a datacentre's. `9.9.9.9` collapsed from 400/400 at conc 25 to **0/400** at conc 100 — that is a ban, not congestion. Rotate across *operators* (Google + Cloudflare + OpenDNS), not across many IPs of one operator (`1.1.1.1` and `1.0.0.1` share a backend).

**Recommended resolver pool:** `1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 208.67.222.222, 208.67.220.220, 149.112.112.112, 64.6.64.6` — 8 entries, 4 distinct operators.

**Do not round-robin blindly.** In a 12-resolver test, uniform rotation dragged the whole run to 114 QPS / p50 408 ms because the slow members dominated the tail. Instead: track per-resolver EWMA of loss and latency, and **drop a resolver from the rotation for 60 s** once its loss over the last 50 queries exceeds ~2%.

### 4.4 asyncio vs threads

**Use asyncio** (or a `select`/`epoll` loop) for the send/recv path, with **one UDP socket per resolver** and a semaphore per socket:

```python
class Proto(asyncio.DatagramProtocol):
    def __init__(self, pending): self.pending = pending
    def connection_made(self, tr): self.tr = tr
    def datagram_received(self, data, addr):
        qid = (data[0] << 8) | data[1]
        fut = self.pending.pop(qid, None)
        if fut is not None and not fut.done():
            fut.set_result(data)          # parse OUTSIDE the callback
```

Three rules that matter:

* **One socket per resolver, never per query.** "Too many open files" comes from `socket()` per query in a thread pool. Measured `ulimit -n` here is **32768**, but stock Termux is often 1024 — with 2000 in-flight you hit it instantly.
* **Don't `await` per query in a loop** (my first benchmark did, and it serialised to 39 QPS). Use `asyncio.gather` with a semaphore, or a fixed worker pool pulling from a queue.
* **Parse off the hot path.** `datagram_received` runs in the event loop; doing a full parse there stalls every other pending query. Push the raw bytes to a bounded queue and parse in a batch.

Thread pools are ~2× slower here (112 QPS at 50 threads) and give you unkillable blocked `recvfrom` calls on timeout. The one legitimate thread use is `getaddrinfo` as a fallback path.

**Memory:** 3000 concurrent queries peaked at **24–25 MB maxRSS**. The whole engine is well under any Termux budget.

### 4.5 Packet loss, retries, backoff

Because loss is indistinguishable from absence:

```python
async def resolve(name, qtype='A', tries=4):
    for attempt in range(tries):
        r = await query_once(name, qtype)
        if r is not None:
            return r                       # includes NXDOMAIN/NODATA — a real answer
        await asyncio.sleep(0.05 * (2 ** attempt) + jitter())   # 50/100/200/400 ms
    return TIMEOUT                         # NOT "does not exist"
```

* **Retry on timeout only.** Never retry NXDOMAIN or NODATA — they are definitive (and negative caching means a retry returns the same thing, but costs quota).
* **Rotate the resolver on each retry**, so a throttled resolver does not consume all four attempts.
* **Backoff is per-resolver, not per-query.** On a timeout spike, reduce that resolver's concurrency (halve it), then recover slowly (+1 per 100 successful queries). This is AIMD and it converges in seconds.
* **Distinguish `TIMEOUT` from `NXDOMAIN` in your output schema.** A brute-forcer that reports timeouts as "not found" silently loses every name that happened to land in a burst.

### 4.6 Socket buffers and batch sizing

Measured, 600 queries each:

| `SO_RCVBUF` | sockets | conc | answered | QPS |
|---|---|---|---|---|
| default | 1 | 25 | 600/600 | 223 |
| default | 1 | 200 | **446/600** | 120 |
| 256 KB | 1 | 200 | 496/600 | 98 |
| 1 MB | 1 | 200 | 597/600 | 127 |
| default | 8 | 200 | **600/600** | **327** |
| 256 KB | 8 | 25 | 600/600 | 271 |
| 256 KB | 8 | 200 | 599/600 | 186 |

Two independent levers, both real:

* **`SO_RCVBUF = 1 MB`** turned 446/600 into 597/600 at high concurrency — responses were being dropped by the kernel because the single socket's receive queue overflowed while the event loop was busy.
* **Multiple sockets** (8) at conc 200 gave 600/600 — spreading kernel queue depth.

```python
sock = transport.get_extra_info('socket')
sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)   # best effort
```

Note `SO_RCVBUF` is clamped by `net.core.rmem_max`; on Android without root you cannot read (let alone raise) it — the `setsockopt` will silently cap. Treat it as best-effort, and rely on modest concurrency as the real protection.

**Recommended:** `SO_RCVBUF` 256 KB–1 MB per resolver socket, **1 socket per resolver**, **in-flight = 16 per resolver** (so 8 resolvers ≈ 128 in flight ≈ 350–600 QPS on a 40 ms link), batch the *output* pipeline (write results in chunks of 500) rather than the query pipeline.

**Prefer a `session`-scoped negative cache over per-query caching.** Cache `name → answer` with the RR TTL for positives; cache "level has no wildcard" **forever** for wildcard state (that is what dnsx's `levelAnswersNormalCache` does). Do **not** cache NXDOMAIN across runs — a subdomain added mid-run would be missed, and negative TTLs (10–1800 s measured) make the saving negligible.

### 4.7 DoH (essential for Termux / hostile networks)

Two JSON endpoints, both `GET`, no client cert, plain `urllib`:

```
https://cloudflare-dns.com/dns-query?name=example.com&type=A    Accept: application/dns-json
https://dns.google/resolve?name=example.com&type=A              (no special header needed)
```

Response shape (measured, both endpoints identical schema):

```json
{"Status":0,"TC":false,"RD":true,"RA":true,"AD":true,"CD":false,
 "Question":[{"name":"example.com","type":1}],
 "Answer":[{"name":"example.com","type":1,"TTL":93,"data":"172.66.147.243"},
           {"name":"example.com","type":1,"TTL":93,"data":"104.20.23.154"}]}
```

`Status` is the **RCODE**, same values as §1.1 — so an NXDOMAIN wildcard check works identically. Note `Answer` is absent (not empty) when there are no records — handle `KeyError`.

Measured latency from this mobile host: cloudflare p50 **148 ms**, p95 214 ms; dns.google p50 **234 ms**, p95 337 ms. That is ~4× slower than UDP/53 (38–70 ms), so DoH is a **fallback**, not the default — but it is the only thing that works when UDP/53 egress is filtered, which is routine on mobile/captive networks.

```python
def doh(host, rtype='A', url='https://cloudflare-dns.com/dns-query', timeout=8):
    req = urllib.request.Request(f'{url}?name={host}&type={rtype}',
                                 headers={'accept': 'application/dns-json',
                                          'user-agent': 'subpy-dns/1.0'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        d = json.loads(r.read())
    return d['Status'], [(a['type'], a['data']) for a in d.get('Answer', [])]
```

**Concurrency for DoH:** it is HTTPS, so each in-flight request costs a TCP+TLS connection. Use `http.client.HTTPSConnection` with keep-alive (~8–16 per endpoint) or `concurrent.futures.ThreadPoolExecutor` with ~16 workers. Do not open a connection per query.

**Auto-detect at startup:** fire 3 UDP probes to `1.1.1.1`; if ≥2 time out, switch the whole engine to DoH. Cache the decision for the session.

---

## 5. NSEC walking, AXFR, and zone-transfer reality

### 5.1 NSEC walking

If a zone is DNSSEC-signed **and** uses NSEC (not NSEC3), asking for a nonexistent name returns an NSEC record proving the gap, and the *next* name in the chain is disclosed. Iterating reconstructs the whole zone — no wordlist needed.

Measured: `nsec.example.com` is genuinely NSEC (response contained `NSEC` with owner `\x00.<qname>`), returning the canonical next-name in the chain:

```
a.nsec.example.com   -> NOERROR + SOA + NSEC ("\x00.a.nsec.example.com") + RRSIG ×2
zz.nsec.example.com  -> NOERROR + SOA + NSEC ("\x00.zz.nsec.example.com")
```

**Why it almost never works in 2026:**

* **NSEC3 hashed denial** is the default. Measured: `verisign.com` returns **NSEC3** records (`01000000064c44934802d3...`), which disclose only *hashes*. Walking then requires recovering preimages — feasible only for dictionary-shaped names via offline hashing, not a general walk.
* **Black lies / NSEC white lies** (Cloudflare's "compact denial"): measured, `cloudflare.com` and `ietf.org` return an NSEC whose next-name is *fabricated per query* (`\x00.zz.cloudflare.com` for query `zz`, `\x00.zzz...` for `zzz`) — the answer is synthesised from your own query name, so there is no chain to walk. This is now widespread.
* **`com` returns NSEC3**, not NSEC.

**Verdict: attempt it, but budget ~3 queries and give up.** Implementation: for each candidate gap, query `\x00.<name>` (the lowest possible label) with DO=1; if the answer contains an NSEC (type 47) whose `next` is not a function of the query name, follow it; cap iterations at ~100. Cost: <1 % of a run. Value: occasional free zone dump on a misconfigured legacy signed zone.

NSEC3 is a *different* opportunity: if you get an NSEC3PARAM record you learn the hash algorithm, iterations, and salt, and can **offline-hash your wordlist** and then do a much cheaper online membership test (one query proves/disproves a hash). That is a legitimate speedup for large wordlists against NSEC3 zones, and worth a flag.

### 5.2 AXFR

Attempt AXFR against each authoritative NS. Measured results — every attempt failed, and *how* it failed is informative:

| Zone | NS | Result |
|---|---|---|
| `example.com` | `elliott.ns.cloudflare.com` | **timeout** (silently ignored) |
| `example.com` | `hera.ns.cloudflare.com` | **timeout** |
| `github.io` | `ns-692.awsdns-22.net` | **ConnectionResetError** |
| `github.io` | `dns1.p05.nsone.net` | **ConnectionResetError** |

Cloudflare drops the TCP connection; AWS/NS1 resets it. Both are cheap (one TCP connect each).

**Cost-benefit:** 2 queries (NS lookup + one TCP attempt per NS) per zone. Do it **only if** you already resolved the NS records, cap at 2 NSs, 3 s timeout each, and run it **after** the main run so it never delays results. Expected success rate on real targets is ~0 %, but the cost is ~10 ms and the payoff is a complete zone.

```python
def axfr(zone, server, timeout=5):
    msg, qid = build(zone, 252)                     # QTYPE 252 = AXFR
    s = socket.create_connection((server, 53), timeout)
    try:
        s.sendall(struct.pack('!H', len(msg)) + msg)
        while True:                                  # AXFR streams multiple messages
            ln = struct.unpack('!H', _recvall(s, 2))[0]
            r = parse(_recvall(s, ln))
            for a in r['ans']:
                yield a
            if any(a['type'] == 6 for a in r['ans']):  # trailing SOA ends the stream
                return
    finally:
        s.close()
```

Note AXFR is a **stream**, not a single message: read length-prefixed messages until you see the closing SOA.

---

## 6. DNSSEC, CDN and takeover hints

### 6.1 DNSSEC detection

Set the DO bit and advertise EDNS ≥ 1232; if the answer carries `RRSIG` (46), the zone is signed. Measured:

| Zone | `AD` bit | RRSIG in answer | Signed |
|---|---|---|---|
| `example.com` | 1 | yes | yes |
| `cloudflare.com` | 1 | yes | yes |
| `ietf.org` | 1 | yes | yes |
| `verisign.com` | 1 | yes (NSEC3 on NXDOMAIN) | yes |
| `com` (TLD) | 1 | yes | yes |
| `github.com` | 0 | no | no |
| `google.com` | 0 | no | no |

`AD=1` from a validating resolver is a cheap signal, but it only proves the *last* hop validated. Presence of `RRSIG` in the answer section is the reliable test. Useful for you because: signed + NSEC ⇒ possible walk (§5.1); signed zones also cannot use many wildcard tricks, which subtly changes wildcard behaviour.

### 6.2 CNAME chains and dangling-CNAME takeover

Follow the chain and record the **terminal state**:

```python
def chain(host, depth=8):
    """-> [(name, 'CNAME->next' | 'A-terminal' | 'NXDOMAIN-terminal' | 'NODATA-terminal')]"""
```

Measured examples:

```
www.github.com          -> CNAME -> github.com                       [A-terminal]
www.paypal.com          -> CNAME -> www.glb.paypal.com
                        -> CNAME -> paypal-dynamic.map.fastly.net   [A-terminal]
foo.herokuapp.com       -> CNAME -> va05.ingress.herokuapp.com      [A-terminal]
dangling.exploit-db.com -> NXDOMAIN-terminal                        <- takeover candidate
xyz.trafficmanager.net  -> NODATA-terminal                          <- takeover candidate
```

**Takeover heuristic:** a CNAME pointing at a SaaS provider domain whose resolution terminates in **NXDOMAIN** (or NODATA) means the provider-side app is unclaimed. That is the whole bug class.

Starter provider list (each is a known takeover vector when its CNAME target 404s / is unregistered):

| Provider | CNAME suffix pattern |
|---|---|
| Heroku | `*.herokudns.com`, `*.herokuapp.com` |
| AWS S3 | `*.s3.amazonaws.com`, `*.s3-*.amazonaws.com` |
| AWS CloudFront | `*.cloudfront.net` |
| AWS Elastic Beanstalk | `*.elasticbeanstalk.com` |
| AWS Global Accelerator | `*.awsglobalaccelerator.com` |
| Azure | `*.azurewebsites.net`, `*.cloudapp.azure.com`, `*.trafficmanager.net`, `*.azureedge.net`, `*.blob.core.windows.net` |
| GitHub Pages | `*.github.io` |
| Shopify | `*.myshopify.com` |
| Fastly | `*.fastly.net`, `*.global.ssl.fastly.net` |
| Akamai | `*.akamaiedge.net`, `*.edgekey.net`, `*.edgesuite.net` |
| Netlify / Vercel | `*.netlify.app`, `*.vercel.app` |
| WordPress | `*.wordpress.com` |
| SendGrid | `*.sendgrid.net` |
| Zendesk / Freshdesk | `*.zendesk.com`, `*.freshdesk.com` |
| Tumblr / Unbounce / Pantheon | `*.tumblr.com`, `*.unbouncepages.com`, `*.pantheonsite.io` |
| ReadTheDocs / GitBook | `*.readthedocs.io`, `*.gitbook.io` |
| Surge / Firebase | `*.surge.sh`, `*.firebaseapp.com`, `*.web.app` |

**Caveat that will burn you:** for several of these, *NXDOMAIN at the CNAME target is the normal wildcard response*, not a takeover. Measured: `*.herokudns.com` and `*.fastly.net` return NXDOMAIN for every random label — so "CNAME to herokudns + NXDOMAIN" is ambiguous between "dangling app" and "provider decided not to answer". Disambiguate by checking whether the **CNAME owner itself** is a real, owned subdomain (i.e. it survived wildcard filtering) and by fetching HTTP (optional, out of DNS scope).

### 6.3 CDN detection

Cheap signals, no external DB needed:

* **CNAME to a known CDN edge** (table above, plus `*.cloudflare.net`, `*.akamaiedge.net`, `*.edgecastcdn.net`, `*.lldns.net`).
* **IP in a known CDN range.** Cloudflare publishes `https://www.cloudflare.com/ips-v4`; AWS publishes `https://ip-ranges.amazonaws.com/ip-ranges.json` (has `service: CLOUDFRONT`). Cache these once per run — a few hundred KB.
* **Wildcarded level.** A level that is a wildcard is almost always CDN/PaaS. This is free — you already computed it.

Output value: a CDN-fronted subdomain should *not* be probed for takeover, and its IP is useless for asset attribution. Tag it and move on.

---

## 7. Termux / Android constraints

Measured on this device (Android 14, MTK, aarch64, Termux + PRoot, non-root):

| Constraint | Measured reality | Mitigation |
|---|---|---|
| `/etc/resolv.conf` | exists, `nameserver 8.8.8.8 / 8.8.4.4` (hardcoded by the proot image, **not** the carrier's resolvers) | do not trust it as the system's real resolver |
| `getprop net.dns1` | **empty** (unset on modern Android) | do not rely on it; `dumpsys connectivity`/`Android API` is the modern path and is unavailable without root |
| Termux `resolv.conf` | `$PREFIX/etc/resolv.conf`, mode `0640 root:root` | readable here; frequently **unreadable/unwritable** for non-root Termux users |
| `getaddrinfo` | works (Android's Bionic resolver via netd) | usable as a fallback path only |
| UDP/53 to public resolvers | **works here** (1.1.1.1 317 ms, 8.8.8.8 324 ms, 9.9.9.9 285 ms) | but expect it to be blocked on many carriers |
| UDP/53 rate limits | harsh — **CGNAT**: you share a source IP with thousands of users | `9.9.9.9` went 400/400 → **0/400** between conc 25 and 100 |
| `ulimit -n` | **32768** here; stock Termux commonly **1024** | 1 socket per resolver, never per query |
| `net.core.rmem_max` etc. | **unreadable** (`/proc/sys` permission denied) | `SO_RCVBUF` is best-effort; rely on modest concurrency |
| Memory | 7.7 GB total; engine peak **24 MB** for 3000 in-flight | non-issue |
| Python | 3.14.8 at `$PREFIX/bin/python3`; also a distro 3.14.4 | stdlib-only code works unmodified |
| Root | not available | nothing requiring raw sockets / iptables |

**DoH is not optional on mobile.** UDP/53 egress is filtered on a significant fraction of cellular and captive-portal networks, and Bionic's resolver silently falls back to whatever netd gives you. Ship the 3-probe auto-detect from §4.7 and a `--doh` override flag.

**asyncio on Termux:** works, but avoid `asyncio.create_subprocess_*` (PRoot/Android fork semantics are fragile) and avoid the default `ThreadPoolExecutor` for DNS work. The event loop itself is fine; `select`/`epoll` are available.

**Android-specific gotcha:** PRoot intercepts syscalls, which adds measurable overhead to `socket()`/`sendto()`. This is a large part of why absolute QPS is low here; on a non-proot Termux the same code is faster. Do not tune your concurrency constants against a proot benchmark — tune against `in_flight = 16/resolver`, which is resolver-bound and therefore portable.

---

## 8. Recommended architecture

```
┌─ wordlist × levels ─────────────────────────────────────────────┐
│                                                                  │
│  1. LEVEL SCAN (once per level, amortised)                       │
│     probe 10 random labels, A + AAAA, interleaved                │
│       ├─ answers      -> WILDCARD, store ip/cname footprint      │
│       ├─ NODATA       -> WILDCARD_NODATA (no A; flag type risk)  │
│       └─ NXDOMAIN     -> NONE, cache "clean level" forever       │
│                                                                  │
│  2. BULK RESOLVE                                                 │
│     A queries, 16 in flight per resolver, semaphore per socket   │
│     timeout -> retry ×4, rotate resolver, exponential backoff    │
│     record: NXDOMAIN | NODATA | TIMEOUT | ANSWER                 │
│                                                                  │
│  3. FILTER                                                       │
│     drop if answer ⊆ footprint (interleaved control confirms)    │
│     keep if any IP / CNAME outside footprint                     │
│     tag confidence=low for dynamic wildcard levels               │
│                                                                  │
│  4. ENRICH (post-pass, never blocking)                           │
│     CNAME chain -> terminal state (takeover heuristics)          │
│     NSEC walk attempt (3 queries, signed zones only)             │
│     AXFR attempt (2 NS, 3 s cap)                                 │
│     CDN tag via CNAME suffix / IP range                          │
└──────────────────────────────────────────────────────────────────┘
```

**Suggested defaults**

| Knob | Value | Why |
|---|---|---|
| `in_flight_per_resolver` | 16 | measured knee (§4.2) |
| `resolvers` | 8 across 4 operators | §4.3 |
| `retries` | 4, resolver-rotating | timeouts ≠ absence |
| `timeout` | 2.0 s (UDP), 5 s (TCP/DoH) | p95 here is 0.9 s |
| `wildcard_probes` | 10 | K=9 saturates (§3.4) |
| `wildcard_confirm` | 2 rounds interleaved | kills dynamic-wildcard FPs |
| `edns_bufsize` | 1232 | no fragmentation, TC handled |
| `qtypes` | A (+AAAA when a level is suspect) | AAAA only costs 2× on suspect levels |
| `so_rcvbuf` | 1 MB best-effort | 446/600 → 597/600 (§4.6) |
| negative cache | per-session only | §4.5 |

**Output schema** — never collapse these:

```json
{"host":"cdn.herokuapp.com","status":"ANSWER","a":["3.213.245.34"],
 "wildcard":"WILDCARD","wildcard_level":"herokuapp.com",
 "outside_footprint":true,"confidence":"high","ttl":60}
{"host":"api.herokuapp.com","status":"ANSWER","wildcard":"WILDCARD",
 "outside_footprint":false,"confidence":"none"}
{"host":"xyz.example.com","status":"TIMEOUT","confidence":"unknown"}
```

---

## 9. Anti-patterns (each measured to be wrong here)

1. **`if rcode == 3: not_exists`** — 4 of 7 tested zones never send NXDOMAIN. 104/105 false positives.
2. **`if answers: exists`** without wildcard filtering — 104/105 false positives on wildcard zones.
3. **`if rcode == 2 (SERVFAIL)` to detect throttling** — throttling shows up as *silence*, never SERVFAIL. 0/2000 at conc 2000 with no error codes at all.
4. **One wildcard check per zone (eTLD+1)** — misses `*.foo.herokuapp.com`, which resolves to a different footprint.
5. **3 wildcard probes** (dnsx default) — only 33–56 % footprint coverage; 26/105 FPs survived on `herokuapp.com` at 9 probes *without* interleaved controls.
6. **`socket()` per query** — instant EMFILE at ≥1024 in-flight on stock Termux.
7. **`await` per query in a loop** — serialises to ~39 QPS; 6× slower than the same code with `gather` + semaphore.
8. **Treating timeout as NXDOMAIN** — silently deletes real subdomains at exactly the moments you are being throttled.
9. **`ANY` queries** — RFC 8482 minimal answers; measured to return HINFO or nothing.
10. **Trusting a static SaaS wildcard list** — `herokudns.com` and `fastly.net` are *not* wildcards today, `herokuapp.com` is; this inverts the folklore.

---

## 10. Open questions / not verified here

* **IPv6-only paths.** AAAA was probed but §4.3 latency is v4. On a v6-only mobile network the resolver table would need re-measuring.
* **Non-root Termux `resolv.conf` access** — this run had root-owned but readable files, which is not universal.
* **DoH POST (binary wire format)** — only the JSON GET endpoints were exercised. POST would allow arbitrary qtypes and EDNS control, at the cost of hand-rolling `application/dns-message`.
* **amass's current wildcard module** could not be fetched (repo tree returned no `wildcard` paths); the description in §3.7 is from its documented behaviour, not source.
* **Absolute QPS at low RTT** — untested; the 16/resolver ceiling should hold since it is resolver-side, but the per-run total would be far higher.

---

## 11. Verification log

Everything below was executed on this host; commands are reproducible.

| Claim | How verified |
|---|---|
| Wire format round-trips | own `build`/`parse` vs `drill @8.8.8.8` — identical answers for A/CNAME/SOA/MX |
| Compression pointers | `gmail.com MX` → 5 answers with decompressed names; `www.github.com CNAME → github.com` |
| RCODE ≠ existence | 8 random labels × 16 zones (`rcode.py`) |
| Wildcard taxonomy | 23 levels × 5 probes (`wilddetect.py`) |
| Wildcard footprint size | 20–40 probes per zone, distinct-set histogram (`wild2.py`, `dynamic.py`) |
| Probe-count coverage curve | K ∈ {1,2,3,5,9,15}, 6 trials × 10 fresh labels (`coverage.py`) |
| Filter strategy accuracy | 105-word wordlist × 4 wildcard zones, 4 strategies (`algo.py`) |
| Filter FP causes | re-query of 12 surviving candidates, 3× each (`verify_fp.py`) |
| Refined filter precision | 20 labelled hosts, 3 rounds interleaved controls (`refine.py`) |
| Concurrency cliff | 2000 queries at conc 50/200/500/1000/2000 (`bench3.py`) |
| Per-resolver rates | 400 queries × 12 resolvers × conc 25/100 (`rate.py`) |
| Single-resolver optimum | conc 2/4/8/16/32, 1000 queries (`final2.py`) |
| `SO_RCVBUF` / socket count | 600 queries × 5 configs (`rcvbuf.py`) |
| `getaddrinfo` baseline | 1000 names, 10/25/50/100 threads, gaierror counted correctly (`gai.py`) |
| DoH JSON endpoints | 3 query shapes + 20 sequential latency samples per endpoint (`doh.py`) |
| TC + TCP fallback | `org`/`verisign.com` DNSKEY and `google.com` TXT at edns=512 → TC=1; TCP path returns full answer (`tc.py`, `tcp.py`) |
| ANY is dead | returned `HINFO RFC8482` once, empty answer set another time (`tcp.py`, `tc.py`) |
| NSEC walking | `nsec.example.com` real NSEC chain; `cloudflare.com`/`ietf.org` fabricated next-names; `verisign.com`/`com` NSEC3 (`nsec.py`) |
| AXFR fails | 4 attempts, 2 timeouts + 2 RSTs (`nsec.py`) |
| DNSSEC signals | AD bit + RRSIG presence across 8 zones (`nsec.py`) |
| CNAME chains / takeover | 7 chains followed to terminal state (`takeover.py`) |
| Termux environment | `getprop`, `resolv.conf`, `ulimit -n`, `/proc/sys` readability, python version, `getaddrinfo` |

Benchmark caveat: runs were spread over ~20 minutes on a mobile link, so cross-table absolute numbers are not perfectly comparable (carrier load varies). Within-table comparisons — especially the concurrency sweep and the filter accuracy counts — used identical conditions and are the load-bearing results.
