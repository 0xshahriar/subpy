# subpy 1.0.0 — Adversarial Bug Hunt

**Reviewer posture:** adversarial. Every claim in the README was treated as false until
reproduced. Findings below are ordered by severity; every one marked *reproduced* was
executed on this host (Python 3.14.4, Linux aarch64, 2026-11-02) with the command shown.

**Note on repository churn:** the tree changed under me mid-review. Two commits
(`ce9fefc`, `814fc46`) landed while I was probing. The SIGTERM bug I found first was
*regressed-then-fixed* by those commits; I re-verified everything against the final tree
(`e032150`). See finding 9 for the residual.

Baseline before changes were considered:

```
$ python3 -m unittest discover -s tests        # initially FAILED (1 failure), now OK (97)
$ /tmp/lintenv/bin/ruff check subpy tests      # All checks passed!
$ /tmp/lintenv/bin/ruff format --check ...     # 26 files already formatted
```

---

## 1. `fly.dev` is listed as a wildcard SaaS suffix but is NOT one — silently deletes real hosts

- **Severity: Critical** (false negative — the failure mode the code itself calls "the worst")
- **File:line** `subpy/core/wildcard.py:82` (`"fly.dev"` in `SAA_WILDCARD_SUFFIXES`),
  consumed at `subpy/core/wildcard.py:394-396` (`matches()` → `if cname_suffix_hit(target): return True`)

**Repro**

```bash
python3 /tmp/probe_fly.py     # 12 random labels under fly.dev, 3 resolvers
python3 /tmp/probe_fly_drop2.py
```

```
c7mmbsrsi5lra1cjv6a2.fly.dev   rcode=NXDOMAIN  answers=0   # 1.1.1.1
kua9bapulhisqf8ui3sb.fly.dev   rcode=NXDOMAIN  answers=0
... 0/12 answered across 1.1.1.1, 8.8.8.8, 9.9.9.9
fly.dev       rcode=NOERROR answers=1 ['77.83.140.34']    # apex exists
flyctl.fly.dev rcode=NOERROR answers=1 ['66.241.125.127']  # real host exists
```

**Observed vs expected**

`fly.dev` answers **NXDOMAIN for every random label**, so it is not a wildcard zone at all
— it is an ordinary zone with individually registered apps. Only 1 of the 45 suffixes in
`SAA_WILDCARD_SUFFIXES` behaves this way; the other 44 correctly answered 3/3.

Because `cname_suffix_hit()` is consulted in `matches()`, *any* real host of the target that
is CNAMEd into Fly.io is unconditionally classified as wildcard noise:

```
apex wildcard active? True footprint: {'10.0.0.1'}
is_wildcard(real fly.dev host) -> True     # status.example.com CNAME example-app.fly.dev
is_wildcard(genuine wildcard artifact) -> True
```

Expected `False` (keep the real host); observed `True` (dropped). The user is never told —
`wildcard_filtered` is incremented and the host simply never appears.

**Suggested fix** Remove `fly.dev` from `SAA_WILDCARD_SUFFIXES`, and gate the CNAME-suffix
shortcut on a verified probe rather than a hardcoded list entry.

---

## 2. Multi-label wildcard names bypass the filter entirely (false positives)

- **Severity: Critical** (false positives; contradicts "zero false positives")
- **File:line** `subpy/core/wildcard.py:377-378` (`parent = name.split(".", 1)[1]`) and
  `subpy/core/wildcard.py:390-392` (`info = self.levels.get(parent)` → `return False`)

**Repro**

```bash
python3 /tmp/probe_wildcard.py
python3 /tmp/probe_nested_live.py     # proves RFC 4592 multi-label synthesis is live
```

```
root fingerprint active: True addr set: {'93.184.216.34'}
  is_wildcard('a.example.com')     -> True    correctly filtered
  is_wildcard('a.b.example.com')   -> False   FALSE POSITIVE!
  is_wildcard('a.b.c.example.com') -> False   FALSE POSITIVE!
```

Live confirmation that the zone really does synthesise multi-label names:

```
herokuapp.com  depth 1: 8ijzvatkwxbr.herokuapp.com                NOERROR  5 answers
herokuapp.com  depth 2: lk1mg5kbcvxe.rj502p6jzx0z.herokuapp.com   NOERROR  5 answers
github.io      depth 3: dn2frlvqrcp7.a8o7c3bbmits.j4sep0vcyv1u.github.io  NOERROR 4 answers
```

**Observed vs expected**

Only the apex level is fingerprinted (`detect()` is called once at `scanner.py:164`).
For a name one or more labels deeper, `parent` is `b.example.com`, which is not in
`self.levels`, so `is_wildcard()` short-circuits to `return False` — *accepting the name
without ever consulting the `*.example.com` fingerprint that already exists.*

`detect_for_name()`, the function written to handle exactly this, is **never called**
(grep finds only its definition). `max_levels` is therefore dead configuration.

**Suggested fix** In `is_wildcard()`, walk up the label chain to the nearest fingerprinted
ancestor instead of requiring an exact `parent` match (or call `detect_for_name`).

---

## 3. `_inflight` leaks a slot on every over-length name, permanently breaking load balancing

- **Severity: High**
- **File:line** `subpy/core/resolver.py:468` (increment) vs `subpy/core/resolver.py:474-477`
  (`except DNSFormatError: self._release_qid(qid); return None` — the `finally` that would
  decrement `_inflight` is never reached)

**Repro**

```bash
python3 /tmp/probe_leak2.py
python3 /tmp/probe_leak3.py
```

```
len: 254 normalize keeps: True is_valid_name: True
encode_name REJECTS: DNSFormatError: name too long (256 > 255)
after 40 queries: {('1.1.1.1', 53): 21, ('8.8.8.8', 53): 19} ids leaked: 0
LEAKED phantom in-flight slots: 40
```

```
_inflight: {('1.1.1.1', 53): 21, ('8.8.8.8', 53): 19, ('9.9.9.9', 53): 20}
channels considered 'ready' by _pick_channels: 0 of 3
```

**Observed vs expected**

A 254-character name passes both `normalize_name()` (`dns.py:200`, limit is `MAX_NAME - 1`)
and `is_valid_name()` (`dns.py:214`), but `encode_name()` counts the terminating root byte
too (`dns.py:263`, `total > MAX_NAME`) and rejects it. The `build_query` failure path
releases the transaction id but **not** the in-flight slot, so `_inflight` grows
monotonically. After 16 such candidates per server, `_pick_channels()`'s `ready` list is
empty for every channel and the least-connections balancer degenerates to raw sort order.

Not purely theoretical: `_kind` of names are reachable both from a hostile passive source and
from `iter_wordlist` honouring long lines. The counter only resets on `clear()`, so this
persists for the whole scan (and, in library use, across scans sharing a resolver).

**Suggested fix** Move the `_inflight` decrement into a `try/finally` that wraps the
`build_query` call as well, so every increment is matched on every exit path.

*(Side note in the same block: `resolver.py:478-480` is dead code —
`finally: if True: pass`. Harmless but it hides that the guard was meant to be here.)*

---

## 4. IPv6-only hosts are silently dropped (false negative)

- **Severity: High**
- **File:line** `subpy/core/scanner.py:487-489` (early `return False` when `not msg.answers`)
  vs `subpy/core/scanner.py:503-506` (the AAAA fallback that can never be reached)

**Repro**

```bash
python3 /tmp/probe_v6live.py        # v6.ident.me is a real IPv6-only host
python3 /tmp/probe_ipv6only.py      # deterministic stub version
```

```
v6.ident.me  _verify_one -> False
   resolved: False  addresses: []  rcode: NOERROR
   => FALSE NEGATIVE: real host silently dropped

AAAA queries issued for v6.example.com: []      # fallback never fires
```

Independent proof the host is real:

```
v6.ident.me    A ans= 0 rcode=NOERROR | AAAA ans= 1 ['2a01:4f9:c012:8091::1']
```

**Observed vs expected**

`_verify_one` queries A first. For an IPv6-only name the A query returns NOERROR with zero
answers, which hits the `if not msg.answers: host.resolved = False; return False` guard
*before* the `if not addresses and self.config.include_ipv6:` AAAA fallback three lines
later. The IPv6 code path is unreachable for exactly the case it exists to handle;
`--no-ipv6` changes nothing observable.

**Suggested fix** Run the AAAA query when the A answer is empty-but-NOERROR, and only
conclude non-existence after both families are exhausted (or after an NXDOMAIN).

---

## 5. `--fail-empty` overwrites the signal exit code (143 becomes 1)

- **Severity: Medium**
- **File:line** `subpy/cli.py:571-572` (`exit_code = EXIT_RUNTIME`)

**Repro**

```bash
python3 -c "
import subprocess,sys,time,signal
p=subprocess.Popen([sys.executable,'-m','subpy','-d','example.com','-a','--wordlist-limit','2',
 '--no-update-check','--no-color','-q','--fail-empty'],stdout=-1,stderr=-1,text=True)
time.sleep(1.2); p.send_signal(signal.SIGTERM); p.communicate(timeout=20); print(p.returncode)"
```

```
rc= 1     # SIGTERM should be 143; --fail-empty must not override it
```

**Observed vs expected**

`exit_code` is set from `terminated["signal"]` earlier, then unconditionally reassigned
when `--fail-empty` is combined with an empty result. A supervisor that sends SIGTERM and
saw `143` before now sees `1`, which is indistinguishable from a runtime error. Expected
`143` (documented in `_EPILOG`); observed `1`.

**Suggested fix** Only apply the `--fail-empty` override when `exit_code == EXIT_OK`.

---

## 6. Duplicate candidates are emitted twice and double-counted

- **Severity: Medium**
- **File:line** `subpy/core/scanner.py:537` (`self.summary.resolved += 1`) and the
  `on_host(host)` call at `subpy/core/scanner.py:539`

**Repro**

```bash
python3 /tmp/probe_conc.py
```

```
hosts dict size: 1
summary.resolved: 2
on_host emitted: ['www.example.com', 'www.example.com']
=> duplicate emission: True
```

**Observed vs expected**

`_verify_one` resolves first and only then looks up `self.hosts`. When passive and brute
force propose the same name in overlapping chunks (the normal case, since the two tasks run
concurrently at `scanner.py:186-192`), both coroutines pass the `host is None` check, both
increment `summary.resolved`, and both fire `on_host` — so quiet-mode stdout prints the host
twice and the JSON `count` is computed from a de-duplicated list while `summary.resolved`
is inflated.

Partially masked: `_finalise()` recomputes `summary.resolved` from `self.hosts`
(`scanner.py:588`), so the *file* is consistent — but the live progress counter and the
duplicate stdout lines are not. Expected one emission; observed two.

**Suggested fix** Claim the `Host` in a `setdefault`-style atomic step under `self._lock`
before awaiting, and bail out early if another coroutine already owns that name.

---

## 7. DoH JSON conversion raises uncaught exceptions on hostile payloads

- **Severity: Medium**
- **File:line** `subpy/core/resolver.py:609-613` (`int(status)`), `resolver.py:620`
  (`ans.get` on a non-dict)

**Repro**

```bash
python3 -c "
import sys; sys.path.insert(0,'.')
from subpy.core.resolver import AsyncResolver as R
for p in [{'Status':'x'},{'Status':0,'Answer':'notalist'},{'Status':0,'Answer':[None]}]:
    try: print(p,'->',R._doh_to_message(p,'x'))
    except Exception as e: print(p,'-> UNCAUGHT',type(e).__name__,e)"
```

```
{'Status': 'x'}                 -> UNCAUGHT ValueError: invalid literal for int() with base 10: 'x'
{'Status': 0, 'Answer': 'notalist'} -> UNCAUGHT AttributeError: 'str' object has no attribute 'get'
{'Status': 0, 'Answer': [None]}     -> UNCAUGHT AttributeError: 'NoneType' object has no attribute 'get'
```

**Observed vs expected**

`_doh_query()` wraps only the *fetch* in `except (asyncio.TimeoutError, OSError, ValueError)`
— the `_doh_to_message(payload, name)` call sits outside it. A captive portal or a
MITM/compromised DoH endpoint returning JSON with an unexpected shape therefore propagates
`AttributeError` straight out of `query()`, contradicting claim 7 ("never crashes on a
malformed packet"). Expected: contained; observed: raises.

Related, same function: `{'Answer':[{'type':1,'data':'999.1.1.1'}]}` is accepted as a
resolved A record with `address=None`, because `_doh_to_message` sets `rr.address` only on
the success path but appends the record regardless — so `msg.resolved()` (dns.py:462)
returns `True` for an answer with **zero usable addresses**. Also note the nonsense
expression at `resolver.py:621`: `int(ans.get("") or 1) if False else 1`.

**Suggested fix** Wrap the whole `_doh_to_message` call in the same `try`, validate each
answer is a `dict` with a sane type, and skip records whose address fails validation.

---

## 8. A bare IP address is accepted as `-d` target and "scanned" like a domain

- **Severity: Low**
- **File:line** `subpy/core/dns.py:208-214` (`is_valid_name` has no numeric-TLD rejection);
  endpoint `subpy/cli.py:361-365`

**Repro**

```bash
python3 -m subpy -d 8.8.8.8 -a --wordlist-limit 5 --no-update-check --no-color
```

```
> 8.8.8.8 active
       found 0          time 0.2s       queries 8 (0/s)
EXIT=0
```

Also accepted: `1.2.3.4`, `0.0.0.0`, `192.168.1.1`, `1.2.3`, and even `999.1.1.1`.

**Observed vs expected**

`normalize_name()`/`is_valid_name()` treat any all-numeric label sequence as a valid
hostname, so the CLI happily brute-forces `www.8.8.8.8`. Expected a usage error
(`EXIT_USAGE`, 2); observed a silent zero-result scan exiting 0 — which a `--fail-empty`
pipeline would read as "no subdomains", not "you gave me an IP".

**Suggested fix** Reject targets where the final label is all-numeric (or where the whole
string parses as an IP literal) in the CLI validation step.

---

## 9. A signal during the first ~450 ms still exits `-15` / `-2` (residual of the startup window)

- **Severity: Low**
- **File:line** `subpy/_startup.py:51` (`_arm_signals()`) — the handler is installed only
  after the interpreter has finished `site`/`importlib` boot, which is exactly the window
  the module claims to close; `subpy/_startup.py:54` delays the heavy import but cannot
  reorder CPython's own startup.

**Repro**

```bash
python3 - <<'EOF'
import subprocess,sys,time,signal
for d in (0.05,0.1,0.2,0.3,0.4,0.5):
    p=subprocess.Popen([sys.executable,"-m","subpy","-d","example.com","-a","--wordlist-limit","900",
                        "--no-update-check","--no-color","-q"],stdout=-1,stderr=-1,text=True)
    time.sleep(d); p.send_signal(signal.SIGTERM)
    try: p.communicate(timeout=20)
    except subprocess.TimeoutExpired: p.kill(); p.communicate()
    print(d, p.returncode)
EOF
```

```
0.05 -15
0.1  -15
0.2  -15
0.3  -15
0.4  -15
0.5  143     # only from ~0.45s onward
```

**Observed vs expected**

Claim 5 says SIGTERM exits 143 promptly. From ~0.45 s onward that now holds (verified across
0.5–4.0 s, both signals, 16/16 correct). Below that the process still dies with the raw
`-15`, and SIGINT with `-2`, because the handler cannot exist before `site` runs.

*Honesty note:* this is the residual of a bug that was live when I started — at that point
the cut-over was ~2.2 s and the shipped test `test_sigterm_exits_143` genuinely failed
(`AssertionError: -15 != 143`). Commits `ce9fefc`/`814fc46` fixed the body of the window;
the first ~450 ms is inherent to CPython and probably only worth documenting rather than
fixing.

**Suggested fix** Document a startup grace period (or have supervisors wait for the first
progress line) rather than promising 143 unconditionally.

---

## 10. `-o` with a NUL byte in the path crashes with an uncaught `ValueError`

- **Severity: Low**
- **File:line** `subpy/cli.py:559` (`except OSError as exc:` — `ValueError` is not caught)

**Repro**

```bash
python3 -c "
import sys; sys.path.insert(0,'.')
from subpy.cli import main
main(['-d','example.com','-a','--wordlist-limit','1','--no-update-check','--no-color','-q','-o','bad\0name.txt'])"
```

```
www.example.com
UNCAUGHT ValueError embedded null byte
```

**Observed vs expected**

`write_output` → `open()` raises `ValueError: embedded null byte`, which is not an
`OSError`, so the clean `subpy: error: cannot write ...` path and `EXIT_USAGE` are skipped
and a raw traceback escapes `main()`. Expected a tidy usage error; observed a traceback.

Everything else in this area is solid: `/dev/full`, a directory, a missing parent, and a
path whose parent is a regular file all produce the intended clean message and exit 2 (I
verified `/dev/full` → `PermissionError`, `/tmp` → `IsADirectoryError`, `/proc/1/x/y` →
`FileNotFoundError`, `README.md/x` → `FileExistsError`, each caught and reported).

**Suggested fix** Add `ValueError` to that `except` clause.

---

## 11. Negative cache entries are keyed on "no answers", so transient NODATA is cached for 300 s

- **Severity: Low**
- **File:line** `subpy/core/resolver.py:406-409` (`if not msg.answers: ttl = min(ttl or 300, 300)`)

**Repro**

```bash
python3 /tmp/probe_cache.py
```

```
NODATA cached: calls= 1  cache_hits= 1
   cache entry TTL window (s): 300.0
2nd query served from cache, addresses: [] => transient failure cached as a negative for up to 300s
cache size after 5000 distinct names: 5000 (no eviction)
```

**Observed vs expected**

Rationale for negative caching is sound, but the predicate is `not msg.answers`, which
also matches a NOERROR/NODATA reply produced by a *degraded* resolver. A single flaky answer
therefore suppresses that name for the rest of a 300 s scan, and `retry_unresolved` cannot
recover it (it sees `resolved is False`, not `None`). The cache also has no size bound
(5000 entries retained after 5000 distinct names) and caches TTL=0 answers.

**Suggested fix** Only negative-cache when an SOA in authority corroborates NODATA, and
bound `_cache` (e.g. drop-oldest past N entries).

---

## 12. Nit: `resolved()` returns `True` for an answer with no usable address

- **Severity: Nit**
- **File:line** `subpy/core/dns.py:459-463`

**Repro**

```bash
python3 -c "
import sys; sys.path.insert(0,'.')
from subpy.core.dns import DNSMessage, ResourceRecord, QTYPE
m=DNSMessage(id=0,flags=0)
m.answers.append(ResourceRecord(name='x',rtype=QTYPE['A'],rclass=1,ttl=60,data=b'\x01\x02\x03'))
print(len(m.answers), m.addresses(), m.resolved())"
```

```
1 [] True
```

`resolved()` only checks `rr.rtype in ADDRESS_TYPES`, not that `rr.address` was actually
decoded, so a malformed A record (rdlength ≠ 4 → `extras = {}`) makes it return `True`.
`_verify_one` is protected by its own later `if not addresses and not cnames` check, so this
is currently latent. **Suggested fix:** test `rr.address` rather than `rr.rtype`.

---

## Suspected but NOT reproduced

- **`_inflight` going negative** — I tried sequential bursts, 100-way concurrency, and
  cancelling 60 in-flight queries mid-flight; it stayed at 0 and `_ids_in_use` drained to 0
  every time. The `max(0, ...)` in the `finally` plus `pop` in `channel.send`'s cancellation
  path appear correct. **Unconfirmed.**
- **Socket/FD growth** — no measurable growth across 300 resolutions; channels are fixed at
  `start()` and closed in `close()`. **Unconfirmed.**
- **Corrupt JSON on SIGINT** — 8 SIGINT runs at 2.0–6.0 s all produced either a missing file
  or a fully valid JSON document (0 corrupt). The `format_hosts`-then-`write` sequence is
  atomic enough in practice. **Unconfirmed.**
- **CSV formula injection** — `=cmd|calc!A1.example.com` *is* written verbatim to CSV
  (unprefixed), which would execute in Excel. I am not counting it as a bug because
  `clean_hostname` rejects every realistic vector that could reach a writer through the
  normal pipeline (a name must match `_HOSTNAME_RE`, which forbids `=`, `|`, `,`, `!`), so
  the only route is a hand-constructed `Host`. **Reported as latent, not as a live vuln.**
- **HTML escaping** — I could not break it. `<script>`, `onerror=`, `</title>` payloads in
  host names, sources and the domain all come out escaped (`&lt;script&gt;`, `onerror=`
  appears only in escaped text, 0 raw `<script>`). Claim 6's escaping half holds.

---

## Verified correct

Worth recording, because these are the claims most likely to be quietly false:

- **`decode_name` / `next_offset`** — correct for root names, pointer-terminated names,
  label-then-pointer names, and 60-deep pointer chains (all returned the exact expected
  offset).
- **Compression-pointer hardening** — self-loops, 2-cycles, forward pointers past the
  buffer, and chains longer than 64 hops all raise `DNSFormatError`; none hung.
- **`parse_message` fuzzing** — 20,000 mutated/truncated packets produced **zero**
  exceptions other than `DNSFormatError`. Every read is bounds-checked; this module is
  genuinely defensive.
- **`clean_hostname` / `belongs_to`** — 35 hostile inputs (unicode/IDN, 253-char, `*`, `..`,
  leading/trailing hyphens, uppercase, trailing dots, percent-encoding, `javascript:`,
  `mailto:`, embedded NUL, `a.example.com.evil.com` suffix confusion) all handled correctly;
  no way found for a source to inject a host outside the target domain or a non-DNS string.
- **HTML output** — fully escaped, zero `<script>`, no external resources.
- **JSON output** — valid JSON for zero hosts (`{"count":0,"hosts":[]}`); markdown and CSV
  also emit well-formed output for the empty case.
- **`_sorted()` stability** — deterministic `(label_count, name)` ordering across all writers.
- **Rate limiter** — 5/s bucket measured 7.5/s over 2 s (5/s steady + 5 burst), i.e. correct.
- **DoH happy path** — live query over the JSON API returned `['104.20.23.154','172.66.147.243']`.
- **Signal handling after the fix** — SIGINT→130 / SIGTERM→143 with partial results kept and
  no traceback, for every delay from 0.5 s to 4.0 s.
- **`ruff check` / `ruff format --check`** — clean, as claimed.
- **Test suite** — 97 tests, currently all passing (it was **not** passing when the review
  began; see finding 9).
