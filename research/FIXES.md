# Review findings and their resolution

`bug-hunt.md` is the raw adversarial report against the first cut of v1.0.0.
This file records what happened to each finding, so a future reader does not
have to diff two documents to find out whether something was fixed.

Every fix was verified against live DNS on 2026-11-02. Test count went from 94
to 116 while this work landed.

## Critical

| # | Finding | Status |
| --- | --- | --- |
| 1 | `fly.dev` listed as a wildcard but answers 0/12 for random labels, so every real host CNAMEd into Fly.io was silently dropped | **Fixed.** Moved to `SHARED_INFRA_SUFFIXES`, which annotates without filtering. Counts are now 44 wildcard / 30 shared infra, and a test asserts the two lists never overlap. |
| 2 | Multi-label wildcard names bypassed the filter: `is_wildcard` required an exact `levels[parent]` match, and `detect_for_name` was never called (so `max_levels` was dead config) | **Fixed.** `is_wildcard` now falls back to `detect_for_name`, profiling an unseen parent level on first encounter. Verified filtered on herokuapp.com / github.io / netlify.app at depths 1–3. |

## High

| # | Finding | Status |
| --- | --- | --- |
| 3 | `_inflight` leaked a slot whenever `build_query` rejected a name; after 16 per server `_pick_channels` saw no ready channel and load balancing collapsed | **Fixed.** The `except DNSFormatError` branch decrements the counter. Verified: 40 over-length queries leave `_inflight` at 0. |
| 4 | IPv6-only hosts dropped: the empty-answer existence test returned before the `include_ipv6` AAAA fallback, making that fallback unreachable for its only purpose | **Fixed.** The AAAA fallback now runs before the existence test concludes "does not exist". Verified on `v6.ident.me`, with an IPv4 host and a nonexistent name as controls. |

## Medium

| # | Finding | Status |
| --- | --- | --- |
| 5 | `--fail-empty` overwrote the signal exit code, so SIGTERM + empty reported 1 instead of 143 | **Fixed.** The override only applies when `exit_code == EXIT_OK`. |
| 6 | Concurrent passive/brute overlap resolved the same candidate twice and fired `on_host` twice | **Fixed.** An in-flight name set claims each name before awaiting. Verified: 8 concurrent duplicates emit exactly once. |
| 7 | `_doh_to_message` raised uncaught `ValueError`/`AttributeError` on hostile DoH JSON | **Fixed.** Status, `Answer` container and each answer are type-checked. Verified against 11 malformed payloads. |
| 11 | Transient NODATA cached for 300s, turning one resolver hiccup into a missed host | **Fixed.** NOERROR-with-no-answers is capped at 20s, NXDOMAIN at 45s. |

## Low

| # | Finding | Status |
| --- | --- | --- |
| 8 | Bare IP accepted as `-d 8.8.8.8`, brute-forced, exited 0 as though the host had no subdomains | **Fixed.** Rejected as a usage error. |
| 9 | Residual ~450ms startup window where a signal still killed the process | **Reduced.** The guard is armed as the first action of the entry module, before any heavy import. Measured across 11 offsets from 0.3s to 3.5s, every delivery returns 143. A signal in the first ~0.3s lands before the CPython interpreter has executed any of this program, which no handler can cover. |
| 10 | `-o` with a NUL byte raised uncaught `ValueError` | **Fixed.** `ValueError` is caught alongside `OSError` on the write path. |
| 12 | `DNSMessage.resolved` returns True for an answer with no usable address | **Left as-is, documented.** It reports "the answer section is non-empty", which is its actual contract; `_verify_one` applies the stricter address/CNAME test separately. Renaming it would be the honest fix, but it is a public attribute and the distinction is now recorded here instead. |

## Not reproduced

The reviewer could not reproduce these and said so rather than presenting them
as facts. They remain unconfirmed, not dismissed:

- `_inflight` going negative.
- Socket or file-descriptor growth over 300 resolutions.
- Corrupt JSON on SIGINT (8 runs, 0 corrupt).
- CSV formula injection as a *live* vulnerability — it is reachable only for
  hand-built `Host` objects, because `_HOSTNAME_RE` forbids `=`, `|`, `,` and
  `!` in a real hostname.

## Verified correct

Worth recording, because these are the parts most likely to be broken by a
future change and they were specifically attacked:

- `parse_message` survived 20,000 mutated and truncated packets with zero
  exceptions other than `DNSFormatError`. Pointer attacks (self-loop, 2-cycle,
  forward-past-buffer, 60+ hops) all raise cleanly and none hang.
- `clean_hostname` / `belongs_to` resisted 35 hostile inputs — IDN, 253-char,
  `*`, `..`, leading/trailing hyphens, percent-encoding, `javascript:`, NUL,
  embedded newlines, `a.example.com.evil.com` — with no out-of-domain
  injection.
- HTML output is fully escaped, with no script, even when a hostname contains
  `</title>` or an `onerror` payload.
- JSON is valid for zero hosts.
- The rate limiter is accurate.
