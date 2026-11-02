# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Nothing yet.

### Changed

- Nothing yet.

### Fixed

- Nothing yet.

### Security

- Nothing yet.

## [1.0.0] - 2026-11-02

First public release.

### Added

- **Zero-dependency core.** Pure Python standard library, Python 3.9 and newer.
  No compilation step, no external binaries, no `dig` or `gobuster` required.
- **Termux/Android support as a first-class target.** `pkg install python` followed
  by `pip install subpy` is a complete installation.
- **Passive enumeration from 21 sources**, ten of which need no API key:
  - Certificate Transparency: crt.sh, Cert Spotter, Meta CT, Censys (key).
  - Public DNS datasets: HackerTarget, RapidDNS, subdomain.center,
    ProjectDiscovery Chaos (key), Netlas (key), DNSDumpster (opt-in),
    Anubis (opt-in).
  - Crawl archives: Wayback Machine, Common Crawl, urlscan.io.
  - Threat intelligence: AlienVault OTX, VirusTotal (key), Shodan (key),
    SecurityTrails (key), BinaryEdge (key), FullHunt (key),
    ThreatCrowd (opt-in).
- **Active scanning.** Embedded 1211-word curated wordlist, a permutation engine
  that generates siblings from already-discovered hosts, AXFR zone transfer
  attempts, and NSEC walking.
- **Wildcard detection for four distinct cases** — true wildcard, NODATA
  wildcard, CNAME wildcard and nested (multi-level) wildcard. Detection uses
  random-label probing with address-**set** comparison plus CNAME-chain
  matching, so round-robin and rotating-IP wildcards are handled correctly.
- **Custom DNS engine.** Own wire-format encoder and decoder, EDNS0 support,
  automatic TCP fallback on truncation, DNS-over-HTTPS fallback for networks
  that block UDP/53, resolver health tracking with demotion of slow or dead
  servers, and positive plus negative caching.
- **Five output formats** — `txt`, `json`, `csv`, `md` and `html`.
- **Automatic update check** against GitHub releases, cached for about 24 hours.
  Disabled with `--no-update-check` or `SUBPY_NO_UPDATE`.
- **Documented exit codes** — `0` success, `1` no results, `2` usage error,
  `130` interrupted.
- **Environment configuration** via `SUBPY_RESOLVER`, `SUBPY_NO_UPDATE`,
  `NO_COLOR` and `FORCE_COLOR`.

### Changed

- Nothing yet.

### Fixed

- Nothing yet.

### Security

- Passive sources run isolated from one another, so a single failing or
  misbehaving third-party API cannot crash a scan or corrupt its results.
- All discovered hostnames are validated and scoped to the target domain before
  they are resolved or reported.

[Unreleased]: https://github.com/0xShahriar/subpy/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/0xShahriar/subpy/releases/tag/v1.0.0
