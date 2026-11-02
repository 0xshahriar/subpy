# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | ✅ |
| < 1.0 | ❌ |

Security fixes land on the latest 1.0.x release. Older versions are not
backported — upgrade to the newest patch release before reporting.

## Reporting a vulnerability

Please do **not** open a public issue for a security problem. A public report
gives everyone who runs subpy the same window you are trying to close.

### GitHub Security Advisories (preferred)

Use the private disclosure form:

<https://github.com/0xShahriar/subpy/security/advisories/new>

This keeps the discussion, the proof of concept and the eventual fix advisory
in one place, and it lets you be credited for the report.

### Email

If you would rather not use GitHub:

**sadjoker.localhost@gmail.com**

Please include:

- A description of the issue and its impact.
- The affected version (`subpy --version`) and platform.
- Reproduction steps or a proof of concept.
- Any known mitigations.

If you want to encrypt the report, say so in a first plaintext message and a
key will be provided.

## Response timeline

| Stage | Target |
| --- | --- |
| Acknowledgement of your report | within 48 hours |
| Initial assessment and severity | within 7 days |
| Fix or mitigation plan communicated | alongside the assessment |
| Coordinated disclosure | by agreement with the reporter |

If a report turns out not to be a vulnerability in subpy, you will get an
explanation of why rather than silence.

## In scope

- The `subpy` package code: DNS engine, resolver, passive sources, wildcard
  handling, output writers, CLI.
- Crashes, hangs or unbounded resource use triggered by untrusted input — for
  example a malicious or malformed response from a passive source or a DNS
  server.
- Code execution, path traversal, or file overwrite reachable through CLI
  arguments or environment variables.
- Injection into any of the five output formats via attacker-influenced
  hostnames.
- Accidental disclosure of API keys — for example a key appearing in logs,
  output files, or the update check.
- Supply-chain issues: the release, packaging or CI pipeline.

## Out of scope

- **Scanning hosts you do not own.** Running subpy against third-party
  infrastructure without authorization is a violation of the tool's terms of
  use and, in many jurisdictions, of the law. It is not a security
  vulnerability, and reports of this kind will be closed. Read the
  [legal notice](README.md#legal).
- Findings on third-party services that subpy merely queries. Report those to
  the provider that owns them — crt.sh, VirusTotal, Shodan and so on.
- Vulnerabilities in domains discovered by subpy. Report those to the owner of
  the affected domain.
- Missing DNS records, subdomain takeover candidates, or exposed hosts found
  with the tool. These are findings about a target, not defects in subpy.
- Rate-limit or quota exhaustion caused by your own scan settings.
- Reports that require an already-compromised machine or an attacker with
  local administrator access.
- Social engineering, physical access and denial-of-service against
  third-party APIs.

## Safe harbour

Research conducted in good faith against your own systems, or against systems
you have explicit written permission to test, is welcome and will not be
treated as hostile. Act on your own infrastructure, use a disposable test
domain, and keep the traffic you generate to the minimum needed to demonstrate
the issue.

## Disclosure

Coordinated disclosure is the default. Once a fix is available:

1. A GitHub Security Advisory is published.
2. A `Security` entry is added to `CHANGELOG.md`.
3. A patched release is tagged.
4. The reporter is credited, unless they ask otherwise.

Thank you for helping keep subpy and its users safe.
