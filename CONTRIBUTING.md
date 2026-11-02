# Contributing to subpy

Thanks for being here. subpy exists because enumeration tooling had become
heavy: a Go toolchain for one job, a C compiler for another, `dig` for a third,
and none of it working on the phone in your pocket. Keeping this project small
and dependency-free is the whole point, and that constraint is what makes
contributions easy to review.

You do not need to be an expert. A clear bug report with a reproduction is
genuinely useful, and a doc fix is a real fix.

## Development setup

subpy targets Python 3.9 and newer. No third-party runtime packages, ever.

```bash
git clone https://github.com/0xShahriar/subpy.git
cd subpy

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -e .
pip install pytest ruff
```

Verify the console entry point works:

```bash
subpy --version
subpy --list-sources
```

## Running the tests

Both test runners are supported, and CI runs both:

```bash
python -m pytest
```

```bash
python -m unittest discover -s tests
```

Please run the full suite before opening a pull request. Tests must not require
network access: passive sources are exercised against fixtures, and DNS is
mocked at the wire level.

## Code style

- **PEP 8**, enforced by `ruff`. Four-space indent, 100-column lines.
- **Type hints** on every public function and method. `from __future__ import
  annotations` keeps them cheap on 3.9.
- **Dataclasses** for anything that is mostly data.
- **Docstrings** on modules, classes and non-obvious functions. Explain *why*,
  not *what* — the code already says what.

```bash
ruff check .
ruff format --check .
```

A few project-specific rules:

- Never add a third-party runtime dependency. If a task seems to need one, it
  needs a design discussion first.
- Anything touching DNS must work on Linux, macOS, Windows and Termux.
- No `asyncio.run()` inside library code; the CLI owns the event loop.
- Never swallow an exception silently. Log it or annotate the result.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):

```text
<type>(<scope>): <short summary>

<optional body>

<optional footer>
```

Common types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`,
`ci`. Useful scopes: `sources`, `dns`, `resolver`, `wildcard`, `output`, `cli`.

```text
feat(sources): add Netlas passive DNS source
fix(wildcard): compare full address set for rotating wildcards
docs(readme): clarify Termux installation steps
```

Breaking changes get a `!` before the colon and a `BREAKING CHANGE:` footer.

## Branch naming

```text
feat/netlas-source
fix/wildcard-rotating-ips
docs/termux-notes
```

Branch from `main`, keep one logical change per branch, and rebase rather than
merging `main` back in.

## Adding a new passive source

A passive source is a small subclass registered by decorator. That is the entire
contract — the runner handles rate limiting, retries, hostname validation,
domain scoping, deduplication and failure isolation for you.

```python
"""Netlas.io passive DNS source."""

from __future__ import annotations

from typing import Iterable, List

from .base import PassiveSource, SourceContext, register


@register
class NetlasSource(PassiveSource):
    """netlas.io domain index - key required, free tier available."""

    name = "netlas"
    category = "dns"                       # ct | dns | crawl | intel | search
    description = "Netlas.io domain WHOIS/DNS index"
    requires_key = True
    key_env = "NETLAS_API_KEY"
    free = True                            # False for commercial-only sources
    reliability = 0.7                      # 0..1 prior, used for ranking
    rate = 1.0                             # requests per second
    enabled_by_default = True              # False for flaky/opt-in sources

    BASE = "https://app.netlas.io/api/domains/"

    async def fetch(self, ctx: SourceContext) -> Iterable[str]:
        key = ctx.key(self.key_env)
        if not key:
            return []

        payload = ctx.http.get_json(
            self.BASE,
            params={"q": f"domain:{ctx.domain}", "fields": "name"},
            headers={"X-API-Key": key},
            timeout=ctx.timeout,
            rate=self.rate,
            rate_key=self.name,
        )

        hosts: List[str] = []
        for item in (payload or {}).get("items", []):
            name = item.get("data", {}).get("name")
            if name:
                hosts.append(name)
        return hosts
```

What the base class does with your return value:

| Concern | Handled by | Behaviour |
| --- | --- | --- |
| Missing key | `PassiveSource.collect` | Marked `skipped`, not an error |
| Rate limiting | `HttpClient` | Per-host token bucket using `rate` |
| Backoff | `HttpClient` | Exponential with jitter on 429/5xx |
| Timeouts | `HttpClient` | Hard deadline, no leaked connections |
| Hostname cleaning | `clean_hostname` | Strips wildcards, ports, URLs, punycode |
| Domain scoping | `belongs_to` | Drops hosts outside the target |
| Exceptions | `collect` | Contained per source, reported not raised |

Checklist for a new source:

- [ ] `name` is lowercase, short and stable — it is the CLI identifier.
- [ ] `category`, `description`, `reliability` and `rate` are filled in.
- [ ] `key_env` names the variable, and the source returns `[]` without it.
- [ ] `enabled_by_default = False` if the service is known to be flaky.
- [ ] A test with a recorded fixture response, no live network call.
- [ ] The source is added to the [SOURCES.md](SOURCES.md) tables.
- [ ] A `CHANGELOG.md` entry under `## [Unreleased]` → `### Added`.

## Pull request checklist

- [ ] Tests pass locally (`python -m pytest`) and new code is covered.
- [ ] `ruff check .` is clean.
- [ ] Docs updated — README, SOURCES.md, help text, whatever the change touches.
- [ ] A `CHANGELOG.md` entry exists under `## [Unreleased]`.
- [ ] No new dependencies were added.
- [ ] Commit messages follow Conventional Commits.
- [ ] The PR description explains the *why*, not just the *what*.

## Reporting bugs

Open an issue with the bug report form and include the output of
`subpy --version`, your OS, and the exact command you ran. If the bug involves a
specific source, `-v` output showing its timing and error is the fastest path to
a fix.

Never paste real API keys into an issue.

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## Code of Conduct

Participation is covered by the [Contributor Covenant](CODE_OF_CONDUCT.md).
Be decent to each other.

## License

By contributing you agree that your work is licensed under the
[MIT License](LICENSE).
