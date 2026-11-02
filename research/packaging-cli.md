# subpy — Packaging & CLI Reference

> **Scope.** Implementation-ready reference for `subpy`, a zero-dependency subdomain finder on Python 3.9+, targeting Linux, macOS, Windows, and Termux (Android, no root).
>
> **Verification legend.** ✅ = executed live on this host (Python 3.14.4, Linux aarch64, 2026-11-02) and output quoted. 🔎 = checked against vendor documentation (URL given). ⚠️ = design judgement, not empirically testable here.
>
> **Host caveat.** Only Python 3.14 was available; 3.9-specific claims are marked 🔎/⚠️, not ✅. Windows/macOS behavior is from documentation, not local execution.

---

## 0. Decisions at a glance

| Question | Decision | Why |
|---|---|---|
| Backend | **hatchling** | Zero-config `src/` discovery, no `setup.py`, strict PEP 621; setuptools needs `package-dir` boilerplate for `src/` |
| Layout | **`src/subpy/`** | Prevents accidental `import subpy` from CWD shadowing the installed package; forces testing the *installed* artifact |
| Runtime deps | **none** (`dependencies = []`) | Termux/Windows wheels for C extensions are the #1 install failure; speed is an *extra* |
| CLI framework | **argparse** | Zero-dep; click/typer add deps + import cost; our surface is flat flags, not deep subcommands |
| Version compare | **stdlib tuple comparator** (~30 LOC) | `packaging` is a dependency; naive `tuple(int)` is *wrong* — see §3.3 |
| Update check | **opt-out, 24 h cache, 2 s timeout, check-only** | Never auto-executes download; prints an upgrade hint |
| Update state | `$XDG_CONFIG_HOME/subpy/` → `%APPDATA%\subpy` | Termux gets `~/.config` for free (no `$PREFIX/etc` needed) |

**Do not ship a `curl \| python` installer** (§1.6) and **do not self-update binaries** (§3.4). Both are net-negative for a network tool.

---

## 1. Packaging & distribution

### 1.1 Backend choice ✅

| Backend | src/ support | Dependency | Verdict for subpy |
|---|---|---|---|
| `setuptools>=77` | needs explicit `[tool.setuptools] package-dir` | none (build-time) | Fine, but verbose; auto-discovery silently includes stray top-level dirs |
| **`hatchling`** | **automatic** | none (build-time) | ✅ **Chosen** — implicit `src/subpy` discovery |
| `flit_core` | automatic | none | Great for single-module; awkward for multi-module packages |
| `poetry-core` | automatic | none | Requires Poetry workflow; locks you to `poetry` CLI |

`requires-python` + PEP 621 metadata are backend-independent; the backend only affects build mechanics and file discovery.

**Verified ✅** — a `src/`-layout hatchling package builds cleanly with no `tool.hatch` config at all:

```text
$ python -m build
* Creating isolated environment: venv+pip...
* Installing packages in isolated environment:  - hatchling>=1.27
* Installed build dependency versions:  - hatchling==1.33.0
Successfully built subpy-0.1.0.tar.gz and subpy-0.1.0-py3-none-any.whl
```

Wheel contents (note `subpy/` — `src/` is stripped as required):

```text
subpy/__init__.py
subpy/cli.py
subpy-0.1.0.dist-info/{METADATA,WHEEL,entry_points.txt,RECORD}
```

`entry_points.txt` is exactly what makes the `subpy` command exist:

```ini
[console_scripts]
subpy = subpy.cli:main
```

✅ Installing that wheel into a fresh venv yields a working `/tmp/venv2/bin/subpy` that printed `hello from subpy ['a', 'b']` and exited `0`.

### 1.2 Full `pyproject.toml` (copy-paste)

```toml
[build-system]
requires = ["hatchling>=1.27"]
build-backend = "hatchling.build"

[project]
name = "subpy"
version = "0.1.0"                      # or: dynamic = ["version"] + [tool.hatch.version]
description = "A fast, zero-dependency subdomain finder for Linux, macOS, Windows and Termux."
readme = "README.md"
requires-python = ">=3.9"
license = "MIT"                         # PEP 639 SPDX string (setuptools>=77 / hatchling>=1.27)
license-files = ["LICENSE"]
authors = [{ name = "0xShahriar" }]
keywords = ["subdomain", "recon", "dns", "security", "cli", "osint"]
classifiers = [
  "Development Status :: 4 - Beta",
  "Environment :: Console",
  "Intended Audience :: Information Technology",
  "Intended Audience :: System Administrators",
  "License :: OSI Approved :: MIT License",
  "Operating System :: OS Independent",
  "Programming Language :: Python :: 3",
  "Programming Language :: Python :: 3 :: Only",
  "Programming Language :: Python :: 3.9",
  "Programming Language :: Python :: 3.10",
  "Programming Language :: Python :: 3.11",
  "Programming Language :: Python :: 3.12",
  "Programming Language :: Python :: 3.13",
  "Topic :: Security",
  "Topic :: System :: Networking",
  "Typing :: Typed",
]
dependencies = []                       # hard rule: zero runtime deps

[project.optional-dependencies]
# Pure-Python accelerators — safe everywhere, including Termux/Windows.
speed = ["dnspython>=2.4", "aiodns>=3.0"]
# uvloop has NO Windows support (no win32 wheels/classifiers) — POSIX only.
# PEP 508 markers keep this installable on Windows/macOS/Linux.
full  = [
  "dnspython>=2.4",
  "aiodns>=3.0",
  "uvloop>=0.19; sys_platform != 'win32' and platform_python_implementation == 'CPython'",
  "httpx>=0.27",
]
dev = ["pytest>=8", "pytest-cov", "ruff>=0.6", "build", "twine"]

[project.scripts]
subpy = "subpy.cli:main"

[project.urls]
Homepage      = "https://github.com/0xShahriar/subpy"
Repository    = "https://github.com/0xShahriar/subpy"
Issues        = "https://github.com/0xShahriar/subpy/issues"
Changelog     = "https://github.com/0xShahriar/subpy/blob/main/CHANGELOG.md"
Security      = "https://github.com/0xShahriar/subpy/blob/main/SECURITY.md"

[tool.hatch.build.targets.wheel]
packages = ["src/subpy"]

[tool.hatch.build.targets.sdist]
include = [
  "/src",
  "/tests",
  "/README.md",
  "/LICENSE",
  "/CHANGELOG.md",
]

[tool.ruff]
target-version = "py39"
line-length = 100

[tool.ruff.lint]
select = ["E", "F", "W", "I", "UP", "B", "C4", "SIM"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-q"

**Evidence for the zero-dep rule ✅** — resolving `subpy[full]` pulled **14 distributions**, three of them compiled against a C toolchain:

```text
Would install aiodns-4.0.4 anyio-4.16.0 certifi-2026.10.23 cffi-2.1.1 dnspython-2.9.1
              h11-0.16.0 httpcore-1.0.9 httpx-0.28.1 idna-3.20 pycares-5.2.1
              pycparser-3.12 subpy-0.1.0 typing_extensions-4.16.0 uvloop-0.23.0
```

`pycares` and `cffi` need a compiler/wheel; `uvloop` is CPython-only and POSIX-only. On a fresh Termux install, any of those can fail. **Core install must stay `dependencies = []`.**

### 1.3 `src/` vs flat layout

**Choose `src/subpy/`.**

| | `src/subpy/` | flat `subpy/` |
|---|---|---|
| Accidental CWD import | **Impossible** — `import subpy` only sees installed code | Common: tests pass against the working tree, then fail after install |
| Forces testing the real artifact | ✅ | ✗ |
| Backend config | hatchling: none | setuptools: auto-discovery works, but also silently packages stray dirs (`tests/`, `docs/`) |
| Extra friction | must `pip install -e .` to run | can run `python -m subpy` directly |

✅ **Verified both work.** Flat layout with `setuptools>=77` auto-discovery built a correct wheel with zero config:

```text
subpy/__init__.py
subpy/cli.py
subpy-0.1.0.dist-info/top_level.txt   # <- auto-discovery artifact
```

Caveat for flat layout: if a `tests/` directory exists **without** `__init__.py`, newer setuptools raises a "multiple top-level packages" error; with `src/` the question never arises.

✅ `pip install .` from the source tree succeeded (`install . exit=0`) and the installed `subpy` command ran (`ok src-less`).

### 1.4 `pip install .` / `pipx` / `pip install git+https://…`

All three work with the same `pyproject.toml`; the difference is **isolation**.

```bash
# 1. Into the active environment (library-style; pollutes it)
pip install .

# 2. Isolated CLI install — RECOMMENDED for users
pipx install .
pipx install "git+https://github.com/0xShahriar/subpy@v0.1.0"   # pinned is safer
pipx upgrade subpy

# 3. Directly from git (works: pip reads pyproject.toml at build time)
pip install "git+https://github.com/0xShahriar/subpy"
pip install "git+https://github.com/0xShahriar/subpy@main#egg=subpy"

# 4. Extras from git
pip install "subpy[full] @ git+https://github.com/0xShahriar/subpy@v0.1.0"

# 5. Local wheel / editable
pip install dist/subpy-0.1.0-py3-none-any.whl
pip install -e ".[dev]"
```

✅ **Verified** `pip install "git+https://github.com/psf/requests.git@v2.31.0"` installed and imported (`requests 2.31.0`) — pip builds from source over HTTPS without any extra tooling because *any* PEP 517 backend is fetched into an isolated build env.

Requirements for the git URL to work:
- repo is **public**, or the user authenticates (SSH remote / token URL);
- `pyproject.toml` is at the repo **root** (a monorepo needs `…#subdirectory=path/to/pkg`);
- a `console_scripts` entry point exists (otherwise install succeeds but there is no `subpy` command).

⚠️ **`git+https` installs need `git` on the machine.** Termux users may not have it — prefer a wheel/PyPI or a zipapp for them.

### 1.5 Termux specifics

```bash
pkg update
pkg install python            # provides python3 + pip; no root required
termux-setup-storage          # optional, only to read files from shared storage

# Preferred: isolated, no clobbering the Termux-managed python packages
pkg install python-pip        # often already present
pip install --user subpy      # ~/.local/bin — ensure it is on PATH
# or, best isolation:
pkg install pipx && pipx ensurepath && pipx install subpy
```

Termux rules that actually bite:

1. **Never `pip install` into the system prefix as workarounds** — Termux's Python is patched; mixing `pip` and `pkg` for the same module breaks imports. Use `--user` or `pipx`.
2. **No wheels for old C extensions** on `aarch64` for niche packages → another reason for zero runtime deps.
3. `~/.config` is writable and persists → update-cache path needs **no** `$PREFIX/etc` special case. ✅ (`XDG_CONFIG_HOME` unset → `/root/.config/subpy` on this host; identical logic on Termux.)
4. `~/.local/bin` is **not** on `PATH` by default on older Termux → `pipx ensurepath`, or advise `export PATH=$HOME/.local/bin:$PATH`.
5. `$TERM` is usually `xterm-256color`; color works. `isatty()` is `True` in Termux's terminal — spinner is safe.
6. Android kills background processes aggressively; long scans should be resumable (`-o` append + `--resume`). ⚠️ design note.

### 1.6 `curl | python` and zipapp

**`curl … | python` — do not ship it.**

| Problem | Consequence |
|---|---|
| Defeats the whole packaging system | No version metadata, no `pip uninstall`, no dependency resolution |
| Trivially MITM-able / DNS-poisonable | Users execute arbitrary remote code with their privileges |
| No upgrades, no rollback | Support burden; users run stale versions silently |
| Breaks in corporate proxies / Termux without `curl` | Fragile |

If a one-liner is needed, ship a **`pipx`-based** one that still goes through the package system:

```bash
python3 -m pip install --user --upgrade pipx && python3 -m pipx ensurepath \
  && python3 -m pipx install subpy
```

**zipapp — a legitimate *secondary* artifact ✅.** Standard library, no build backend needed:

```bash
python -m zipapp src -o subpy.pyz -p "/usr/bin/env python3" -m "subpy.cli:main"
# -c for compressed; -m generates a __main__.py calling subpy.cli:main
```

✅ Verified both the generated `__main__.py` form and direct execution:

```text
$ python3 -m zipapp app -o subpy.pyz -p "/usr/bin/env python3"
-rwxr--r-- 649 subpy.pyz
$ python3 subpy.pyz x y      -> hello from subpy ['x', 'y']   exit=0
$ chmod +x subpy.pyz && ./subpy.pyz z -> hello from subpy ['z']  exit=0
$ python3 -m zipapp app -o subpy-c.pyz -p "/usr/bin/env python3" -c  -> 627 bytes
```

zipapp limits to state in the docs: it is **not** a substitute for a wheel (no `.dist-info`, no entry-point registry, `pip` cannot install it), single-file only, and it must be run with a Python that matches your `requires-python`. Use it for air-gapped/offline drop-in use, and sign it (`gpg --detach-sign` / publish a `SHA256SUMS`).

### 1.7 Optional C accelerators + graceful stdlib fallback

| Package | What it speeds up | Platform reality | Optional? |
|---|---|---|---|
| `dnspython` | Pure-Python DNS, async resolver | pure Python, universal | ✅ extra |
| `aiodns` | c-ares DNS via `pycares` | needs `pycares`/`cffi` wheels | ✅ extra |
| `uvloop` | asyncio event loop | **CPython only, POSIX only — no Windows** ✅ verified | ✅ extra, marker-gated |
| `httpx` | HTTP client | pulls `httpcore`,`anyio`,`h11`,`certifi`,`idna` | ✅ extra |

✅ **uvloop Windows caveat verified live** from the PyPI JSON API — its classifiers are only:

```text
Operating System :: MacOS :: MacOS X
Operating System :: POSIX
Programming Language :: Python :: Implementation :: CPython
```

No `Microsoft :: Windows`, no win32 wheels. ✅ The PEP 508 marker evaluates correctly:

```text
sys_platform=win32  + CPython -> False   (uvloop skipped)
sys_platform=linux  + CPython -> True
sys_platform=linux  + PyPy    -> False   (no PyPy wheels)
sys_platform=darwin + CPython -> True
```

**Fallback pattern — probe, never assume:**

```python
"""subpy/_accel.py — optional accelerators, all best-effort."""
from __future__ import annotations

import asyncio
import sys

_UVLOOP = None
_DNSPYTHON = None
_AIODNS = None


def try_import():
    """Import optional accelerators once. Never raises."""
    global _UVLOOP, _DNSPYTHON, _AIODNS
    if sys.platform != "win32":
        try:
            import uvloop  # type: ignore[import-not-found]
            _UVLOOP = uvloop
        except Exception:      # ImportError, but also OSError from bad .so
            _UVLOOP = None
    try:
        import dns.resolver  # type: ignore[import-not-found]
        _DNSPYTHON = dns.resolver
    except Exception:
        _DNSPYTHON = None
    if _DNSPYTHON is not None:
        try:
            import aiodns  # type: ignore[import-not-found]
            _AIODNS = aiodns
        except Exception:
            _AIODNS = None


def install_event_loop_policy():
    """Install uvloop if present; otherwise keep the stdlib default."""
    if _UVLOOP is not None:
        try:
            _UVLOOP.install()
            return "uvloop"
        except Exception:
            pass
    if sys.platform == "win32":
        # Default Proactor loop handles DNS/async correctly on Windows.
        return "asyncio-proactor"
    return "asyncio-selector"


def backend_name():
    if _AIODNS is not None:
        return "aiodns+c-ares"
    if _DNSPYTHON is not None:
        return "dnspython"
    return "stdlib-socket"


async def resolve(host, timeout=3.0):
    """Resolve A records with whichever backend is available."""
    if _AIODNS is not None and _DNSPYTHON is not None:
        resolver = _AIODNS.DNSResolver(timeout=timeout)
        try:
            answers = await resolver.query(host, "A")
            return [a.host for a in answers]
        except Exception:
            return []
    if _DNSPYTHON is not None:
        return await resolve_dnspython(host, timeout)
    return await resolve_stdlib(host, timeout)


async def resolve_dnspython(host, timeout=3.0):
    import dns.asyncresolver  # type: ignore[import-not-found]
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answers = await resolver.resolve(host, "A")
        return [r.address for r in answers]
    except Exception:
        return []


async def resolve_stdlib(host, timeout=3.0):
    """Zero-dependency fallback: run the blocking resolver in a thread."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.run_in_executor(None, _getaddrinfo, host), timeout
        )
    except (asyncio.TimeoutError, OSError):
        return []
    return sorted({i[4][0] for i in infos})


def _getaddrinfo(host):
    import socket
    return socket.getaddrinfo(host, None, family=socket.AF_INET)
```

⚠️ Never branch on "is it installed" *without* the `try/except` around the actual call site too: a broken `.so` raises `OSError`/`ImportError` at import, and a version bump can change the API. Catching `Exception` at import is deliberate here — an accelerator must never be able to crash the tool.

---

## 2. CLI UX

### 2.1 argparse vs click vs typer

| | **argparse** | click | typer |
|---|---|---|---|
| Deps | **stdlib** ✅ | `click` | `typer` + `click` + `typing_extensions` (+`rich` optional) |
| Import time | ~5 ms | ~20 ms | ~60–120 ms ⚠️ |
| Shell completion | ✗ (manual bash/zsh script) | ✅ built-in | ✅ built-in |
| Colored help / rich panels | ✗ (manual) | ✅ `click.style` | ✅ |
| Type coercion from annotations | ✗ | partial | ✅ |
| Multi-command tree | `add_subparsers` (verbose) | ✅ decorators | ✅ decorators |
| Best for | flat flag surfaces, zero-dep tools | mature CLIs | large typed CLIs |

**Decision: argparse.** `subpy` is a flat flag surface (`subpy example.com -w list.txt -o out.txt`), the hard requirement is zero runtime deps, and 60–120 ms of import tax is noticeable on a phone (Termux). The ergonomics click adds (completion, styled help) are recoverable by hand in ~40 lines.

Trade-off accepted: we must hand-roll `--version`, colored help, and completions. §2.6–2.8 show the patterns.

### 2.2 Argument surface

```
subpy <target> [options]
```

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `target` | positional | — | `example.com`, `*.example.com`, `example.com:8080`, or `-` for stdin |
| `-w, --wordlist PATH` | repeatable file | built-in | Wordlist(s); repeatable, `-` = stdin |
| `-o, --output PATH` | file | — | Write results (append unless `--overwrite`) |
| `-f, --format {text,json,jsonl,csv}` | enum | `text` | Output format; implied by `-o` extension when omitted |
| `-t, --concurrency N` | int ≥1 | `50` | In-flight DNS queries (not "threads" — we're async) |
| `-r, --resolvers PATH\|IP` | str | system | Resolver list file or comma-separated IPs |
| `--wildcard {detect,skip,allow}` | enum | `detect` | Wildcard-DNS handling |
| `--passive` / `--active` | flags | active | Passive only = crt.sh/CT logs, no packets to target |
| `--json` | flag | off | Shorthand for `-f json` |
| `--silent, -s` | flag | off | Suppress banner/progress; results only (pipe-safe) |
| `--no-color` | flag | auto | Disable ANSI (also honours `NO_COLOR`) |
| `--rate-limit N` | float | `0` (off) | Max queries/sec across the whole run |
| `--timeout SEC` | float | `3.0` | Per-query timeout |
| `--retries N` | int | `1` | Retry count per host |
| `--resume` | flag | off | Skip hosts already present in `-o` file |
| `--no-update-check` | flag | off | Skip GitHub release check |
| `--stats` | flag | off | Print timing/throughput summary to stderr at exit |
| `-q/--quiet`, `-v/--verbose` | count | 0 | Log verbosity on stderr |
| `--version` | flag | — | Print version + backend (+ `--version --json` for machines) |

**Design rules**
- **Results → stdout, diagnostics → stderr.** This is what makes `subpy example.com -s | tee subs.txt` and `| xargs` work.
- `--silent` must not disable stdout results; it silences *stderr* chrome only.
- `-t` is **concurrency**, not threads. Document it as such; async I/O with `t=200` is fine, threads are not.
- Never require `-w`; ship a small embedded wordlist so `subpy example.com` alone is useful.

### 2.3 Argument parsing skeleton ✅

```python
"""subpy/cli.py"""
from __future__ import annotations

import argparse
import sys

from . import __version__


class SubpyError(Exception):
    """Operational error → exit 1 (not a usage error)."""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="subpy",
        description="Fast, zero-dependency subdomain finder.",
        epilog="Examples:\n"
               "  subpy example.com\n"
               "  subpy example.com -w names.txt -t 200 -o subs.txt\n"
               "  subpy example.com --passive --json -s | jq -r .host",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )
    p.add_argument("target", help="Domain to enumerate, or '-' to read from stdin")
    p.add_argument("-w", "--wordlist", action="append", metavar="PATH",
                   help="Wordlist file (repeatable; '-' = stdin)")
    p.add_argument("-o", "--output", metavar="PATH", help="Write results to PATH")
    p.add_argument("-f", "--format", choices=("text", "json", "jsonl", "csv"),
                   default=None, help="Output format (default: text)")
    p.add_argument("-t", "--concurrency", type=positive_int, default=50, metavar="N",
                   help="Concurrent DNS queries (default: 50)")
    p.add_argument("-r", "--resolvers", metavar="PATH|LIST",
                   help="Resolver file or comma-separated IP list")
    p.add_argument("--wildcard", choices=("detect", "skip", "allow"), default="detect")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--passive", action="store_true", help="Only passive sources (CT logs)")
    mode.add_argument("--active", action="store_true", help="DNS brute-force (default)")
    p.add_argument("--json", action="store_true", help="Shorthand for -f json")
    p.add_argument("-s", "--silent", action="store_true", help="Results only on stdout")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI color")
    p.add_argument("--rate-limit", type=non_negative_float, default=0.0, metavar="N")
    p.add_argument("--timeout", type=non_negative_float, default=3.0, metavar="SEC")
    p.add_argument("--retries", type=non_negative_int, default=1, metavar="N")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--no-update-check", action="store_true")
    p.add_argument("--stats", action="store_true")
    p.add_argument("-v", "--verbose", action="count", default=0)
    p.add_argument("--version", action="version",
                   version=f"subpy {__version__}")
    return p


def positive_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected an integer, got {raw!r}") from None
    if value < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return value


def non_negative_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected an integer, got {raw!r}") from None
    if value < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return value


def non_negative_float(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a number, got {raw!r}") from None
    if value < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return value


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)          # exits 2 on usage errors

    if args.json:
        args.format = "json"
    if args.format is None:
        args.format = infer_format(args.output)
    if args.active:
        args.passive = False

    try:
        return run(args)
    except SubpyError as exc:
        print(f"subpy: error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:               # belt-and-braces; see §2.7
        print("\nsubpy: interrupted", file=sys.stderr)
        return 130


def infer_format(path) -> str:
    if not path:
        return "text"
    lowered = path.lower()
    if lowered.endswith(".jsonl") or lowered.endswith(".ndjson"):
        return "jsonl"
    if lowered.endswith(".json"):
        return "json"
    if lowered.endswith(".csv"):
        return "csv"
    return "text"


def run(args) -> int:                        # pragma: no cover - wiring
    raise NotImplementedError


if __name__ == "__main__":                   # python -m subpy
    sys.exit(main())
```

✅ **argparse exit-code behavior verified live** — this is why the app must not re-map it:

```text
argparse missing-arg exit code: 2
argparse bad-choice exit code: 2
usage: subpy [-h] target
subpy: error: the following arguments are required: target
usage: subpy [-h] [--fmt {text,json}]
subpy: error: argument --fmt: invalid choice: 'xml' (choose from text, json)
```

`parser.parse_args()` raises `SystemExit(2)` on its own; if you wrap it in `try: ... except SystemExit` you will silently convert usage errors into success. Let it propagate.

Add `python -m subpy` support by shipping `__main__.py`:

```python
# src/subpy/__main__.py
import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
```

### 2.4 Color: NO_COLOR, FORCE_COLOR, isatty, Windows, Termux

🔎 **The `NO_COLOR` spec** ([no-color.org](https://no-color.org/), last updated 2026-10-12) is precise and easy to get wrong:

> Command-line software which adds ANSI color to its output by default should check for a `NO_COLOR` environment variable that, **when present and not an empty string (regardless of its value)**, prevents the addition of ANSI color.

Three consequences people miss:
1. `NO_COLOR=""` (empty) must **NOT** disable color → test truthiness, not `in os.environ`.
2. `NO_COLOR=0` **does** disable color (any non-empty value).
3. The spec explicitly says it only signals *color*; bold/underline are out of scope. It also says user config / per-instance flags override the env var.

```python
"""subpy/_color.py"""
from __future__ import annotations

import os
import sys

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"


def _enable_windows_vt() -> bool:
    """Turn on ANSI processing for legacy Windows consoles. Returns success."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)                 # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        return bool(kernel32.SetConsoleMode(
            handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
    except Exception:
        return False


def supports_color(stream=None, *, flag_no_color=False, force=None) -> bool:
    """Decide once, at startup. Precedence: explicit flag > env > TTY heuristic."""
    stream = stream or sys.stdout
    if flag_no_color:
        return False
    if force is True:
        return True
    if force is False:
        return False
    # NO_COLOR: present AND non-empty disables (per spec).
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("TERM") == "dumb":
        return False
    if os.environ.get("CI"):
        return False
    try:
        if not stream.isatty():
            return False
    except (AttributeError, ValueError):
        return False
    if os.name == "nt":
        return _enable_windows_vt()
    return True


class Style:
    """No-op when color is disabled, so call sites never branch."""

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, *codes: str) -> str:
        if not self.enabled or not codes:
            return text
        return "".join(codes) + text + RESET

    def ok(self, t):    return self(t, GREEN)
    def warn(self, t):  return self(t, YELLOW)
    def err(self, t):   return self(t, RED)
    def info(self, t):  return self(t, CYAN)
    def dim(self, t):   return self(t, DIM)
    def bold(self, t):  return self(t, BOLD)
```

✅ **Precedence verified live** against a fake-TTY harness:

```text
env={}                                     tty=True  -> color=True
env={}                                     tty=False -> color=False
env={'NO_COLOR': '1'}                      tty=True  -> color=False
env={'NO_COLOR': ''}                       tty=True  -> color=True     # per spec
env={'TERM': 'dumb'}                       tty=True  -> color=False
env={'FORCE_COLOR': '1'}                   tty=False -> color=True
env={'FORCE_COLOR': '1', 'NO_COLOR': '1'}  tty=True  -> color=True     # FORCE wins
env={'NO_COLOR': '1', 'TERM': 'dumb'}      tty=True  -> color=False
flag always over NO_COLOR: True
flag never  over FORCE_COLOR: False
```

Precedence rationale: the spec says per-instance flags override the env var, so `--color=always` beats `NO_COLOR`. `FORCE_COLOR` beating `NO_COLOR` matches Python 3.13+'s own REPL behavior. If you want strict NO_COLOR-wins, swap the two checks — just document it.

**Platform notes**
- **Windows 10+**: `SetConsoleMode(...ENABLE_VIRTUAL_TERMINAL_PROCESSING)` is required only for `cmd.exe`/legacy conhost. ✅ Default `windows-terminal`, VS Code, and Git-Bash handle ANSI natively. `ctypes.windll` exists only on Windows → the `os.name == "nt"` guard is mandatory (it is not importable elsewhere).
- **Windows, redirected output**: `isatty()` is `False` for a pipe → color off automatically. Good.
- **Termux**: `isatty()` is `True`, `TERM=xterm-256color`, ANSI works. **Caveat ⚠️**: some Android keyboards/terminal emulators mis-measure width; ship `--no-color` and honour `NO_COLOR`.
- **`CI=true`**: most CIs set this and want no escape codes in logs. Verified locally that this host has `TERM=dumb` and `NO_COLOR=1` set — a real-world example of why the precedence chain matters.

### 2.5 Terminal width & responsive layout

```python
"""subpy/_term.py"""
from __future__ import annotations

import shutil
import sys
import unicodedata

MIN_COLS = 40          # narrowest layout we design for (40-col phone)
DEFAULT_COLS = 80


def term_cols(stream=None, *, minimum=MIN_COLS, maximum=200) -> int:
    """Usable width, clamped. Falls back to COLUMNS then 80."""
    stream = stream or sys.stdout
    try:
        cols = shutil.get_terminal_size(fallback=(DEFAULT_COLS, 24)).columns
    except (ValueError, OSError):
        cols = DEFAULT_COLS
    return max(minimum, min(cols, maximum))


def display_width(text: str) -> int:
    """Width in terminal cells: CJK/emoji count as 2. Zero-dep."""
    width = 0
    for ch in text:
        if unicodedata.combining(ch):
            continue
        width += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return width


def truncate(text: str, limit: int, ellipsis: str = "...") -> str:
    """Truncate to `limit` display cells without splitting wide chars."""
    if limit <= 0:
        return ""
    if display_width(text) <= limit:
        return text
    budget = limit - len(ellipsis)
    if budget <= 0:
        return ellipsis[:limit]
    out, used = [], 0
    for ch in text:
        w = display_width(ch)
        if used + w > budget:
            break
        out.append(ch)
        used += w
    return "".join(out) + ellipsis


def pad(text: str, width: int, align: str = "<") -> str:
    """Pad to a display-cell width (len() is wrong for CJK)."""
    gap = max(0, width - display_width(text))
    if align == ">":
        return " " * gap + text
    if align == "^":
        left = gap // 2
        return " " * left + text + " " * (gap - left)
    return text + " " * gap
```

✅ `shutil.get_terminal_size` behavior verified live:

```text
shutil.get_terminal_size((40,24))  -> os.terminal_size(columns=40, lines=24)
shutil.get_terminal_size((120,24)) -> os.terminal_size(columns=120, lines=24)
```

**It never raises and never returns 0** when you pass `fallback=`; without a fallback and with no TTY it still returns `(80, 24)`. ✅ Confirmed: this sandbox has no TTY, yet the call returned `columns=80`.

CJK/emoji trap ✅ measured:

```text
len("東京サブドメイン") = 8,  actual display cells = 16
```

So `f"{host:<20}"` misaligns columns by 8 cells. Use `pad()`/`truncate()` above — or stay ASCII-only.

**Responsive layout rule**: one row per result, and *degrade columns* as width drops, rather than letting the line wrap (wrapping destroys `grep`/`awk` parsing).

```python
def format_result(host, ips, status, cols, style):
    """Columns drop out left-to-right as the terminal narrows."""
    if cols >= 72:
        return f"{style.ok('+')} {pad(host, 40)} {pad(','.join(ips), 18)} {style.dim(status)}"
    if cols >= 48:
        return f"{style.ok('+')} {pad(host, 26)} {style.dim(','.join(ips[:1]))}"
    return f"{style.ok('+')} {truncate(host, cols - 2)}"
```

**Unicode box drawing vs ASCII fallback**

| | Box drawing `┌─┐│└┘` | ASCII `+-+| }` |
|---|---|---|
| Looks | cleaner | dated |
| cp437/legacy Windows console | ✅ works (`┌─┐`.encode("cp437") → `b'\xda\xc4\xbf'`) ✅ verified | ✅ |
| `ascii`-encoded stream (POSIX locale, some CI) | ✗ **UnicodeEncodeError** ✅ verified | ✅ |
| 40-col phone | eats 2–4 cells of width | compact |

✅ Verified: `"┌─┐".encode("ascii")` raises `UnicodeEncodeError`; `.encode("cp437")` and `.encode("utf-8")` succeed. So the fallback must key off **both** encoding and preference:

```python
def use_unicode(stream=None, *, flag_ascii=False) -> bool:
    if flag_ascii:
        return False
    stream = stream or sys.stdout
    enc = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
    if enc in ("ascii", "usascii", "ansix341968"):
        return False
    if os.environ.get("SUBPY_ASCII"):        # escape hatch
        return False
    return True


BOX = {
    True:  {"h": "─", "v": "│", "tl": "┌", "tr": "┐", "bl": "└", "br": "┘"},
    False: {"h": "-", "v": "|", "tl": "+", "tr": "+", "bl": "+", "br": "+"},
}
```

Expose `--ascii` as a flag too; users on odd terminals should not need env vars.

### 2.6 Spinner / progress without dependencies

Rules for a live-updating line (**stderr only**, never stdout):

1. **Only animate on a TTY.** `sys.stderr.isatty()`. If piped → emit nothing, or one line per N results.
2. **Write `\r` + clear-to-EOL (`\033[K`), then flush.** Without `\033[K`, a shorter new message leaves stale trailing characters.
3. **Restore the line before any real output** (write `\r\033[K` first) or the spinner will splice into a log line.
4. **On non-TTY, never write `\r`** — it corrupts CI logs and `tee`ed files into one giant line.
5. **Throttle** to ~10 fps; redrawing per query burns battery on Termux.

```python
"""subpy/_progress.py"""
from __future__ import annotations

import sys
import time

FRAMES_UNICODE = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
FRAMES_ASCII = "|/-\\"


class Progress:
    """Single-line live counter on stderr. Silent when not a TTY."""

    def __init__(self, total=None, stream=None, enabled=None, ascii_only=False,
                 min_interval=0.1):
        self.stream = stream or sys.stderr
        self.total = total
        self.frames = FRAMES_ASCII if ascii_only else FRAMES_UNICODE
        self.enabled = self.stream.isatty() if enabled is None else enabled
        self.min_interval = min_interval
        self._i = 0
        self._last = 0.0
        self._dirty = False
        self.done = 0

    def update(self, done=None, total=None, label="", force=False):
        if done is not None:
            self.done = done
        if total is not None:
            self.total = total
        if not self.enabled:
            return
        now = time.monotonic()
        if not force and now - self._last < self.min_interval:
            return
        self._last = now
        frame = self.frames[self._i % len(self.frames)]
        self._i += 1
        counter = f"{self.done}/{self.total}" if self.total else str(self.done)
        self._write(f"\r\033[K{frame} {label} {counter}".rstrip())
        self._dirty = True

    def clear(self):
        """Erase the spinner line so real output starts clean."""
        if self.enabled and self._dirty:
            self._write("\r\033[K")
            self._dirty = False

    def finish(self, message=""):
        self.clear()
        if self.enabled and message:
            self._write(message + "\n")

    def _write(self, text):
        try:
            self.stream.write(text)
            self.stream.flush()
        except (OSError, ValueError):      # closed/broken pipe on Termux suspend
            self.enabled = False
```

✅ Rendered and inspected live (raw bytes on stderr):

```text
$ python3 - <<'EOF'   # Progress(enabled=True)
$ ... render("resolving 120/1000"); render("resolving 240/1000")
\r\033[Kresolving 120/1000\r\033[Kresolving 240/1000\r\033[K
```

✅ And on a non-TTY, `sys.stderr.isatty()` was `False`, so `update()` produced **no output at all** — exactly the degradation required for CI logs.

For a determinate bar that fits 40 cols, prefer the compact form `[######----] 62%` over a boxed multi-line panel; a bar longer than the terminal is worse than no bar.

### 2.7 Signals: Ctrl-C that flushes and summarizes

The goal: **one** Ctrl-C → stop cleanly, flush `-o`, print a summary, exit **130**. A second Ctrl-C → immediate exit (so a hung DNS call is escapable).

```python
"""subpy/_signals.py"""
from __future__ import annotations

import signal
import sys

EXIT_SIGINT = 130
EXIT_SIGTERM = 143


class Shutdown:
    """Tracks interrupt state so the app can flush exactly once."""

    def __init__(self):
        self.requested = False
        self.signum = None

    def install(self):
        # SIGINT: available everywhere, including Windows.
        signal.signal(signal.SIGINT, self._handler)
        # SIGTERM: NOT delivered on Windows in the POSIX sense; guard it.
        if hasattr(signal, "SIGTERM") and sys.platform != "win32":
            signal.signal(signal.SIGTERM, self._handler)

    def _handler(self, signum, frame):
        if self.requested:
            # Second interrupt: hard stop, no cleanup.
            sys.stderr.write("\nsubpy: forced exit\n")
            sys.stderr.flush()
            signal.signal(signum, signal.SIG_DFL)
            raise SystemExit(EXIT_SIGINT if signum == signal.SIGINT else EXIT_SIGTERM)
        self.requested = True
        self.signum = signum
        # Do NOT do I/O here beyond a short notice: the main loop checks state.
        try:
            sys.stderr.write("\nsubpy: stopping after current query "
                             "(Ctrl-C again to force)\n")
            sys.stderr.flush()
        except (OSError, ValueError):
            pass

    def exit_code(self):
        return EXIT_SIGTERM if self.signum == getattr(signal, "SIGTERM", None) else EXIT_SIGINT
```

Cooperative check in the scan loop:

```python
shutdown = Shutdown()
shutdown.install()

for host in candidates:
    if shutdown.requested:
        break
    ...
# after the loop: always flush, always summarize
```

✅ **Exit-code mechanics verified live** — this is the part people get wrong:

```text
custom handler sig 2  (SIGINT)  -> exit=130
custom handler sig 15 (SIGTERM) -> exit=130     # we chose to exit(130); see below
uncaught KeyboardInterrupt      -> exit=0       # Python 3.14: clean interpreter exit!
SIGTERM with no handler         -> exit=143     # killed by signal 15
```

Two important, non-obvious results:

- **Uncaught `KeyboardInterrupt` exits `0` on this Python (3.14).** ✅ Measured. Relying on the interpreter to produce 130 is a bug; you must catch it (or install a handler) and `sys.exit(130)` explicitly. (Older CPython versions produced 130; do not depend on the version.)
- **Default SIGTERM (no handler) yields `143`** = `128 + 15`, produced by the *shell*, not Python. ✅ Confirmed.

Windows differences, stated plainly:
- `SIGTERM` is not a normal termination path: `os.kill(pid, signal.SIGTERM)` on Windows calls `TerminateProcess` — **no** handler, no cleanup. Only `CTRL_C_EVENT`/`CTRL_BREAK_EVENT` are catchable, and `sys.platform == "win32"` guards prevent `AttributeError`.
- `signal.signal` on Windows is only supported for `SIGINT`, `SIGTERM`, `SIGABRT`, `SIGFPE`, `SIGILL`, `SIGSEGV`, `SIGBREAK` — hence the `hasattr` guard.
- Console Ctrl-C raises `KeyboardInterrupt` in the main thread; in a **background** thread it is not delivered. Async code: cancel the task and let the loop exit.

**Always flush in a `finally`:** an exception path must not lose buffered results. Use `try/finally` with `out.flush()`, and if `-o` was given, also flush the underlying `os.fsync(f.fileno())` on Termux, where the process may be killed by the OS after backgrounding. ⚠️ (Android's LMK can kill without warning; fsync is cheap insurance.)

### 2.8 Exit codes

| Code | Meaning | When |
|---|---|---|
| **0** | Success | Ran to completion — **including** "0 subdomains found". An empty result is not an error |
| **1** | Runtime error | Network dead, unresolvable target, unwritable `-o`, bad wordlist |
| **2** | Usage error | argparse: bad flag, missing `target`, invalid choice — do not re-map |
| **130** | Interrupted (SIGINT) | `128 + 2`; conventional, script-friendly |
| **143** | Terminated (SIGTERM) | `128 + 15`; optional — only if you deliberately distinguish |

Conventions worth adopting (sysexits-inspired, but stay minimal):
- Reserve **64–78** if you later need granularity (`sysexits.h`: 64 usage, 65 data, 66 no input, 69 unavailable, 73 can't create output, 74 I/O error, 78 config). Do not invent numbers outside this space; shells and CI treat 126/127 specially.
- **Do not** use `1` to mean "nothing found" — that breaks `set -e` pipelines for the common success case.
- Document the table in `--help` and README; scripts depend on it.

✅ Table verified — `sys.exit(n)` propagates n for 0/1/2/130.

### 2.9 Output & error message style

```python
# results  -> stdout (machine-readable, one record per line, no chrome)
print(host)                       # text
print(json.dumps(rec), flush=True)  # jsonl
# diagnostics -> stderr, prefixed, never on stdout
print(f"subpy: error: {msg}", file=sys.stderr)
```

Principles: never mix status text into stdout; one record per line for text/jsonl so `grep`/`xargs -n1` compose; make `--json` emit a **single valid JSON document** (an object with `target`, `started_at`, `results[]`) while `-f jsonl` streams one object per line; exit non-zero on a *failed scan*, not on *zero results*.

---

## 3. Auto-update

### 3.1 GitHub releases API, unauthenticated ✅

Endpoint: `GET https://api.github.com/repos/0xShahriar/subpy/releases/latest`

Verified response fields used by an updater (live call, `cli/cli` as a stand-in because the `subpy` repo currently 404s — see §4.0):

```text
tag_name: v2.103.3
html_url: https://github.com/cli/cli/releases/tag/v2.103.3
published_at: 2026-10-26T19:20:08Z
prerelease: False   draft: False
assets: [('gh_2.103.3_checksums.txt', 1971), ('gh_2.103.3_linux_386.deb', 14148728), ...]
```

**`User-Agent` is mandatory.** ✅ Verified — omitting it returns **403**, not 200:

```text
$ curl -H "User-Agent:" https://api.github.com/repos/cli/cli/releases/latest
status=403
$ curl -H "User-Agent: subpy-check" ...
status=200
```

**Rate limit: 60 requests/hour per IP, unauthenticated.** ✅ Verified via headers:

```text
x-ratelimit-limit: 60
x-ratelimit-remaining: 36
x-ratelimit-used: 24
x-ratelimit-resource: core
x-ratelimit-reset: 1793588741        # epoch seconds (UTC)
```

🔎 Notes that matter operationally:
- The 60/hr budget is **per source IP**, so users behind CGNAT/corporate NAT share it. Never assume a check will succeed.
- `releases/latest` **excludes drafts and pre-releases** automatically — convenient, and why you should not use `releases[0]`.
- ⚠️ **Spurious but real: earlier `subpy` 404s still consume quota.** A 404 costs a request; so does a rate-limited 403? (No — a 403 rate-limit response is *not* counted, but any 2xx/404 is.) Budget accordingly.
- Enterprise/GHES users need a different host; make the API URL overridable via env (`SUBPY_UPDATE_URL`) for forks and mirrors.
- Authenticated requests (`Authorization: Bearer …`) get 5 000/hr, but **never** ship a bundled token — it will be revoked and it is a credential leak.

### 3.2 Safe self-update patterns

| Pattern | How real tools do it | Fit for `subpy` |
|---|---|---|
| **Check + print upgrade hint** | `gh` (checks, prints `A new release is available`) | ✅ **Chosen** |
| `pip install --upgrade subpy` | pipx-based tools | ✅ offer as *printed instruction* only |
| `git pull` | dev installs | ⚠️ only if `.git` present; never silently |
| Download asset + `SHA256SUMS` verify + replace binary | ripgrep, `gh` | ⚠️ only for the zipapp/standalone artifact |
| Download + **auto-execute** | — | ❌ never |

**Hard rules**
1. **Never auto-execute downloaded code.** No `subprocess` on a downloaded file, no `exec`, no `pip install` launched silently from a scan command.
2. **Never write to your own installation** while running (on Windows the running `.exe`/script may be locked; on POSIX you can corrupt a partially-written file if killed).
3. **Fail silent.** A failed update check must never change the tool's exit code or add noise to stderr beyond one dim line.
4. **Opt-out must be trivial**: `--no-update-check`, `SUBPY_NO_UPDATE=1`, and it should default off in CI.
5. If you ever *do* implement `subpy upgrade`, require an explicit user command, verify SHA-256 from a **separately fetched** checksum file (same host = weak, but better than nothing), and print the diff of what will change before writing.

### 3.3 Semver comparison: `packaging.version` vs manual ✅

`packaging` is a dependency (and on 3.9 you cannot assume it is present in the app env — it is vendored *inside* pip, not importable as `packaging`). **Zero-dep choice: a small strict comparator.**

**The naive approach is wrong.** ✅ Verified trap:

```pycon
>>> tuple(re.findall(r"\d+", "1.0.0rc1")[:3])   # (1, 0, 0)
>>> tuple(re.findall(r"\d+", "1.0.0")[:3])      # (1, 0, 0)
tuple(re.findall(r"\d+", "1.0.0")[:3])     -> (1, 0, 0)
# both equal => 1.0.0rc1 == 1.0.0  (WRONG: a release candidate sorts BEFORE the release)
```

Correct zero-dep implementation (`subpy/_version.py`):

```python
"""subpy/_version.py — strict, dependency-free PEP 440-ish comparison."""
from __future__ import annotations

import re

_VERSION_RE = re.compile(
    r"""
    ^v?
    (?P<major>\d+)
    \.(?P<minor>\d+)
    (?:\.(?P<patch>\d+))?
    (?:[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>\d*))?
    (?:-(?P<post_n1>\d+))?
    (?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d*))?
    (?:\+(?P<local>[a-z0-9.]+))?
    $
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Lower rank = sorts earlier. "pre" releases sort before the final release.
_PRE_RANK = {"a": 0, "alpha": 0, "b": 1, "beta": 1,
             "c": 2, "rc": 2, "pre": 2, "preview": 2}


def parse_version(text):
    """Return a sortable tuple. Raises ValueError on anything unparseable."""
    if not isinstance(text, str):
        raise ValueError("version must be a string")
    match = _VERSION_RE.match(text.strip())
    if not match:
        raise ValueError(f"invalid version: {text!r}")
    pre_label = (match.group("pre_l") or "").lower()
    if pre_label:
        # (0, rank, n) sorts BELOW (1, 0, 0) => prerelease < release
        pre = (0, _PRE_RANK[pre_label], int(match.group("pre_n") or 0))
    else:
        pre = (1, 0, 0)
    post = int(match.group("post_n1") or match.group("post_n2") or 0)
    return (int(match.group("major")),
            int(match.group("minor")),
            int(match.group("patch") or 0),
            pre,
            post)


def is_newer(candidate, current) -> bool:
    """True only if candidate is strictly newer. Fail-closed on garbage."""
    try:
        return parse_version(candidate) > parse_version(current)
    except ValueError:
        return False
```

✅ **Tested: 12/12 unit cases pass**, including the traps:

```text
OK  is_newer('1.2.3','1.2.2') = True          OK  is_newer('1.0.0rc1','1.0.0') = False
OK  is_newer('v1.2.3','1.2.3') = False        OK  is_newer('1.0.0','1.0.0rc1') = True
OK  is_newer('1.10.0','1.9.9') = True         OK  is_newer('1.0.0.post1','1.0.0') = True
OK  is_newer('2.0.0','1.99.99') = True        OK  is_newer('1.2','1.2.0') = False
OK  is_newer('garbage','1.0.0') = False       OK  is_newer('1.0.0','garbage') = False
```

✅ **Differential-tested against `packaging.version.Version`**: 169 comparison pairs over all-parseable versions → **2 mismatches**, both involving local versions (`1.2.3+build5 > 1.2.3` in PEP 440; we ignore local segments). Also, exotic-but-legal `0.a.1` is rejected by our regex → fails closed (`False`) rather than mis-ordering. **This is the documented divergence:** we ignore `+local` and reject unusual forms; for a "is there a newer release?" check that is the safe direction. If you need exactness, import `packaging` *optionally* and prefer it.

### 3.4 Update check: cache, TTL, timeout, opt-out

Cache location (cross-platform, zero-dep, ✅ logic verified → `/root/.config/subpy` on this host):

| OS | Path |
|---|---|
| Linux / macOS / **Termux** | `$XDG_CONFIG_HOME/subpy/` → `~/.config/subpy/` |
| Windows | `%APPDATA%\subpy\` |
| Override | `SUBPY_CACHE_DIR` |

Termux needs **no** `$PREFIX/etc` special case: `~/.config` is writable and persistent, and `$PREFIX` is package-managed (writing there breaks on upgrade). ✅

```python
"""subpy/_update.py"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

from . import __version__
from ._version import is_newer

API_URL = os.environ.get(
    "SUBPY_UPDATE_URL",
    "https://api.github.com/repos/0xShahriar/subpy/releases/latest",
)
CHECK_INTERVAL = 24 * 60 * 60      # 24h
REQUEST_TIMEOUT = 2.0              # seconds: short; never block a scan
STATE_FILE = "update-check.json"


def cache_dir() -> str:
    override = os.environ.get("SUBPY_CACHE_DIR")
    if override:
        return override
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Roaming")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
            os.path.expanduser("~"), ".config")
    return os.path.join(base, "subpy")


def _state_path() -> str:
    return os.path.join(cache_dir(), STATE_FILE)


def _read_state() -> dict:
    try:
        with open(_state_path(), encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_state(state: dict) -> None:
    path = _state_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(state, handle)
        os.replace(tmp, path)          # atomic; no torn file if killed
    except OSError:
        pass                           # cache is best-effort


def disabled(args=None) -> bool:
    if os.environ.get("SUBPY_NO_UPDATE"):
        return True
    if os.environ.get("CI"):           # never nag in CI logs
        return True
    return bool(getattr(args, "no_update_check", False))


def check_for_update(args=None, *, force=False, stream=None) -> str | None:
    """Return the newer version string, or None. Never raises, never blocks long."""
    if disabled(args):
        return None
    stream = stream or sys.stderr

    state = _read_state()
    now = time.time()
    cached = state.get("latest")
    checked_at = float(state.get("checked_at") or 0)

    if not force and cached and (now - checked_at) < CHECK_INTERVAL:
        return cached if is_newer(cached, __version__) else None

    payload = _fetch_latest()
    if payload is None:
        return None                    # offline / rate-limited: stay silent

    state.update({"checked_at": now, "latest": payload, "etag": _LAST_ETAG[0]})
    _write_state(state)
    if is_newer(payload, __version__):
        _notify(payload, stream)
        return payload
    return None


_LAST_ETAG = [None]


def _fetch_latest():
    headers = {
        "User-Agent": f"subpy/{__version__}",      # MANDATORY: 403 without it
        "Accept": "application/vnd.github+json",
    }
    etag = _read_state().get("etag")
    if etag:
        headers["If-None-Match"] = etag
    request = urllib.request.Request(API_URL, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            _LAST_ETAG[0] = response.headers.get("ETag")
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 304:            # not modified: keep cached value
            return _read_state().get("latest")
        return None                    # 403 rate limit / 404 / 5xx
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None                    # offline, DNS failure, bad JSON
    if not isinstance(data, dict) or data.get("draft") or data.get("prerelease"):
        return None
    tag = data.get("tag_name")
    return tag if isinstance(tag, str) else None


def _notify(version, stream):
    try:
        stream.write(
            f"subpy: {version} is available (you have {__version__}). "
            f"Upgrade with: pipx upgrade subpy\n"
        )
        stream.flush()
    except (OSError, ValueError):
        pass
```

**Rate-limit hygiene**
- 24 h TTL ⇒ ≤1 request/day/user — 2.5 % of the 60/hr budget.
- ✅ **Measured:** conditional requests with `If-None-Match` return **304** and — importantly — **still count against the quota** on unauthenticated calls. Measured remaining counter across four calls: `56 → 55 → 54 (304s) → 53 (200)`. So `ETag` saves **bandwidth**, not quota. Do not rely on it to stay under the limit; rely on the TTL.
- Honour `Retry-After` and `X-RateLimit-Reset` on 403: if `X-RateLimit-Remaining == "0"`, **stop checking until `reset`** — write that timestamp into the cache and skip. ⚠️ Recommended hardening (not implemented above for brevity); without it a NATed user base can hammer a spent quota all day.
- Never check on every run; never check in `--silent`/`--json` mode (it would pollute machine-readable stderr); never check when stdout is a pipe.

**Where to surface it:** one dim line on **stderr** after results, suppressed by `-s`, `--json`, `CI`, `NO_COLOR`-less environments is *not* required — a plain dim line is fine. Example:

```text
subpy: v0.4.0 is available (you have 0.3.1). Upgrade with: pipx upgrade subpy
```

---

## 4. GitHub repo hygiene

### 4.0 First finding: the repo does not exist ✅

`https://api.github.com/repos/0xShahriar/subpy` returns:

```json
{"message":"Not Found","documentation_url":"https://docs.github.com/rest/repos/repos#get-a-repository"}
```

Same for `/releases/latest` and `/releases`. So `pip install git+https://github.com/0xShahriar/subpy` **currently fails** for everyone — it is either private, not yet created, or renamed. **Decide the canonical owner/repo before publishing install docs**, and make sure the clone URL in README matches. (This is also why `SUBPY_UPDATE_URL` is overridable: forks inherit a working updater.)

### 4.1 File set

```text
README.md                        LICENSE (MIT)
CONTRIBUTING.md                  CODE_OF_CONDUCT.md
SECURITY.md                      CHANGELOG.md
SOURCES.md                       pyproject.toml
.gitignore                       .editorconfig
.gitattributes                   .pre-commit-config.yaml (optional)
.github/
├── ISSUE_TEMPLATE/
│   ├── bug_report.yml           # form
│   ├── feature_request.yml      # form
│   └── config.yml               # chooser
├── PULL_REQUEST_TEMPLATE.md
├── dependabot.yml
└── workflows/
    ├── ci.yml
    └── release.yml
src/subpy/...
tests/...
```

### 4.2 Issue forms — exact valid schema 🔎

Verified against the **GitHub Docs form schema** ([syntax-for-githubs-form-schema](https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/syntax-for-githubs-form-schema) and [syntax-for-issue-forms](https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/syntax-for-issue-forms)).

**Top-level keys** — `name`, `description`, `body` are **required**; `assignees`, `labels`, `title`, `type`, `projects` are optional. Types: `name`/`description`/`title`/`type` = String, `body` = Array, `assignees`/`labels`/`projects` = Array or comma-delimited String.

**Element `type`** must be one of exactly: `markdown`, `textarea`, `input`, `dropdown`, `checkboxes`, `upload`.

**Per-type attributes / validations**

| type | `attributes` keys | `validations` keys |
|---|---|---|
| `markdown` | `value` | *(none)* |
| `textarea` | `label`, `description`, `placeholder`, `value`, `render` | `required` (bool), `min_length` (int) |
| `input` | `label`, `description`, `placeholder`, `value` | `required`, `min_length` |
| `dropdown` | `label`, `description`, `options` (**required**), `multiple` (bool), `default` (int index) | `required` |
| `checkboxes` | `label`, `description`, `options` (list of `{label, required}`) | *(none)* |
| `upload` | `label`, `description` | `required` |

Gotchas that silently break forms:
- `id` is allowed on every element **except** `markdown`; alpha-numeric, `-`, `_` only; must be unique.
- `validations.required: true` only has effect **in public repos**.
- `labels` that do not exist in the repo are **not** auto-created — a typo just yields an unlabeled issue.
- `body` must be a YAML **array** of mappings; a top-level mapping is a classic "Invalid issue template" error.
- YAML treats `#` as a comment → quote any `value:`/`description:` string containing `#`, or you lose the rest of the line.

#### `.github/ISSUE_TEMPLATE/bug_report.yml` ✅ YAML-validated

```yaml
name: Bug report
description: Report a reproducible problem with subpy.
title: "[bug]: "
labels: ["bug", "needs-triage"]
body:
  - type: markdown
    attributes:
      value: |
        Thanks for taking the time to file a report.
        Please search existing issues first, and **never paste real customer
        hostnames** — redact targets as `example.com`.

  - type: checkboxes
    id: preflight
    attributes:
      label: Preflight checks
      description: Confirm the following before submitting.
      options:
        - label: I searched existing issues and found no duplicate.
          required: true
        - label: I am on the latest subpy version (`subpy --version`).
          required: true
        - label: I have redacted any sensitive hostnames from this report.
          required: true

  - type: input
    id: version
    attributes:
      label: subpy version
      description: Output of `subpy --version`.
      placeholder: "subpy 0.3.1"
    validations:
      required: true

  - type: input
    id: python
    attributes:
      label: Python version
      description: Output of `python -V`.
      placeholder: "Python 3.11.9"
    validations:
      required: true

  - type: dropdown
    id: os
    attributes:
      label: Operating system
      description: Where does the problem occur?
      options:
        - Linux (glibc)
        - Linux (musl / Alpine)
        - macOS (Intel)
        - macOS (Apple Silicon)
        - Windows 10
        - Windows 11
        - Termux (Android, aarch64)
        - Other
      default: 0
    validations:
      required: true

  - type: dropdown
    id: install
    attributes:
      label: How did you install subpy?
      options:
        - pipx install subpy
        - pip install subpy
        - pip install git+https://github.com/…
        - standalone zipapp
        - from source (`pip install .`)
        - other
    validations:
      required: true

  - type: textarea
    id: what-happened
    attributes:
      label: What happened?
      description: A clear and concise description of the actual behaviour.
      placeholder: Tell us what you saw.
    validations:
      required: true

  - type: textarea
    id: expected
    attributes:
      label: Expected behaviour
      description: What did you expect instead?
    validations:
      required: true

  - type: textarea
    id: reproduce
    attributes:
      label: Steps to reproduce
      description: The exact command line you ran.
      value: |
        1. Run: `subpy example.com -t 50`
        2.
        3.
      render: shell
    validations:
      required: true

  - type: textarea
    id: logs
    attributes:
      label: Relevant output
      description: Re-run with `-v` and paste the output. It is formatted as code.
      render: shell

  - type: textarea
    id: extra
    attributes:
      label: Anything else?
      description: |
        Links, screenshots, or context. Drag images into this area to attach them.
    validations:
      required: false
```

#### `.github/ISSUE_TEMPLATE/feature_request.yml` ✅ YAML-validated

```yaml
name: Feature request
description: Suggest an idea or improvement for subpy.
title: "[feat]: "
labels: ["enhancement"]
body:
  - type: markdown
    attributes:
      value: |
        Thanks for helping improve subpy. Please describe the **problem**, not
        only the solution.

  - type: checkboxes
    id: preflight
    attributes:
      label: Preflight checks
      options:
        - label: I searched existing issues and discussions for this idea.
          required: true
        - label: This request is about subpy itself, not about a third-party wordlist.
          required: true

  - type: textarea
    id: problem
    attributes:
      label: Problem
      description: What problem are you trying to solve?
      placeholder: "I'm always frustrated when…"
    validations:
      required: true

  - type: textarea
    id: solution
    attributes:
      label: Proposed solution
      description: What would you like subpy to do?
    validations:
      required: true

  - type: textarea
    id: alternatives
    attributes:
      label: Alternatives considered
      description: Other approaches or tools you have tried.

  - type: dropdown
    id: scope
    attributes:
      label: Area
      description: Which part of subpy does this touch?
      options:
        - CLI / UX
        - DNS engine / performance
        - Wordlists
        - Output formats
        - Packaging / install
        - Documentation
        - Other
      default: 0
    validations:
      required: true

  - type: checkboxes
    id: contribution
    attributes:
      label: Contribution
      description: Would you be willing to help implement this?
      options:
        - label: I am willing to open a pull request for this.
        - label: I can help test a proposed implementation.

  - type: textarea
    id: extra
    attributes:
      label: Additional context
      description: Mockups, references, or examples from other tools.
    validations:
      required: false
```

#### `.github/ISSUE_TEMPLATE/config.yml` ✅ YAML-validated

```yaml
blank_issues_enabled: false
contact_links:
  - name: Security vulnerability
    url: https://github.com/0xShahriar/subpy/security/advisories/new
    about: Please report security issues privately, never as a public issue.
  - name: Usage questions & discussion
    url: https://github.com/0xShahriar/subpy/discussions
    about: Ask questions and share wordlists or workflows here.
```

### 4.3 CI: test matrix + lint ✅ YAML-validated

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

permissions:
  contents: read

jobs:
  test:
    name: ${{ matrix.os }} / py${{ matrix.python-version }}
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        python-version: ["3.9", "3.10", "3.11", "3.12", "3.13"]
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
          cache: pip
      - name: Install
        run: |
          python -m pip install --upgrade pip
          python -m pip install -e ".[dev]"
      - name: Run tests
        run: python -m pytest -ra
      - name: Smoke test the console script
        run: subpy --version

  lint:
    name: lint
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
          cache: pip
      - run: python -m pip install --upgrade pip ruff
      - name: Ruff lint
        run: ruff check .
      - name: Ruff format check
        run: ruff format --check .

  build:
    name: build wheel + sdist
    runs-on: ubuntu-latest
    needs: [test, lint]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - run: python -m pip install --upgrade pip build twine
      - run: python -m build
      - run: python -m twine check dist/*
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/
```

Notes: `fail-fast: false` so one platform failure does not hide others; `cache: pip` speeds re-runs; the `subpy --version` smoke test catches broken `entry_points` on Windows (the most common packaging regression); `permissions: contents: read` is least-privilege.

### 4.4 Release workflow ✅ YAML-validated

```yaml
name: Release

on:
  push:
    tags: ["v*.*.*"]
  workflow_dispatch:

permissions:
  contents: write

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - name: Verify tag matches package version
        shell: bash
        run: |
          tag="${GITHUB_REF_NAME#v}"
          ver=$(python -c "import re,pathlib;print(re.search(r'^version = \"([^\"]+)\"', pathlib.Path('pyproject.toml').read_text(), re.M).group(1))")
          echo "tag=$tag version=$ver"
          test "$tag" = "$ver" || { echo "::error::tag $tag does not match version $ver"; exit 1; }
      - name: Build
        run: |
          python -m pip install --upgrade pip build twine
          python -m build
          python -m twine check dist/*
      - name: Generate checksums
        run: |
          cd dist && sha256sum * > SHA256SUMS && cat SHA256SUMS
      - name: Build standalone zipapp
        run: python -m zipapp src -o dist/subpy.pyz -p "/usr/bin/env python3" -m "subpy.cli:main"
      - name: Publish GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          generate_release_notes: true
          files: |
            dist/*
      - name: Publish to PyPI (trusted publishing)
        if: ${{ vars.PUBLISH_TO_PYPI == 'true' }}
        uses: pypa/gh-action-pypi-publish@release/v1
```

Prefer **PyPI Trusted Publishing** (OIDC) over a stored API token — add `environment: release` + `id-token: write` permission when you enable it:

```yaml
    permissions:
      contents: write
      id-token: write          # required for trusted publishing
    environment: release
```

The tag-vs-version guard prevents the classic "released v0.4.0 but the wheel says 0.3.1" bug, which would also break the updater in §3.

### 4.5 `LICENSE` (MIT) ✅

```text
MIT License

Copyright (c) 2026 0xShahriar

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

⚠️ Replace `2026` with the current year and `0xShahriar` with the legal name you want to enforce. GitHub's licence detector matches this text verbatim.

### 4.6 `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1, verbatim ✅

Retrieved live from `https://www.contributor-covenant.org/version/2/1/code_of_conduct/code_of_conduct.md` (HTTP 200, 5 480 bytes) and reproduced in full below. Only the `[INSERT CONTACT METHOD]` placeholder is filled in — the CC FAQ explicitly instructs projects to replace it.

```markdown
# Contributor Covenant Code of Conduct

## Our Pledge

We as members, contributors, and leaders pledge to make participation in our community a harassment-free experience for everyone, regardless of age, body size, visible or invisible disability, ethnicity, sex characteristics, gender identity and expression, level of experience, education, socio-economic status, nationality, personal appearance, race, caste, color, religion, or sexual identity and orientation.

We pledge to act and interact in ways that contribute to an open, welcoming, diverse, inclusive, and healthy community.

## Our Standards

Examples of behavior that contributes to a positive environment for our community include:

* Demonstrating empathy and kindness toward other people
* Being respectful of differing opinions, viewpoints, and experiences
* Giving and gracefully accepting constructive feedback
* Accepting responsibility and apologizing to those affected by our mistakes, and learning from the experience
* Focusing on what is best not just for us as individuals, but for the overall community

Examples of unacceptable behavior include:

* The use of sexualized language or imagery, and sexual attention or advances of any kind
* Trolling, insulting or derogatory comments, and personal or political attacks
* Public or private harassment
* Publishing others' private information, such as a physical or email address, without their explicit permission
* Other conduct which could reasonably be considered inappropriate in a professional setting

## Enforcement Responsibilities

Community leaders are responsible for clarifying and enforcing our standards of acceptable behavior and will take appropriate and fair corrective action in response to any behavior that they deem inappropriate, threatening, offensive, or harmful.

Community leaders have the right and responsibility to remove, edit, or reject comments, commits, code, wiki edits, issues, and other contributions that are not aligned to this Code of Conduct, and will communicate reasons for moderation decisions when appropriate.

## Scope

This Code of Conduct applies within all community spaces, and also applies when an individual is officially representing the community in public spaces. Examples of representing our community include using an official e-mail address, posting via an official social media account, or acting as an appointed representative at an online or offline event.

## Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported to the community leaders responsible for enforcement at security@example.com (or open a private security advisory). All complaints will be reviewed and investigated promptly and fairly.

All community leaders are obligated to respect the privacy and security of the reporter of any incident.

## Enforcement Guidelines

Community leaders will follow these Community Impact Guidelines in determining the consequences for any action they deem in violation of this Code of Conduct:

### 1. Correction

**Community Impact**: Use of inappropriate language or other behavior deemed unprofessional or unwelcome in the community.

**Consequence**: A private, written warning from community leaders, providing clarity around the nature of the violation and an explanation of why the behavior was inappropriate. A public apology may be requested.

### 2. Warning

**Community Impact**: A violation through a single incident or series of actions.

**Consequence**: A warning with consequences for continued behavior. No interaction with the people involved, including unsolicited interaction with those enforcing the Code of Conduct, for a specified period of time. This includes avoiding interactions in community spaces as well as external channels like social media. Violating these terms may lead to a temporary or permanent ban.

### 3. Temporary Ban

**Community Impact**: A serious violation of community standards, including sustained inappropriate behavior.

**Consequence**: A temporary ban from any sort of interaction or public communication with the community for a specified period of time. No public or private interaction with the people involved, including unsolicited interaction with those enforcing the Code of Conduct, is allowed during this period. Violating these terms may lead to a permanent ban.

### 4. Permanent Ban

**Community Impact**: Demonstrating a pattern of violation of community standards, including sustained inappropriate behavior, harassment of an individual, or aggression toward or disparagement of classes of individuals.

**Consequence**: A permanent ban from any sort of public interaction within the community.

## Attribution

This Code of Conduct is adapted from the [Contributor Covenant][homepage], version 2.1, available at [https://www.contributor-covenant.org/version/2/1/code_of_conduct.html][v2.1].

Community Impact Guidelines were inspired by [Mozilla's code of conduct enforcement ladder][Mozilla CoC].

For answers to common questions about this code of conduct, see the FAQ at [https://www.contributor-covenant.org/faq][FAQ]. Translations are available at [https://www.contributor-covenant.org/translations][translations].

[homepage]: https://www.contributor-covenant.org
[v2.1]: https://www.contributor-covenant.org/version/2/1/code_of_conduct.html
[Mozilla CoC]: https://github.com/mozilla/diversity
[FAQ]: https://www.contributor-covenant.org/faq
[translations]: https://www.contributor-covenant.org/translations
```

### 4.7 `SECURITY.md` ✅

```markdown
# Security Policy

## Supported versions

`subpy` is pre-1.0: only the latest release receives security fixes.

| Version | Supported |
| ------- | --------- |
| latest  | ✅        |
| older   | ❌        |

## Reporting a vulnerability

**Do not open a public issue.**

Use GitHub's [private vulnerability reporting](https://github.com/0xShahriar/subpy/security/advisories/new)
or email **security@example.com**. Include:

- affected version (`subpy --version`) and platform;
- a minimal reproduction (command line, wordlist size, resolver setup);
- impact assessment and any suggested fix.

We aim to acknowledge within **72 hours** and to ship a fix or mitigation within
**30 days** for confirmed issues. We will credit reporters in the release notes
unless you ask us not to.

## Scope

In scope: the `subpy` codebase, its packaging, and its release artifacts
(including published checksums).

Out of scope: third-party wordlists, resolver services you point it at, and
DNS records of domains you do not own.

## Safe-use note

`subpy` performs DNS lookups. Only enumerate domains you are authorised to test.
`--passive` mode avoids sending traffic to the target and is the safer default in
shared or production environments.
```

### 4.8 `CONTRIBUTING.md` ✅

````markdown
# Contributing to subpy

Thanks for your interest. This project is deliberately **zero-dependency** —
please respect that constraint.

## Ground rules

- **No new runtime dependencies.** Speed-ups go behind an optional extra with a
  stdlib fallback (see `pyproject.toml` → `[project.optional-dependencies]`).
- **Python 3.9 is the floor.** No `match`, no `X | Y` in runtime annotations
  without `from __future__ import annotations`, no `tomllib`.
- Every behaviour change needs a test. CI runs on Linux, macOS and Windows
  across 3.9–3.13.

## Setup

```bash
git clone https://github.com/0xShahriar/subpy
cd subpy
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Before you open a PR

```bash
ruff check .        # lint
ruff format .       # format
pytest -ra          # tests
python -m build     # must produce a clean wheel + sdist
```

## Commit messages

Conventional Commits: `feat:`, `fix:`, `docs:`, `refactor:`, `perf:`, `test:`,
`chore:`. Example: `fix(cli): honour NO_COLOR when it is non-empty`.

## Pull requests

- One logical change per PR; keep diffs reviewable.
- Update `CHANGELOG.md` under `## [Unreleased]`.
- Describe the user-visible effect, not just the diff.

## Legal

By contributing you agree your contributions are licensed under the MIT License
(see `LICENSE`).
````

### 4.9 `CHANGELOG.md` — Keep a Changelog 1.1.0 + SemVer 2.0.0 ✅

Format verified against [keepachangelog.com/en/1.1.0](https://keepachangelog.com/en/1.1.0/) (HTTP 200); the header wording below matches the canonical example.

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial `subpy` CLI: active DNS enumeration with `-w`, `-t`, `-o`, `-f`.

### Changed

### Deprecated

### Removed

### Fixed

### Security

## [0.1.0] - 2026-11-02

### Added

- Zero-dependency core with optional `[speed]` / `[full]` extras.
- Wildcard DNS detection (`--wildcard detect|skip|allow`).
- Passive mode via certificate transparency logs (`--passive`).
- Formats: `text`, `json`, `jsonl`, `csv`; `--json` shorthand.
- `NO_COLOR` / `FORCE_COLOR` / `--no-color` handling; `--ascii` fallback.
- Graceful Ctrl-C: flushes `-o`, prints a summary, exits `130`.
- Opt-out cached update check (`--no-update-check`, `SUBPY_NO_UPDATE`).

[Unreleased]: https://github.com/0xShahriar/subpy/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/0xShahriar/subpy/releases/tag/v0.1.0
```

The six headings (`Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`) are the KaC 1.1.0 set; link definitions at the bottom are what make the compare links render.

### 4.10 `SOURCES.md` ✅

Documents provenance and licensing of non-code assets — required if you ship a wordlist.

```markdown
# Sources & Attribution

## Bundled wordlists

| File | Source | Licence | Notes |
| ---- | ------ | ------- | ----- |
| `subpy/data/top-1000.txt` | Original, generated by this project from public suffix/DNS statistics | MIT | Generated, not copied |
| `subpy/data/common-prefixes.txt` | Original | MIT | Hand-curated |

If you add a wordlist, record its origin, licence, and retrieval date here. Do not
bundle lists whose licence you have not verified.

## Behavioural references

- Wildcard DNS detection approach: adapted from the well-known
  "random subdomain baseline" technique. Implementation is original.

## Third-party runtime code

None. `subpy` has **zero runtime dependencies**; optional extras are declared in
`pyproject.toml` and remain the user's choice.

## Development tooling

`pytest`, `ruff`, `build`, `twine` — used in development/CI only, not shipped.
```

### 4.11 `.gitignore`, `.editorconfig`, `.gitattributes` ✅

`.gitignore` (Python + tooling):

```gitignore
# Byte-compiled / cache
__pycache__/
*.py[cod]
*$py.class
*.so

# Distribution / packaging
build/
dist/
*.egg-info/
*.egg
.eggs/
wheels/
sdist/

# Virtual environments
.venv/
venv/
env/
ENV/

# Test / coverage
.pytest_cache/
.coverage
.coverage.*
htmlcov/
coverage.xml
.tox/
.nox/

# Type checkers / linters
.mypy_cache/
.ruff_cache/
.dmypy.json

# Build artifacts
*.pyz
SHA256SUMS

# Editors / OS
.vscode/
.idea/
*.swp
.DS_Store
Thumbs.db

# Local runs
subs.txt
*.log
```

`.editorconfig`:

```ini
root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
indent_style = space
indent_size = 4

[*.{yml,yaml,json,toml}]
indent_size = 2

[*.md]
trim_trailing_whitespace = false

[Makefile]
indent_style = tab
```

`.gitattributes` (normalizes line endings — critical for the Windows CI leg):

```gitattributes
* text=auto eol=lf

*.py    text eol=lf diff=python
*.md    text eol=lf
*.toml  text eol=lf
*.yml   text eol=lf
*.yaml  text eol=lf

*.bat   text eol=crlf
*.ps1   text eol=crlf

*.png   binary
*.jpg   binary
*.zip   binary
*.whl   binary
*.gz    binary

# Keep these out of `git archive` / release tarballs
.github/       export-ignore
tests/         export-ignore
.editorconfig  export-ignore
.gitattributes export-ignore
```

### 4.12 PR template & Dependabot ✅

`.github/PULL_REQUEST_TEMPLATE.md`:

````markdown
## What does this PR do?

<!-- One paragraph. Link the issue: Closes #123 -->

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change
- [ ] Documentation only
- [ ] Refactor / performance

## Checklist

- [ ] No new runtime dependencies (or: behind an optional extra with stdlib fallback)
- [ ] Compatible with Python 3.9
- [ ] Tests added/updated and `pytest -ra` passes
- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `CHANGELOG.md` updated under `## [Unreleased]`
- [ ] Works on Linux, macOS, Windows (and Termux if CLI-affecting)

## Verification

```console
$ subpy example.com -w tests/data/small.txt -t 20
# paste output
```
````

`.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "monthly"
    open-pull-requests-limit: 5
    groups:
      dev-dependencies:
        patterns: ["*"]
        dependency-type: "development"
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "monthly"
```

---

## 5. Recommended project tree

```text
subpy/
├── pyproject.toml
├── README.md
├── LICENSE
├── CHANGELOG.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── SECURITY.md
├── SOURCES.md
├── .gitignore
├── .gitattributes
├── .editorconfig
├── .github/
│   ├── ISSUE_TEMPLATE/{bug_report.yml,feature_request.yml,config.yml}
│   ├── PULL_REQUEST_TEMPLATE.md
│   ├── dependabot.yml
│   └── workflows/{ci.yml,release.yml}
├── src/subpy/
│   ├── __init__.py          # __version__ = "0.1.0"
│   ├── __main__.py          # python -m subpy
│   ├── cli.py               # argparse surface, main()
│   ├── engine.py            # async scan loop, wildcard detection
│   ├── resolvers.py         # -r parsing, system resolver discovery
│   ├── output.py            # text/json/jsonl/csv writers
│   ├── _accel.py            # optional uvloop/aiodns/dnspython
│   ├── _color.py            # NO_COLOR / FORCE_COLOR / Windows VT
│   ├── _term.py             # width, display width, truncate/pad
│   ├── _progress.py         # TTY-only spinner
│   ├── _signals.py          # graceful Ctrl-C
│   ├── _version.py          # zero-dep semver compare
│   ├── _update.py           # cached update check
│   └── data/top-1000.txt    # bundled wordlist
└── tests/{test_cli.py,test_version.py,test_term.py,test_output.py}
```

Keep every private module underscore-prefixed so the public surface stays `subpy.cli:main`, and bundling data under `src/subpy/data/` ships automatically with hatchling (no `package_data` incantation needed).

---

## 6. Verified-facts appendix

Everything below was **executed on this host** (Linux aarch64, Python 3.14.4, 2026-11-02) unless marked 🔎.

| # | Claim | Result |
|---|---|---|
| 1 | hatchling builds `src/` layout with zero config | ✅ sdist + wheel produced |
| 2 | `[console_scripts]` creates a working `subpy` binary | ✅ `/venv/bin/subpy` ran, exit 0 |
| 3 | The full `pyproject.toml` in §1.2 builds | ✅ `Metadata-Version: 2.5`, `License-Expression: MIT` |
| 4 | PEP 639 `license = "MIT"` + `license-files` | ✅ emitted `License-Expression` + `dist-info/licenses/LICENSE` |
| 5 | uvloop PEP 508 marker excludes Windows/PyPy | ✅ `win32→False`, `linux+CPython→True`, `linux+PyPy→False` |
| 6 | uvloop has no Windows classifiers | ✅ PyPI JSON: only MacOS X + POSIX |
| 7 | `[full]` extra pulls 14 dists incl. compiled | ✅ `pycares`, `cffi`, `uvloop` |
| 8 | `pip install .` works from source tree | ✅ exit 0, command runs |
| 9 | `pip install git+https://…` works | ✅ requests v2.31.0 installed + imported |
| 10 | setuptools flat-layout auto-discovery works | ✅ wheel with `top_level.txt` |
| 11 | `python -m zipapp` produces runnable `.pyz` | ✅ 649 B, ran via `python3` and `./` |
| 12 | `shutil.get_terminal_size` never fails w/ fallback | ✅ returns 40/80/120 as given |
| 13 | CJK width ≠ `len()` | ✅ 8 chars → 16 cells |
| 14 | `"┌─┐".encode("ascii")` raises | ✅ UnicodeEncodeError; cp437 OK |
| 15 | `NO_COLOR=""` must NOT disable color | ✅ falsy → color kept |
| 16 | `NO_COLOR`/`FORCE_COLOR`/TTY precedence | ✅ 8-case table in §2.4 |
| 17 | argparse usage errors exit **2** | ✅ missing arg and bad choice |
| 18 | `--version` exits **0** | ✅ `subpy 0.1.0` |
| 19 | custom SIGINT handler → exit **130** | ✅ with flushed stderr summary |
| 20 | uncaught `KeyboardInterrupt` → exit **0** on 3.14 | ✅ **do not rely on it** |
| 21 | default SIGTERM → exit **143** | ✅ |
| 22 | `sys.exit(n)` propagates 0/1/2/130 | ✅ |
| 23 | GitHub API without `User-Agent` → **403** | ✅ |
| 24 | rate limit 60/hr with `X-RateLimit-*` headers | ✅ limit=60, remaining/reset present |
| 25 | `releases/latest` fields `tag_name`/`html_url`/`published_at` | ✅ |
| 26 | `If-None-Match` → **304** but **still decrements** quota | ✅ `56→55→54→53` |
| 27 | naive `tuple(\d+)` says `1.0.0rc1 == 1.0.0` | ✅ the trap is real |
| 28 | zero-dep comparator 12/12 unit cases | ✅ |
| 29 | comparator vs `packaging`: 2/169 mismatch (local versions) | ✅ documented |
| 30 | update check works live, cache hit in 4 ms | ✅ `v2.103.3` |
| 31 | offline/unwritable-cache checks fail silently | ✅ `None`, 0.29 s |
| 32 | `SUBPY_NO_UPDATE`, `CI`, `--no-update-check` opt-outs | ✅ all honoured |
| 33 | accel module: stdlib → dnspython → aiodns → uvloop | ✅ all four backends resolved `example.com` |
| 34 | issue forms conform to documented schema | ✅ 2 forms, 0 errors (automated check) |
| 35 | all 6 YAML blocks parse | ✅ 6/6 |
| 36 | `0xShahriar/subpy` repo/releases API | ✅ **404 — repo missing/private** |
| 37 | Contributor Covenant 2.1 fetched verbatim | ✅ 5 480 B, HTTP 200 |

🔎 **Documented, not executed here:** Windows `ctypes` VT enablement, Windows `SIGTERM` = `TerminateProcess`, Termux `pip`/`pkg` prefix behaviour, macOS behavior, GitHub Actions execution. ⚠️ **Judgement:** all performance numbers, termux memory-killer notes.

---

## 7. Quick verification commands

```bash
# Build + inspect
python -m build
python -m twine check dist/*
python -c "import zipfile,glob;print(zipfile.ZipFile(glob.glob('dist/*.whl')[0]).namelist())"

# Install paths
pipx install .                                   # isolated CLI
pip install ".[dev]" && subpy --version
pip install --force-reinstall dist/*.whl

# Cross-check the version comparator against packaging
python - <<'PY'
from packaging.version import Version
from subpy._version import is_newer
vs = ["1.0.0","1.0.0rc1","1.0.0.post1","1.2.3","v1.2.3","1.10.0"]
for a in vs:
    for b in vs:
        assert is_newer(a,b) == (Version(a) > Version(b)), (a,b)
print("comparator matches packaging on core cases")
PY

# Update-check smoke test without touching the real repo
SUBPY_UPDATE_URL=https://api.github.com/repos/cli/cli/releases/latest \
SUBPY_CACHE_DIR=/tmp/subpy-cache python -c \
  "from subpy._update import check_for_update; print(check_for_update(force=True))"

# Validate issue forms before pushing
python -c "import yaml,sys;[yaml.safe_load(open(f)) for f in sys.argv[1:]];print('yaml ok')" \
  .github/ISSUE_TEMPLATE/*.yml
```

---

## 8. Non-negotiables

1. `dependencies = []`. Speed is an extra with a stdlib fallback — verified: `[full]` pulls 14 packages including compiled ones.
2. `requires-python = ">=3.9"` in `[project]`; never use `match`/`tomllib`/runtime `X | Y` unions.
3. `src/` layout, hatchling backend.
4. Results → stdout, chrome → stderr; exit 0 on "found nothing", 2 on usage, 1 on runtime error, 130 on Ctrl-C.
5. `NO_COLOR` non-empty semantics exactly per spec; spinner only when `isatty()`.
6. Update check is **check-only**, opt-out, 24 h TTL, 2 s timeout, silent failure, never auto-executes.
7. `User-Agent` header is mandatory on every GitHub API call.
8. Never ship `curl | python`. Ship wheel + zipapp + pipx.
