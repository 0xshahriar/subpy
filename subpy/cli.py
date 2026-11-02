"""The ``subpy`` command line interface.

Built on :mod:`argparse` (stdlib, no click) but tuned for real use:

* A terse default view: no banner, no legend, results first.
* Grouped help with examples, because ``--help`` is the real documentation.
* Exit codes that scripts can branch on: 0 found, 1 nothing found, 2 usage
  error, 130 interrupted.
* SIGINT flushes what has been found so far instead of discarding it — the
  single most common frustration with long scans.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import signal
import sys
from collections.abc import Sequence

from . import __version__
from .core.models import Host
from .core.scanner import ScanConfig, Scanner
from .core.wordlists import resolve_wordlist_path
from .output.console import Reporter
from .output.writers import FORMATS, write_output

__all__ = ["main", "build_parser"]

PROG = "subpy"

EXIT_OK = 0
EXIT_RUNTIME = 1
EXIT_USAGE = 2
EXIT_INTERRUPT = 130
EXIT_TERM = 143

# Widths used to keep the epilog examples aligned without monospace tricks.
_EPILOG = """\
examples:
  subpy -d example.com
      Passive sources plus the built-in wordlist.

  subpy -d example.com -p
      Passive only. Fastest mode, usually a few seconds.

  subpy -d example.com -a -w words.txt --wordlist-limit 5000
      Active only, with your own list capped at 5000 words.

  subpy -d example.com -o hosts.json -f json --no-color
      Machine-readable output for a pipeline.

  subpy -d example.com -s crtsh,hackertarget -q -f txt
      Only two sources, silent, one host per line - safe to pipe.

  subpy --list-sources
      Show every passive source and whether it needs an API key.

exit codes:
  0  scan completed      1  runtime error      2  usage error
  130  interrupted (SIGINT)                  143  terminated (SIGTERM)

documentation: https://github.com/0xShahriar/subpy
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Fast, dependency-free subdomain finder with correct wildcard handling.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )

    parser.add_argument(
        "-d",
        "--domain",
        metavar="DOMAIN",
        help="target domain, e.g. example.com",
    )
    parser.add_argument(
        "-h",
        "--help",
        action="help",
        help="show this help message and exit",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{PROG} {__version__}",
        help="show version and exit",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="check for a newer release and exit",
    )

    scan = parser.add_argument_group("scan mode")
    scan.add_argument("-p", "--passive-only", action="store_true", help="passive sources only")
    scan.add_argument("-a", "--active-only", action="store_true", help="brute force only")
    scan.add_argument(
        "--no-permutations",
        action="store_true",
        help="skip permutation of discovered hosts",
    )
    scan.add_argument(
        "--include-unresolved",
        action="store_true",
        help="also report names that did not resolve",
    )
    scan.add_argument(
        "--axfr",
        action="store_true",
        help="attempt a zone transfer (rarely succeeds)",
    )

    words = parser.add_argument_group("wordlist")
    words.add_argument(
        "-w",
        "--wordlist",
        metavar="PATH",
        action="append",
        default=[],
        help="wordlist file or built-in name (repeatable)",
    )
    words.add_argument(
        "--wordlist-limit",
        metavar="N",
        type=int,
        default=0,
        help="cap the number of words tried (0 = no cap)",
    )
    words.add_argument(
        "--no-wordlist",
        action="store_true",
        help="disable the built-in wordlist",
    )
    words.add_argument(
        "--max-permutations",
        metavar="N",
        type=int,
        default=40,
        help="permutations generated per discovered host (default 40)",
    )

    net = parser.add_argument_group("network")
    net.add_argument(
        "-r",
        "--resolver",
        metavar="IP[,IP...]",
        help="comma-separated resolvers (default: system + public pool)",
    )
    net.add_argument(
        "--no-system-resolvers",
        action="store_true",
        help="ignore resolvers from /etc/resolv.conf",
    )
    net.add_argument(
        "-c",
        "--concurrency",
        metavar="N",
        type=int,
        default=100,
        help="max concurrent DNS queries (default 100)",
    )
    net.add_argument(
        "-t",
        "--timeout",
        metavar="SEC",
        type=float,
        default=2.0,
        help="per-query timeout in seconds (default 2.0)",
    )
    net.add_argument(
        "--retries",
        metavar="N",
        type=int,
        default=1,
        help="resolver retries per query (default 1)",
    )
    net.add_argument(
        "--no-ipv6",
        action="store_true",
        help="skip AAAA lookups",
    )

    wildcard = parser.add_argument_group("wildcard")
    wildcard.add_argument(
        "--no-wildcard",
        action="store_true",
        help="disable wildcard filtering (not recommended)",
    )
    wildcard.add_argument(
        "--wildcard-samples",
        metavar="N",
        type=int,
        default=3,
        help="random probes used per level (default 3)",
    )

    sources = parser.add_argument_group("sources")
    sources.add_argument(
        "-s",
        "--sources",
        metavar="A,B",
        help="comma-separated source names to use",
    )
    sources.add_argument(
        "--exclude-sources",
        metavar="A,B",
        help="comma-separated source names to skip",
    )
    sources.add_argument(
        "--source-timeout",
        metavar="SEC",
        type=float,
        default=20.0,
        help="per-source timeout in seconds (default 20)",
    )
    sources.add_argument(
        "--list-sources",
        action="store_true",
        help="list passive sources and exit",
    )

    output = parser.add_argument_group("output")
    output.add_argument("-o", "--output", metavar="PATH", help="write results to a file")
    output.add_argument(
        "-f",
        "--format",
        metavar="FMT",
        choices=FORMATS,
        help="output format: " + ", ".join(FORMATS),
    )
    output.add_argument("--json", action="store_true", help="shorthand for -f json")
    output.add_argument(
        "--with-ip",
        action="store_true",
        help="include the address in txt output",
    )
    output.add_argument("-q", "--quiet", action="store_true", help="only hostnames, no chrome")
    output.add_argument("-v", "--verbose", action="store_true", help="show per-source detail")
    output.add_argument(
        "--no-progress",
        action="store_true",
        help="disable the live status line",
    )
    output.add_argument(
        "--no-color",
        action="store_true",
        help="disable colour (also honours NO_COLOR)",
    )
    output.add_argument(
        "--no-update-check",
        action="store_true",
        help="skip the version check",
    )
    output.add_argument(
        "--fail-empty",
        action="store_true",
        help="exit 1 when no hosts were found (for scripted checks)",
    )

    return parser


# --------------------------------------------------------------------------
# Subcommands expressed as flags (argparse subparsers would be heavier here)
# --------------------------------------------------------------------------
def _cmd_list_sources(as_json: bool = False) -> int:
    from .sources import list_sources

    entries = list_sources()
    if as_json:
        import json

        print(json.dumps(entries, indent=2))
        return EXIT_OK

    name_width = max((len(e["name"]) for e in entries), default=10)
    keyed = [e for e in entries if e["requires_key"]]
    free = [e for e in entries if not e["requires_key"]]

    def dump(title: str, items: list[dict]) -> None:
        if not items:
            return
        print(f"{title}")
        for entry in items:
            marker = "*" if entry["requires_key"] else " "
            print(f" {marker} {entry['name']:<{name_width}}  {entry['description']}")
        print()

    dump("no key needed", free)
    dump("requires an API key (*)", keyed)
    print("Use -s name1,name2 to select, --exclude-sources to skip.")
    return EXIT_OK


def _cmd_update() -> int:
    from .update import check_for_update, current_version

    info = check_for_update(force=True)
    print(f"installed: {current_version()}")
    if info.error:
        print(f"latest:    could not check ({info.error})")
        return EXIT_OK
    print(f"latest:    {info.latest or 'unknown'}")
    if info.available:
        print(f"\nA newer version is available: {info.url}")
        print("Upgrade with: pip install -U subpy")
    else:
        print("\nYou are up to date.")
    return EXIT_OK


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _fail(message: str) -> int:
    print(f"{PROG}: error: {message}", file=sys.stderr)
    print(f"try '{PROG} --help' for usage", file=sys.stderr)
    return EXIT_USAGE


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.list_sources:
        return _cmd_list_sources(as_json=bool(args.json))
    if args.update:
        return _cmd_update()

    if not args.domain:
        parser.print_usage(sys.stderr)
        print(f"{PROG}: error: a domain is required (-d)", file=sys.stderr)
        return EXIT_USAGE

    domain = args.domain.strip().lower()
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/", 1)[0].split(":", 1)[0].strip(".")
    if not domain or "." not in domain:
        return _fail(f"'{args.domain}' does not look like a domain")

    if args.passive_only and args.active_only:
        return _fail("--passive-only and --active-only are mutually exclusive")

    # Resolve wordlist shorthands ("small", "subdomains.txt", "/path/list").
    wordlist_paths: list[str] = []
    for entry in args.wordlist:
        resolved = resolve_wordlist_path(entry)
        if resolved is None:
            return _fail(f"wordlist not found: {entry}")
        wordlist_paths.append(resolved)

    if args.concurrency < 1:
        return _fail("--concurrency must be at least 1")
    if args.timeout <= 0:
        return _fail("--timeout must be greater than 0")

    resolver_list = _split_csv(args.resolver)
    fmt = args.format or ("json" if args.json else "txt")

    passive = not args.active_only
    active = not args.passive_only

    config = ScanConfig(
        domain,
        passive=passive,
        active=active,
        permutations=active and not args.no_permutations,
        concurrency=args.concurrency,
        timeout=args.timeout,
        retries=max(1, args.retries),
        resolvers=resolver_list,
        use_system_resolvers=not args.no_system_resolvers,
        wildcard=not args.no_wildcard,
        wildcard_samples=args.wildcard_samples,
        sources=_split_csv(args.sources),
        exclude_sources=_split_csv(args.exclude_sources),
        wordlist_paths=wordlist_paths,
        use_builtin_wordlist=not args.no_wordlist and not wordlist_paths,
        wordlist_limit=args.wordlist_limit,
        max_permutations=args.max_permutations,
        include_ipv6=not args.no_ipv6,
        source_timeout=args.source_timeout,
        zone_transfer=args.axfr,
        include_unresolved=args.include_unresolved,
        verbose=args.verbose,
    )

    color = False if args.no_color else None
    reporter = Reporter(
        color=color,
        quiet=args.quiet,
        verbose=args.verbose,
        progress=not args.no_progress and not args.quiet,
    )

    mode = "passive+active" if (passive and active) else ("passive" if passive else "active")
    if not args.quiet:
        reporter.header(domain, mode)

    scanner = Scanner(
        config,
        on_host=reporter.host,
        logger=reporter.note,
    )

    # -- signal handling ---------------------------------------------------
    loop_holder: dict = {}

    terminated = {"signal": 0}

    def _on_interrupt(signum, frame) -> None:  # noqa: ANN001, ARG001
        scanner.stop()
        terminated["signal"] = EXIT_INTERRUPT
        raise KeyboardInterrupt

    def _on_term(signum, frame) -> None:  # noqa: ANN001, ARG001
        # SIGTERM means "stop now, keep what you have" rather than a crash.
        scanner.stop()
        terminated["signal"] = EXIT_TERM
        raise KeyboardInterrupt

    previous: dict = {}
    handlers = {"SIGINT": _on_interrupt, "SIGTERM": _on_term}
    for sig_name, handler in handlers.items():
        sig = getattr(signal, sig_name, None)
        if sig is None:
            continue
        with contextlib.suppress(OSError, ValueError):
            previous[sig_name] = signal.signal(sig, handler)

    async def _run() -> list[Host]:
        loop_holder["loop"] = asyncio.get_running_loop()
        progress_task = None
        if reporter.progress_enabled:
            progress_task = asyncio.ensure_future(_progress_loop())
        try:
            return await scanner.run()
        finally:
            if progress_task is not None:
                progress_task.cancel()

    async def _progress_loop() -> None:
        import time as _time

        started = _time.monotonic()
        while True:
            await asyncio.sleep(0.15)
            reporter.progress(
                {
                    "queries": scanner.summary.queries,
                    "found": scanner.summary.resolved,
                    "elapsed": _time.monotonic() - started,
                    "phase": "scanning",
                }
            )

    hosts: list[Host] = []
    exit_code = EXIT_OK
    try:
        hosts = asyncio.run(_run())
    except KeyboardInterrupt:
        reporter.finish_progress()
        scanner.summary.interrupted = True
        hosts = scanner.results()
        exit_code = terminated["signal"] or EXIT_INTERRUPT
        if not args.quiet:
            label = "terminated" if exit_code == EXIT_TERM else "interrupted"
            reporter.warn(f"{label} - keeping {len(hosts)} hosts found so far")
    finally:
        for sig_name, handler in previous.items():
            sig = getattr(signal, sig_name, None)
            if sig is not None:
                with contextlib.suppress(OSError, ValueError):
                    signal.signal(sig, handler)
        reporter.finish_progress()

    if exit_code != EXIT_INTERRUPT:
        reporter.summary(scanner.summary, hosts)

    if args.output:
        try:
            write_output(
                hosts,
                args.output,
                fmt,
                summary=scanner.summary,
                with_ip=args.with_ip,
            )
        except OSError as exc:
            print(f"{PROG}: error: cannot write {args.output}: {exc}", file=sys.stderr)
            return EXIT_USAGE
        if not args.quiet:
            print(f"  wrote {len(hosts)} hosts to {args.output}")

    if not args.no_update_check and not args.quiet and sys.stdout.isatty():
        _maybe_notify_update()

    # A completed scan exits 0 even when nothing was found: "no subdomains"
    # is a valid answer, and non-zero would break pipelines that use subpy as
    # a probe step. Scripts that want the opposite opt in with --fail-empty.
    if args.fail_empty and not hosts:
        return EXIT_RUNTIME
    return exit_code


def _maybe_notify_update() -> None:
    """Print a one-line upgrade notice when a newer release exists."""
    try:
        from .update import check_for_update

        info = check_for_update()
        message = info.message()
        if message:
            print(f"\n{message}", file=sys.stderr)
    except Exception:
        return


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
