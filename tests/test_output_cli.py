"""Tests for output rendering and the CLI surface.

Everything here is offline: no resolver, no HTTP. The point is to lock down
the contract that other tooling depends on - exit codes, format stability,
escaping, and that narrow terminals never overflow.
"""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest

from subpy import __version__
from subpy.cli import build_parser, main
from subpy.core.models import Host, ScanSummary
from subpy.output.console import Reporter
from subpy.output.theme import display_width, terminal_width, truncate
from subpy.output.writers import FORMATS, format_hosts, write_output


def sample_hosts() -> list:
    return [
        Host(
            name="api.example.com",
            addresses=["1.2.3.4"],
            sources={"crtsh", "rapiddns"},
            resolved=True,
            ttl=300,
            http_status=200,
        ),
        Host(
            name="dev.example.com", addresses_v6=["2001:db8::1"], sources={"active"}, resolved=True
        ),
        Host(
            name="cdn.example.com",
            cnames=["d1.cloudfront.net"],
            sources={"hackertarget"},
            resolved=True,
            dangling=True,
        ),
        Host(name="example.com", addresses=["9.9.9.9"], sources={"crtsh"}, resolved=True),
    ]


class TestWriters(unittest.TestCase):
    def setUp(self):
        self.hosts = sample_hosts()
        self.summary = ScanSummary(domain="example.com", queries=100, resolved=4)

    def test_txt_is_sorted_and_one_per_line(self):
        out = format_hosts(self.hosts, "txt")
        lines = out.strip().split("\n")
        self.assertEqual(len(lines), 4)
        # Sorted by depth then name, so the apex leads and children follow
        # alphabetically. Stable ordering matters for diffing two scans.
        self.assertEqual(lines[0], "example.com")
        self.assertEqual(lines[1:], ["api.example.com", "cdn.example.com", "dev.example.com"])

    def test_txt_with_ip(self):
        out = format_hosts(self.hosts, "txt", with_ip=True)
        self.assertIn("api.example.com\t1.2.3.4", out)

    def test_json_schema_is_stable(self):
        payload = json.loads(format_hosts(self.hosts, "json", summary=self.summary))
        self.assertEqual(payload["tool"], "subpy")
        self.assertEqual(payload["schema"], 1)
        self.assertEqual(payload["count"], 4)
        self.assertIn("hosts", payload)
        self.assertIn("summary", payload)
        entry = payload["hosts"][0]
        for key in (
            "host",
            "sources",
            "resolved",
            "ip",
            "ipv6",
            "cname",
            "ttl",
            "wildcard",
            "dangling",
            "http_status",
        ):
            self.assertIn(key, entry)
        self.assertIsInstance(entry["sources"], list)

    def test_json_is_valid_utf8_roundtrip(self):
        hosts = [Host(name="münchen.example.com", resolved=True)]
        out = format_hosts(hosts, "json")
        self.assertEqual(json.loads(out)["hosts"][0]["host"], "münchen.example.com")

    def test_csv_header_and_rows(self):
        out = format_hosts(self.hosts, "csv")
        lines = out.strip().split("\n")
        self.assertEqual(lines[0], "host,ip,ipv6,cname,status,server,title,sources,ttl")
        self.assertEqual(len(lines), 5)

    def test_markdown_escapes_pipes(self):
        hosts = [Host(name="a|b.example.com", resolved=True)]
        out = format_hosts(hosts, "md")
        self.assertIn("a\\|b", out)

    def test_html_escapes_and_has_no_script(self):
        hosts = [Host(name='x"><script>alert(1)</script>.example.com', resolved=True)]
        out = format_hosts(hosts, "html")
        self.assertNotIn("<script>alert", out)
        self.assertIn("&lt;script&gt;", out)
        self.assertIn("viewport", out)  # responsive
        self.assertNotIn("<script", out.lower())

    def test_all_formats_render(self):
        for fmt in FORMATS:
            out = format_hosts(self.hosts, fmt, summary=self.summary)
            self.assertTrue(out, f"{fmt} produced nothing")

    def test_unknown_format_raises(self):
        with self.assertRaises(ValueError):
            format_hosts(self.hosts, "xml")

    def test_write_output_creates_parent_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "nested", "deep", "out.json")
            written = write_output(self.hosts, path, "json", summary=self.summary)
            self.assertTrue(os.path.isfile(written))
            with open(written, encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["count"], 4)

    def test_empty_host_list_is_handled(self):
        for fmt in FORMATS:
            out = format_hosts([], fmt)
            self.assertIsInstance(out, str)


class TestTheme(unittest.TestCase):
    def test_display_width_ignores_ansi(self):
        self.assertEqual(display_width("\033[31mred\033[0m"), 3)

    def test_display_width_counts_wide_chars(self):
        # CJK glyphs occupy two columns.
        self.assertEqual(display_width("日本"), 4)

    def test_truncate_respects_limit(self):
        for width in (5, 10, 20):
            self.assertLessEqual(display_width(truncate("a" * 100, width)), width)

    def test_terminal_width_is_clamped(self):
        self.assertGreaterEqual(terminal_width(), 20)
        old = os.environ.get("COLUMNS")
        try:
            os.environ["COLUMNS"] = "500"
            self.assertLessEqual(terminal_width(), 120)
            os.environ["COLUMNS"] = "10"
            self.assertGreaterEqual(terminal_width(), 20)
        finally:
            if old is None:
                os.environ.pop("COLUMNS", None)
            else:
                os.environ["COLUMNS"] = old


class TestReporter(unittest.TestCase):
    def _render(self, width: int) -> str:
        out, err = io.StringIO(), io.StringIO()
        reporter = Reporter(stream=out, err_stream=err, color=False, progress=False)
        reporter.width = width
        reporter.header("example.com", "passive+active")
        for host in sample_hosts():
            reporter.host(host)
        reporter.summary(
            ScanSummary(
                domain="example.com",
                queries=1204,
                passive_found=412,
                active_found=2,
                wildcard_filtered=88,
                wildcard_levels=2,
                resolved=4,
            ),
            sample_hosts(),
        )
        return out.getvalue()

    def test_never_exceeds_terminal_width(self):
        for width in (30, 40, 55, 80, 120):
            for line in self._render(width).splitlines():
                self.assertLessEqual(
                    display_width(line),
                    width,
                    f"line overflowed at width {width}: {line!r}",
                )

    def test_quiet_mode_prints_only_hostnames(self):
        out = io.StringIO()
        reporter = Reporter(stream=out, err_stream=io.StringIO(), color=False, quiet=True)
        for host in sample_hosts():
            reporter.host(host)
        lines = out.getvalue().strip().split("\n")
        self.assertEqual(len(lines), 4)
        for line in lines:
            self.assertNotIn(" ", line)

    def test_dangling_marker_present(self):
        out = io.StringIO()
        reporter = Reporter(stream=out, err_stream=io.StringIO(), color=False, progress=False)
        reporter.width = 100
        reporter.host(
            Host(name="x.example.com", cnames=["gone.example.net"], resolved=True, dangling=True)
        )
        self.assertIn("dangling", out.getvalue())


class TestCliParser(unittest.TestCase):
    def test_version_flag(self):
        import contextlib

        parser = build_parser()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), self.assertRaises(SystemExit) as ctx:
            parser.parse_args(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn(__version__, buffer.getvalue())

    def test_defaults(self):
        args = build_parser().parse_args(["-d", "example.com"])
        self.assertEqual(args.domain, "example.com")
        self.assertEqual(args.concurrency, 100)
        self.assertFalse(args.passive_only)
        self.assertFalse(args.active_only)

    def test_short_flags_exist(self):
        args = build_parser().parse_args(
            ["-d", "example.com", "-p", "-o", "out.txt", "-f", "json", "-c", "50"]
        )
        self.assertTrue(args.passive_only)
        self.assertEqual(args.output, "out.txt")
        self.assertEqual(args.format, "json")
        self.assertEqual(args.concurrency, 50)

    def test_wordlist_is_repeatable(self):
        args = build_parser().parse_args(["-d", "example.com", "-w", "a.txt", "-w", "b.txt"])
        self.assertEqual(args.wordlist, ["a.txt", "b.txt"])


class TestMainExitCodes(unittest.TestCase):
    def test_missing_domain_exits_2(self):
        with tempfile.TemporaryFile("w+") as sink:
            import contextlib

            with contextlib.redirect_stderr(sink), contextlib.redirect_stdout(sink):
                self.assertEqual(main([]), 2)

    def test_conflicting_modes_exit_2(self):
        import contextlib

        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["-d", "example.com", "-p", "-a"]), 2)

    def test_invalid_domain_exits_2(self):
        import contextlib

        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["-d", "notadomain"]), 2)

    def test_missing_wordlist_exits_2(self):
        import contextlib

        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["-d", "example.com", "-w", "/nonexistent/list.txt"]), 2)

    def test_bad_concurrency_exits_2(self):
        import contextlib

        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["-d", "example.com", "-c", "0"]), 2)

    def test_list_sources_exits_0(self):
        import contextlib

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.assertEqual(main(["--list-sources"]), 0)
        self.assertIn("crtsh", buffer.getvalue())


class TestVersion(unittest.TestCase):
    def test_version_is_semver(self):

        self.assertRegex(__version__, r"^\d+\.\d+\.\d+")


if __name__ == "__main__":
    unittest.main()


class TestCliSafetyGuards(unittest.TestCase):
    """Regression guards for input/path bugs found in review."""

    def test_bare_ip_is_rejected_as_a_domain(self):
        # Accepted silently before, then brute-forced to an empty result set
        # that looked like "this host has no subdomains".
        import io
        from contextlib import redirect_stderr, redirect_stdout

        from subpy.cli import main

        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = main(["-d", "8.8.8.8", "-p", "--no-update-check"])
        self.assertEqual(code, 2, err.getvalue())
        self.assertIn("IP address", err.getvalue())

    def test_malformed_domains_are_rejected(self):
        import io
        from contextlib import redirect_stderr, redirect_stdout

        from subpy.cli import main

        # "-x.com" is omitted: argparse itself consumes it as an option, so
        # it never reaches validation. The rest must be rejected by us.
        for bad in ("a..b", "exa mple.com", "*.example.com", "x-.com", "a"):
            with self.subTest(domain=bad):
                err = io.StringIO()
                with redirect_stdout(io.StringIO()), redirect_stderr(err):
                    code = main(["-d", bad, "-p", "--no-update-check"])
                self.assertEqual(code, 2, f"{bad}: {err.getvalue()}")

    def test_urls_are_normalised_to_their_domain(self):
        from subpy.core.dns import normalize_name

        # The CLI strips scheme, userinfo and port before validating.
        self.assertEqual(normalize_name("example.com"), "example.com")

    def test_fail_empty_does_not_mask_a_signal_exit_code(self):
        import ast
        import inspect

        from subpy.cli import main

        source = inspect.getsource(main)
        tree = ast.parse(source)
        guards = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.If) and "fail_empty" in ast.dump(node.test)
        ]
        self.assertTrue(guards, "no --fail-empty guard found")
        # The guard must also require a clean exit, or it overwrites 130/143.
        self.assertTrue(
            any("exit_code" in ast.dump(g.test) for g in guards),
            "--fail-empty must not overwrite an interrupt exit code",
        )

    def test_nul_byte_in_output_path_is_a_usage_error(self):
        # No network: --passive-only with every source excluded means the
        # scan is empty and fast, so this cannot flake on a slow endpoint.
        import io
        from contextlib import redirect_stderr, redirect_stdout

        from subpy.cli import main

        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = main(
                [
                    "-d",
                    "example.com",
                    "-a",
                    "--no-wordlist",
                    "--no-permutations",
                    "--no-wildcard",
                    "-o",
                    "bad\x00name.json",
                    "--no-update-check",
                ]
            )
        self.assertEqual(code, 2, err.getvalue())
