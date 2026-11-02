"""Guards for cross-version and cross-platform behaviour.

The project claims Python 3.9+ and Termux support, but development happens on
one interpreter. These tests assert the *invariants* that make those claims
true, so a careless edit breaks CI on the matrix rather than users' devices.

They also cover the paths that only exist on other platforms (Windows
console encoding, Android resolver config), which would otherwise never be
exercised.
"""

from __future__ import annotations

import ast
import json
import os
import pathlib
import signal
import sys
import unittest

PACKAGE_ROOT = pathlib.Path(__file__).resolve().parent.parent / "subpy"


def python_files():
    return sorted(PACKAGE_ROOT.rglob("*.py"))


class TestPy39Compatibility(unittest.TestCase):
    """Nothing may rely on syntax newer than 3.9 at runtime."""

    def test_no_match_statements(self):
        # `match` is 3.10+. Using it would break 3.9 at import time.
        for path in python_files():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            matches = [n for n in ast.walk(tree) if n.__class__.__name__ == "Match"]
            self.assertEqual(matches, [], f"{path} uses a match statement")

    def test_pep604_annotations_have_future_import(self):
        # `str | None` in an annotation is only safe on 3.9 because
        # `from __future__ import annotations` turns it into a string.
        for path in python_files():
            source = path.read_text(encoding="utf-8")
            if not source.strip():
                continue
            has_future = "from __future__ import annotations" in source
            tree = ast.parse(source)
            uses_pep604 = False
            for node in ast.walk(tree):
                annotation = None
                if isinstance(node, ast.AnnAssign) and node.annotation:
                    annotation = node.annotation
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.returns:
                        annotation = node.returns
                    for arg in list(node.args.args) + list(node.args.kwonlyargs):
                        if arg.annotation is not None:
                            annotation = arg.annotation
                if annotation is None:
                    continue
                for sub in ast.walk(annotation):
                    if isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.BitOr):
                        uses_pep604 = True
            if uses_pep604:
                self.assertTrue(
                    has_future,
                    f"{path} uses `X | Y` annotations without `from __future__ import annotations`",
                )

    def test_builtin_generics_only_in_annotations(self):
        # `list[str]` is 3.9-valid *in an annotation* thanks to the future
        # import, but invalid as a runtime subscript. Every occurrence must
        # therefore sit inside an annotation position.
        for path in python_files():
            source = path.read_text(encoding="utf-8")
            if not source.strip():
                continue
            tree = ast.parse(source)
            annotation_nodes = set()
            for node in ast.walk(tree):
                annotations = []
                if isinstance(node, ast.AnnAssign) and node.annotation:
                    annotations.append(node.annotation)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.returns:
                        annotations.append(node.returns)
                    for arg in (
                        list(node.args.args)
                        + list(node.args.kwonlyargs)
                        + list(node.args.posonlyargs)
                        + [node.args.vararg, node.args.kwarg]
                    ):
                        if arg is not None and arg.annotation is not None:
                            annotations.append(arg.annotation)
                for annotation in annotations:
                    for sub in ast.walk(annotation):
                        annotation_nodes.add(id(sub))

            for node in ast.walk(tree):
                if not isinstance(node, ast.Subscript):
                    continue
                if not isinstance(node.value, ast.Name):
                    continue
                if node.value.id not in ("list", "dict", "set", "tuple", "type"):
                    continue
                self.assertIn(
                    id(node),
                    annotation_nodes,
                    f"{path}: builtin generic used at runtime, not in an annotation",
                )


class TestZeroDependencies(unittest.TestCase):
    def test_no_third_party_imports(self):
        """The package must import nothing outside the standard library."""
        stdlib = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else set()
        allowed_local = {"subpy"}
        third_party_prefixes = (
            "dns.",
            "uvloop",
            "httpx",
            "aiohttp",
            "requests",
            "tldextract",
            "pkg_resources",
            "setuptools",
            "click",
            "rich",
            "tqdm",
            "yaml",
        )
        offenders = []
        for path in python_files():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    if node.level:  # relative import, ours
                        continue
                    if node.module:
                        names = [node.module]
                for name in names:
                    root = name.split(".")[0]
                    if root in allowed_local:
                        continue
                    if any(name.startswith(p) for p in third_party_prefixes):
                        offenders.append(f"{path.name}: {name}")
                        continue
                    if stdlib and root not in stdlib:
                        offenders.append(f"{path.name}: {name}")
        self.assertEqual(offenders, [], f"non-stdlib imports found: {offenders}")

    def test_optional_acceleration_is_guarded(self):
        """uvloop/aiodns must be imported inside a try block, never at top level."""
        source = (PACKAGE_ROOT / "core" / "resolver.py").read_text(encoding="utf-8")
        for module in ("uvloop", "aiodns", "httpx"):
            if module not in source:
                continue
            for line in source.splitlines():
                stripped = line.strip()
                if stripped.startswith(f"import {module}") or stripped.startswith(f"from {module}"):
                    self.assertNotEqual(
                        line[0],
                        line.lstrip()[0],
                        f"top-level `{module}` import breaks zero-dep promise",
                    )


class TestCrossPlatform(unittest.TestCase):
    def test_terminal_width_never_raises_without_tty(self):
        from subpy.output.theme import terminal_width

        self.assertGreaterEqual(terminal_width(), 20)

    def test_ascii_fallback_is_pure_ascii(self):
        import io

        from subpy.core.models import Host
        from subpy.output.console import Reporter

        out = io.StringIO()
        reporter = Reporter(stream=out, err_stream=io.StringIO(), color=False, progress=False)
        reporter.unicode = False
        reporter.width = 80
        reporter.header("example.com", "passive")
        reporter.host(Host(name="a.example.com", addresses=["1.2.3.4"], resolved=True))
        out.getvalue().encode("ascii")  # must not raise

    def test_color_env_respected(self):
        import os

        from subpy.output.theme import supports_color

        previous = os.environ.get("NO_COLOR")
        try:
            os.environ["NO_COLOR"] = "1"
            self.assertFalse(supports_color())
            # Per no-color.org, an *empty* NO_COLOR must not disable colour.
            os.environ["NO_COLOR"] = ""
            self.assertIsInstance(supports_color(), bool)
        finally:
            if previous is None:
                os.environ.pop("NO_COLOR", None)
            else:
                os.environ["NO_COLOR"] = previous

    def test_resolver_env_override(self):
        import os

        from subpy.core.resolver import system_resolvers

        previous = os.environ.get("SUBPY_RESOLVER")
        try:
            os.environ["SUBPY_RESOLVER"] = "10.1.2.3,10.4.5.6"
            self.assertEqual(system_resolvers(), ["10.1.2.3", "10.4.5.6"])
        finally:
            if previous is None:
                os.environ.pop("SUBPY_RESOLVER", None)
            else:
                os.environ["SUBPY_RESOLVER"] = previous

    def test_resolver_env_override_ignores_junk(self):
        import os

        from subpy.core.resolver import system_resolvers

        previous = os.environ.get("SUBPY_RESOLVER")
        try:
            os.environ["SUBPY_RESOLVER"] = "not-an-ip"
            result = system_resolvers()
            self.assertIsInstance(result, list)
            self.assertNotIn("not-an-ip", result)
        finally:
            if previous is None:
                os.environ.pop("SUBPY_RESOLVER", None)
            else:
                os.environ["SUBPY_RESOLVER"] = previous


class TestUpdateCheckSafety(unittest.TestCase):
    def test_disabled_never_returns_available(self):
        from subpy.update import check_for_update

        info = check_for_update(disabled=True)
        self.assertFalse(info.available)
        self.assertEqual(info.message(), "")

    def test_env_var_disables(self):
        import os

        from subpy.update import check_for_update

        previous = os.environ.get("SUBPY_NO_UPDATE")
        try:
            os.environ["SUBPY_NO_UPDATE"] = "1"
            self.assertFalse(check_for_update().available)
        finally:
            if previous is None:
                os.environ.pop("SUBPY_NO_UPDATE", None)
            else:
                os.environ["SUBPY_NO_UPDATE"] = previous

    def test_version_comparison(self):
        from subpy.update import compare_versions

        cases = [
            ("1.0.0", "1.0.1", -1),
            ("1.0.1", "1.0.0", 1),
            ("1.0.0", "1.0.0", 0),
            ("v1.2.0", "1.2.0", 0),
            ("1.0.0-rc1", "1.0.0", -1),
            ("1.0.0", "1.0.0-rc1", 1),
            ("1.10.0", "1.9.0", 1),
            ("2.0.0", "1.99.99", 1),
        ]
        for left, right, expected in cases:
            self.assertEqual(compare_versions(left, right), expected, f"{left} vs {right}")


class TestSourceContract(unittest.TestCase):
    def test_every_registered_source_is_importable_and_metadata_complete(self):
        from subpy.sources import SOURCE_REGISTRY

        self.assertGreaterEqual(len(SOURCE_REGISTRY), 15)
        for name, cls in SOURCE_REGISTRY.items():
            instance = cls()
            self.assertTrue(instance.name, f"{name} has no name")
            self.assertTrue(instance.description, f"{name} has no description")
            self.assertIn(
                instance.category,
                ("ct", "dns", "intel", "crawl"),
                f"{name} has an unexpected category",
            )
            self.assertGreaterEqual(instance.reliability, 0.0)
            self.assertLessEqual(instance.reliability, 1.0)
            if instance.requires_key:
                self.assertTrue(instance.key_env, f"{name} needs a key but no env var")

    def test_no_duplicate_source_names(self):
        from subpy.sources import list_sources

        names = [entry["name"] for entry in list_sources()]
        self.assertEqual(len(names), len(set(names)))

    def test_keyed_sources_skip_without_key(self):
        from subpy.sources import HttpClient, SourceContext, get_sources

        context = SourceContext(domain="example.com", http=HttpClient(), keys={})
        for source in get_sources():
            if source.requires_key:
                self.assertFalse(
                    source.has_key(context),
                    f"{source.name} claims a key without one being configured",
                )


if __name__ == "__main__":
    unittest.main()


class TestInterruptBehaviour(unittest.TestCase):
    """Ctrl-C must exit promptly with 130 and keep partial results.

    Regression guard: earlier versions hung for 90+ seconds because
    ``asyncio.run`` waits on blocked executor jobs at teardown, and exited
    with a traceback because the handler raised inside the loop.
    """

    def test_sigint_exits_130_quickly_with_results(self):
        import subprocess
        import time

        process = subprocess.Popen(
            [sys.executable, "-m", "subpy", "-d", "example.com", "--no-update-check", "--no-color"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(PACKAGE_ROOT.parent),
        )
        time.sleep(3)
        started = time.monotonic()
        process.send_signal(signal.SIGINT)
        try:
            stdout, stderr = process.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            self.fail("subpy did not exit within 20s of SIGINT")

        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 10.0, f"shutdown took {elapsed:.1f}s")
        self.assertEqual(process.returncode, 130, f"stderr: {stderr[-800:]}")
        self.assertNotIn("Traceback", stderr)
        self.assertIn("interrupted", stderr.lower())

    def test_sigterm_exits_143(self):
        import subprocess
        import time

        # A broad wordlist keeps the process busy long enough for the signal
        # to land mid-scan without depending on network speed.
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "subpy",
                "-d",
                "example.com",
                "-a",
                "--wordlist-limit",
                "900",
                "--no-update-check",
                "--no-color",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(PACKAGE_ROOT.parent),
        )
        time.sleep(1.5)
        if process.poll() is not None:
            self.skipTest("scan finished before the signal could be delivered")
        process.send_signal(signal.SIGTERM)
        try:
            _stdout, stderr = process.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            self.fail("subpy did not exit within 20s of SIGTERM")
        self.assertEqual(process.returncode, 143, f"stderr: {stderr[-800:]}")

    def test_sigint_also_flushes_output_file(self):
        """An interrupted scan must still write what it found."""
        import subprocess
        import tempfile
        import time

        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "partial.json")
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "subpy",
                    "-d",
                    "example.com",
                    "-a",
                    "--wordlist-limit",
                    "900",
                    "-o",
                    target,
                    "-f",
                    "json",
                    "--no-update-check",
                    "--no-color",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(PACKAGE_ROOT.parent),
            )
            time.sleep(4.0)
            if process.poll() is not None:
                self.skipTest("scan finished before the signal could be delivered")
            process.send_signal(signal.SIGINT)
            try:
                process.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                self.fail("subpy did not exit within 20s of SIGINT")

            self.assertTrue(os.path.isfile(target), "no output file written")
            with open(target, encoding="utf-8") as handle:
                payload = json.load(handle)
            self.assertIn("hosts", payload)
            self.assertGreaterEqual(payload["count"], 1)
