"""Terminal reporting: live hits, a single-line progress bar, and a summary.

Design rules that come straight from using these tools on a phone over SSH:

* **The results are the interface.** No banner art, no spinner, no table
  borders that eat 8 columns. One host per line, columns that collapse as the
  terminal narrows.
* **Progress never fights output.** The status line lives on stderr and is
  redrawn in place; hosts go to stdout and are never overwritten.
* **Nothing is printed twice.** Live mode and summary mode are alternatives,
  so a piped run does not get a header repeated every 50 lines.
* **Degrade, do not break.** ASCII fallback, colour opt-out, and a compact
  layout below 60 columns are all automatic.
"""

from __future__ import annotations

import sys
import time
from typing import TextIO

from ..core.models import Host, ScanSummary
from .theme import Style, detect_unicode, display_width, supports_color, terminal_width, truncate

__all__ = ["Reporter"]


class Reporter:
    """Writes live results, progress and the final summary."""

    def __init__(
        self,
        *,
        stream: TextIO | None = None,
        err_stream: TextIO | None = None,
        color: bool | None = None,
        quiet: bool = False,
        verbose: bool = False,
        progress: bool = True,
        show_header: bool = True,
    ) -> None:
        self.out = stream or sys.stdout
        self.err = err_stream or sys.stderr
        self.quiet = quiet
        self.verbose = verbose
        self.show_header = show_header and not quiet

        self.style = Style(supports_color(self.out, force=color))
        self.style_err = Style(supports_color(self.err, force=color))
        self.unicode = detect_unicode(self.out)
        self._width_override = None
        self._width = terminal_width(self.out)

        # Progress is only useful on a real terminal; piped output gets none.
        self.progress_enabled = progress and not quiet and self._isatty(self.err)
        self._progress_active = False
        self._last_progress = 0.0

        self.count = 0
        self._name_width = 0
        self._width_override: int | None = None

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def _isatty(stream: TextIO) -> bool:
        try:
            return bool(stream.isatty())
        except (AttributeError, ValueError):
            return False

    def _refresh_width(self) -> None:
        if self._width_override is not None:
            self.width = self._width_override
        else:
            self.width = terminal_width(self.out)

    @property
    def width(self) -> int:
        return self._width

    @width.setter
    def width(self, value: int) -> None:
        # An explicit assignment pins the width; otherwise the reporter keeps
        # tracking terminal resizes.
        self._width = max(20, int(value))
        self._width_override = self._width

    @property
    def _compact(self) -> bool:
        return self.width < 62

    @property
    def _narrow(self) -> bool:
        return self.width < 44

    # -- header -----------------------------------------------------------
    def header(self, domain: str, mode: str = "") -> None:
        if self.quiet or not self.show_header:
            return
        self._refresh_width()
        title = self.style(domain, "bold", "bright_white")
        if mode:
            mode = self.style(f" {mode}", "dim")
        line = f"{self.style('>', 'bright_cyan')} {title}{mode}"
        self.out.write(line + "\n")
        self.out.flush()

    def note(self, message: str) -> None:
        """A quiet informational line (only in verbose mode)."""
        if self.quiet or not self.verbose:
            return
        self._clear_progress()
        self.err.write(self.style_err(f"  {message}", "dim") + "\n")
        self.err.flush()

    def warn(self, message: str) -> None:
        if self.quiet:
            return
        self._clear_progress()
        prefix = "!" if not self.unicode else "!"
        self.err.write(self.style_err(f"{prefix} {message}", "yellow") + "\n")
        self.err.flush()

    # -- live results -----------------------------------------------------
    def host(self, host: Host) -> None:
        """Print one confirmed host. This is the hot path: keep it tight."""
        self._clear_progress()
        self.count += 1

        if self.quiet:
            self.out.write(host.name + "\n")
            self.out.flush()
            return

        self._refresh_width()
        name = host.name
        name_width = display_width(name)
        if name_width > self._name_width:
            self._name_width = name_width

        parts: list[str] = []

        address = host.ip
        if address:
            colour = "bright_green" if ":" not in address else "bright_cyan"
            parts.append(self.style(address, colour))

        if host.http_status is not None and not self._narrow:
            status = host.http_status
            colour = (
                "bright_green"
                if 200 <= status < 300
                else ("bright_yellow" if 300 <= status < 400 else "bright_red")
            )
            parts.append(self.style(str(status), colour))

        # A dangling CNAME is the most actionable finding a scan produces,
        # so it gets a marker even on a 40-column terminal.
        if host.dangling:
            parts.append(self.style("dangling", "bright_red"))

        if not self._compact:
            if host.cnames and not host.addresses:
                parts.append(self.style("cname:" + host.cnames[0], "dim"))
            tags = sorted(host.sources)
            if tags:
                # Two sources is plenty; the rest become a count.
                shown = ", ".join(tags[:2])
                if len(tags) > 2:
                    shown += f" +{len(tags) - 2}"
                parts.append(self.style(shown, "grey"))

        # Align the trailing columns, but only while the names are short
        # enough that alignment still reads as a table rather than as gaps.
        pad = 0
        if not self._narrow and self._name_width <= 34:
            pad = max(0, self._name_width - name_width)

        line = self.style(name, "bold") + (" " * pad)
        if parts:
            line += "  " + "  ".join(parts)
        self.out.write(truncate(line, self.width) + "\n")
        self.out.flush()

    # -- progress ---------------------------------------------------------
    def progress(self, stats: dict[str, object]) -> None:
        """Redraw the one-line status. Called on a timer, not per host."""
        if not self.progress_enabled:
            return
        now = time.monotonic()
        if now - self._last_progress < 0.08:
            return
        self._last_progress = now

        self._refresh_width()
        queries = int(stats.get("queries", 0) or 0)
        elapsed = float(stats.get("elapsed", 0.0) or 0.0)
        found = int(stats.get("found", self.count) or 0)
        sources = int(stats.get("sources_done", 0) or 0)
        sources_total = int(stats.get("sources_total", 0) or 0)
        phase = str(stats.get("phase", "") or "")

        rate = (queries / elapsed) if elapsed > 0.2 else 0.0

        segments: list[str] = []
        if phase:
            segments.append(self.style_err(phase, "cyan"))
        segments.append(self.style_err(f"{found} found", "bright_green"))
        if queries:
            segments.append(self.style_err(f"{queries} q", "dim"))
        if rate >= 1:
            segments.append(self.style_err(f"{rate:.0f}/s", "dim"))
        if sources_total:
            segments.append(self.style_err(f"src {sources}/{sources_total}", "dim"))
        if elapsed >= 1:
            segments.append(self.style_err(_duration(elapsed), "dim"))

        sep = " " if self._narrow else "  "
        body = sep.join(segments)
        # Leave one column free so the cursor never wraps onto a new line.
        body = truncate(body, max(10, self.width - 1))
        padding = " " * max(0, self.width - 1 - display_width(body))

        self.err.write("\r" + body + padding)
        self.err.flush()
        self._progress_active = True

    def _clear_progress(self) -> None:
        if not self._progress_active:
            return
        self.err.write("\r" + " " * max(10, self.width - 1) + "\r")
        self.err.flush()
        self._progress_active = False

    def finish_progress(self) -> None:
        self._clear_progress()

    # -- summary ----------------------------------------------------------
    def summary(self, summary: ScanSummary, hosts: list[Host]) -> None:
        self._clear_progress()
        if self.quiet:
            return
        self._refresh_width()

        self.out.write("\n")
        self.out.flush()
        if not self.show_header:
            return

        rule = "-" if not self.unicode else "─"
        self.out.write(self.style(rule * min(self.width, 56), "grey") + "\n")

        rows: list[tuple] = []
        rows.append(("found", str(len(hosts)), "bright_green"))
        rows.append(("time", _duration(summary.elapsed), "bright_white"))
        if summary.queries:
            rows.append(("queries", f"{summary.queries} ({summary.qps:.0f}/s)", "bright_white"))
        if summary.passive_found:
            rows.append(("passive", str(summary.passive_found), "cyan"))
        if summary.active_found:
            rows.append(("brute", str(summary.active_found), "cyan"))
        if summary.permutation_found:
            rows.append(("permuted", str(summary.permutation_found), "cyan"))
        if summary.wildcard_filtered:
            rows.append(("wildcard", f"{summary.wildcard_filtered} filtered", "yellow"))
        if summary.wildcard_levels:
            rows.append(("wildcard lvls", str(summary.wildcard_levels), "yellow"))
        dangling = sum(1 for h in hosts if h.dangling)
        if dangling:
            rows.append(("dangling", str(dangling), "bright_red"))

        # Greedy packing: add cells until the next one would overflow the
        # terminal. Measured widths (not assumed column counts) mean a
        # 40-column phone never wraps a stat mid-cell.
        cells = [
            (
                f"{label:>12} {value}",
                f"{self.style(f'{label:>12}', 'grey')} {self.style(value, colour)}",
            )
            for label, value, colour in rows
        ]
        line_styled: list[str] = []
        line_width = 0
        gap = 2
        for plain, styled in cells:
            cell_width = display_width(plain)
            addition = cell_width if not line_styled else cell_width + gap
            if line_styled and line_width + addition > self.width:
                self.out.write("  ".join(line_styled) + "\n")
                line_styled = [styled]
                line_width = cell_width
            else:
                line_styled.append(styled)
                line_width += addition
        if line_styled:
            self.out.write("  ".join(line_styled) + "\n")

        if summary.source_errors and self.verbose:
            self.out.write(self.style("  source issues", "grey") + "\n")
            for message in summary.source_errors[:12]:
                self.out.write(self.style(f"    - {message}", "dim") + "\n")

        if summary.interrupted:
            self.out.write(self.style("  interrupted", "yellow") + "\n")

        self.out.write(self.style(rule * min(self.width, 56), "grey") + "\n")
        self.out.flush()


def _duration(seconds: float) -> str:
    """Compact human duration: 0.4s, 12s, 1m04s, 1h02m."""
    if seconds < 1:
        return f"{seconds:.1f}s"
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        minutes, secs = divmod(int(seconds), 60)
        return f"{minutes}m{secs:02d}s"
    hours, remainder = divmod(int(seconds), 3600)
    minutes = remainder // 60
    return f"{hours}h{minutes:02d}m"
