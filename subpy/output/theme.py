"""Colour handling and terminal capability detection.

Terminals are hostile: they lie about width, strip colours, render CJK as
double-width, and some (Termux, Windows conhost, CI logs) break on box
drawing. Everything visual funnels through here so the rest of the code can
assume a sane, already-decided palette.
"""

from __future__ import annotations

import os
import shutil
import sys

__all__ = ["Style", "terminal_width", "detect_unicode", "is_tty", "supports_color"]

# SGR codes kept as a plain dict rather than a class hierarchy: it is one
# lookup, it costs nothing, and it makes `Style.NONE` a simple no-op.
_CODES: dict[str, str] = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "italic": "\033[3m",
    "underline": "\033[4m",
    "black": "\033[30m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "grey": "\033[90m",
    "bright_red": "\033[91m",
    "bright_green": "\033[92m",
    "bright_yellow": "\033[93m",
    "bright_blue": "\033[94m",
    "bright_magenta": "\033[95m",
    "bright_cyan": "\033[96m",
    "bright_white": "\033[97m",
}


def _env_flag(name: str) -> bool | None:
    value = os.environ.get(name)
    if value is None:
        return None
    return value.strip().lower() not in ("", "0", "false", "no", "off")


def is_tty(stream=None) -> bool:
    stream = stream or sys.stdout
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def supports_color(stream=None, *, force: bool | None = None) -> bool:
    """Decide once whether ANSI escapes are welcome.

    Precedence: explicit flag > ``FORCE_COLOR`` > ``NO_COLOR`` > ``TERM``/TTY.
    Follows https://no-color.org so the tool composes with everything else.
    """
    if force is not None:
        return force
    forced = _env_flag("FORCE_COLOR")
    if forced:
        return True
    if _env_flag("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    if os.environ.get("CLICOLOR_FORCE", "") not in ("", "0"):
        return True
    if os.environ.get("CI"):
        # Most CI log viewers handle colour, but plain text diffs do not.
        return bool(os.environ.get("CLICOLOR", ""))
    return is_tty(stream)


def detect_unicode(stream=None) -> bool:
    """Whether it is safe to emit non-ASCII glyphs.

    Box drawing looks better but renders as mojibake on legacy Windows code
    pages, some Termux font setups, and anything piped through a strict
    ASCII consumer. When in doubt we fall back to ASCII.
    """
    if _env_flag("SUBPY_ASCII"):
        return False
    if _env_flag("SUBPY_UNICODE"):
        return True
    encoding = (getattr(stream or sys.stdout, "encoding", "") or "").lower()
    if not encoding:
        encoding = (os.environ.get("PYTHONIOENCODING") or "").lower()
    if not encoding:
        return False
    normalised = encoding.replace("-", "").replace("_", "")
    if normalised in ("ascii", "usascii", "ansix341968"):
        return False
    return "utf" in normalised


def terminal_width(stream=None, *, default: int = 80, maximum: int = 120) -> int:
    """Usable column count, clamped to a sane range.

    ``COLUMNS`` wins when set (so users and CI can pin it), then the real
    terminal size, then a conservative default. The cap keeps output from
    sprawling across ultrawide terminals while still adapting to a 40-column
    phone screen.
    """
    raw: str | None = os.environ.get("COLUMNS")
    width = 0
    if raw:
        try:
            width = int(raw)
        except ValueError:
            width = 0
    if width <= 0:
        try:
            width = shutil.get_terminal_size((default, 24)).columns
        except (OSError, ValueError):
            width = default
    if width <= 0:
        width = default
    return max(20, min(width, maximum))


class Style:
    """ANSI palette that degrades to plain text when colour is unwanted."""

    __slots__ = ("enabled",)

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    def __call__(self, text: str, *names: str) -> str:
        if not self.enabled or not names or not text:
            return text
        prefix = "".join(_CODES.get(n, "") for n in names)
        if not prefix:
            return text
        return f"{prefix}{text}{_CODES['reset']}"

    # Convenience shorthands for the handful used everywhere.
    def bold(self, text: str) -> str:
        return self(text, "bold")

    def dim(self, text: str) -> str:
        return self(text, "dim")

    def red(self, text: str) -> str:
        return self(text, "red")

    def green(self, text: str) -> str:
        return self(text, "green")

    def yellow(self, text: str) -> str:
        return self(text, "yellow")

    def cyan(self, text: str) -> str:
        return self(text, "cyan")

    def grey(self, text: str) -> str:
        return self(text, "grey")

    def magenta(self, text: str) -> str:
        return self(text, "magenta")


def display_width(text: str) -> int:
    """Visible width of *text*, ignoring ANSI escapes and counting wide glyphs.

    Needed to align columns: ``len()`` is wrong for coloured strings and for
    CJK/emoji hostnames (which do occur — IDNs are legitimate targets).
    """
    import unicodedata

    width = 0
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\033":
            # Skip CSI sequences: ESC [ ... final-byte
            index += 1
            if index < length and text[index] == "[":
                index += 1
                while index < length and not ("@" <= text[index] <= "~"):
                    index += 1
                index += 1
            continue
        if unicodedata.combining(char):
            index += 1
            continue
        east = unicodedata.east_asian_width(char)
        width += 2 if east in ("W", "F") else 1
        index += 1
    return width


def truncate(text: str, limit: int, ellipsis: str = "...") -> str:
    """Truncate to *limit* visible columns, preserving ANSI state."""
    if limit <= 0:
        return ""
    if display_width(text) <= limit:
        return text
    if limit <= len(ellipsis):
        return ellipsis[:limit]

    target = limit - len(ellipsis)
    out = []
    width = 0
    index = 0
    length = len(text)
    while index < length and width < target:
        char = text[index]
        if char == "\033":
            start = index
            index += 1
            if index < length and text[index] == "[":
                index += 1
                while index < length and not ("@" <= text[index] <= "~"):
                    index += 1
                index += 1
            out.append(text[start:index])
            continue
        from unicodedata import east_asian_width

        step = 2 if east_asian_width(char) in ("W", "F") else 1
        if width + step > target:
            break
        out.append(char)
        width += step
        index += 1
    return "".join(out) + ellipsis
