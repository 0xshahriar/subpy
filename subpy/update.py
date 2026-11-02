"""Self-update checking against GitHub releases.

Deliberately *not* a self-updater: silently replacing installed code is how a
security tool gets compromised. We check, we tell the user, they decide.

Constraints that shaped this module:

* The unauthenticated GitHub API allows 60 requests/hour per IP, shared with
  everything else on that network (CI runners, corporate NAT, Termux on
  mobile). So: check at most once per ``CHECK_INTERVAL``, cache the answer
  including "you are up to date", and never let a failure surface as an error.
* The check must never delay a scan. It runs only when cached data is stale
  and the caller opts in, and any network problem is swallowed.
* Offline-by-default: ``--no-update-check``, ``SUBPY_NO_UPDATE`` and a
  non-TTY stdout all skip it.
"""

from __future__ import annotations

import json
import os
import re
import time

__all__ = [
    "check_for_update",
    "latest_release",
    "parse_version",
    "compare_versions",
    "clear_cache",
    "current_version",
    "UpdateInfo",
]

REPO = "0xShahriar/subpy"
RELEASES_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
CHECK_INTERVAL = 24 * 60 * 60  # one day
REQUEST_TIMEOUT = 6.0


def _config_dir() -> str:
    """Per-user cache directory that works on Linux, macOS, Windows, Termux."""
    override = os.environ.get("SUBPY_CONFIG_DIR")
    if override:
        return override
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    elif os.uname().sysname == "Darwin" if hasattr(os, "uname") else False:
        base = os.path.join(os.path.expanduser("~"), "Library", "Application Support")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "subpy")


def _cache_path() -> str:
    return os.path.join(_config_dir(), "update.json")


def current_version() -> str:
    try:
        from . import __version__

        return str(__version__)
    except Exception:
        return "0.0.0"


# --------------------------------------------------------------------------
# Version comparison
# --------------------------------------------------------------------------
_VERSION_RE = re.compile(
    r"^[vV]?"
    r"(?P<major>\d+)"
    r"(?:\.(?P<minor>\d+))?"
    r"(?:\.(?P<patch>\d+))?"
    r"(?:[-.]?(?P<pre>[a-zA-Z]+\d*(?:[-.]\d+)*))?",
    re.ASCII,
)

_PRE_RANK = {"dev": 0, "a": 1, "alpha": 1, "b": 2, "beta": 2, "rc": 3, "pre": 3, "c": 3}


def parse_version(text: str) -> tuple[int, int, int, int, int]:
    """Parse a semver-ish string into a sortable tuple.

    Pre-releases sort *before* the release they precede (``1.0.0-rc1`` is
    older than ``1.0.0``), matching SemVer 2.0.0 precedence rules.
    """
    if not text:
        return (0, 0, 0, 1, 0)
    match = _VERSION_RE.match(str(text).strip())
    if match is None:
        return (0, 0, 0, 1, 0)

    major = int(match.group("major") or 0)
    minor = int(match.group("minor") or 0)
    patch = int(match.group("patch") or 0)
    pre = match.group("pre")

    if not pre:
        return (major, minor, patch, 1, 0)

    pre_lower = pre.lower()
    label = re.match(r"[a-z]+", pre_lower)
    key = label.group(0) if label else "pre"
    digits = re.findall(r"\d+", pre_lower)
    number = int(digits[0]) if digits else 0
    return (major, minor, patch, 0, _PRE_RANK.get(key, 0) * 1000 + number)


def compare_versions(left: str, right: str) -> int:
    """Return -1, 0 or 1 as *left* is older, equal or newer than *right*."""
    a = parse_version(left)
    b = parse_version(right)
    if a == b:
        return 0
    return -1 if a < b else 1


# --------------------------------------------------------------------------
# Update check
# --------------------------------------------------------------------------
class UpdateInfo:
    """Result of a version check."""

    __slots__ = ("current", "latest", "url", "notes", "checked_at", "error")

    def __init__(
        self,
        current: str,
        latest: str = "",
        *,
        url: str = "",
        notes: str = "",
        checked_at: float = 0.0,
        error: str = "",
    ) -> None:
        self.current = current
        self.latest = latest
        self.url = url
        self.notes = notes
        self.checked_at = checked_at
        self.error = error

    @property
    def available(self) -> bool:
        if not self.latest or self.error:
            return False
        return compare_versions(self.latest, self.current) > 0

    def to_dict(self) -> dict[str, object]:
        return {
            "current": self.current,
            "latest": self.latest,
            "available": self.available,
            "url": self.url,
            "checked_at": self.checked_at,
            "error": self.error,
        }

    def message(self) -> str:
        """One-line, copy-pasteable notice."""
        if not self.available:
            return ""
        return (
            f"subpy {self.latest} is available (you have {self.current}) - "
            f"upgrade with: pip install -U subpy"
        )


def _read_cache() -> dict[str, object] | None:
    try:
        with open(_cache_path(), encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _write_cache(data: dict[str, object]) -> None:
    """Best-effort cache write; a read-only home directory is not an error."""
    try:
        directory = _config_dir()
        os.makedirs(directory, exist_ok=True)
        temp = os.path.join(directory, "update.json.tmp")
        with open(temp, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        os.replace(temp, _cache_path())
    except (OSError, ValueError):
        return


def clear_cache() -> bool:
    try:
        os.unlink(_cache_path())
        return True
    except OSError:
        return False


def latest_release(timeout: float = REQUEST_TIMEOUT) -> tuple[str, str, str]:
    """Fetch the newest release tag, its HTML URL and body.

    Returns ``("", "", "")`` on any failure: an update check must never be the
    reason a scan fails.
    """
    import urllib.error
    import urllib.request

    request = urllib.request.Request(
        RELEASES_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"subpy/{current_version()}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return ("", "", "")
    except Exception:  # pragma: no cover - defence in depth
        return ("", "", "")

    if not isinstance(payload, dict):
        return ("", "", "")
    tag = str(payload.get("tag_name") or payload.get("name") or "").strip()
    url = str(payload.get("html_url") or "")
    notes = str(payload.get("body") or "")
    return (tag, url, notes)


def check_for_update(
    *,
    force: bool = False,
    timeout: float = REQUEST_TIMEOUT,
    disabled: bool = False,
) -> UpdateInfo:
    """Return update status, using and refreshing the on-disk cache.

    Never raises. Never blocks for long. Returns an :class:`UpdateInfo` whose
    ``available`` property says whether the user should upgrade.
    """
    current = current_version()
    if disabled:
        return UpdateInfo(current)
    if os.environ.get("SUBPY_NO_UPDATE"):
        return UpdateInfo(current)

    now = time.time()
    cached = _read_cache()
    if cached and not force:
        checked_at = float(cached.get("checked_at") or 0.0)
        if now - checked_at < CHECK_INTERVAL:
            return UpdateInfo(
                current,
                str(cached.get("latest") or ""),
                url=str(cached.get("url") or ""),
                notes=str(cached.get("notes") or ""),
                checked_at=checked_at,
            )

    tag, url, notes = latest_release(timeout=timeout)
    if not tag:
        # Network or rate limit: keep the previous answer if it still parses.
        if cached:
            return UpdateInfo(
                current,
                str(cached.get("latest") or ""),
                url=str(cached.get("url") or ""),
                checked_at=float(cached.get("checked_at") or 0.0),
                error="check failed",
            )
        return UpdateInfo(current, error="check failed")

    latest = tag.lstrip("vV")
    _write_cache(
        {
            "checked_at": now,
            "latest": latest,
            "url": url,
            "notes": notes[:4000],
        }
    )
    return UpdateInfo(current, latest, url=url, notes=notes, checked_at=now)
