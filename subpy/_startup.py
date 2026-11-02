"""Entry point that arms signal handling before anything expensive loads.

Importing ``asyncio`` plus the scanner costs about 2.3 s cold on a phone.
For that whole window a started process had no handler at all, so a SIGTERM
arriving during startup killed it outright (exit ``-15``) instead of reporting
the documented ``143``. Startup is exactly when a supervisor is most likely to
send one — a slow start looks like a hang.

So this module does the cheapest possible thing first (arm a handler), and
only then imports the CLI. Both entry points route through here:
``python -m subpy`` and the ``subpy`` console script.
"""

from __future__ import annotations

import contextlib
import signal
import sys
from collections.abc import Sequence

__all__ = ["main"]

#: Exit codes, duplicated here so this module needs no heavy imports.
_EXIT_INTERRUPT = 130
_EXIT_TERM = 143

#: Set by the early handler; read by the CLI once the event loop exists.
EARLY_SIGNAL: dict = {"value": 0}


def _record_signal(signum: int, _frame) -> None:  # noqa: ANN001
    code = _EXIT_TERM if signum == getattr(signal, "SIGTERM", -1) else _EXIT_INTERRUPT
    if EARLY_SIGNAL["value"]:
        # A second signal means "stop now". Restore the platform default so
        # the process can always be killed, even if it is wedged.
        with contextlib.suppress(OSError, ValueError):
            signal.signal(signum, signal.SIG_DFL)
        raise SystemExit(code)
    EARLY_SIGNAL["value"] = code


def _arm_signals() -> None:
    for name in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        with contextlib.suppress(OSError, ValueError, RuntimeError):
            signal.signal(sig, _record_signal)


_arm_signals()

# Heavy imports come after the handler is live.
from .cli import main as _cli_main  # noqa: E402


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI, reporting a signal that arrived during startup."""
    if EARLY_SIGNAL["value"]:
        # Interrupted before the scan could even begin.
        label = "terminated" if EARLY_SIGNAL["value"] == _EXIT_TERM else "interrupted"
        print(f"! {label} during startup", file=sys.stderr)
        return EARLY_SIGNAL["value"]
    return _cli_main(argv, early_signal=EARLY_SIGNAL)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
