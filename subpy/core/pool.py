"""Make a cancelled scan actually exit, even with HTTP still in flight.

Passive sources perform blocking HTTP inside ``loop.run_in_executor``. When a
scan is cancelled mid-source, the worker thread stays parked inside a socket
read. Two stdlib mechanisms then keep the interpreter alive:

* ``concurrent.futures.thread`` spawns **non-daemon** workers, and
* ``threading._shutdown`` joins every non-daemon thread before the process
  may exit.

Confirmed by dumping the stacks of a hung run: the main thread sat in
``threading._shutdown`` waiting on a worker blocked in
``urllib.request.urlopen``. Measured before the fix, SIGINT during a
wikipedia.org scan hung in roughly two runs out of three.

An earlier attempt reimplemented the executor's worker loop to set
``daemon=True``. That broke outright on Python 3.14, where ``_WorkItem.run``
gained a ``ctx`` argument, and every source failed with ``TypeError``. A
second attempt unregistered the threads from ``threads_queues``, but
``threading._shutdown`` still joined them because they remained non-daemon.

So this module takes the only approach that is robust across versions and
does not touch private worker internals: after the reporter has flushed and
the output file has been written, *if* blocked threads would delay exit, the
process terminates through ``os._exit``. All user-visible work has already
completed by then; what is abandoned is only the sockets, which the OS
reclaims.
"""

from __future__ import annotations

import contextlib
import sys
import threading
import time

__all__ = ["abandon_blocked_threads", "hard_exit"]

#: How long to let well-behaved threads finish before giving up on them.
_GRACE_SECONDS = 0.35


def abandon_blocked_threads(grace: float = _GRACE_SECONDS) -> bool:
    """Return True when a non-daemon thread is still running after *grace*.

    Only blocking HTTP workers are expected here. Anything still alive after
    a third of a second is parked in a socket and will not finish soon.
    """
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        alive = [
            t
            for t in threading.enumerate()
            if t is not threading.main_thread() and t.is_alive() and not t.daemon
        ]
        if not alive:
            return False
        time.sleep(0.02)
    return True


def hard_exit(code: int) -> None:
    """Flush stdio and exit immediately, skipping thread joins.

    ``os._exit`` bypasses ``threading._shutdown``, which is the join that
    hangs. Streams are flushed first so no output is lost.
    """
    import os

    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(Exception):
            stream.flush()
    with contextlib.suppress(Exception):
        sys.stdout.flush()
    os._exit(code)
