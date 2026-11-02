"""Keep blocked HTTP calls from holding the process open on Ctrl-C.

Passive sources perform blocking HTTP through ``loop.run_in_executor``. Three
stdlib behaviours then conspire to hang a cancelled scan:

* ``ThreadPoolExecutor`` creates **non-daemon** threads;
* ``concurrent.futures.thread`` registers an ``atexit`` hook that *joins*
  every worker; and
* ``asyncio.run`` calls ``loop.shutdown_default_executor()``, which waits for
  in-flight work to drain.

Measured on Ctrl-C during a slow source: the process was still alive 90+
seconds later, stuck in ``Runner.close`` -> ``run_until_complete`` ->
``select``. That is indistinguishable from a freeze.

Two changes fix it, and both are needed:

1. Worker threads are daemons, created that way (Python forbids setting
   ``daemon`` on a thread that has already started).
2. The CLI drives a loop directly instead of ``asyncio.run``, so teardown
   does not wait for blocked sockets. Abandoned sockets are reclaimed by the
   OS, which is the right outcome for a short-lived process.
"""

from __future__ import annotations

import contextlib
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import thread as _cf_thread

__all__ = ["DaemonThreadPoolExecutor", "install_default_executor", "shutdown"]


class DaemonThreadPoolExecutor(ThreadPoolExecutor):
    """A ThreadPoolExecutor whose workers never delay interpreter exit.

    Subclassing (rather than wrapping) matters: ``set_default_executor``
    rejects anything that is not a ``ThreadPoolExecutor`` instance.
    """

    def _adjust_thread_count(self) -> None:
        """Spawn workers as daemons, honouring the max_workers cap."""
        try:
            idle = self._idle_semaphore  # type: ignore[attr-defined]
            threads = self._threads  # type: ignore[attr-defined]
            work_queue = self._work_queue  # type: ignore[attr-defined]
        except AttributeError:  # pragma: no cover - unexpected internals
            super()._adjust_thread_count()
            return

        if idle.acquire(blocking=False):
            return

        if len(threads) >= self._max_workers:
            return

        def _worker_loop() -> None:
            # Mirrors concurrent.futures.thread._worker closely enough for
            # our use, without registering in the shared atexit registry.
            while True:
                work_item = work_queue.get()
                if work_item is None:
                    work_queue.put(None)
                    return
                if not work_item.future.set_running_or_notify_cancel():
                    continue
                try:
                    result = work_item.run()
                except BaseException as exc:  # noqa: BLE001 - surfaced via future
                    work_item.future.set_exception(exc)
                else:
                    work_item.future.set_result(result)

        name = f"{self._thread_name_prefix or 'subpy'}_{len(threads)}"
        thread = threading.Thread(name=name, target=_worker_loop, daemon=True)
        thread.start()
        threads.add(thread)

    def _forget_atexit_registry(self) -> None:
        """Drop our threads from the interpreter's join-on-exit registry."""
        registry = getattr(_cf_thread, "_threads_queues", None)
        if not registry:
            return
        for thread in list(getattr(self, "_threads", ())):  # type: ignore[attr-defined]
            registry.pop(thread, None)


_SHARED: DaemonThreadPoolExecutor | None = None
_LOCK = threading.Lock()


def install_default_executor(loop, max_workers: int = 24) -> DaemonThreadPoolExecutor:
    """Give *loop* a daemon-backed default executor."""
    global _SHARED
    with _LOCK:
        if _SHARED is None:
            _SHARED = DaemonThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="subpy")
        pool = _SHARED
    pool._forget_atexit_registry()
    loop.set_default_executor(pool)
    return pool


def shutdown(wait: bool = False) -> None:
    """Release the shared pool. Never waits by default."""
    global _SHARED
    with _LOCK:
        pool, _SHARED = _SHARED, None
    if pool is None:
        return
    pool._forget_atexit_registry()
    try:
        pool.shutdown(wait=wait, cancel_futures=True)
    except TypeError:  # pragma: no cover - Python 3.8
        with contextlib.suppress(Exception):
            pool.shutdown(wait=wait)
    except Exception:
        pass
