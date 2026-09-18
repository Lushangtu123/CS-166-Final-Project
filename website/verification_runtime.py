"""A non-queueing, bounded pool for best-effort outbound verification checks."""

from concurrent.futures import ThreadPoolExecutor
from threading import BoundedSemaphore


class BoundedExecutor:
    def __init__(self, workers=10):
        self._slots = BoundedSemaphore(workers)
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix='verification')

    def submit(self, function, *args):
        if not self._slots.acquire(blocking=False):
            return None
        try:
            future = self._pool.submit(function, *args)
        except BaseException:
            self._slots.release()
            raise
        # A timeout does not stop a running thread: retain its slot until done.
        future.add_done_callback(lambda _: self._slots.release())
        return future

    def shutdown(self):
        self._pool.shutdown(wait=False, cancel_futures=True)
