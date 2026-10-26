"""Line reading with a time limit, for tests/tls/tls_util.mojo (test-only
Python; not a test file itself): a thread reads a child's stdout into a
queue, so a test that waits for a line it will never get fails after
`timeout` seconds instead of hanging."""

import queue
import threading


class Lines:
    def __init__(self, stream):
        self._q = queue.Queue()
        threading.Thread(target=self._read, args=(stream,), daemon=True).start()

    def _read(self, stream):
        for line in stream:
            self._q.put(line.rstrip("\n"))
        self._q.put(None)

    def next(self, timeout):
        """The next line, "" once the stream has ended; raises TimeoutError."""
        try:
            line = self._q.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError(f"no line from the peer within {timeout} s") from None
        if line is None:
            self._q.put(None)
            return ""
        return line
