import os
import threading
import unittest

from kyber6g.ground.sched import lower_priority
from kyber6g.transport.link import udp_counters


class TestSched(unittest.TestCase):
    def test_only_the_calling_thread_is_demoted(self):
        if not hasattr(os, "setpriority"):
            self.skipTest("no setpriority on this platform")
        main_before = os.getpriority(os.PRIO_PROCESS, threading.get_native_id())
        got = []
        t = threading.Thread(target=lambda: got.append(lower_priority(8)))
        t.start()
        t.join()
        self.assertEqual(got[0], min(19, max(main_before, 8)) if main_before < 8 else main_before)  # a worker thread: nice 8
        self.assertEqual(os.getpriority(os.PRIO_PROCESS, threading.get_native_id()), main_before)   # the caller (receiver) is untouched

    def test_workers_block_while_there_is_no_frame_instead_of_spinning(self):
        """Before the first frame of a session the picture is None but its sequence number (0) differs from a fresh
        worker's -1. The wait used to return at once: both ML workers spun at 100 % CPU from start-up until LIVE was
        pressed and starved every other thread (the finder model took 128 s to load instead of 8 s)."""
        import time
        from kyber6g.ground.sched import next_frame

        class Video:
            latest, jpeg_seq, latest_ts, cond = None, 0, None, threading.Condition()
        v = Video()
        t0, cpu0, calls = time.monotonic(), time.thread_time(), 0
        while time.monotonic() - t0 < 1.0:
            self.assertIsNone(next_frame(v, -1, timeout=0.2))
            calls += 1
        self.assertLessEqual(calls, 7)                                  # ~5 waits of 0.2 s, not thousands of spins
        self.assertLess(time.thread_time() - cpu0, 0.2)                 # and almost no CPU time
        with v.cond:                                                    # first frame arrives
            v.latest, v.jpeg_seq, v.latest_ts = b"jpeg", 1, 123.5
            v.cond.notify_all()
        self.assertEqual(next_frame(v, -1), (b"jpeg", 1, 123.5))
        t0 = time.monotonic()
        self.assertIsNone(next_frame(v, 1, timeout=0.2))                # the same frame is never handed out twice
        self.assertGreaterEqual(time.monotonic() - t0, 0.15)

    def test_udp_counters_are_numbers(self):
        c = udp_counters()
        if c:
            self.assertIn("InDatagrams", c)
            self.assertIn("RcvbufErrors", c)
            self.assertTrue(all(isinstance(v, int) for v in c.values()))


if __name__ == "__main__":
    unittest.main()
