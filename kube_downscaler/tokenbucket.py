import time
from threading import Lock


class TokenBucket:
    def __init__(self, qps, burst):
        self.qps = qps
        self.burst = burst
        self.tokens = burst
        self.last_update = time.time()
        self.lock = Lock()

    def acquire(self, tokens=1):
        with self.lock:
            if self.qps > 0 and self.burst > 0:
                while True:
                    now = time.time()
                    elapsed = now - self.last_update

                    self.tokens = min(float(self.burst), self.tokens + elapsed * self.qps)
                    self.last_update = now

                    if self.tokens >= tokens:
                        self.tokens -= tokens
                        return

                    sleep_time = (tokens - self.tokens) / self.qps
                    time.sleep(sleep_time)