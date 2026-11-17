"""时钟与确定性 ID 生成。

Clock 可被显式冻结/拨快，使过期类测试可重放；IdGenerator 基于固定种子的
HMAC-SHA256 计数器产生 jti/request_id，同一注册表、同一调用序列下输出稳定，
满足“固定种子可重放”。
"""

from __future__ import annotations

import hashlib
import threading
import time


class Clock:
    """秒级时钟；默认走系统时间，也可固定为虚拟时间。"""

    def __init__(self, fixed: int | None = None):
        self._fixed = fixed
        self._lock = threading.Lock()

    def now(self) -> int:
        with self._lock:
            if self._fixed is not None:
                return self._fixed
            return int(time.time())

    def freeze(self, unix_seconds: int) -> None:
        with self._lock:
            self._fixed = int(unix_seconds)

    def advance(self, seconds: int) -> None:
        with self._lock:
            if self._fixed is None:
                self._fixed = int(time.time())
            self._fixed += int(seconds)


class IdGenerator:
    """确定性 ID 生成器：HMAC-SHA256(seed, namespace || counter) 的 hex 截断。"""

    def __init__(self, seed: bytes):
        self._seed = bytes(seed)
        self._counter = 0
        self._lock = threading.Lock()

    def _next(self, namespace: str) -> str:
        with self._lock:
            counter = self._counter
            self._counter += 1
        digest = hashlib.sha256(
            self._seed + b"|" + namespace.encode("ascii") + b"|" + str(counter).encode("ascii")
        ).hexdigest()
        return f"{namespace}-{digest[:32]}"

    def jti(self) -> str:
        return self._next("jti")

    def request_id(self) -> str:
        return self._next("req")
