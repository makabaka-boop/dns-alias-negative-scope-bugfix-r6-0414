"""时钟抽象。

生产代码使用 :class:`SystemClock`；测试使用 :class:`FakeClock`，其
``sleep`` 注册定时器，``advance`` 让时间快进到某一时刻，并在每一步
把已就绪的回调全部排空。
"""

import asyncio
import heapq
from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    def monotonic(self) -> float: ...

    async def sleep(self, delay: float) -> None: ...


class SystemClock:
    """基于事件循环真实时间的时钟。"""

    def monotonic(self) -> float:
        return asyncio.get_running_loop().time()

    async def sleep(self, delay: float) -> None:
        await asyncio.sleep(delay)


class _TimerHandle:
    """FakeClock 内部的一个定时唤醒。"""

    def __init__(self, loop, when: float, fut: asyncio.Future):
        self._loop = loop
        self.when = when
        self._fut = fut
        self.cancelled = False

    def fire(self) -> None:
        if not self._fut.done():
            self._loop.call_soon(self._fut.set_result, None)


class FakeClock:
    """可控时钟：时间只随 :meth:`advance` / :meth:`sleep` 前进。"""

    def __init__(self) -> None:
        self._now = 0.0
        self._timers: list = []  # (when, seq, handle)
        self._seq = 0

    def monotonic(self) -> float:
        return self._now

    async def sleep(self, delay: float) -> None:
        if delay <= 0:
            await _drain()
            return
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        seq = self._seq
        self._seq += 1
        heapq.heappush(
            self._timers,
            (self._now + delay, seq, _TimerHandle(loop, self._now + delay, fut)),
        )
        await fut

    async def advance(self, seconds: float) -> None:
        """把时钟向前拨 ``seconds`` 秒，排空期间所有就绪回调。"""
        # 先让已就绪的任务体跑完（它们可能在此注册新的定时器）
        await _drain()
        target = self._now + seconds
        while self._timers and self._timers[0][0] <= target:
            when, _seq, handle = heapq.heappop(self._timers)
            if handle.cancelled:
                continue
            self._now = when
            handle.fire()
            await _drain()
        self._now = target
        await _drain()

    def pending_timer_count(self) -> int:
        return sum(1 for _t, _s, h in self._timers if not h.cancelled)


async def _drain() -> None:
    """反复让出直到事件循环的 ready 队列为空。"""
    loop = asyncio.get_running_loop()
    ready = getattr(loop, "_ready", None)
    if ready is None:  # pragma: no cover - 非 CPython 事件循环的保守退路
        await asyncio.sleep(0)
        return
    for _ in range(10000):
        if not ready:
            return
        await asyncio.sleep(0)
    raise RuntimeError("fake clock drain did not settle (callback loop?)")
