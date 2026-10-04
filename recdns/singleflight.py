"""相同查询共享同一个正在进行的上游请求。

* 同一 ``key`` 的并发调用只执行一次工厂协程，其余调用等待同一次执行；
* 某个等待者（包括发起者）被取消时，只中断它自己：每个等待者 await
  的是自己的私有 Future，由共享飞行在完成时统一喂结果；工厂在与
  等待者无关的独立任务里运行，不会被等待者的取消带走；
* 飞行在工厂完成后保留一个事件循环周期再摘除登记，让同批恢复的
  等待者（它们可能在恢复路径上再次以同 key 进入）复用结果，杜绝
  “结果刚产生、等待者尚未重入”窗口里的重复上游查询；
* 通过 ContextVar 沿调用链记录进行中的 key，用来识别“区域内 NS
  名称需要解析自身区域的 glue”这类自引用环（此时不存在可用 glue，
  应直接判 NoGlue，而不是死锁）。
"""

import asyncio
import contextvars
from collections.abc import Callable
from typing import Any

from .exceptions import NoGlue

_active: contextvars.ContextVar[frozenset[Any]] = contextvars.ContextVar(
    "recdns_inflight", default=frozenset()
)


class _Flight:
    __slots__ = ("result", "factory_task", "waiters", "settled")

    def __init__(self):
        # result: 完成后保存 ("ok", value) 或 ("err", exception)
        self.result: tuple | None = None
        self.factory_task: asyncio.Task | None = None
        self.waiters: list[asyncio.Future] = []
        self.settled = False


class SingleFlight:
    def __init__(self) -> None:
        self._inflight: dict[Any, _Flight] = {}

    async def do(self, key: Any, factory: "Callable[[], Any]") -> Any:
        flight = self._inflight.get(key)
        if flight is not None and key in _active.get():
            # 自己的上游调用链又需要自己：区域内 NS 却没有可用 glue
            raise NoGlue(f"in-bailiwick nameserver {key} has no usable glue")
        if flight is None:
            flight = _Flight()
            self._inflight[key] = flight
            flight.factory_task = asyncio.create_task(
                self._run_factory(key, flight, factory)
            )

        # 每个等待者拥有私有 Future，取消它不会触及共享飞行状态
        mine: asyncio.Future = asyncio.get_running_loop().create_future()
        if flight.result is not None:
            # 工厂已完成（宽限期内）：直接复用结果，不登记为等待者
            self._deliver(flight, mine)
        else:
            flight.waiters.append(mine)
        try:
            return await mine
        finally:
            if mine in flight.waiters:
                flight.waiters.remove(mine)

    @staticmethod
    def _deliver(flight: _Flight, fut: asyncio.Future) -> None:
        kind, value = flight.result
        if not fut.done():
            if kind == "ok":
                fut.set_result(value)
            else:
                fut.set_exception(value)

    async def _run_factory(
        self, key: Any, flight: _Flight, factory: "Callable[[], Any]"
    ) -> None:
        token = _active.set(_active.get() | {key})
        try:
            try:
                result = await factory()
            except BaseException as exc:
                flight.result = ("err", exc)
            else:
                flight.result = ("ok", result)
            flight.settled = True
            for fut in list(flight.waiters):
                self._deliver(flight, fut)
            # 再让出一个循环步后才摘除登记：此刻同批等待者必然都已
            # 恢复并有机会以同 key 重入，从而复用结果而不重复查询。
            asyncio.get_running_loop().call_soon(self._schedule_cleanup, key, flight)
        finally:
            _active.reset(token)

    def _schedule_cleanup(self, key: Any, flight: _Flight) -> None:
        async def _cleanup():
            # 再让一个循环步，保证所有因 set_result 就绪的等待者跑完
            await asyncio.sleep(0)
            cur = self._inflight.get(key)
            if cur is flight and flight.settled:
                self._inflight.pop(key, None)

        asyncio.create_task(_cleanup())
