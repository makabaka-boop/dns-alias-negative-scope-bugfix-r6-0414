"""SingleFlight 单元行为：共享、取消隔离、自引用检测。"""

import asyncio

import pytest

from recdns.exceptions import NoGlue
from recdns.singleflight import SingleFlight


async def test_factory_runs_once_for_concurrent_callers():
    sf = SingleFlight()
    started = asyncio.Event()
    calls = 0

    async def factory():
        nonlocal calls
        calls += 1
        started.set()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        return "v"

    async def go():
        return await sf.do("k", factory)

    results = await asyncio.gather(*[asyncio.create_task(go()) for _ in range(5)])
    assert results == ["v"] * 5
    assert calls == 1


async def test_waiter_cancellation_is_isolated():
    sf = SingleFlight()
    release = asyncio.Event()
    cancelled_waiter_got = object()

    async def factory():
        await release.wait()
        return 42

    a = asyncio.create_task(sf.do("k", factory))
    b = asyncio.create_task(sf.do("k", factory))
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    a.cancel()
    with pytest.raises(asyncio.CancelledError):
        await a
    assert not b.done()  # b 与工厂都没被取消
    release.set()
    assert await b == 42


async def test_second_wave_after_completion_reuses_result():
    sf = SingleFlight()
    calls = 0

    async def factory():
        nonlocal calls
        calls += 1
        await asyncio.sleep(0)
        return "once"

    first = await sf.do("k", factory)
    assert first == "once"
    # 紧接着的并发同 key 调用应在宽限期内复用
    results = await asyncio.gather(
        *[asyncio.create_task(sf.do("k", factory)) for _ in range(3)]
    )
    assert results == ["once"] * 3
    assert calls == 1


async def test_self_referential_key_detected_as_no_glue():
    """工厂执行期间又以同 key 进入 -> 自引用，直接 NoGlue。"""
    sf = SingleFlight()

    async def recursive_factory():
        return await sf.do(
            ("ns.loop.", 1),
            lambda: (_ for _ in ()).throw(AssertionError("unreachable")),
        )

    with pytest.raises(NoGlue):
        await sf.do(("ns.loop.", 1), recursive_factory)
