"""可控时钟 FakeClock 的行为测试。"""

import asyncio

import pytest

from recdns.clock import FakeClock


async def test_sleep_blocks_until_advance():
    clk = FakeClock()
    done = []

    async def waiter():
        await clk.sleep(10)
        done.append(clk.monotonic())

    task = asyncio.create_task(waiter())
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert done == []
    assert clk.monotonic() == 0

    await clk.advance(5)
    assert done == []  # 还没到 10
    await clk.advance(5)
    assert done == [10]
    assert task.done()


async def test_multiple_timers_fire_in_time_order():
    clk = FakeClock()
    order = []

    async def w(d, tag):
        await clk.sleep(d)
        order.append((tag, clk.monotonic()))

    t2 = asyncio.create_task(w(8, "late"))
    t1 = asyncio.create_task(w(3, "early"))
    t0 = asyncio.create_task(w(3, "early2"))
    await clk.advance(10)
    assert [tag for tag, _t in order] == ["early", "early2", "late"]
    assert all(t.done() for t in (t0, t1, t2))


async def test_cancelled_timer_removed_on_advance():
    clk = FakeClock()

    async def waiter():
        await clk.sleep(10)
        pytest.fail("should have been cancelled")

    task = asyncio.create_task(waiter())
    await asyncio.sleep(0)
    assert clk.pending_timer_count() == 1
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await clk.advance(20)  # 不应抛错
    assert clk.monotonic() == 20
