"""相同查询共享上游请求、等待者取消互不影响。"""

import asyncio

import pytest

from recdns.clock import FakeClock
from tests.tree import build_tree


async def test_concurrent_same_query_shares_single_upstream():
    clk = FakeClock()
    r, net, zones = build_tree(clk)
    # 让根对第一次 www.test. 查询挂起，直到测试显式放行
    release = zones["."].add_hold("www.test.")
    await asyncio.sleep(0)  # 让 event 完成创建

    t1 = asyncio.create_task(r.resolve("www.test.", "A"))
    t2 = asyncio.create_task(r.resolve("www.test.", "A"))
    t3 = asyncio.create_task(r.resolve("www.test.", "A"))
    await asyncio.sleep(0)
    for _ in range(10):
        await asyncio.sleep(0)
    assert not t1.done() and not t2.done() and not t3.done()

    # 挂起期间三个请求只产生一次对根的上游查询
    held_queries = net.queries
    assert held_queries == 1
    zones["."].release("www.test.")
    results = await asyncio.gather(t1, t2, t3)
    # 三个等待者结果一致；整条递归（root + test 两跳）只执行了一次，
    # 总查询数等于 2，而不是每个等待者各走一遍
    assert net.queries == 2
    ips_sets = [sorted(x.address for rr in a.rrsets for x in rr) for a in results]
    assert ips_sets == [["1.1.1.1", "1.1.1.2"]] * 3


async def test_cancelling_one_waiter_does_not_cancel_others():
    clk = FakeClock()
    r, net, zones = build_tree(clk)
    release = zones["."].add_hold("www.test.")
    await asyncio.sleep(0)

    t1 = asyncio.create_task(r.resolve("www.test.", "A"))
    t2 = asyncio.create_task(r.resolve("www.test.", "A"))
    await asyncio.sleep(0)
    for _ in range(10):
        await asyncio.sleep(0)

    t1.cancel()
    with pytest.raises(asyncio.CancelledError):
        await t1
    # t2 仍然活着
    assert not t2.done()

    zones["."].release("www.test.")
    ans = await t2
    assert sorted(x.address for rr in ans.rrsets for x in rr) == ["1.1.1.1", "1.1.1.2"]


async def test_new_waiter_after_cancelled_one_still_gets_result():
    """取消等待者后再加入同 key 的新请求，共享的驱动仍可服务它。"""
    clk = FakeClock()
    r, net, zones = build_tree(clk)
    zones["."].add_hold("www.test.")
    await asyncio.sleep(0)

    t1 = asyncio.create_task(r.resolve("www.test.", "A"))
    t2 = asyncio.create_task(r.resolve("www.test.", "A"))
    await asyncio.sleep(0)
    for _ in range(10):
        await asyncio.sleep(0)

    t1.cancel()
    with pytest.raises(asyncio.CancelledError):
        await t1

    t3 = asyncio.create_task(r.resolve("www.test.", "A"))
    await asyncio.sleep(0)
    zones["."].release("www.test.")
    a2, a3 = await asyncio.gather(t2, t3)
    for a in (a2, a3):
        assert sorted(x.address for rr in a.rrsets for x in rr) == [
            "1.1.1.1",
            "1.1.1.2",
        ]


async def test_distinct_queries_are_not_merged():
    clk = FakeClock()
    r, net, zones = build_tree(clk)
    a = await r.resolve("www.test.", "A")
    b = await r.resolve("host.org.test.", "A")
    assert a.canonical_name.to_text() == "www.test."
    assert b.canonical_name.to_text() == "host.org.test."
    assert net.queries >= 4  # 两组查询，各走各的委派链
