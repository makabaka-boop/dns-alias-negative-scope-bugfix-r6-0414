"""UDP 截断 -> TCP 重试，以及跨区别名链的测试。"""

import pytest

from recdns.clock import FakeClock
from tests.tree import build_tree


def ips(answer):
    return sorted(rd.address for rr in answer.rrsets for rd in rr)


async def test_truncated_udp_response_triggers_tcp_retry():
    clk = FakeClock()
    r, net, zones = build_tree(clk)
    # www.test. 第一次 UDP 查询返回 TC=1
    zones["test."].set_tc("www.test.", times=1)
    ans = await r.resolve("www.test.", "A")
    assert ips(ans) == ["1.1.1.1", "1.1.1.2"]
    # 有且仅有一次 UDP 后接 TCP
    assert net.udp_count >= 1
    assert net.tcp_count == 1


async def test_tc_only_applies_configured_times():
    clk = FakeClock()
    r, net, zones = build_tree(clk)
    zones["test."].set_tc("www.test.", times=1)
    await r.resolve("www.test.", "A")
    assert net.tcp_count == 1
    # 缓存命中，根本不产生新流量
    before = (net.udp_count, net.tcp_count)
    await r.resolve("www.test.", "A")
    assert (net.udp_count, net.tcp_count) == before


async def test_truncation_during_referral_followed_over_tcp():
    """截断发生在沿委派向下的查询上，TCP 重试后解析仍成功。"""
    clk = FakeClock()
    r, net, zones = build_tree(clk)
    # test 权威对 host.org.test. 的查询第一次返回 TC
    zones["test."].set_tc("host.org.test.", times=1)
    ans = await r.resolve("host.org.test.", "A")
    assert ips(ans) == ["2.2.2.2"]
    assert net.tcp_count == 1


async def test_cname_across_zone_boundary():
    """test 区把 goto.test. CNAME 到 org.test 区，需重新找区割。"""
    clk = FakeClock()
    r, _net, _z = build_tree(clk)
    ans = await r.resolve("goto.test.", "A")
    assert [c.name.to_text() for c in ans.cnames] == ["goto.test."]
    assert ans.canonical_name.to_text() == "target.org.test."
    assert ips(ans) == ["2.2.2.3"]


async def test_cross_zone_alias_cached_second_time_no_queries():
    clk = FakeClock()
    r, net, _z = build_tree(clk)
    await r.resolve("goto.test.", "A")
    before = net.queries
    ans = await r.resolve("goto.test.", "A")
    assert net.queries == before
    assert ips(ans) == ["2.2.2.3"]


async def test_cross_zone_alias_target_nxdomain_cached_by_target_name():
    import dns.name

    from recdns.exceptions import NXDOMAINError

    clk = FakeClock()
    r, net, _z = build_tree(clk)
    with pytest.raises(NXDOMAINError) as ei:
        await r.resolve("dead.test.", "A")
    # 不存在的是跨区后的目标名
    assert ei.value.qname == dns.name.from_text("ghost.org.test.")
    # 负缓存按目标名称：再查直接命中，且对不同类型同样生效
    before = net.queries
    with pytest.raises(NXDOMAINError):
        await r.resolve("ghost.org.test.", "A")
    with pytest.raises(NXDOMAINError):
        await r.resolve("ghost.org.test.", "NS")
    with pytest.raises(NXDOMAINError):
        await r.resolve("dead.test.", "A")
    assert net.queries == before
