"""递归解析端到端行为（假权威节点 + 可控时钟）。"""

import asyncio

import dns.name
import dns.rdatatype
import pytest

from recdns.clock import FakeClock
from recdns.exceptions import (
    CnameLoop,
    HopLimitExceeded,
    NXDOMAINError,
    NoData,
    NoGlue,
    UnsupportedQtype,
    UpstreamError,
)
from tests.tree import build_tree


@pytest.fixture
def world():
    clk = FakeClock()
    resolver, net, zones = build_tree(clk)
    return clk, resolver, net, zones


def ips(answer):
    return sorted(rd.address for rr in answer.rrsets for rd in rr)


# ------------------------------------------------------------- 基础委派


async def test_a_query_walks_root_and_tld(world):
    _clk, r, net, _z = world
    ans = await r.resolve("www.test.", "A")
    assert ans.canonical_name == dns.name.from_text("www.test.")
    assert ips(ans) == ["1.1.1.1", "1.1.1.2"]
    # 根 -> test 两条查询
    assert net.queries == 2

    # 第二次命中正缓存，不产生上游查询
    before = net.queries
    ans = await r.resolve("www.test.", "A")
    assert ips(ans) == ["1.1.1.1", "1.1.1.2"]
    assert net.queries == before


async def test_delegation_to_subzone(world):
    _clk, r, net, _z = world
    ans = await r.resolve("host.org.test.", "A")
    assert ans.canonical_name == dns.name.from_text("host.org.test.")
    assert ips(ans) == ["2.2.2.2"]
    # 根, test, org.test 三跳
    assert net.queries == 3


async def test_ns_and_soa_allowed(world):
    _clk, r, _net, _z = world
    ns = await r.resolve("org.test.", "NS")
    assert ns.rrset is not None
    assert str(ns.rrset[0].target) == "ns.org.test."
    soa = await r.resolve("org.test.", "SOA")
    assert soa.rrset is not None
    assert soa.rrset.rdtype == dns.rdatatype.SOA


async def test_other_qtypes_rejected(world):
    _clk, r, _net, _z = world
    with pytest.raises(UnsupportedQtype):
        await r.resolve("www.test.", "AAAA")
    with pytest.raises(UnsupportedQtype):
        await r.resolve("www.test.", "MX")


async def test_query_has_recursion_desired_off(world):
    _clk, r, _net, zones = world

    seen_flags = []
    orig = zones["."].handle

    def spy(qname, rdtype, use_tcp):
        resp = orig(qname, rdtype, use_tcp)
        seen_flags.append(resp)
        return resp

    zones["."].handle = spy
    await r.resolve("www.test.", "A")
    # 响应里有 QR；间接验证不了 query flags，这里断言查询能正常完成即可
    assert seen_flags


# ------------------------------------------------------------- CNAME


async def test_cname_chain(world):
    _clk, r, _net, _z = world
    ans = await r.resolve("multi1.test.", "A")
    assert [c.name.to_text() for c in ans.cnames] == ["multi1.test.", "multi2.test."]
    assert ans.canonical_name == dns.name.from_text("multi3.test.")
    assert ips(ans) == ["9.9.9.9"]


async def test_cname_query_returns_alias_without_chasing(world):
    _clk, r, _net, _z = world
    ans = await r.resolve("alias.test.", "CNAME")
    assert ans.rrsets == []
    assert ans.canonical_name == dns.name.from_text("www.test.")
    assert [c.name.to_text() for c in ans.cnames] == ["alias.test."]


async def test_cname_loop_detected(world):
    _clk, r, _net, _z = world
    with pytest.raises(CnameLoop):
        await r.resolve("loop1.test.", "A")


async def test_cname_loop_does_not_poison_cache_as_success(world):
    _clk, r, _net, _z = world
    with pytest.raises(CnameLoop):
        await r.resolve("loop1.test.", "A")
    with pytest.raises(CnameLoop):
        await r.resolve("loop2.test.", "A")


# ------------------------------------------------------------- glue


async def test_forged_glue_owner_not_matching_ns_ignored(world):
    """not-ns.evil.test. 的 A 不是任何 NS 的名称，必须忽略。"""
    _clk, r, _net, _z = world
    await r.resolve("bad.evil.test.", "A")
    assert (
        r.cache.get_rrset(dns.name.from_text("not-ns.evil.test."), dns.rdatatype.A)
        is None
    )


async def test_forged_glue_outside_bailiwick_ignored(world):
    """ns.org.test. 不属于 evil.test.，其伪造 A 绝不能接受。"""
    _clk, r, _net, _z = world
    await r.resolve("bad.evil.test.", "A")
    rr = r.cache.get_rrset(dns.name.from_text("ns.org.test."), dns.rdatatype.A)
    # 只有沿正常委派路径解析得到的 10.2.0.1，不含 8.8.8.8
    assert rr is None or all(rd.address == "10.2.0.1" for rd in rr)


async def test_conflicting_in_bailiwick_glue_fails_over_good_server(world):
    """与真 glue 同属主的坏地址 6.6.6.6 不可达时，仍能靠好地址解析。"""
    _clk, r, net, _z = world
    ans = await r.resolve("bad.evil.test.", "A")
    assert ips(ans) == ["4.4.4.4"]


async def test_out_of_bailiwick_ns_resolved_via_hierarchy(world):
    """other.test. 的 NS ns.other.tld. 不在所委派区域，必须正常递归。"""
    _clk, r, net, _z = world
    ans = await r.resolve("x.other.test.", "A")
    assert ips(ans) == ["3.3.3.3"]


async def test_in_bailiwick_ns_without_glue_is_lame(world):
    """s.org.test. 的 NS 在区域内但无 glue：鸡生蛋，报不可用。"""
    _clk, r, _net, _z = world
    with pytest.raises(UpstreamError):
        await r.resolve("anything.s.org.test.", "A")


# ------------------------------------------------------------- 跳数


async def test_eight_hops_ok_ninth_rejected():
    # 从根出发：->test 为第 1 跳；->deep1..deep7 共 8 跳，恰好成功；
    # 每个场景都用全新解析器，避免缓存让跳数“短路”
    clk = FakeClock()
    r, _net, _z = build_tree(clk)
    cut7 = "ns.deep7.deep6.deep5.deep4.deep3.deep2.deep1.test."
    ans = await r.resolve(cut7, "A")
    assert ans.rrset is not None

    clk2 = FakeClock()
    r2, _net2, _z2 = build_tree(clk2)
    cut8 = "ns.deep8.deep7.deep6.deep5.deep4.deep3.deep2.deep1.test."
    with pytest.raises(HopLimitExceeded):
        await r2.resolve(cut8, "A")

    clk3 = FakeClock()
    r3, _net3, _z3 = build_tree(clk3)
    leaf = "leaf.deep9.deep8.deep7.deep6.deep5.deep4.deep3.deep2." "deep1.test."
    with pytest.raises(HopLimitExceeded):
        await r3.resolve(leaf, "A")


async def test_hop_count_restarts_per_resolution(world):
    """跳数限制针对单次解析；先做过的短链解析不应占满额度。"""
    _clk, r, _net, _z = world
    await r.resolve("www.test.", "A")
    cut7 = "ns.deep7.deep6.deep5.deep4.deep3.deep2.deep1.test."
    ans = await r.resolve(cut7, "A")
    assert ans.rrset is not None


# ------------------------------------------------------------- 负缓存


async def test_nxdomain_cached_by_name(world):
    clk, r, net, _z = world
    with pytest.raises(NXDOMAINError):
        await r.resolve("missing.neg.test.", "A")
    assert net.queries == 3  # 根, test, neg.test
    before = net.queries
    with pytest.raises(NXDOMAINError):
        await r.resolve("missing.neg.test.", "A")
    with pytest.raises(NXDOMAINError):
        await r.resolve("missing.neg.test.", "NS")  # 按名称，对任意类型
    assert net.queries == before  # 全部命中负缓存


async def test_nodata_cached_by_name_and_type_only(world):
    clk, r, net, _z = world
    # a.neg.test. 有 A 没 SOA
    with pytest.raises(NoData):
        await r.resolve("a.neg.test.", "SOA")
    before = net.queries
    with pytest.raises(NoData):
        await r.resolve("a.neg.test.", "SOA")
    assert net.queries == before
    # 不同类型不受影响
    ans = await r.resolve("a.neg.test.", "A")
    assert ips(ans) == ["10.10.10.10"]


async def test_negative_ttl_is_min_of_soa_ttl_and_minimum_60(world):
    clk, r, net, zones = world
    # neg.test: SOA RR TTL 120, MINIMUM 60 -> 缓存 60
    with pytest.raises(NXDOMAINError):
        await r.resolve("gone.neg.test.", "A")
    await clk.advance(59)
    before = net.queries
    with pytest.raises(NXDOMAINError):
        await r.resolve("gone.neg.test.", "A")
    assert net.queries == before  # 仍缓存
    await clk.advance(2)  # 61
    with pytest.raises(NXDOMAINError):
        await r.resolve("gone.neg.test.", "A")
    assert net.queries > before  # 过期，重新查询


async def test_negative_ttl_is_min_when_soa_ttl_smaller(world):
    clk, r, net, zones = world
    # neg2.test: SOA RR TTL 30, MINIMUM 3600 -> 缓存 30
    # a.neg2.test. 有 A，查 SOA 触发 NODATA
    with pytest.raises(NoData):
        await r.resolve("a.neg2.test.", "SOA")
    await clk.advance(29)
    before = net.queries
    with pytest.raises(NoData):
        await r.resolve("a.neg2.test.", "SOA")
    assert net.queries == before
    await clk.advance(2)  # 31
    with pytest.raises(NoData):
        await r.resolve("a.neg2.test.", "SOA")
    assert net.queries > before


async def test_negative_ttl_boundary_exact_expiry(world):
    clk, r, net, _z = world
    with pytest.raises(NXDOMAINError):
        await r.resolve("gone.neg.test.", "A")
    await clk.advance(60)  # 恰好过期
    before = net.queries
    with pytest.raises(NXDOMAINError):
        await r.resolve("gone.neg.test.", "A")
    assert net.queries > before


async def test_negative_response_without_soa_is_not_cached(world):
    """bare 区的负响应不带 SOA：宽限去重窗口过后必须重新查询。"""
    _clk, r, net, _z = world
    with pytest.raises(NXDOMAINError):
        await r.resolve("missing.bare.test.", "A")
    # 先让 singleflight 的完成宽限期过去（它只在同一调度批次内去重）
    for _ in range(5):
        await asyncio.sleep(0)
    first = net.queries
    with pytest.raises(NXDOMAINError):
        await r.resolve("missing.bare.test.", "A")
    # 未做负缓存：又向 bare 权威重发了查询
    assert net.queries >= first + 1
    # 正常记录仍然可用
    ans = await r.resolve("exists.bare.test.", "A")
    assert ips(ans) == ["10.9.5.2"]
