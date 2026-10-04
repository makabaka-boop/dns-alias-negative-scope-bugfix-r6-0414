"""多级别名链尾的否定结论：归因、缓存一致性、恢复与无关记录隔离。

场景：域名通过多级别名指向暂时不存在（NXDOMAIN）或缺少指定记录
（NODATA）的目标，稍后目标恢复可用。要求：

* 否定结论只落在链尾名称上，链上别名本身的有效信息（CNAME）按各自
  TTL 保留，冷热查询报告同一个失败名称；
* 没有权威 SOA 覆盖的失败不变成可复用结论；
* 成环响应与同查询无关的记录不留下成功缓存。
"""

import asyncio

import dns.name
import dns.rdatatype
import dns.rrset
import pytest

from recdns.clock import FakeClock
from recdns.exceptions import CnameLoop, NXDOMAINError, NoData
from recdns.fakenet import FakeNetwork, FakeTransport, Zone
from recdns.resolver import RecursiveResolver
from tests.tree import build_tree

GONE1 = dns.name.from_text("gone1.test.")
GONE2 = dns.name.from_text("gone2.test.")
GONE3 = dns.name.from_text("gone3.test.")
VOID1 = dns.name.from_text("void1.test.")
VOID2 = dns.name.from_text("void2.test.")


@pytest.fixture
def world():
    clk = FakeClock()
    resolver, net, zones = build_tree(clk)
    return clk, resolver, net, zones


def ips(answer):
    return sorted(rd.address for rr in answer.rrsets for rd in rr)


async def _settle():
    """让 singleflight 的完成宽限期过去（它只在同一调度批次内去重），
    确保后续查询真正经过缓存而不是复用进行中的飞行。"""
    for _ in range(5):
        await asyncio.sleep(0)


# ------------------------------------------------------------- NXDOMAIN 链尾


async def test_nxdomain_attributed_to_chain_tail_not_alias(world):
    _clk, r, _net, _z = world
    with pytest.raises(NXDOMAINError) as ei:
        await r.resolve("gone1.test.", "A")
    # 失败名称是链尾，不是被查询的别名
    assert ei.value.qname == GONE3
    # 别名本身的 CNAME 仍作为有效信息各自缓存
    assert r.cache.get_rrset(GONE1, dns.rdatatype.CNAME) is not None
    assert r.cache.get_rrset(GONE2, dns.rdatatype.CNAME) is not None
    # 否定结论只落在链尾；别名名称上没有负缓存
    assert r.cache.negative_status(GONE3, dns.rdatatype.A) == "nxdomain"
    assert r.cache.negative_status(GONE1, dns.rdatatype.A) is None
    assert r.cache.negative_status(GONE2, dns.rdatatype.A) is None


async def test_alias_itself_not_judged_nonexistent(world):
    """一次失败后，仍然存在的别名不能被误判不存在。"""
    _clk, r, _net, _z = world
    with pytest.raises(NXDOMAINError):
        await r.resolve("gone1.test.", "A")
    # 查询别名自己的 CNAME 记录：别名存在，正常返回
    ans = await r.resolve("gone1.test.", "CNAME")
    assert ans.canonical_name == GONE2
    assert [c.name for c in ans.cnames] == [GONE1]
    # 从中间别名进入也一样：失败名称仍是链尾
    with pytest.raises(NXDOMAINError) as ei:
        await r.resolve("gone2.test.", "A")
    assert ei.value.qname == GONE3


async def test_cold_and_cached_report_same_failure_name(world):
    _clk, r, net, _z = world
    with pytest.raises(NXDOMAINError) as cold:
        await r.resolve("gone1.test.", "A")
    await _settle()
    before = net.queries
    with pytest.raises(NXDOMAINError) as cached:
        await r.resolve("gone1.test.", "A")
    # 冷查询与缓存查询报告同一个失败名称
    assert cold.value.qname == cached.value.qname == GONE3
    assert net.queries == before  # 第二次完全命中缓存，不产生上游查询


async def test_recovery_after_negative_ttl_expires(world):
    """目标恢复后，负缓存按各自有效期失效即可得到新结果。"""
    clk, r, net, zones = world
    with pytest.raises(NXDOMAINError):
        await r.resolve("gone1.test.", "A")
    # 目标恢复可用
    zones["test."].add("gone3.test.", "A", "7.7.7.7", ttl=100)
    # 别名 CNAME（TTL 100）与链尾否定结论（SOA TTL 3600 / MINIMUM 300
    # -> 300s）各自独立有效：别名还在有效期内时，沿缓存链走到链尾仍
    # 命中负缓存，不产生上游查询——这是负缓存的本意
    await clk.advance(50)
    before = net.queries
    with pytest.raises(NXDOMAINError) as ei:
        await r.resolve("gone1.test.", "A")
    assert ei.value.qname == GONE3
    assert net.queries == before
    # 负缓存到期后必须拿到恢复的新结果
    await clk.advance(251)  # 301
    ans = await r.resolve("gone1.test.", "A")
    assert ans.canonical_name == GONE3
    assert ips(ans) == ["7.7.7.7"]
    # 新到的权威数据清掉了链尾的负缓存
    assert r.cache.negative_status(GONE3, dns.rdatatype.A) is None


# ------------------------------------------------------------- NODATA 链尾


async def test_nodata_attributed_to_chain_tail_and_type_only(world):
    _clk, r, net, _z = world
    # void1 -> void2（有 A，无 SOA）：NODATA 归因 (void2, SOA)
    with pytest.raises(NoData) as ei:
        await r.resolve("void1.test.", "SOA")
    assert ei.value.qname == VOID2
    await _settle()
    before = net.queries
    with pytest.raises(NoData) as ei2:
        await r.resolve("void1.test.", "SOA")
    assert ei2.value.qname == VOID2
    assert net.queries == before  # 命中 (链尾, 类型) 负缓存
    # 另一种记录不受影响：void2 的 A 经别名链正常解析
    ans = await r.resolve("void1.test.", "A")
    assert ips(ans) == ["6.6.6.6"]
    # 查询别名记录也不受影响
    ans = await r.resolve("void1.test.", "CNAME")
    assert ans.canonical_name == VOID2


# ------------------------------------------------------------- 权威依据


async def test_nxdomain_without_covering_soa_is_not_cached(world):
    """负响应附带的 SOA 不覆盖失败名称：没有权威依据，不得缓存。"""
    _clk, r, net, zones = world
    zone = zones["test."]
    foreign = dns.rrset.from_text(
        "elsewhere.test.",
        300,
        "IN",
        "SOA",
        "ns.elsewhere.test. hostmaster.elsewhere.test. 1 7200 3600 1209600 300",
    )
    zone.soa_rrset = lambda ttl=None: foreign  # SOA 属主与失败名称无关

    with pytest.raises(NXDOMAINError):
        await r.resolve("missing.test.", "A")
    assert r.cache.negative_status(
        dns.name.from_text("missing.test."), dns.rdatatype.A
    ) is None
    await _settle()
    before = net.queries
    with pytest.raises(NXDOMAINError):
        await r.resolve("missing.test.", "A")
    assert net.queries > before  # 未缓存：重新向上游查询


# ------------------------------------------------------------- 无关记录与环


async def test_unrelated_answer_records_are_not_cached(world):
    """响应附带的无关名称不改变后续独立查询的结果。"""
    _clk, r, _net, zones = world
    zone = zones["test."]
    orig = zone.handle
    junk = dns.rrset.from_text("stuffed.test.", 300, "IN", "A", "9.9.9.1")

    def handle(qname, rdtype, use_tcp):
        resp = orig(qname, rdtype, use_tcp)
        if qname == dns.name.from_text("www.test."):
            resp.answer.append(junk)  # 与本次查询无关的附带记录
        return resp

    zone.handle = handle
    ans = await r.resolve("www.test.", "A")
    assert ips(ans) == ["1.1.1.1", "1.1.1.2"]
    # 无关记录不进缓存
    assert r.cache.get_rrset(dns.name.from_text("stuffed.test."), dns.rdatatype.A) is None
    # 后续独立查询不受其影响：stuffed.test. 实际不存在
    with pytest.raises(NXDOMAINError):
        await r.resolve("stuffed.test.", "A")


async def test_loop_response_leaves_no_cached_records(world):
    """成环响应整体作废：环上的 CNAME 不留下成功缓存。"""
    _clk, r, _net, _z = world
    with pytest.raises(CnameLoop):
        await r.resolve("loop1.test.", "A")
    assert r.cache.get_rrset(dns.name.from_text("loop1.test."), dns.rdatatype.CNAME) is None
    assert r.cache.get_rrset(dns.name.from_text("loop2.test."), dns.rdatatype.CNAME) is None


# ------------------------------------------------------------- 跨区链尾


def build_two_zone_tree(clk, other_records):
    """root 下挂 test. 与 other. 两个区；test. 的别名指向 other. 但响应里
    不给 other. 的委派（解析器须从链尾重新定位区割）。"""
    net = FakeNetwork()
    root = Zone(".", soa_ttl=3600)
    root.add(".", "NS", "ns.root.", ttl=3600)
    root.add("ns.root.", "A", "10.0.0.1", ttl=3600)
    root.delegate("test.", ["ns.test."], glue={"ns.test.": ["10.1.0.1"]})
    root.delegate("other.", ["ns.other."], glue={"ns.other.": ["10.3.0.1"]})
    net.add_node("10.0.0.1", root)

    test = Zone("test.", soa_ttl=3600)
    test.add("test.", "NS", "ns.test.", ttl=300)
    test.add("ns.test.", "A", "10.1.0.1", ttl=300)
    test.add("hop.test.", "CNAME", "z.other.", ttl=100)
    net.add_node("10.1.0.1", test)

    other = Zone("other.", soa_ttl=3600)
    other.add("other.", "NS", "ns.other.", ttl=300)
    other.add("ns.other.", "A", "10.3.0.1", ttl=300)
    for owner, rdtype, values in other_records:
        other.add(owner, rdtype, *values, ttl=100)
    net.add_node("10.3.0.1", other)

    r = RecursiveResolver(
        root_hints={dns.name.from_text("ns.root."): ["10.0.0.1"]},
        transport=FakeTransport(net),
        clock=clk,
    )
    return r, net


async def test_out_of_zone_tail_restarts_resolution_from_deepest_cut():
    """链尾送出本区且响应不带委派：从链尾重新定位区割继续解析。"""
    r, _net = build_two_zone_tree(FakeClock(), [("z.other.", "A", ["8.8.8.8"])])
    ans = await r.resolve("hop.test.", "A")
    assert ans.canonical_name == dns.name.from_text("z.other.")
    assert ips(ans) == ["8.8.8.8"]
    assert [c.name for c in ans.cnames] == [dns.name.from_text("hop.test.")]


async def test_cross_zone_cname_loop_detected():
    """环横跨两个区、分两次响应到达：合并后必须检测出环。"""
    r, _net = build_two_zone_tree(
        FakeClock(), [("z.other.", "CNAME", ["hop.test."])]
    )
    with pytest.raises(CnameLoop):
        await r.resolve("hop.test.", "A")


async def test_aa_chain_with_referral_does_not_duplicate_chain(world):
    """权威位与委派同时出现的响应：别名链不得重复拼接。"""
    _clk, r, _net, zones = world
    zone = zones["test."]
    orig = zone.handle

    def handle(qname, rdtype, use_tcp):
        resp = orig(qname, rdtype, use_tcp)
        if qname == dns.name.from_text("goto.test."):
            resp.flags |= dns.flags.AA  # AA + answer 链 + authority 委派
        return resp

    zone.handle = handle
    ans = await r.resolve("goto.test.", "A")
    assert [c.name.to_text() for c in ans.cnames] == ["goto.test."]
    assert ans.canonical_name == dns.name.from_text("target.org.test.")
    assert ips(ans) == ["2.2.2.3"]
