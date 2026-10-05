"""CNAME、临时失败与缓存边界的回归测试。"""

import asyncio

import dns.name
import dns.rdatatype
import pytest

from recdns.clock import FakeClock
from recdns.exceptions import CnameLoop, NoData, NXDOMAINError
from tests.tree import build_tree


def cname(r, name):
    return r.cache.get_rrset(dns.name.from_text(name), dns.rdatatype.CNAME)


async def test_temporarily_missing_target_keeps_alias_and_recovers(world):
    _clk, r, _net, zones = world
    test = zones["test."]
    test.add("temp.test.", "CNAME", "future.test.", ttl=1000)
    # 目标尚无 A 记录；用 NS 记录让名称存在，从而得到 AA NODATA/SOA。
    test.add(
        "leaf.future.test.", "NS", "ns.future.test.", ttl=1000
    )
    test.add("future.test.", "CNAME", "leaf.future.test.", ttl=900)

    with pytest.raises(NoData) as first:
        await r.resolve("temp.test.", "A")
    assert first.value.qname == dns.name.from_text("leaf.future.test.")

    # 两级别名都是权威正缓存；否定结论只属于链尾，不能污染别名名称。
    assert cname(r, "temp.test.") is not None
    assert cname(r, "future.test.") is not None
    assert r.cache.negative_status(
        dns.name.from_text("temp.test."), dns.rdatatype.A
    ) is None
    assert r.cache.negative_status(
        dns.name.from_text("future.test."), dns.rdatatype.A
    ) is None
    # 链上名称的 CNAME 查询和另一类型查询不应被链尾否定结论影响。
    cname_answer = await r.resolve("temp.test.", "CNAME")
    assert cname_answer.canonical_name == dns.name.from_text("future.test.")
    alias_type_answer = await r.resolve("goto.test.", "CNAME")
    assert alias_type_answer.canonical_name == dns.name.from_text(
        "target.org.test."
    )
    assert (
        r.cache.negative_status(
            dns.name.from_text("leaf.future.test."), dns.rdatatype.NS
        )
        is None
    )
    assert (
        r.cache.negative_status(
            dns.name.from_text("leaf.future.test."), dns.rdatatype.A
        )
        == "nodata"
    )
    assert (
        r.cache.get_rrset(dns.name.from_text("test."), dns.rdatatype.SOA)
        is None
    )

    # 否定 TTL（SOA minimum=300）先于别名 TTL 过期；目标恢复后应获得新结果。
    await _clk.advance(301)
    test.add("leaf.future.test.", "A", "4.4.4.4", ttl=100)
    ans = await r.resolve("temp.test.", "A")
    assert ans.canonical_name == dns.name.from_text("leaf.future.test.")
    assert sorted(x.address for rr in ans.rrsets for x in rr) == ["4.4.4.4"]


async def test_cold_and_cached_failures_report_same_chain_tail(world):
    _clk, r, _net, zones = world
    neg = zones["neg.test."]
    neg.add("a.nx.neg.test.", "CNAME", "b.nx.neg.test.", ttl=1000)
    neg.add("b.nx.neg.test.", "CNAME", "c.nx.neg.test.", ttl=1000)

    with pytest.raises(NXDOMAINError) as cold:
        await r.resolve("a.nx.neg.test.", "A")
    expected = dns.name.from_text("c.nx.neg.test.")
    assert cold.value.qname == expected

    # 第二次完全走缓存：失败名称必须仍是链尾，而不是最初别名。
    with pytest.raises(NXDOMAINError) as cached:
        await r.resolve("a.nx.neg.test.", "A")
    assert cached.value.qname == expected


async def test_unrelated_answer_name_does_not_become_success_cache(world):
    _clk, r, _net, zones = world
    test = zones["test."]
    test.add("victim.test.", "A", "7.7.7.7", ttl=100)

    def answer_with_unrelated_name(qname, rdtype, use_tcp):
        response = orig(qname, rdtype, use_tcp)
        if (
            qname == dns.name.from_text("victim.test.")
            and rdtype == dns.rdatatype.A
        ):
            response.answer.append(
                test._records[
                    (dns.name.from_text("alias.test."), dns.rdatatype.CNAME)
                ]
            )
            response.answer.append(
                test._records[
                    (dns.name.from_text("multi1.test."), dns.rdatatype.CNAME)
                ]
            )
        return response

    orig = test.handle
    test.handle = answer_with_unrelated_name

    ans = await r.resolve("victim.test.", "A")
    assert sorted(x.address for rr in ans.rrsets for x in rr) == ["7.7.7.7"]
    # 响应里夹带的名称与 victim.test. 无关，不能改变后续独立查询。
    assert cname(r, "multi1.test.") is None
    direct = await r.resolve("multi1.test.", "A")
    assert direct.canonical_name == dns.name.from_text("multi3.test.")


async def test_cname_loop_removes_newly_learned_success_cache(world):
    _clk, r, _net, zones = world
    with pytest.raises(CnameLoop):
        await r.resolve("loop1.test.", "A")
    assert cname(r, "loop1.test.") is None
    assert cname(r, "loop2.test.") is None
    with pytest.raises(CnameLoop):
        await r.resolve("loop1.test.", "CNAME")
    assert cname(r, "loop1.test.") is None
    assert cname(r, "loop2.test.") is None


async def test_negative_failure_without_soa_is_not_reusable():
    clk = FakeClock()
    r, net, zones = build_tree(clk)
    with pytest.raises(NXDOMAINError) as exc:
        await r.resolve("missing.bare.test.", "A")
    for _ in range(5):
        await asyncio.sleep(0)
    assert exc.value.qname == dns.name.from_text("missing.bare.test.")
    assert (
        r.cache.negative_status(
            dns.name.from_text("missing.bare.test."), dns.rdatatype.A
        )
        is None
    )

    before = net.queries
    zones["bare.test."].add("missing.bare.test.", "A", "9.9.9.9", ttl=100)
    ans = await r.resolve("missing.bare.test.", "A")
    assert net.queries > before
    assert sorted(x.address for rr in ans.rrsets for x in rr) == ["9.9.9.9"]
