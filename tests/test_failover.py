"""多服务器容错、lame 权威与畸形响应处理。"""

import asyncio

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import pytest

from recdns.clock import FakeClock
from recdns.exceptions import UpstreamError
from recdns.fakenet import FakeNetwork, FakeTransport, Zone
from recdns.resolver import RecursiveResolver


def make_tree(clk, net):
    root = Zone(".", soa_ttl=3600)
    root.add(".", "NS", "ns.root.", ttl=3600)
    root.add("ns.root.", "A", "10.0.0.1", ttl=3600)
    # test 有两台权威：坏 IP（无节点）在前，好 IP 在后
    root.delegate(
        "test.",
        ["ns1.test.", "ns2.test."],
        glue={"ns1.test.": ["10.1.0.254"], "ns2.test.": ["10.1.0.1"]},
    )
    net.add_node("10.0.0.1", root)

    good = Zone("test.", soa_ttl=3600)
    good.add("test.", "NS", "ns2.test.", ttl=300)
    good.add("ns2.test.", "A", "10.1.0.1", ttl=300)
    good.add("ok.test.", "A", "4.4.4.4", ttl=300)
    net.add_node("10.1.0.1", good)
    return root, good


async def test_fails_over_to_second_server_when_first_unreachable():
    clk = FakeClock()
    net = FakeNetwork()
    make_tree(clk, net)
    r = RecursiveResolver(
        root_hints={dns.name.from_text("ns.root."): ["10.0.0.1"]},
        transport=FakeTransport(net),
        clock=clk,
    )
    ans = await r.resolve("ok.test.", "A")
    assert sorted(x.address for rr in ans.rrsets for x in rr) == ["4.4.4.4"]


class _StaticTransport:
    """对根只返回固定响应，用来构造畸形/lame 场景。"""

    def __init__(self, response_builder):
        self._build = response_builder

    async def exchange(self, query, where, port=53):
        return self._build(query)


def _query(qname, rdtype):
    q = dns.message.make_query(qname, rdtype, rdclass=dns.rdataclass.IN)
    q.flags &= ~dns.flags.RD
    return q


async def test_lame_referral_without_ns_is_error():
    # 根对 test. 的查询返回非权威、无 NS 的 NOERROR -> lame
    def build(query):
        resp = dns.message.make_response(query)
        resp.set_rcode(dns.rcode.NOERROR)  # 无 AA、无 NS、无 answer
        return resp

    r = RecursiveResolver(
        root_hints={dns.name.from_text("ns.root."): ["10.0.0.1"]},
        transport=_StaticTransport(build),
        clock=FakeClock(),
    )
    with pytest.raises(UpstreamError):
        await r.resolve("x.test.", "A")


async def test_servfail_from_all_servers_is_upstream_error():
    def build(query):
        resp = dns.message.make_response(query)
        resp.set_rcode(dns.rcode.SERVFAIL)
        return resp

    r = RecursiveResolver(
        root_hints={dns.name.from_text("ns.root."): ["10.0.0.1"]},
        transport=_StaticTransport(build),
        clock=FakeClock(),
    )
    with pytest.raises(UpstreamError):
        await r.resolve("x.test.", "A")


async def test_question_mismatch_rejected():
    def build(query):
        # 响应的 question 与查询不一致
        resp = dns.message.make_response(query)
        resp.question = []
        resp.set_rcode(dns.rcode.NOERROR)
        resp.flags |= dns.flags.AA
        return resp

    r = RecursiveResolver(
        root_hints={dns.name.from_text("ns.root."): ["10.0.0.1"]},
        transport=_StaticTransport(build),
        clock=FakeClock(),
    )
    with pytest.raises(UpstreamError):
        await r.resolve("x.test.", "A")
