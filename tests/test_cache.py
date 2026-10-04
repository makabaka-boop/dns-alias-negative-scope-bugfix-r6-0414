"""正/负缓存 TTL 语义测试。"""

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from recdns.cache import NXDOMAIN, Cache
from recdns.clock import FakeClock


def a_rrset(name, ip, ttl):
    rr = dns.rrset.RRset(dns.name.from_text(name), dns.rdataclass.IN, dns.rdatatype.A)
    rr.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, ip), ttl)
    return rr


async def test_positive_expires_by_ttl_with_clock():
    clk = FakeClock()
    cache = Cache(clk)
    cache.put_rrset(a_rrset("a.test.", "1.1.1.1", 30))
    await clk.advance(29)
    assert cache.get_rrset(dns.name.from_text("a.test."), dns.rdatatype.A) is not None
    await clk.advance(2)  # 31
    assert cache.get_rrset(dns.name.from_text("a.test."), dns.rdatatype.A) is None


async def test_returned_rrset_shows_remaining_ttl():
    clk = FakeClock()
    cache = Cache(clk)
    cache.put_rrset(a_rrset("a.test.", "1.1.1.1", 30))
    await clk.advance(10)
    rr = cache.get_rrset(dns.name.from_text("a.test."), dns.rdatatype.A)
    assert rr.ttl == 20


async def test_nxdomain_cached_by_name_only():
    clk = FakeClock()
    cache = Cache(clk)
    n = dns.name.from_text("x.test.")
    cache.put_nxdomain(n, 60)
    assert cache.negative_status(n, dns.rdatatype.A) == "nxdomain"
    assert cache.negative_status(n, dns.rdatatype.NS) == "nxdomain"
    assert cache.negative_status(dns.name.from_text("y.test."), dns.rdatatype.A) is None
    await clk.advance(61)
    assert cache.negative_status(n, dns.rdatatype.A) is None


async def test_nodata_cached_by_name_and_type():
    clk = FakeClock()
    cache = Cache(clk)
    n = dns.name.from_text("x.test.")
    cache.put_nodata(n, dns.rdatatype.SOA, 60)
    assert cache.negative_status(n, dns.rdatatype.SOA) == "nodata"
    assert cache.negative_status(n, dns.rdatatype.A) is None
    await clk.advance(61)
    assert cache.negative_status(n, dns.rdatatype.SOA) is None


async def test_positive_insert_clears_negative():
    clk = FakeClock()
    cache = Cache(clk)
    n = dns.name.from_text("x.test.")
    cache.put_nodata(n, dns.rdatatype.A, 60)
    cache.put_nxdomain(dns.name.from_text("y.test."), 60)
    cache.put_rrset(a_rrset("x.test.", "1.1.1.1", 10))
    cache.put_rrset(a_rrset("y.test.", "2.2.2.2", 10))
    assert cache.negative_status(n, dns.rdatatype.A) is None
    assert cache.negative_status(dns.name.from_text("y.test."), dns.rdatatype.A) is None


async def test_merge_keeps_both_rdatas_conservative_ttl():
    clk = FakeClock()
    cache = Cache(clk)
    cache.put_rrset(a_rrset("ns.test.", "1.1.1.1", 100), merge=True)
    await clk.advance(10)
    cache.put_rrset(a_rrset("ns.test.", "2.2.2.2", 200), merge=True)
    rr = cache.get_rrset(dns.name.from_text("ns.test."), dns.rdatatype.A)
    assert sorted(r.address for r in rr) == ["1.1.1.1", "2.2.2.2"]
    # 绝对过期时刻取最早的 t=100；t=99 仍有效，t=101 失效
    await clk.advance(89)
    rr = cache.get_rrset(dns.name.from_text("ns.test."), dns.rdatatype.A)
    assert rr is not None
    await clk.advance(2)
    rr = cache.get_rrset(dns.name.from_text("ns.test."), dns.rdatatype.A)
    assert rr is None
