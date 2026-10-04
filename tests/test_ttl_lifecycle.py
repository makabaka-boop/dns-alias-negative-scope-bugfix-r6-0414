"""委派/区割学习在 TTL 过期后的行为。"""

import dns.name
import dns.rdatatype

from recdns.clock import FakeClock
from tests.tree import build_tree


async def test_ns_and_glue_expire_then_relearn_from_parent():
    clk = FakeClock()
    r, net, zones = build_tree(clk)
    await r.resolve("host.org.test.", "A")
    assert net.queries == 3

    # org.test. 的 NS/glue TTL 都是 300；过期后再次解析应重新走委派链
    await clk.advance(301)
    before = net.queries
    await r.resolve("host.org.test.", "A")
    # 重新向根/父区学 NS+glue，然后再问 org.test.
    assert net.queries >= before + 2


async def test_positive_answer_ttl_expiry_re_queries_authoritative():
    clk = FakeClock()
    r, net, zones = build_tree(clk)
    # www.test. TTL 60
    await r.resolve("www.test.", "A")
    before = net.queries
    await clk.advance(30)
    await r.resolve("www.test.", "A")
    assert net.queries == before  # 仍有效
    await clk.advance(31)  # 61
    await r.resolve("www.test.", "A")
    assert net.queries > before


async def test_cname_ttl_expires_independently_of_target():
    clk = FakeClock()
    r, net, zones = build_tree(clk)
    # alias.test. CNAME TTL 100；www.test. A TTL 60
    await r.resolve("alias.test.", "A")
    before = net.queries
    await clk.advance(70)
    # www 的 A 已过期、CNAME 仍有效：重查只需从 www 开始
    await r.resolve("alias.test.", "A")
    # CNAME 命中缓存，链能从缓存走到 www
    assert (
        r.cache.get_rrset(dns.name.from_text("alias.test."), dns.rdatatype.CNAME)
        is not None
    )
