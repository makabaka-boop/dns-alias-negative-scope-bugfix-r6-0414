"""构造测试权威树并返回 (resolver, net, zones)。

树结构::

    .                  ns.root.      10.0.0.1
    test.              ns.test.      10.1.0.1
      org.test.        ns.org.test.  10.2.0.1  (org.test 内 glue)
        s.org.test.    ns.s.org.test.           (区域内、无 glue，残缺)
      other.test.      ns.other.tld.           (区外 NS，真实委派链解析)
      evil.test.       ns.evil.test. 198.51.100.9 + 伪造 glue 6.6.6.6
      neg.test.        ns.neg.test.  10.9.0.1  SOA TTL 120/MIN 60
      neg2.test.       ns.neg2.test. 10.9.0.2  SOA TTL 30/MIN 3600
      deep0..deep8     8 跳/9 跳边界
"""

import dns.name
import dns.rdatatype

from recdns.fakenet import FakeNetwork, FakeTransport, Zone
from recdns.resolver import RecursiveResolver

IP_ROOT = "10.0.0.1"
IP_TEST = "10.1.0.1"
IP_ORG = "10.2.0.1"
IP_NEG = "10.9.0.1"
IP_NEG2 = "10.9.0.2"


def build_tree(clock):
    net = FakeNetwork()
    transport = FakeTransport(net)
    zones = {}

    root = Zone(".", soa_ttl=3600, minimum=3600)
    root.add(".", "NS", "ns.root.", ttl=3600)
    root.add("ns.root.", "A", IP_ROOT, ttl=3600)
    root.delegate("test.", ["ns.test."], glue={"ns.test.": [IP_TEST]})
    root.delegate("tld.", ["ns.tld."], glue={"ns.tld.": ["10.5.0.1"]})
    net.add_node(IP_ROOT, root)
    zones["."] = root

    test = Zone("test.", soa_ttl=3600, minimum=300)
    test.add("test.", "NS", "ns.test.", ttl=300)
    test.add("ns.test.", "A", IP_TEST, ttl=300)
    test.add("www.test.", "A", "1.1.1.1", "1.1.1.2", ttl=60)
    test.add("alias.test.", "CNAME", "www.test.", ttl=100)
    test.add("multi1.test.", "CNAME", "multi2.test.", ttl=100)
    test.add("multi2.test.", "CNAME", "multi3.test.", ttl=100)
    test.add("multi3.test.", "A", "9.9.9.9", ttl=100)
    test.add("loop1.test.", "CNAME", "loop2.test.", ttl=100)
    test.add("loop2.test.", "CNAME", "loop1.test.", ttl=100)
    test.add("present.test.", "A", "5.5.5.5", ttl=60)  # NODATA for SOA
    test.delegate("org.test.", ["ns.org.test."], glue={"ns.org.test.": [IP_ORG]})
    test.delegate("s.org.test.", ["ns.s.org.test."])  # 区域内但无 glue
    test.delegate("other.test.", ["ns.other.tld."])  # 区外 NS
    test.delegate(
        "evil.test.",
        ["ns.evil.test."],
        glue={"ns.evil.test.": ["198.51.100.9"]},
        forged_glue=[
            ("ns.evil.test.", "A", ["6.6.6.6"], 300),
            ("not-ns.evil.test.", "A", ["7.7.7.7"], 300),
            ("ns.org.test.", "A", ["8.8.8.8"], 300),
        ],
    )
    test.delegate("neg.test.", ["ns.neg.test."], glue={"ns.neg.test.": [IP_NEG]})
    test.delegate("neg2.test.", ["ns.neg2.test."], glue={"ns.neg2.test.": [IP_NEG2]})
    net.add_node(IP_TEST, test)
    zones["test."] = test

    org = Zone("org.test.", soa_ttl=3600, minimum=300)
    org.add("org.test.", "NS", "ns.org.test.", ttl=300)
    org.add("ns.org.test.", "A", IP_ORG, ttl=300)
    org.add("host.org.test.", "A", "2.2.2.2", ttl=30)
    # 跨区别名：test 区把 goto.test. 指到 org.test 区的名字
    org.add("target.org.test.", "A", "2.2.2.3", ttl=45)
    net.add_node(IP_ORG, org)
    zones["org.test."] = org

    test.add("goto.test.", "CNAME", "target.org.test.", ttl=100)
    # 别名跨区且目标在 org.test. 内不存在：NXDOMAIN 应按目标名称缓存
    test.add("dead.test.", "CNAME", "ghost.org.test.", ttl=100)

    # 多级别名指向暂时不存在的同区目标（测试中用 add("gone3.test.", ...)
    # 模拟目标稍后恢复）；否定结论应只落在链尾 gone3.test.
    test.add("gone1.test.", "CNAME", "gone2.test.", ttl=100)
    test.add("gone2.test.", "CNAME", "gone3.test.", ttl=100)
    # 多级别名指向存在但缺少指定记录的目标：NODATA 按 (链尾, 类型) 缓存
    test.add("void1.test.", "CNAME", "void2.test.", ttl=100)
    test.add("void2.test.", "A", "6.6.6.6", ttl=100)

    # tld 提供 ns.other.tld 的 A 记录（区外 NS 的正常解析路径）
    tld = Zone("tld.", soa_ttl=3600, minimum=300)
    tld.add("tld.", "NS", "ns.tld.", ttl=300)
    tld.add("ns.tld.", "A", "10.5.0.1", ttl=300)
    tld.add("ns.other.tld.", "A", "10.6.0.1", ttl=300)
    net.add_node("10.5.0.1", tld)
    zones["tld."] = tld

    other = Zone("other.test.", soa_ttl=3600, minimum=300)
    other.add("other.test.", "NS", "ns.other.tld.", ttl=300)
    other.add("x.other.test.", "A", "3.3.3.3", ttl=300)
    net.add_node("10.6.0.1", other)
    zones["other.test."] = other

    # evil 权威区：真实 glue 地址上的节点给出合法数据
    evil = Zone("evil.test.", soa_ttl=3600, minimum=300)
    evil.add("evil.test.", "NS", "ns.evil.test.", ttl=300)
    evil.add("ns.evil.test.", "A", "198.51.100.9", ttl=300)
    evil.add("bad.evil.test.", "A", "4.4.4.4", ttl=300)
    net.add_node("198.51.100.9", evil)
    zones["evil.test."] = evil

    neg = Zone("neg.test.", soa_ttl=120, minimum=60)
    neg.add("neg.test.", "NS", "ns.neg.test.", ttl=120)
    neg.add("ns.neg.test.", "A", IP_NEG, ttl=120)
    neg.add("a.neg.test.", "A", "10.10.10.10", ttl=120)
    # 空非终结点（NODATA）与不存在名称（NXDOMAIN）
    net.add_node(IP_NEG, neg)
    zones["neg.test."] = neg

    # 无 SOA 的权威区：负响应不带 SOA，按规范不应被负缓存
    bare = Zone("bare.test.", soa_ttl=60, minimum=60)
    bare.strip_negative_soa = True
    bare.add("bare.test.", "NS", "ns.bare.test.", ttl=60)
    bare.add("ns.bare.test.", "A", "10.9.5.1", ttl=60)
    bare.add("exists.bare.test.", "A", "10.9.5.2", ttl=60)
    net.add_node("10.9.5.1", bare)
    zones["bare.test."] = bare
    test.delegate("bare.test.", ["ns.bare.test."], glue={"ns.bare.test.": ["10.9.5.1"]})

    neg2 = Zone("neg2.test.", soa_ttl=30, minimum=3600)
    neg2.add("neg2.test.", "NS", "ns.neg2.test.", ttl=30)
    neg2.add("ns.neg2.test.", "A", IP_NEG2, ttl=30)
    neg2.add("a.neg2.test.", "A", "10.11.11.11", ttl=30)
    net.add_node(IP_NEG2, neg2)
    zones["neg2.test."] = neg2

    # 9 层嵌套区割 deep1..deep9.test.，每跳一个区域内 NS/glue
    parent = test
    cuts = ["test."]
    for i in range(1, 10):
        cut = "deep%d.%s" % (i, cuts[-1])
        ns = "ns.%s" % cut
        ip = "10.7.%d.1" % i
        z = Zone(cut, soa_ttl=3600, minimum=300)
        z.add(cut, "NS", ns, ttl=300)
        z.add(ns, "A", ip, ttl=300)
        if i == 9:
            z.add("leaf." + cut, "A", "10.200.0.1", ttl=300)
        net.add_node(ip, z)
        zones[cut] = z
        parent.delegate(cut, [ns], glue={ns: [ip]})
        parent = z
        cuts.append(cut)

    resolver = RecursiveResolver(
        root_hints={dns.name.from_text("ns.root."): [IP_ROOT]},
        transport=transport,
        clock=clock,
    )
    return resolver, net, zones
