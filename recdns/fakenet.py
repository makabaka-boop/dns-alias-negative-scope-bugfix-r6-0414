"""进程内假权威节点与假网络。

* :class:`Zone` 是一个权威区：保存区内记录、SOA，并声明对子区的委派；
* :class:`FakeNetwork` 实现 :class:`~recdns.transport.Transport`，
  按服务器 IP 把查询交给对应 :class:`Zone` 处理，全程不碰真实 socket；
* UDP 截断由区按名称配置：第一次查询返回 TC=1 的空响应，
  :class:`FakeNetwork` 记录走的是 UDP 还是 TCP，供测试断言重试。

仅用于测试。
"""

import asyncio
from collections import defaultdict

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset


def _make_rrset(owner, rdtype, values, ttl):
    rrset = dns.rrset.RRset(
        dns.name.from_text(owner) if isinstance(owner, str) else owner,
        dns.rdataclass.IN,
        rdtype,
    )
    for v in values:
        rrset.add(v, ttl)
    return rrset


def _rdata(rdtype, text):
    return dns.rdata.from_text(dns.rdataclass.IN, rdtype, text)


class Delegation:
    """一条对子区的委派：NS 名称列表 + 配置在父区附加区里的 glue。"""

    def __init__(self, ns_names, glue=None, forged_glue=None):
        self.ns_names = ns_names
        # 合规 glue: {A 记录属主名: [ip,...]}，仅区域内名称应放这里
        self.glue = glue or {}
        # 伪造附加：无论属主/bailiwick 都原样放进 additional
        self.forged_glue = forged_glue or []


class Zone:
    def __init__(
        self,
        origin,
        soa_rname="hostmaster",
        serial=1,
        refresh=7200,
        retry=3600,
        expire=1209600,
        minimum=3600,
        soa_ttl=3600,
    ):
        self.origin = dns.name.from_text(origin) if isinstance(origin, str) else origin
        self._soa_rname = soa_rname
        self._serial = serial
        self._soa_ttl = soa_ttl
        self._soa = (refresh, retry, expire, minimum)
        # (name, rdtype) -> RRset
        self._records: dict[tuple[dns.name.Name, int], dns.rrset.RRset] = {}
        self._delegations: dict[dns.name.Name, Delegation] = {}
        # 名称 -> 触发 TC 的剩余次数（UDP）
        self._tc: dict[dns.name.Name, int] = {}
        # 名称 -> 处理前等待的事件数（测试取消竞争用）
        self._holds: dict[dns.name.Name, int] = defaultdict(int)
        self._hold_events: dict[dns.name.Name, asyncio.Event] = {}
        # 不返回权威 SOA（构造无 SOA 的负响应）
        self.strip_negative_soa = False

    # ---------------------------------------------------------- 配置

    def add(self, owner, rdtype, *values, ttl=300):
        if isinstance(rdtype, str):
            rdtype = dns.rdatatype.from_text(rdtype.upper())
        name = dns.name.from_text(owner) if isinstance(owner, str) else owner
        rdata_list = [
            v if not isinstance(v, str) else _rdata(rdtype, v) for v in values
        ]
        self._records[(name, rdtype)] = _make_rrset(name, rdtype, rdata_list, ttl)

    def delegate(self, child, ns_names, glue=None, forged_glue=None):
        name = dns.name.from_text(child) if isinstance(child, str) else child
        ns_names = [
            dns.name.from_text(n) if isinstance(n, str) else n for n in ns_names
        ]
        glue_parsed = {}
        for gname, ips in (glue or {}).items():
            gn = dns.name.from_text(gname) if isinstance(gname, str) else gname
            glue_parsed[gn] = list(ips)
        forged = []
        for owner, rdtype, vals, ttl in forged_glue or []:
            rt = (
                dns.rdatatype.from_text(rdtype.upper())
                if isinstance(rdtype, str)
                else rdtype
            )
            forged.append(
                _make_rrset(
                    owner,
                    rt,
                    [_rdata(rt, v) if isinstance(v, str) else v for v in vals],
                    ttl,
                )
            )
        self._delegations[name] = Delegation(ns_names, glue_parsed, forged)

    def set_tc(self, name, times=1):
        """对该名称的前 ``times`` 次 UDP 查询返回截断标记。"""
        self._tc[dns.name.from_text(name) if isinstance(name, str) else name] = times

    def add_hold(self, name):
        n = dns.name.from_text(name) if isinstance(name, str) else name
        self._holds[n] += 1
        ev = asyncio.Event()
        self._hold_events[n] = ev
        return ev

    def release(self, name):
        n = dns.name.from_text(name) if isinstance(name, str) else name
        ev = self._hold_events.get(n)
        if ev is not None:
            ev.set()

    # ---------------------------------------------------------- 查询

    def soa_rrset(self, ttl=None):
        refresh, retry, expire, minimum = self._soa
        if self.origin == dns.name.root:
            mname = dns.name.from_text("ns.root.")
            rname = dns.name.from_text(f"{self._soa_rname}.root.")
        else:
            mname = dns.name.from_text(f"ns1.{self.origin.to_text()}")
            rname = dns.name.from_text(f"{self._soa_rname}.{self.origin.to_text()}")
        rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.SOA,
            f"{mname.to_text()} {rname.to_text()} "
            f"{self._serial} {refresh} {retry} {expire} {minimum}",
        )
        return _make_rrset(
            self.origin,
            dns.rdatatype.SOA,
            [rdata],
            self._soa_ttl if ttl is None else ttl,
        )

    def _matching_delegation(self, qname):
        """返回 qname 之下（含等于）最长的已委派区割，没有则 None。"""
        best = None
        for cut in self._delegations:
            if qname.is_subdomain(cut):
                if best is None or cut.is_subdomain(best) and cut != best:
                    best = cut
        return best

    def handle(self, qname, rdtype, use_tcp):
        """构造对一个查询的响应（:class:`dns.message.Message`）。"""
        if not qname.is_subdomain(self.origin):
            return self._reply(qname, rdtype, dns.rcode.REFUSED)

        # 截断测试
        if not use_tcp and self._tc.get(qname, 0) > 0:
            self._tc[qname] -= 1
            resp = self._reply(qname, rdtype, dns.rcode.NOERROR)
            resp.flags |= dns.flags.TC
            return resp

        # 1) 精确属主记录
        rr = self._records.get((qname, rdtype))
        if rr is not None:
            return self._aa(qname, rdtype, [rr])

        # 1.5) 区顶 SOA：按需合成权威应答
        if qname == self.origin and rdtype == dns.rdatatype.SOA:
            return self._aa(qname, rdtype, [self.soa_rrset()])

        # 2) CNAME 链（链上落在本区的记录）
        if rdtype != dns.rdatatype.CNAME:
            chain, final, target, looped = self._follow_cnames(qname, rdtype)
            if chain:
                if final is not None:
                    return self._aa(qname, rdtype, chain + [final])
                if looped:
                    # 环：把环原样返回，由解析器检测
                    return self._aa(qname, rdtype, chain)
                # 链尾不在本区：权威 CNAME + 对链尾的委派（若存在）
                cut = self._matching_delegation(target)
                if cut is not None:
                    return self._referral(qname, rdtype, chain, cut)
                if target.is_subdomain(self.origin):
                    # 链尾落在本区：与真实权威一致，对链尾给出
                    # NXDOMAIN / NODATA，answer 携带整条别名链
                    return self._negative_for_target(qname, rdtype, chain, target)
                return self._aa(qname, rdtype, chain)  # 权威但不完整

        # 3) 区顶 NS
        if qname == self.origin and rdtype == dns.rdatatype.NS:
            rr = self._records.get((self.origin, dns.rdatatype.NS))
            if rr is not None:
                return self._aa(qname, rdtype, [rr])

        # 4) 命中委派：referral
        cut = self._matching_delegation(qname)
        if cut is not None:
            return self._referral(qname, rdtype, [], cut)

        # 5) 有属主但无该类型 / 空非终结点 -> NODATA；否则 NXDOMAIN
        owner_exists = any(n == qname for n, _t in self._records)
        rcode = dns.rcode.NOERROR if owner_exists else dns.rcode.NXDOMAIN
        resp = self._reply(qname, rdtype, rcode)
        resp.flags |= dns.flags.AA
        if not self.strip_negative_soa:
            resp.authority.append(self.soa_rrset())
        return resp

    def _follow_cnames(self, start, rdtype):
        """返回 (别名链, 最终记录或 None, 链尾名称, 是否成环)。"""
        chain = []
        cur = start
        seen = {start}
        while True:
            cn = self._records.get((cur, dns.rdatatype.CNAME))
            if cn is None:
                return chain, None, cur, False
            target = cn[0].target
            chain.append(cn)
            if target in seen:  # 环
                return chain, None, target, True
            seen.add(target)
            final = self._records.get((target, rdtype))
            if final is not None:
                return chain, final, target, False
            cur = target

    def _negative_for_target(self, qname, rdtype, chain, target):
        """链尾在本区但无法给出所求记录：NXDOMAIN 或 NODATA。

        answer 携带整条别名链，authority 附本区 SOA（除非配置为剥离）。
        """
        owner_exists = any(n == target for n, _t in self._records)
        rcode = dns.rcode.NOERROR if owner_exists else dns.rcode.NXDOMAIN
        resp = self._reply(qname, rdtype, rcode)
        resp.flags |= dns.flags.AA
        resp.answer.extend(chain)
        if not self.strip_negative_soa:
            resp.authority.append(self.soa_rrset())
        return resp

    def _aa(self, qname, rdtype, answer):
        resp = self._reply(qname, rdtype, dns.rcode.NOERROR)
        resp.flags |= dns.flags.AA
        resp.answer.extend(answer)
        return resp

    def _referral(self, qname, rdtype, answer, cut):
        resp = self._reply(qname, rdtype, dns.rcode.NOERROR)
        resp.answer.extend(answer)
        delegation = self._delegations[cut]
        ns = _make_rrset(
            cut,
            dns.rdatatype.NS,
            [_rdata(dns.rdatatype.NS, n.to_text()) for n in delegation.ns_names],
            300,
        )
        resp.authority.append(ns)
        for ns_name, ips in delegation.glue.items():
            resp.additional.append(
                _make_rrset(
                    ns_name,
                    dns.rdatatype.A,
                    [_rdata(dns.rdatatype.A, ip) for ip in ips],
                    300,
                )
            )
        resp.additional.extend(delegation.forged_glue)
        return resp

    @staticmethod
    def _reply(qname, rdtype, rcode):
        resp = dns.message.make_response(
            dns.message.make_query(qname, rdtype, rdclass=dns.rdataclass.IN)
        )
        resp.set_rcode(rcode)
        return resp


class NetworkUnreachable(Exception):
    """假网络：IP 上没有权威节点（模拟不可达，触发解析器换下一台）。"""


class FakeNetwork:
    """裸网络：IP -> Zone 节点，区分 UDP/TCP 两种投递。

    截断 (TC) 的处理不在本类，而在 :class:`FakeTransport`，与生产
    :class:`~recdns.transport.AsyncioTransport` 的行为保持一致。
    """

    def __init__(self):
        self._nodes: dict[str, Zone] = {}
        self.udp_count = 0
        self.tcp_count = 0
        self.queries = 0  # 送到权威节点 handle 的查询总数

    def add_node(self, ip, zone):
        self._nodes[ip] = zone

    async def send_udp(self, query, where, port=53):
        self.queries += 1
        self.udp_count += 1
        return await self._deliver(query, where, use_tcp=False)

    async def send_tcp(self, query, where, port=53):
        self.queries += 1
        self.tcp_count += 1
        return await self._deliver(query, where, use_tcp=True)

    async def _deliver(self, query, where, use_tcp):
        zone = self._nodes.get(where)
        if zone is None:
            await asyncio.sleep(0)  # 模拟一次真实 I/O 让出
            raise NetworkUnreachable(f"no server at {where}")

        q = query.question[0]

        # 取消竞争：处理前等待，测试可以在挂起时取消等待者
        if zone._holds.get(q.name, 0) > 0:
            zone._holds[q.name] -= 1
            ev = zone._hold_events[q.name]
            await ev.wait()
            if zone._holds.get(q.name, 0) <= 0:
                zone._hold_events.pop(q.name, None)

        return zone.handle(q.name, q.rdtype, use_tcp=use_tcp)


class FakeTransport:
    """与 :class:`AsyncioTransport` 同构：先 UDP，TC 置位则 TCP 重试。"""

    def __init__(self, network: "FakeNetwork | None" = None):
        self.net = network or FakeNetwork()
        # 记录每次 exchange 最终是否走了 TCP 重试
        self.tcp_retries = 0

    async def exchange(self, query, where, port=53):
        response = await self.net.send_udp(query, where, port)
        if response.flags & dns.flags.TC:
            self.tcp_retries += 1
            response = await self.net.send_tcp(query, where, port)
        return response
