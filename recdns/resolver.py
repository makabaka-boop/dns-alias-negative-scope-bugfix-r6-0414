"""递归解析器核心。

流程：从根提示出发，在“已知最深区割 (zone cut)”向对应权威服务器发
RD=0 查询；响应是委派（referral）就校验 bailiwick 后吸收 NS/glue 并
继续，最多 8 跳；响应里有 CNAME 就缓存并跟随，检测环；NXDOMAIN 按
名称、NODATA 按 (名称,类型) 做负缓存，TTL 取 SOA RR TTL 与 MINIMUM
的较小值。并发同查询经 :class:`~recdns.singleflight.SingleFlight` 共享。
"""

import asyncio
from dataclasses import dataclass, field

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from .cache import Cache
from .clock import Clock, SystemClock
from .exceptions import (
    CnameLoop,
    HopLimitExceeded,
    NXDOMAINError,
    NoData,
    NoGlue,
    RecursiveResolutionError,
    UnsupportedQtype,
    UpstreamError,
)
from .singleflight import SingleFlight
from .transport import Transport

ALLOWED_RDTYPES = frozenset(
    {
        dns.rdatatype.A,
        dns.rdatatype.CNAME,
        dns.rdatatype.NS,
        dns.rdatatype.SOA,
    }
)
MAX_REFERRAL_HOPS = 8
_MAX_CNAMES = 16  # 防呆上限；环另有显式检测


@dataclass
class Answer:
    """一次成功解析的结果。

    ``cnames`` 是按顺序经过的别名 RRset；``rrsets`` 是规范名上命中的
    答案 RRset（CNAME 查询时为空）。
    """

    qname: dns.name.Name
    rdtype: int
    canonical_name: dns.name.Name
    cnames: list[dns.rrset.RRset] = field(default_factory=list)
    rrsets: list[dns.rrset.RRset] = field(default_factory=list)

    @property
    def rrset(self) -> dns.rrset.RRset | None:
        return self.rrsets[0] if self.rrsets else None


def normalize_rdtype(rdtype) -> int:
    if isinstance(rdtype, str):
        rdtype = dns.rdatatype.from_text(rdtype.upper())
    if rdtype not in ALLOWED_RDTYPES:
        raise UnsupportedQtype(
            f"rdtype {dns.rdatatype.to_text(rdtype)} " "not in A/CNAME/NS/SOA"
        )
    return rdtype


class RecursiveResolver:
    def __init__(
        self,
        root_hints: dict,
        transport: Transport,
        clock: Clock | None = None,
        port: int = 53,
    ):
        """``root_hints``: {根 NS 名称(str/Name): [IP, ...]}。"""
        self._clock = clock or SystemClock()
        self._transport = transport
        self._port = port
        self.cache = Cache(self._clock)
        self._flight = SingleFlight()
        # 已学到的区割名称集合；根区恒在其中
        self._cuts: set[dns.name.Name] = {dns.name.root}
        self._root_servers: list[str] = []
        for ips in root_hints.values():
            self._root_servers.extend(ips)

    # ---------------------------------------------------------------- API

    async def resolve(self, qname, rdtype) -> Answer:
        """递归解析；``rdtype`` 仅限 A/CNAME/NS/SOA。"""
        rdtype = normalize_rdtype(rdtype)
        if isinstance(qname, str):
            qname = dns.name.from_text(qname)
        if not qname.is_absolute():
            raise ValueError("qname must be absolute")
        key = (qname, rdtype)
        return await self._flight.do(key, lambda: self._resolve(qname, rdtype))

    # ------------------------------------------------------------- 主流程

    async def _resolve(self, qname: dns.name.Name, rdtype: int) -> Answer:
        seen: set[dns.name.Name] = {qname}
        chain: list[dns.rrset.RRset] = []
        current = qname
        hops = 0

        while True:
            # 1) 负缓存
            neg = self.cache.negative_status(current, rdtype)
            if neg == "nxdomain":
                raise NXDOMAINError(current)
            if neg == "nodata":
                raise NoData(current, rdtype)

            # 2) 正缓存：沿 CNAME 走，能在缓存内答完就直接返回
            hit = self._walk_cache(qname, rdtype, current, chain, seen)
            if hit is not None:
                return hit
            # 缓存若新加了别名，下一轮从链尾继续（_walk_cache 已把
            # 别名并入 seen/chain，但 current 需要显式推进）
            if chain:
                tail = chain[-1][0].target
                if tail != current:
                    current = tail
                    seen.add(current)
                    continue

            # 3) 已知最深区割 + 对应服务器地址
            cut_name = self._deepest_known_cut(current)
            servers = await self._servers_for_cut(cut_name)

            # 4) 逐台服务器查询，返回可接受的响应及其分类
            response, kind, data = await self._query_servers(current, rdtype, servers)

            # 先缓存 answer 中允许的 RRset（referral 的 answer 里也可能
            # 携带把名称送出本区的 CNAME）
            for rrset in response.answer:
                if rrset.rdtype in ALLOWED_RDTYPES:
                    self.cache.put_rrset(rrset)

            if kind == "referral":
                hops = self._follow_referral(response, data, hops, qname)
                # answer 里若带有把名称送出本区的 CNAME，推进到链尾
                current = self._advance_over_cached_cnames(current, chain, seen)
                continue

            if kind == "nxdomain":
                ttl = self._negative_ttl(response)
                if ttl is not None:
                    self.cache.put_nxdomain(current, ttl)
                raise NXDOMAINError(current)

            if kind == "nodata":
                ttl = self._negative_ttl(response)
                if ttl is not None:
                    self.cache.put_nodata(current, rdtype, ttl)
                raise NoData(current, rdtype)

            # kind == "answer"：沿 answer 区的 CNAME owner 图找出最终答案
            final, local, target = self._walk_answer(response, current, rdtype)
            chain.extend(local)
            if final is not None:
                return Answer(qname, rdtype, target, list(chain), [final])
            if rdtype == dns.rdatatype.CNAME and local:
                return Answer(qname, rdtype, target, list(chain), [])

            # CNAME 指向的新名称没有答案：若权威区同时给出了对目标的
            # 委派，则吸收后跟随；否则按 NODATA 处理
            cut = self._referral_cut(response, target)
            if cut is not None:
                hops = self._follow_referral(response, cut, hops, qname)
                current = self._advance_over_cached_cnames(current, chain, seen)
                continue

            # 只有当权威区的 SOA 属主覆盖链尾时才做负缓存；
            # 否则保守地只报错不缓存
            ttl = self._negative_ttl_if_covering(response, target)
            if ttl is not None:
                self.cache.put_nodata(target, rdtype, ttl)
            raise NoData(target, rdtype)

    def _follow_referral(self, response, cut_name, hops, qname) -> int:
        """吸收一条委派，返回新的跳数；超限则抛 HopLimitExceeded。"""
        if hops >= MAX_REFERRAL_HOPS:
            raise HopLimitExceeded(
                f"more than {MAX_REFERRAL_HOPS} delegations for {qname}"
            )
        self._absorb_referral(response, cut_name)
        return hops + 1

    def _advance_over_cached_cnames(self, current, chain, seen):
        """referral 前 answer 里的 CNAME 已入缓存，沿它推进查询名。"""
        cur = current
        local_seen: set[dns.name.Name] = set()
        while True:
            cname = self.cache.get_rrset(cur, dns.rdatatype.CNAME)
            if cname is None:
                return cur
            if cur in local_seen or cname[0].target in seen:
                raise CnameLoop(f"CNAME loop at {cname[0].target}")
            local_seen.add(cur)
            if len(chain) >= _MAX_CNAMES:
                raise CnameLoop("CNAME chain too long")
            chain.append(cname)
            seen.add(cname[0].target)
            cur = cname[0].target

    # ---------------------------------------------------------- 缓存链行走

    def _walk_cache(self, qname, rdtype, start, chain, seen):
        """沿缓存中的 CNAME 行走；完整命中返回 Answer，否则返回 None。

        命中的别名链会并入 ``chain``；途中命中负缓存直接抛异常。
        """
        cur = start
        local: list[dns.rrset.RRset] = []
        local_seen: set[dns.name.Name] = set()
        while True:
            if cur in local_seen:
                raise CnameLoop(f"CNAME loop at {cur}")
            local_seen.add(cur)

            cname = self.cache.get_rrset(cur, dns.rdatatype.CNAME)
            if cname is None:
                break
            local.append(cname)
            if rdtype == dns.rdatatype.CNAME and cur == start:
                chain.extend(local)
                return Answer(qname, rdtype, cname[0].target, list(chain))
            target = cname[0].target
            neg = self.cache.negative_status(target, rdtype)
            if neg == "nxdomain":
                raise NXDOMAINError(target)
            if neg == "nodata":
                raise NoData(target, rdtype)
            cur = target

        final = None
        if rdtype != dns.rdatatype.CNAME:
            final = self.cache.get_rrset(cur, rdtype)
        if final is not None:
            chain.extend(local)
            seen.update(rr.name for rr in local)
            seen.add(cur)
            return Answer(qname, rdtype, cur, list(chain), [final])
        # 只走到部分别名链：把进度并入外层，下一轮从链尾继续查网络
        if local:
            chain.extend(local)
            seen.update(rr.name for rr in local)
            seen.add(cur)
        return None

    # ------------------------------------------------------------- 响应分类

    def _evaluate(self, response, qname, rdtype):
        """返回 (kind, data)。

        kind ∈ answer / nxdomain / nodata / referral / error；
        referral 时 data 为区割名称。
        """
        if (
            len(response.question) != 1
            or response.question[0].name != qname
            or response.question[0].rdtype != rdtype
            or response.question[0].rdclass != dns.rdataclass.IN
        ):
            return ("error", "question section mismatch")

        rcode = response.rcode()
        if rcode == dns.rcode.NXDOMAIN:
            return ("nxdomain", None)
        if rcode != dns.rcode.NOERROR:
            return ("error", f"rcode {dns.rcode.to_text(rcode)}")

        if response.flags & dns.flags.AA:
            return ("answer", None) if response.answer else ("nodata", None)

        # 非权威：answer 里可能先有把名称送出本区的 CNAME，权威区
        # 同时给出对链尾（或 qname 本身）的委派——仍算 referral
        cut = self._referral_cut(response, qname)
        if cut is None:
            # 沿 answer 中的 CNAME 找到链尾，在其下找区割
            _final, _chain, target = self._walk_answer(response, qname, rdtype)
            if _chain:
                cut = self._referral_cut(response, target)
        if cut is not None:
            return ("referral", cut)
        # 既非权威又不是合法委派：lame 服务器
        return ("error", "non-authoritative response without referral")

    @staticmethod
    def _referral_cut(response, qname):
        """权威区中属于 qname 后缀的最长 NS RRset 所有者；没有则 None。"""
        best = None
        for rrset in response.authority:
            if (
                rrset.rdtype == dns.rdatatype.NS
                and rrset.rdclass == dns.rdataclass.IN
                and qname.is_subdomain(rrset.name)
            ):
                if best is None or (
                    rrset.name != best and rrset.name.is_subdomain(best)
                ):
                    best = rrset.name
        return best

    # ------------------------------------------------------------- 吸收委派

    def _absorb_referral(self, response, cut_name) -> None:
        """登记区割；只接受 bailiwick 内、且确为 NS 名称的 A 记录作 glue。"""
        ns_rrset = None
        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.NS and rrset.name == cut_name:
                ns_rrset = rrset
                break
        if ns_rrset is None:  # 分类时已确认存在，防御性处理
            return
        self.cache.put_rrset(ns_rrset)
        self._cuts.add(cut_name)

        ns_targets = {rdata.target for rdata in ns_rrset}
        for rrset in response.additional:
            if rrset.rdtype != dns.rdatatype.A:
                continue  # 范围只含 A；任何其它类型的伪 glue 都不接受
            if rrset.name not in ns_targets:
                continue  # 必须对应一台被委派的服务器名称
            if not rrset.name.is_subdomain(cut_name):
                continue  # 必须属于所委派区域 (bailiwick)
            # 多个地址（含可能冲突的伪造地址）合并；查询时逐台容错
            self.cache.put_rrset(rrset, merge=True)

    # ---------------------------------------------------------- answer 行走

    @staticmethod
    def _walk_answer(response, start, rdtype):
        """沿 answer 区的 CNAME 图行走。

        返回 (final_rrset|None, 别名链, 终点名称)；遇到环抛 CnameLoop。
        """
        owners = {
            (rr.name, rr.rdtype): rr
            for rr in response.answer
            if rr.rdtype in ALLOWED_RDTYPES
        }
        cur = start
        local_seen = {start}
        local: list[dns.rrset.RRset] = []
        while True:
            cname = owners.get((cur, dns.rdatatype.CNAME))
            if cname is not None:
                if rdtype == dns.rdatatype.CNAME and cur == start:
                    return None, [cname], cname[0].target
                target = cname[0].target
                if target in local_seen:
                    raise CnameLoop(f"CNAME loop at {target}")
                local_seen.add(target)
                if len(local) >= _MAX_CNAMES:
                    raise CnameLoop("CNAME chain too long")
                local.append(cname)
                cur = target
                continue
            return owners.get((cur, rdtype)), local, cur

    # ------------------------------------------------------------- 区割/服务器

    def _deepest_known_cut(self, qname) -> dns.name.Name:
        for i in range(len(qname.labels)):
            suffix = dns.name.Name(qname.labels[i:])
            if suffix == dns.name.root:
                return dns.name.root
            if suffix in self._cuts:
                if self.cache.get_rrset(suffix, dns.rdatatype.NS) is not None:
                    return suffix
                self._cuts.discard(suffix)  # NS 记录已过期
        return dns.name.root

    async def _servers_for_cut(self, cut_name) -> list[str]:
        if cut_name == dns.name.root:
            return list(self._root_servers)
        ns_rrset = self.cache.get_rrset(cut_name, dns.rdatatype.NS)
        if ns_rrset is None:
            return list(self._root_servers)
        ips: list[str] = []
        errors = []
        for rdata in ns_rrset:
            ns_name = rdata.target
            if ns_name.is_subdomain(cut_name):
                a = self.cache.get_rrset(ns_name, dns.rdatatype.A)
                if a is None:
                    # 区域内名称却无 glue：鸡生蛋，委派残缺
                    errors.append(NoGlue(ns_name))
                    continue
                ips.extend(r.address for r in a)
            else:
                try:
                    ans = await self.resolve(ns_name, dns.rdatatype.A)
                except RecursiveResolutionError as exc:
                    errors.append(exc)
                    continue
                for rrset in ans.rrsets:
                    ips.extend(r.address for r in rrset)
        if not ips:
            raise UpstreamError(
                f"no usable addresses for nameservers of {cut_name}: " f"{errors!r}"
            )
        return ips

    # ------------------------------------------------------------- 发查询

    async def _query_servers(self, qname, rdtype, servers):
        query = dns.message.make_query(qname, rdtype, rdclass=dns.rdataclass.IN)
        query.flags &= ~dns.flags.RD
        errors = []
        for ip in servers:
            try:
                response = await self._transport.exchange(query, ip, self._port)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # 超时/网络错误：换下一台
                errors.append(f"{ip}: {exc!r}")
                continue
            kind, data = self._evaluate(response, qname, rdtype)
            if kind == "error":
                errors.append(f"{ip}: {data}")
                continue
            return response, kind, data
        raise UpstreamError(f"no server answered for {qname}: {errors}")

    # ------------------------------------------------------------- 负缓存 TTL

    @staticmethod
    def _authority_soa(response):
        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.SOA:
                return rrset
        return None

    def _negative_ttl(self, response) -> int | None:
        """负缓存期限：SOA RR TTL 与 MINIMUM 的较小值；无 SOA 不缓存。"""
        soa = self._authority_soa(response)
        if soa is None:
            return None
        self.cache.put_rrset(soa)
        return max(0, min(soa.ttl, soa[0].minimum))

    def _negative_ttl_if_covering(self, response, name) -> int | None:
        """同 :meth:`_negative_ttl`，但要求 SOA 属主是 ``name`` 的后缀。"""
        soa = self._authority_soa(response)
        if soa is None or not name.is_subdomain(soa.name):
            return None
        self.cache.put_rrset(soa)
        return max(0, min(soa.ttl, soa[0].minimum))
