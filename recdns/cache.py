"""按 TTL 失效的正缓存与按名称/名称+类型的负缓存。

* 正缓存：``(name, rdtype)`` -> RRset，TTL 从时钟换算成绝对过期时刻；
* NXDOMAIN：按名称缓存（对任意类型生效）；
* NODATA：按 ``(名称, 类型)`` 缓存；
* 负缓存 TTL 取权威区 SOA 的 RR TTL 与 SOA MINIMUM 字段的较小值。
"""

import copy

import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from .clock import Clock

NXDOMAIN = 0  # 负缓存中代表“名称不存在”的通配类型


class _Positive:
    __slots__ = ("rrset", "expires")

    def __init__(self, rrset: dns.rrset.RRset, expires: float):
        self.rrset = rrset
        self.expires = expires


class _Negative:
    __slots__ = ("expires",)

    def __init__(self, expires: float):
        self.expires = expires


class Cache:
    def __init__(self, clock: Clock):
        self._clock = clock
        self._positive: dict[tuple[dns.name.Name, int], _Positive] = {}
        self._negative: dict[tuple[dns.name.Name, int], _Negative] = {}

    # ---- 正缓存 ----------------------------------------------------------

    def put_rrset(self, rrset: dns.rrset.RRset, merge: bool = False) -> None:
        """存入一份 RRset 的副本，过期时刻由其 TTL 决定。

        ``merge=True`` 时把 rdata 并入同键的已有条目（TTL 取较小值，
        即先过期，保持保守）。
        """
        if not rrset:
            return
        rrset = copy.copy(rrset)
        key = (rrset.name, rrset.rdtype)
        if merge:
            old = self._positive.get(key)
            if old is not None and old.expires > self._clock.monotonic():
                # 先定保守过期时刻，再合并 rdata（add 会把 TTL 归一成 rrset.ttl）
                expires = min(old.expires, self._clock.monotonic() + rrset.ttl)
                for rd in old.rrset:
                    if rd not in rrset:
                        rrset.add(rd, rrset.ttl)
                self._positive[key] = _Positive(rrset, expires)
                self._negative.pop(key, None)
                self._negative.pop((rrset.name, NXDOMAIN), None)
                return
        self._positive[key] = _Positive(rrset, self._clock.monotonic() + rrset.ttl)
        # 新的权威数据到来，清掉与之矛盾的负缓存
        self._negative.pop(key, None)
        self._negative.pop((rrset.name, NXDOMAIN), None)

    def get_rrset(self, name: dns.name.Name, rdtype: int) -> dns.rrset.RRset | None:
        rec = self._positive.get((name, rdtype))
        if rec is None:
            return None
        if rec.expires <= self._clock.monotonic():
            del self._positive[(name, rdtype)]
            return None
        out = copy.copy(rec.rrset)
        # 以剩余 TTL 对外呈现，保持缓存内原件不变
        out.ttl = max(0, int(rec.expires - self._clock.monotonic()))
        return out

    # ---- 负缓存 ----------------------------------------------------------

    def put_nxdomain(self, name: dns.name.Name, ttl: int) -> None:
        if ttl < 0:
            return
        self._negative[(name, NXDOMAIN)] = _Negative(self._clock.monotonic() + ttl)

    def put_nodata(self, name: dns.name.Name, rdtype: int, ttl: int) -> None:
        if ttl < 0:
            return
        self._negative[(name, rdtype)] = _Negative(self._clock.monotonic() + ttl)

    def negative_status(self, name: dns.name.Name, rdtype: int) -> str | None:
        """返回 ``'nxdomain'`` / ``'nodata'`` / ``None``。"""
        kind = self._lookup(name, NXDOMAIN)
        if kind is not None:
            return "nxdomain"
        if rdtype != dns.rdatatype.ANY and self._lookup(name, rdtype) is not None:
            return "nodata"
        return None

    def _lookup(self, name: dns.name.Name, rdtype: int) -> str | None:
        key = (name, rdtype)
        rec = self._negative.get(key)
        if rec is None:
            return None
        if rec.expires <= self._clock.monotonic():
            del self._negative[key]
            return None
        return "nxdomain" if rdtype == NXDOMAIN else "nodata"

    def clear(self) -> None:
        self._positive.clear()
        self._negative.clear()
