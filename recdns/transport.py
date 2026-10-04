"""DNS 消息传输。

:class:`Transport` 是解析器依赖的接口：给定查询消息、服务器 IP 与端口，
返回响应消息。UDP 收到截断 (TC) 响应后必须自动用 TCP 重试。

:class:`AsyncioTransport` 用 dnspython 的 ``dns.asyncquery`` 实现，
测试中由 :mod:`recdns.fakenet` 提供进程内假实现。
"""

from typing import Protocol, runtime_checkable

import dns.asyncquery
import dns.message


@runtime_checkable
class Transport(Protocol):
    async def exchange(
        self, query: dns.message.Message, where: str, port: int = 53
    ) -> dns.message.Message:
        """向单个权威服务器发送一条查询并返回响应。"""
        ...


class AsyncioTransport:
    """真实网络传输：先 UDP，TC 置位则 TCP 重试。"""

    def __init__(self, udp_timeout: float = 3.0, tcp_timeout: float = 5.0):
        self._udp_timeout = udp_timeout
        self._tcp_timeout = tcp_timeout

    async def exchange(
        self, query: dns.message.Message, where: str, port: int = 53
    ) -> dns.message.Message:
        response = await dns.asyncquery.udp(
            query,
            where,
            timeout=self._udp_timeout,
            port=port,
        )
        if response.flags & dns.flags.TC:
            response = await dns.asyncquery.tcp(
                query,
                where,
                timeout=self._tcp_timeout,
                port=port,
            )
        return response
