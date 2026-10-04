"""用真实 loopback socket 验证 AsyncioTransport 的 UDP/TCP 与截断重试。"""

import asyncio

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest

from recdns.transport import AsyncioTransport


def _answer(query, truncated=False):
    resp = dns.message.make_response(query)
    resp.set_rcode(dns.rcode.NOERROR)
    resp.flags |= dns.flags.AA
    if truncated:
        resp.flags |= dns.flags.TC
        return resp
    q = query.question[0]
    rr = dns.rrset.RRset(q.name, dns.rdataclass.IN, dns.rdatatype.A)
    rr.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.53"), 300)
    resp.answer.append(rr)
    return resp


class _DualServer:
    """UDP 前 N 次返回截断，之后给完整答案；TCP 始终给完整答案。"""

    def __init__(self, truncations=1):
        self.truncations = truncations
        self.udp_received = 0
        self.tcp_received = 0
        self.port = None

    async def serve_udp(self):
        loop = asyncio.get_running_loop()
        transport, _proto = await loop.create_datagram_endpoint(
            lambda: _UdpProto(self), local_addr=("127.0.0.1", 0)
        )
        self._udp_transport = transport
        self.port = transport.get_extra_info("socket").getsockname()[1]

    async def serve_tcp(self):
        self._tcp_server = await asyncio.start_server(
            self._handle_tcp, "127.0.0.1", self.port
        )

    async def start(self):
        await self.serve_udp()
        await self.serve_tcp()

    def close(self):
        self._udp_transport.close()
        self._tcp_server.close()

    def _handle_udp(self, data, addr):
        self.udp_received += 1
        query = dns.message.from_wire(data)
        trunc = self.udp_received <= self.truncations
        resp = _answer(query, truncated=trunc)
        self._udp_transport.sendto(resp.to_wire(), addr)

    async def _handle_tcp(self, reader, writer):
        while True:
            header = await reader.readexactly(2)
            length = int.from_bytes(header, "big")
            data = await reader.readexactly(length)
            self.tcp_received += 1
            query = dns.message.from_wire(data)
            wire = _answer(query).to_wire()
            writer.write(len(wire).to_bytes(2, "big") + wire)
            await writer.drain()


class _UdpProto(asyncio.DatagramProtocol):
    def __init__(self, server):
        self._server = server

    def connection_made(self, transport):
        self._server._udp_transport = transport

    def datagram_received(self, data, addr):
        self._server._handle_udp(data, addr)


async def test_udp_roundtrip():
    server = _DualServer(truncations=0)
    await server.start()
    try:
        t = AsyncioTransport(udp_timeout=2, tcp_timeout=2)
        q = dns.message.make_query("x.test.", "A")
        resp = await t.exchange(q, "127.0.0.1", server.port)
        assert resp.rcode() == dns.rcode.NOERROR
        assert server.udp_received == 1
        assert server.tcp_received == 0
        assert resp.answer[0][0].address == "127.0.0.53"
    finally:
        server.close()


async def test_truncated_udp_falls_back_to_tcp():
    server = _DualServer(truncations=1)
    await server.start()
    try:
        t = AsyncioTransport(udp_timeout=2, tcp_timeout=2)
        q = dns.message.make_query("x.test.", "A")
        resp = await t.exchange(q, "127.0.0.1", server.port)
        assert server.udp_received == 1
        assert server.tcp_received == 1
        assert not (resp.flags & dns.flags.TC)
        assert resp.answer[0][0].address == "127.0.0.53"
    finally:
        server.close()
