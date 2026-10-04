"""只访问测试权威服务器的递归解析器（A / CNAME / NS / SOA）。"""

from .clock import Clock, FakeClock, SystemClock
from .exceptions import (
    CnameLoop,
    HopLimitExceeded,
    NXDOMAINError,
    NoData,
    NoGlue,
    RecursiveResolutionError,
    UpstreamError,
    UnsupportedQtype,
)
from .resolver import Answer, RecursiveResolver
from .transport import AsyncioTransport, Transport

__all__ = [
    "Answer",
    "Clock",
    "CnameLoop",
    "FakeClock",
    "HopLimitExceeded",
    "NXDOMAINError",
    "NoData",
    "NoGlue",
    "RecursiveResolutionError",
    "RecursiveResolver",
    "SystemClock",
    "Transport",
    "AsyncioTransport",
    "UnsupportedQtype",
    "UpstreamError",
]
