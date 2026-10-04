"""递归解析过程中的异常类型。"""


class RecursiveResolutionError(Exception):
    """所有解析错误的基类。"""


class UnsupportedQtype(RecursiveResolutionError):
    """查询类型不在允许范围 (A/CNAME/NS/SOA) 内。"""


class NXDOMAINError(RecursiveResolutionError):
    """权威服务器返回名称不存在。

    ``qname`` 为被判定不存在的名称（CNAME 链时是目标名称）。
    """

    def __init__(self, qname):
        self.qname = qname
        super().__init__(f"{qname} does not exist")


class NoData(RecursiveResolutionError):
    """名称存在但没有所请求类型的记录（NODATA）。"""

    def __init__(self, qname, rdtype):
        self.qname = qname
        self.rdtype = rdtype
        super().__init__(f"{qname} has no {rdtype} records")


class CnameLoop(RecursiveResolutionError):
    """跟随别名时发现了名称重复的环。"""


class HopLimitExceeded(RecursiveResolutionError):
    """跟随委派的跳数超过上限（8 跳）。"""


class NoGlue(RecursiveResolutionError):
    """NS 名称位于所委派区域内，但委派响应没有提供可用 glue。"""


class UpstreamError(RecursiveResolutionError):
    """所有候选上游服务器均不可达或返回畸形/错误响应。"""
