# recdns —— 只访问测试权威服务器的递归解析器

基于 asyncio 与 dnspython 的递归 DNS 解析器，查询类型限定为
**A / CNAME / NS / SOA**，默认向查询发送 `RD=0`，只与配置的根/权威
服务器通信，绝不向系统解析器或其它主机发起请求。

## 特性与对应实现

| 需求 | 实现位置 |
| --- | --- |
| 从配置根逐级跟随委派，最多 8 跳 | `resolver._follow_referral` / `MAX_REFERRAL_HOPS` |
| glue 必须属于所委派区域且对应 NS 名称 | `resolver._absorb_referral` |
| CNAME 跟随与环检测 | `resolver._walk_cache` / `_walk_answer` / `_commit_cnames_and_advance` |
| UDP 收到 TC 后 TCP 重试 | `transport.AsyncioTransport` |
| 正缓存按 TTL 失效 | `cache.Cache.get_rrset` |
| NXDOMAIN 按名称缓存 | `cache.Cache.put_nxdomain`（类型用通配键） |
| 无该类型按 (名称,类型) 缓存 | `cache.Cache.put_nodata` |
| 负缓存 TTL = 覆盖链尾 SOA 的 RR TTL 与 MINIMUM 较小值 | `resolver._negative_ttl_if_covering`，无覆盖 SOA 不缓存 |
| 相同查询共享进行中的上游请求 | `singleflight.SingleFlight` |
| 一个等待者取消不影响其他等待者 | 每个等待者私有 Future + 工厂独立任务 |
| 可控时钟 | `clock.FakeClock` |
| 假权威节点 | `fakenet.Zone` / `FakeNetwork` / `FakeTransport` |

## 使用

```python
import asyncio
from recdns import RecursiveResolver, AsyncioTransport, SystemClock

async def main():
    resolver = RecursiveResolver(
        root_hints={"a.test-root.": ["10.0.0.1"]},
        transport=AsyncioTransport(),
        clock=SystemClock(),
    )
    answer = await resolver.resolve("www.example.", "A")
    print(answer.canonical_name,
          [r.address for rr in answer.rrsets for r in rr])

asyncio.run(main())
```

## 测试

```
python3 -m pytest tests/ -q
```

测试主要运行在进程内的假网络上（`tests/tree.py` 构造根/多级区/委派/
伪造 glue 的权威树），另含两组 loopback 真实 socket 测试
（`tests/test_real_transport.py`）验证 UDP→TCP 重试。

### 覆盖的关键场景

* **伪造 glue**：附加区中不对应 NS 名称的地址、bailiwick 之外的地址
  一律拒绝；与真实 glue 同属主的伪造坏地址与好地址合并，逐台容错后
  仍能解析成功。
* **别名链**：区内多级 CNAME、跨区 CNAME（权威在 answer 给 CNAME、
  authority 给目标区委派）、CNAME 环、跨区别名目标 NXDOMAIN 按目标名
  缓存。
* **负缓存边界**：SOA TTL 120 / MIN 60 缓存 60 秒；SOA TTL 30 /
  MIN 3600 缓存 30 秒；恰好到期重查；负响应缺 SOA 时不缓存；NODATA
  只对 (名称, 类型) 生效。
* **取消竞争**：上游挂起时三个并发等待者共享一次查询；取消其中任一
  个，其余等待者和底层工厂照常完成；取消后新加入的等待者也能拿到
  结果。
* **跳数**：8 跳成功、第 9 跳拒绝，跳数按单次解析计数。
* **截断**：假网络与真实 loopback socket 两种方式验证 TC→TCP。
