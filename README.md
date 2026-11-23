# srv6-policy-steering-validator

SRv6 策略段列表与行为链路径校验器(Node.js 24.16.0)。

同一业务流量需要经过安全清洗、跨域转发和本地解封装时,控制面段列表正确并不代表
转发语义正确——例如某个 SID 实际命中普通 `End` 而非 `End.X` / `End.DT`,报文会在
中途失去转发语义。本工具在控制面逐跳推演剩余段列表、SL、下一跳与封装状态,提前
发现这类问题。

> 注意:本工具只做控制面仿真与校验,**不生成、不发送真实 IPv6 报文**。

## 使用

```bash
node src/cli.js examples/broken-policy.json
```

输出每跳段栈、命中行为、失败节点与修复顺序;校验失败时退出码为 1。

## 输入字段

| 字段 | 说明 |
| --- | --- |
| `segmentList` | 段列表,按执行顺序排列 |
| `behaviors` | SID -> `{ node, type, nextHop?, vrf?, usidBlock?, segmentList? }` |
| `adjacency` | 节点 -> 邻居节点列表(校验 End.X 下一跳) |
| `vrfs` | 节点 -> 已配置 VRF 列表(校验 End.DT) |
| `encap` | `{ type: H.Encaps / H.Encaps.Red / H.Insert / H.Insert.Red, packetSize? }` |
| `mtu` | 路径 MTU(缺失时报 `MTU_NOT_CONFIGURED`) |
| `returnPolicy` | `{ symmetric, path }` 回程策略 |
| `packetDst` | 内层报文目的地址(校验 DT4/DT6 地址族) |
| `vrf` | 期望解封装进入的 VRF |

## 识别的故障

- `UNKNOWN_BEHAVIOR`:SID 未注册行为或行为类型不受支持
- `LOST_FORWARDING_SEMANTICS`:策略中段命中普通 End,失去转发语义
- `SEGMENT_LIST_RECURSION`:绑定 SID 段列表循环引用 / 状态重复
- `USID_MISALIGNMENT`:uSID 容器与节点块前缀错位,或移位后活动 uSID 为 0
- `MTU_NOT_CONFIGURED` / `MTU_EXCEEDED`:MTU 丢失或封装开销后空间不足
- `END_DT_WRONG_VRF`:End.DT 使用节点上未配置的 VRF 或地址族不匹配
- `ADJACENCY_MISSING`:End.X 下一跳不在邻接表中
- `DECAP_TOO_EARLY`:End.DT 在 SL≠0 处提前解封装
- `ASYMMETRIC_RETURN`:回程不经过与去程镜像的对称策略

修复顺序按依赖优先级排序:先补行为注册与转发语义,再解递归/uSID/邻接,
然后修 VRF 与 MTU,最后处理回程对称。

## 测试

```bash
node --test
```

覆盖 End、End.X、End.DT4、uSID、路径回程与 MTU 丢失等场景。
