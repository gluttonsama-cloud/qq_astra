# QQ 桥接服务基础（Draft）

已实现可复用的持久化服务核心与本机 HTTP 验证入口。**尚未连接真实 QQ、SnowLuma、OAuth 或 dot；不能直接作为生产插件部署。**

## 当前范围

- SQLite 原子收件去重、持久事件队列、回复状态与固定账号/唯一好友绑定。
- MCP `server/discover`、`events/list`、订阅/刷新/取消订阅，以及只读状态和受限回复工具。
- 回调先验 challenge，再按 Standard Webhooks 签名；刷新轮换支持双签名。HTTPS 连接逐次检查并固定公网 IP，保留 TLS 主机验证，不跟随重定向。
- 事件重试有上限、指数退避和租约隔离；410/413 不重试。2xx 只代表回调收到，不代表 dot 已处理。
- SnowLuma v2.0.3 的真实 OneBot HTTP 文本格式适配：校验原始报文 HMAC-SHA1、账号及好友 ID；拒绝群聊、临时会话、自发回声、超时消息和非文本段。
- 回复收件人不可从工具传入，只能来自预绑定好友；每个收件事件最多一条回复。发送前复核网关登录账号。结果不明确或进程中断后标为 uncertain，不盲目重发。

## 本地验证

Python 3.11+，在仓库根目录运行：

```sh
python -m venv .venv
.venv/bin/pip install -r bridge_service/requirements.txt
.venv/bin/python -m unittest bridge_service.test_service bridge_service.test_webhooks -v
.venv/bin/python -m unittest discover -s offline_bridge -p 'test_*.py' -v
.venv/bin/python -m bridge_service.server --fixture
```

Windows 用 `.venv\Scripts\python` / `pip`。fixture 仅监听 127.0.0.1，使用源码中公开的虚构测试身份，数据库默认置于临时目录。它提供 `/mcp` 与 `/onebot/events`，**外发回调和 QQ 发送都关闭**。不要将此入口公开或接入 Tunnel。

不加 `--fixture` 时会拒绝启动。服务测试使用合成消息、模拟回调/网关或本机 HTTP；没有真实 QQ 验签/登录、dot 触发或公网交付的验证记录。原始离线示例保留在 `offline_bridge/`。

## 接入前仍需完成

1. 接入并验证 OAuth 2.1 的可信 principal，与用户明确授权的唯一 QQ 好友绑定。不得从消息正文、昵称或任意请求头推导主人身份。消息内容始终作为外部数据；此服务不提供 shell、通用工具执行或任意收件人发送接口。
2. 实际部署的认证入口、HTTPS 或 Secure MCP Tunnel、私密状态存储/加密和密钥轮换。当前 SQLite 保存消息及回调 secret，只用于测试；生产需受保护目录、容量/保留策略和备份。生产凭据不能写入仓库。
3. 单一回复 worker 的生命周期管理、健康监测、限流及进程级请求/DNS 总超时。网络适配器只有 socket 超时。已有 in-flight 请求不能撤回；撤销阻止后续排队交付。
4. 使用真实账号逐项验证插件发现、订阅、challenge、同一个 dot 接收、QQ 回复和停止订阅，再启用生产启动路径。HTTP harness 不是完整 MCP 客户端互通认证。

不支持事件历史回放（cursor 始终 null）、多好友/群聊、媒体、语音通话或无来源事件的主动发送。活跃订阅期间已入队的重试可跨重启保留；订阅过期时未交付队列取消，重订阅不会伪造历史回放。网关自身离线漏掉的消息不保证补回。`uncertain` 发送需先核查 QQ 侧记录，再决定是否人工恢复。

云端或 PC 都可采用“QQ 网关 + 本服务同机，dot 在云端”的结构。`LoopbackOneBot` 只接受明确的本机 HTTP 地址，不包含登录、下载网关、启用插件或公开端口功能。

## 协议来源

- [OpenAI MCP Events](https://developers.openai.com/plugins/build/mcp-events)：按 `2026-07-28` 集成文档实现；CallbackEndpointError 使用该文档的 -32015。draft MCP 上游可能变动，真实客户端互通仍待验证。
- [Standard Webhooks Python](https://github.com/standard-webhooks/standard-webhooks/tree/main/libraries/python)：签名直接使用官方库，无自创兼容算法。
- [SnowLuma HTTP 上报签名](https://github.com/SnowLuma/SnowLuma/blob/v2.0.3/packages/onebot/src/network/http-post-adapter.ts)、[私聊事件](https://github.com/SnowLuma/SnowLuma/blob/v2.0.3/packages/onebot/src/event-converter/to-message.ts)、[私聊发送](https://github.com/SnowLuma/SnowLuma/blob/v2.0.3/packages/onebot/src/actions/message.ts)、[登录账号查询](https://github.com/SnowLuma/SnowLuma/blob/v2.0.3/packages/onebot/src/actions/info.ts)：静态源码对齐，不代表实际登录联调通过。
