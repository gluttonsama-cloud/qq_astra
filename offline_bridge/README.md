# 离线桥接基础

当前仅验证：合成 QQ 消息 → 白名单 → 去重 → MCP Events 格式事件 → 模拟回复。

**尚未连接真实 QQ 或 dot，也没有启动 MCP 服务。** 所有账号、消息和回复都是测试数据；不使用网络或凭据。

## 运行

Python 3.11+，仅使用标准库：

```sh
cd offline_bridge
python3 bridge_sim.py
python3 -m unittest -v
```

演示应只记录一次模拟回复，`sent` 和全部 `verified_live` 项保持 `false`。

现有 14 项测试覆盖输入校验、白名单、去重、回声过滤、事件大小和回复目标约束。

## 接入边界

- 消息字段是网关无关的规范化设计，尚未验证 QQ 或 SnowLuma 的真实报文。
- 事件信封参考 [MCP Events](https://developers.openai.com/plugins/build/mcp-events)；`qq.message.created` 是本项目拟定的事件名。
- 状态仅保存在内存，重启即丢失。真实接入仍需网关适配、身份验证、持久存储、OAuth、事件订阅和签名回调。
- 回复工具只记录调用，没有发送能力。离线测试通过不代表端到端接通，当前代码不能直接作为生产服务部署。
