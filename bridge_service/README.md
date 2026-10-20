# QQ 文本桥接服务（Draft）

已有可配置运行入口，已验证本机合成闭环。**尚未完成真实 QQ、OAuth 授权、dot 或 Tunnel 联调。** 原始离线示例保留在 `offline_bridge/`。

## 范围与运行方式

最小架构是 **QQ 网关与桥接服务同机，dot 通过 HTTPS 或受支持的 Secure MCP Tunnel 访问桥接服务**。QQ 网关只接受 loopback 地址，不需要公开网关端口。Linux 已做本机验证；Windows 已完成部分原生检查，**备份发布仍有共享冲突，完整验收未通过，不代表已经可用或接通**。

已实现：
- 单一可信 OAuth 主人与唯一 QQ 好友的固定绑定。文本是外部数据，不能授权其他工具；回复工具不接受收件人或任意动作。
- MCP `2026-07-28` 发现、事件目录、订阅/刷新/取消、状态和受限回复。只保留一个活跃订阅，持续消息可送到该订阅；本账号的同一 dot 实际承接尚待验证。
- SQLite 持久收件去重、事件重试和回复状态；消息、回复、绑定、回调 URL/secret 使用 Fernet 加密。私密目录、单进程锁、完整性检查和停止时备份。
- Standard Webhooks challenge、签名和轮换双签名；HTTPS 逐次校验公网 DNS 并固定 IP，验证 TLS，不跟随跳转。DNS、连接、慢速响应均有总截止时间。
- 单 worker、限流、并发/体积限制、健康检查与优雅停止。SnowLuma v2.0.3 OneBot 文本收发格式、HMAC-SHA1 入站校验和发送前账号复核。

## Linux 本机验证

Python 3.11+，在仓库根目录运行：

```sh
python -m venv .venv
.venv/bin/pip install -r bridge_service/requirements.txt
.venv/bin/python -m unittest bridge_service.test_service bridge_service.test_webhooks bridge_service.test_auth bridge_service.test_state bridge_service.test_runtime -v
.venv/bin/python -m unittest bridge_service.test_windows_state bridge_service.test_platform_state -v
.venv/bin/python -m unittest discover -s offline_bridge -p 'test_*.py' -v
```

测试只使用合成账号、临时测试密钥、模拟传输和本机连接。可选 `python -m bridge_service.server --fixture` 是单独的演示入口，使用公开测试身份，外发全部关闭，禁止接入公网或 Tunnel。

## 配置后启动

`config.example.json` 是故意不能直接启动的模板，不含可用凭据。配置必须由操作者提供；服务不会生成账号、OAuth grant、密钥或 Tunnel。

1. 使用已有 OAuth 授权服务器，支持 ChatGPT 的授权流程、PKCE 和资源指示符。配置准确的 issuer、主人 subject、公开 `/mcp` URL，以及可信公钥 JWKS。服务是资源服务器，不是授权服务器。
2. 配置当前网关的 loopback HTTP 地址、已授权的账号/好友 ID 和既有 token 文件。网关 HTTP 服务与 HTTP 上报两侧的 `accessToken` 都须与该文件一致，消息格式设为 `messageFormat=array`。事件 POST 到 `http://127.0.0.1:8765/onebot/events`，原始 JSON 使用该 token 签名；桥接响应不执行 quick-operation 回复。端口可改。
3. 将配置与秘密文件放在仓库外的私密目录。Linux 上配置、token、既有 Fernet state key 文件需当前用户所有、0400/0600；状态目录0700，数据库0600。JWKS可0644，但不得可被其他用户写入。Windows 使用下述 ACL 流程，不以 chmod 代替权限检查。父路径不得使用符号链接或不可信可写目录。保管好 state key，丢失后无法解密。
4. 验证配置，再运行服务：

```sh
python -m bridge_service.runtime --config /private/path/config.json --check
python -m bridge_service.runtime --config /private/path/config.json
```

`--check` 仅验证配置、认证信任和秘密文件；不验证账号、网关、网络连通或状态目录。真正启动会额外验证状态并取得独占锁。默认监听 `127.0.0.1:8765`，只支持一个进程/worker，不要加 Uvicorn 多 worker 或 reload。SIGINT/SIGTERM 会停止收件、等待当前发送结束并备份。用受信任的进程管理器管理长期运行，当前仓库不安装系统服务。

HTTPS 代理/Tunnel 只转发 `/mcp` 和 OAuth protected-resource metadata 路径；**不要转发 `/onebot/events`**。保留公共 Host，转发 Authorization；不信任 X-Forwarded-*。本机 `/healthz` 仅报告队列 worker 是否存活，不证明 QQ 登录或 dot 在线。公网访问、证书、Tunnel 和插件配置仍由操作者接入。

### 可选：显式本机 HTTP CONNECT 出站代理

`webhook_proxy_url` 默认 `null`（直连）。如操作者已有可信本机 HTTP CONNECT 代理，可显式配置为 `http://127.0.0.1:8080` 或 `http://[::1]:8080`，端口按实际填写。只影响 webhook 出站；不改变 QQ loopback 网关、入站 HTTPS/Tunnel 或系统设置。不读取 HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY、Windows 代理设置或 PAC，也不自动回退到直连。

首版只支持上述字面 loopback 地址、显式端口和无凭据 HTTP 代理。拒绝远程代理、localhost 域名、SOCKS、HTTPS 代理、用户名/密码、路径、查询和 fragment；代理要求认证时失败，不产生或保存凭据。`--check` 检查配置格式，不证明代理或网络可用。

回调仍只允许公网 HTTPS:443。每次请求先在本机解析回调域名，检查**全部**结果均为允许的公网地址，再发送 `CONNECT <已验证数字IP>:443`（IPv6 使用方括号）。代理只收到数字目标；随后对原回调域名进行 TLS/SNI/证书校验，HTTP Host 仍为原域名，路径、签名及正文只在目标 TLS 内发送。不跟随回调或 CONNECT 跳转。DNS、代理连接、CONNECT 响应、目标 TLS 和 HTTP 共用总截止时间，CONNECT 响应头另有 16KiB 上限。

本机 DNS 失败、返回私网/保留/合成地址（包括常见 fake-IP 段），或代理不支持数字 IP CONNECT 时都会拒绝，**不会改成代理解析域名或跳过 SSRF 检查**。经代理的普通 curl 成功不能替代这些检查。显式选择代理意味着信任其路由行为；应用固定 CONNECT 数字目标并验证目标 TLS，但无法证明代理内部未重映射目标。首版不承诺适配依赖代理远端 DNS 的环境。

增量验证：`python -m unittest bridge_service.test_webhooks bridge_service.test_proxy_webhooks -v`。使用模拟 socket、合成回调地址与固定测试数据；不接触真实账号、网络代理或 Windows ACL。

### Windows PC 网关后备（验收未通过）

QQ 网关与桥接均在 PC 上，dot 仍在云端。使用本地固定 NTFS 盘和普通用户 Python 3.11+；暂不支持 UNC/网络盘、SUBST、重解析目录、OneDrive占位文件和长路径。PC 必须在线；本项目不改防火墙、不安装系统服务、不公开 QQ 网关。Windows 使用 Ctrl+C 正常停止；关闭窗口、强制结束或断电可能硬中断，不能保证生成最后一份备份，重启按已提交状态恢复。

同一个运行入口也负责创建私密项目目录。安装上述依赖时 Windows 会额外安装已固定版本的 pywin32，无需全局 post-install 或管理员权限：

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r bridge_service/requirements.txt
.\.venv\Scripts\python.exe -m bridge_service.windows_selfcheck
.\.venv\Scripts\python.exe -m bridge_service.runtime --prepare-windows-directory "$env:LOCALAPPDATA\qq-astra"
.\.venv\Scripts\python.exe -m bridge_service.runtime --config "$env:LOCALAPPDATA\qq-astra\config.json" --check
.\.venv\Scripts\python.exe -m bridge_service.runtime --config "$env:LOCALAPPDATA\qq-astra\config.json"
```

准备目录后，将模板另存为其中的 `config.json`，填写同一组配置；已有 `public-jwks.json`、`onebot.token` 和 `state.key` 也放在该目录，禁止放进仓库。准备命令不产生密钥或授权。新目录在创建时设置受保护 DACL，仅当前用户、SYSTEM 和 Administrators；已有宽权限目录直接拒绝，不自动修改 ACL。在受保护私密父目录内创建的文件可继承同一严格权限。

自检只在新建、可删除的项目测试目录验证真实 ACL、宽/NULL DACL 拒绝、目录句柄防写入/重命名、双进程锁、SQLite备份/重开和链接拒绝，不读取真实账号/配置。非 Windows 明确返回 `not_tested`；无法创建重解析测试样本会返回 `partial`，不会自动提权或修改开发者模式。只有 Windows 实测结果才能确认此候选支持。

如果默认 `%LOCALAPPDATA%` 路径的祖先 ACL 被拒绝，可显式选择另一个**已有**的本地父目录，例如用户主目录，再运行同一组自检：

```powershell
.\.venv\Scripts\python.exe -m bridge_service.windows_selfcheck --parent-directory "$env:USERPROFILE"
```

该选项只决定新建的 `QQAstra-selfcheck-<随机ID>` 临时目录位置，不改变默认状态路径，不创建或修复父目录，不绕过任何 NTFS、祖先 ACL、私密 ACL 或句柄检查。已有目录的继承 ACE 若实际授予额外主体删除子项、修改 DACL 等权限，仍会拒绝；只有 `INHERIT_ONLY` ACE 不作用于当前对象。自检报告增加 `failure_stage` 和不含 SID/路径的 `details`，可区分 `ancestor_unsafe_allow` 与 Win32 `winerror`，避免把所有失败都归为权限不足。

自检通过后，操作者可另行把私密项目目录选为 `%USERPROFILE%\qq-astra`，使用已有 `--prepare-windows-directory` 入口准备，再将配置和已有秘密文件放入其中。配置需显式设置 `"state_dir": "./state"`，让状态位于该私密目录下；仅移动 `config.json` 不会改变默认状态位置。此处不会自动搬迁现有状态或改动 AppData/Local 的 ACL。

2026-10-20 的 Windows x64 / Python 3.13.3 原生检查：用户主目录下的新建临时目录通过私密/继承 ACL、宽/NULL DACL 拒绝、硬链接拒绝、目录写入/重命名保护和双进程锁。备份发布在 `MoveFileEx` 返回 `winerror=32`，重开和重解析点检查未完成。独立合成样本确认：保护句柄打开时重命名文件失败，关闭后成功。当前保留目录保护语义，未放开写入共享；须解决该冲突后才能完整验收。测试目录均已清理。自检已修正硬链接样本创建时机，并保证 SQLite 连接在异常路径关闭。

### OAuth 与状态约束

- 仅接收 `typ=at+jwt` 或 `application/at+jwt` 的 RS256/ES256 access token，严格校验签名、issuer、单一精确 audience、固定 subject、时间和 scope。持久身份同时绑定 issuer、resource 与 subject，改变其中任一项不能复用旧状态。通用 `typ=JWT`、ID token、opaque token 不支持；身份提供方必须匹配此配置。
- `qq:read` 用于发现/目录/状态，`qq:events` 用于订阅，`qq:reply` 用于回复；完整桥接需授予三项权限。工具缺权限或凭据过期时返回标准重新授权 metadata；发现/Events 使用 HTTP challenge，实际授权界面仍待联调。公钥文件每次校验重读，原子替换支持公钥轮换。服务不下载不受信任的 token 内 JWKS URL。
- 生产订阅最多持续1小时，并且不能超过创建/刷新 access token 的有效期。没有 OAuth introspection；已创建的订阅在租约内仍有效，停服务或本地撤销绑定可立即阻止后续工作。已开始的网络发送无法撤回。
- 默认状态路径：Linux 为 `$XDG_STATE_HOME/qq-astra` 或 `~/.local/state/qq-astra`，需本机可靠 SQLite/flock 文件系统；Windows 为 `%LOCALAPPDATA%\qq-astra`，需上述本地 NTFS/ACL 与 LockFileEx 支持。自动保留最多10,000条收件，可用 `max_messages` 调至1–100,000；达到上限会拒绝新消息，不暗中删数据。暂不提供保留期清理或密钥迁移。
- 正常重启自动恢复已提交队列；中断的 QQ 发送标记 `uncertain`，不重发。停止备份为 `bridge.backup.sqlite3`；损坏时保留原库和 sidecar，拒绝启动，不自动用旧备份覆盖。人工恢复需停服务、保留原文件、验证备份及同一 state key/绑定。加密不隐藏数量、时序等元数据，也不防御已控制服务账号的攻击者。

## 明确限制与下一步

仅支持好友私聊文本：入站最多64KB文字，回复最多16KB；媒体、文件、群聊、实时语音、主动无来源消息尚未实现。每个收到的事件最多一条回复；延迟回复可在该事件上完成，但不是无限次多消息会话发送接口。

事件无历史回放（cursor 为 null）；订阅过期的未交付任务取消。活跃租约内重试最多5次；410/413等终止，不把2xx当作 dot 已处理。网关自身漏报不能补回。QQ 发送只有明确成功确认才标记 confirmed，结果不明需先核查 QQ 记录，不能盲目重发。

接下来必须用真实配置验证：OAuth 授权与发现 → 订阅 challenge → 同一 dot 收到私聊事件 → 受限回复 → 取消订阅/重启。当前本地测试通过不能替代这一记录，也未注册、部署或启用任何真实插件。

## 主要来源

- [OpenAI MCP Events](https://developers.openai.com/plugins/build/mcp-events) 与 [插件认证](https://developers.openai.com/plugins/build/auth)：2026-07-28 集成；CallbackEndpointError 使用该文档的 -32015。
- [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks/tree/main/libraries/python)、[PyJWT](https://pyjwt.readthedocs.io/en/stable/api.html)、[JWT access token 类型](https://www.rfc-editor.org/rfc/rfc9068.html)。
- SnowLuma v2.0.3：[HTTP 签名](https://github.com/SnowLuma/SnowLuma/blob/v2.0.3/packages/onebot/src/network/http-post-adapter.ts)、[私聊事件](https://github.com/SnowLuma/SnowLuma/blob/v2.0.3/packages/onebot/src/event-converter/to-message.ts)、[发送](https://github.com/SnowLuma/SnowLuma/blob/v2.0.3/packages/onebot/src/actions/message.ts)、[账号查询](https://github.com/SnowLuma/SnowLuma/blob/v2.0.3/packages/onebot/src/actions/info.ts)。只做静态源码对齐，未运行网关。
- Windows：[CreateFileW 句柄与共享模式](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)、[文件访问权限](https://learn.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants)、[pywin32 API](https://mhammond.github.io/pywin32/)；候选实现仍需 Windows 本机自检与联调。
