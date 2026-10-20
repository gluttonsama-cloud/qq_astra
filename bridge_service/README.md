# QQ 文字与媒体桥接服务（Draft）

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

### Windows PC 网关后备（本机存储自检已通过；端到端未验收）

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

2026-10-20 在 Windows x64 / Python 3.13.3 原生验收：用户根目录下的新建临时目录通过全部十组自检，包括私密/继承 ACL、宽/NULL DACL 拒绝、硬链接拒绝、目录写入/重命名保护、双进程锁、首次和覆盖 WAL 备份、旧备份保留与失败重试、完整性和重开、硬链接备份目标拒绝，以及目录/备份目标的重解析点拒绝。读者禁止删除共享时，发布返回 `winerror=5`，旧备份和源数据库均保留；读者关闭后重试成功。`not_tested` 为空，临时目录清理完成。策略及平台契约另有 21 项测试通过。

备份发布使用 `NtSetInformationFile` 的同目录 `FileRenameInformation`：目标限定为备份文件名，源文件句柄一直保留，发布前后刷新数据并验证同一对象；所有祖先与状态目录的保护句柄持续开启，未放宽共享模式或 ACL 信任范围。重开和失败恢复已验证，但未进行断电测试，不保证强制终止/断电时最后一次目录元数据提交。该结果只覆盖本机存储实现，不代表 QQ 登录、OAuth、云端 dot 回调或端到端通信已经验收。

### OAuth 与状态约束

- Accept only explicitly typed `at+jwt` / `application/at+jwt` RS256/ES256 access tokens. Verify signature, exact issuer, fixed owner subject, time and route scope. `aud` must be the exact resource string or a nonempty array of nonempty strings containing that exact resource. ID tokens, generic `typ=JWT`, opaque tokens and local transport URLs as audience are rejected. Persisted identity remains bound to issuer + external resource + subject.
- `qq:read` protects discovery/status, `qq:events` subscriptions, and `qq:reply` replies. Permission failures keep the existing HTTP/MCP relinking challenges. Local public JWKS files are reread for every validation; opt-in issuer retrieval follows the bounded cache policy below. Token-provided key URLs are always rejected.
- 生产订阅最多持续1小时，并且不能超过创建/刷新 access token 的有效期。没有 OAuth introspection；已创建的订阅在租约内仍有效，停服务或本地撤销绑定可立即阻止后续工作。已开始的网络发送无法撤回。
- 默认状态路径：Linux 为 `$XDG_STATE_HOME/qq-astra` 或 `~/.local/state/qq-astra`，需本机可靠 SQLite/flock 文件系统；Windows 为 `%LOCALAPPDATA%\qq-astra`，需上述本地 NTFS/ACL 与 LockFileEx 支持。自动保留最多10,000条收件，可用 `max_messages` 调至1–100,000；达到上限会拒绝新消息，不暗中删数据。暂不提供保留期清理或密钥迁移。
- 正常重启自动恢复已提交队列；中断的 QQ 发送标记 `uncertain`，不重发。停止备份为 `bridge.backup.sqlite3`；损坏时保留原库和 sidecar，拒绝启动，不自动用旧备份覆盖。人工恢复需停服务、保留原文件、验证备份及同一 state key/绑定。加密不隐藏数量、时序等元数据，也不防御已控制服务账号的攻击者。

## 明确限制与下一步

支持固定好友私聊文字和下述受限图片/表情；入站 JSON 最多64KB，文字回复最多16KB。通用文件、群聊、实时语音和任意来源消息尚未实现。文字回复仍限定每个事件一条；新增媒体写操作使用独立 request_id 和持久化队列。

事件无历史回放（cursor 为 null）；订阅过期的未交付任务取消。活跃租约内重试最多5次；410/413等终止，不把2xx当作 dot 已处理。网关自身漏报不能补回。QQ 发送只有明确成功确认才标记 confirmed，结果不明需先核查 QQ 记录，不能盲目重发。

接下来必须用真实配置验证：OAuth 授权与发现 → 订阅 challenge → 同一 dot 收到私聊事件 → 受限回复 → 取消订阅/重启。当前本地测试通过不能替代这一记录，也未注册、部署或启用任何真实插件。

## 主要来源

- [OpenAI MCP Events](https://developers.openai.com/plugins/build/mcp-events) 与 [插件认证](https://developers.openai.com/plugins/build/auth)：2026-07-28 集成；CallbackEndpointError 使用该文档的 -32015。
- [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks/tree/main/libraries/python)、[PyJWT](https://pyjwt.readthedocs.io/en/stable/api.html)、[JWT access token 类型](https://www.rfc-editor.org/rfc/rfc9068.html)。
- SnowLuma v2.0.3：[HTTP 签名](https://github.com/SnowLuma/SnowLuma/blob/v2.0.3/packages/onebot/src/network/http-post-adapter.ts)、[私聊事件](https://github.com/SnowLuma/SnowLuma/blob/v2.0.3/packages/onebot/src/event-converter/to-message.ts)、[发送](https://github.com/SnowLuma/SnowLuma/blob/v2.0.3/packages/onebot/src/actions/message.ts)、[账号查询](https://github.com/SnowLuma/SnowLuma/blob/v2.0.3/packages/onebot/src/actions/info.ts)。只做静态源码对齐，未运行网关。
- Windows：[CreateFileW 句柄与共享模式](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)、[文件访问权限](https://learn.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants)、[pywin32 API](https://mhammond.github.io/pywin32/)；候选实现仍需 Windows 本机自检与联调。

### Secure MCP Tunnel and opt-in issuer JWKS

The listener always serves `/mcp` and `/.well-known/oauth-protected-resource/mcp`
on loopback. With `"secure_mcp_tunnel": true`, `public_resource_url` is the exact
connector-facing HTTPS resource after OpenAI's rewrite, independent of those local
routes. Copy the actual resource from the connection; do not invent a tunnel URL.
The local 401 challenge points to the fixed loopback metadata endpoint for Tunnel
client discovery. Direct HTTPS mode keeps the existing `/mcp` requirement.
Changing only the transport mode/port does not change the persisted identity.

For Auth0-style HTTPS root issuers, replace `jwks_file` with
`"jwks_from_issuer": true`. These sources are mutually exclusive. The only remote
key URL is `<configured issuer>/.well-known/jwks.json`; issuer paths, URL discovery,
redirects and token-supplied URLs cannot change it. `--check` remains offline and
does not prove remote keys are available. Retrieval starts on authentication.

Remote JWKS accepts at most 1 MiB / 64 validated public signing keys. A fetch has
a 5-second total network deadline; DNS answers must all be public, the connection
pins a validated IP, and TLS verifies the original issuer hostname. Redirects,
compressed responses and ambient proxies are rejected. Optional `jwks_proxy_url`
uses the same explicit credential-free loopback CONNECT policy as webhooks; it
is separate from `webhook_proxy_url` and never changes global proxy settings.

The memory cache expires after 5 minutes. An unknown `kid` may trigger an early
refresh, with one shared 60-second cooldown and one concurrent fetch; unknown IDs
are not retained. Failed refreshes clear every cached key and fail authentication
closed (503), including during the cooldown. A successful refresh replaces the
whole key set. Removed keys stop working at refresh, at latest cache expiry;
there is no stale fallback or immediate remote revocation promise.

Configure Auth0's RFC 9068 access-token profile, RS256, resource-parameter support,
and only the API permissions needed below. The provider still performs authorization
code + PKCE, user consent and token issuance; this bridge does not create them.
Real account availability, OAuth linking, Tunnel discovery and event delivery
remain untested. No credentials or real tokens are included in these examples.

Portable regressions (mocked network, no live account):
`python -m unittest bridge_service.test_oauth_tunnel bridge_service.test_webhooks bridge_service.test_proxy_webhooks -v`

Sources: [OpenAI Tunnel v0.0.16 configuration](https://github.com/openai/tunnel-client/blob/v0.0.16/docs/configuration.md),
[Auth0 access-token profiles](https://auth0.com/docs/secure/tokens/access-tokens/access-token-profiles),
[Auth0 JWKS](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets).

### 图片、表情与显式空间发布（SnowLuma v2.0.3）

| 工具 | 行为 | 独立 OAuth scope |
| --- | --- | --- |
| `qq_read_image` | 读取已准入事件的附件，返回真正的 MCP image 内容 | `qq:media:read` |
| `qq_list_faces` / `qq_list_custom_faces` | 查询网关的系统表情/机器人自己的收藏表情目录 | `qq:media:read` |
| `qq_send_image` | 将用户提供的 PNG/JPEG/WebP/GIF 发给固定好友，可选择表情展示 | `qq:media:send` |
| `qq_send_face` / `qq_send_custom_face` | 验证实际目录后发送；收藏使用专门的 `send_custom_face` | `qq:media:send` |
| `qq_send_market_face` | 复用已准入消息的商城表情；缺少 package/key 时拒绝发送 | `qq:media:send` |
| `qq_publish_qzone` | 发布明确请求的文字或最多三张图片到**机器人自己的空间** | `qq:qzone:publish` |
| `qq_operation_status` | 查询持久化操作结果；不触发重发 | `qq:read` |

原有 `qq:read`、`qq:events`、`qq:reply` 不隐式授予新权限；模板和代码不会创建或扩大真实 grant。空间正文、`images`（无图为 `[]`）、`ugc_right`、`target_uins` 都必须明确传入：1 所有人、4 好友、16 指定好友、64 自己、128 排除指定好友。16/128 需要非空目标名单，其他可见范围要求 `[]`；没有公开默认值。工具声明为外部写操作，只应响应 ChatGPT 用户直接提出的发布请求，不能由收到的 QQ 内容或事件自动发布。入站处理程序不会调用发布。服务端不能仅凭同一个 bearer token 区分真人指令和自动化；部署时须单独限制发布 scope 并保留客户端写操作审批，不应将它授予收信自动化。

身份由配置的 `peer_id` 与签名入站 sender 一致性确定，`account_id/self_id` 是机器人账号。事件中独立的 `sender_identity` 提供 `bound_owner`、真实固定 QQ ID、bot QQ ID 和稳定 `conversation_key`，不从昵称、第一位发信人或正文“我是主人”推断。它帮助 dot 关联同一人的聊天上下文，但不保证 dot 自动共享记忆、接续原对话或持续保留人格；这些须真实连接后验收。

图片输入遵守 OpenAI `_meta["openai/fileParams"]`：对象声明 `download_url`、`file_id`、`mime_type`、`file_name`，只要求前两项。`file_download_hosts` 默认为 `[]`，因此用户文件下载默认关闭。实际连接后，由操作者核实文件提供方的精确域名再配置（最多八个）；不要推测域名、使用通配符或相信模型提供的任意 URL。文件名从不作为本地路径使用。入站只接受已签名且属于固定好友事件的 QQ CDN 源，公开事件仅含 opaque 附件引用；`get_image` 刷新只允许同一资源的 rkey 更新。

所有下载限定 HTTPS:443、完整 DNS 公网检查、固定 IP 和原域名 TLS 校验；禁跳转、压缩和隐式代理。`media_proxy_url` 默认 `null`，可单独选择与 webhook 相同规则的无凭据 loopback HTTP CONNECT 代理，不修改系统设置。网络总截止时间10秒，最多两个并发读取/解码。实际字节与 MIME 必须一致：每张最多4MiB、每帧400万像素、最多64帧且合计3200万像素；只允许 GIF 动画。读图生成无元数据、最长边1024像素以内的 PNG；GIF 只展示首帧，不能据此声称看过完整动作。发送 GIF 保留已验证的原始动画字节。真实 dot 是否展示/理解图片、实际文件下载域名和 QQ 展示效果仍未验收。

不缓存图片文件。私有源信息加密保存24小时，过期逻辑清理；发送字节仅在加密 outbox 中暂存，15分钟未发送即过期。最多16个待处理操作、32MiB序列化载荷、1000个持久去重记录，容量满时拒绝新操作。终态清空载荷，备份/WAL可能仍保留旧加密页，这不是安全擦除。相同 `request_id`/内容重试返回既有状态；不同内容冲突。网关响应丢失或发送中进程中断标记 `uncertain`，不自动重发，也不要换 request_id 重试；空间图片可能已上传而发布结果未知。

合成验证，不读取真实收藏/聊天，不发布真实消息：

```powershell
.\.venv\Scripts\python.exe -m unittest bridge_service.test_media bridge_service.test_service bridge_service.test_oauth_tunnel bridge_service.test_webhooks bridge_service.test_proxy_webhooks bridge_service.test_windows_state bridge_service.test_platform_state -q
.\.venv\Scripts\python.exe -m bridge_service.windows_media_assembly --parent-directory "$env:USERPROFILE"
```

Windows 装配创建可清理的受保护临时目录、真实桥接子进程及 loopback 模拟 QQ/回调/图片 HTTP 服务；仅测试入口将固定合成源映射到模拟服务器。它验证 OAuth scope、签名事件、图像解码、各类发送、幂等、不确定状态、备份与重启；不验证公网 DNS/TLS、真实 QQ 或 dot。旧 `test_auth` 中的 POSIX chmod/软链接权限用例不适用于 Windows；这里由 portable OAuth 用例、Windows ACL 测试和受保护 JWKS 的实际装配覆盖相关路径，未修改生产权限校验。

协议与固定版本来源：[OpenAI fileParams](https://developers.openai.com/plugins/reference#define-file-inputs)、[MCP 图像内容](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#image-content)、[SnowLuma 发送与收藏表情](https://github.com/SnowLuma/SnowLuma/blob/v2.0.3/packages/onebot/src/actions/message.ts)、[扩展读接口](https://github.com/SnowLuma/SnowLuma/blob/v2.0.3/packages/onebot/src/actions/extended.ts)、[图片与商城表情编码](https://github.com/SnowLuma/SnowLuma/blob/v2.0.3/packages/onebot/src/element-codecs.ts)、[空间发布](https://github.com/SnowLuma/SnowLuma/blob/v2.0.3/packages/onebot/src/actions/qzone.ts)。
