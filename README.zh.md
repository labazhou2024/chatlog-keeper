# chatlog-keeper · 留住对话框背后的那些故事

> 把属于你的 QQ / 微信聊天记录，留在你自己的电脑里。
> *Keep the stories behind every conversation — your chat history, kept local, kept yours.*

[English](README.md) · 中文

---

我一直觉得，真正有意义的从来不是某个聊天软件，而是那一个个对话框背后的故事——
深夜里家人的一句"早点睡"，和老朋友隔着屏幕的玩笑，那些只属于你、再也回不去的瞬间。

这些话是你说的，是发给你的，它们本就属于你。**chatlog-keeper** 帮你把它们从本机的
聊天数据库里取出来，导成一份可以长久保存、随时翻看的备份——一切都在你自己的电脑上
完成，不联网、不上传、不外传。

## 这是什么

一个**纯本地、离线**的小工具，把**你自己**已登录的 QQ / 微信客户端里的聊天记录，
导出成 `JSON` + 一份怀旧风格的 `HTML`（聊天气泡、按会话和日期排列，像你记忆里的样子）。

## 这不是什么

- ❌ **不是**用来获取**别人**数据的工具——它只处理你本人账号、你本机上的数据。
- ❌ **不**联网、**不**上传、**不**收集任何信息——解密全程没有一行网络代码。
- ❌ **不**破解他人的加密、**不**入侵任何服务器——它读的是**你自己电脑上、你本就有权访问的**本地文件。

## 核心原则

| | |
|---|---|
| 🔒 仅限本人 | 只导出你**自己账号**、你**自己设备**上的数据 |
| 🏠 仅在本地 | 全程在你的电脑上运行，**不联网** |
| 🚫 数据不外传 | **不上传、不收集、零遥测** |
| 📖 开源透明 | 全部源码公开，你可以**审计每一行** |

## 功能

- **QQ**：导出 NTQQ 本地聊天记录
- **微信**：导出 WeChat 本地聊天记录
- **微信图片**：把本地 `.dat` 加密图片还原成 `jpg` / `png`
- **Windows + macOS**：Windows 11 与 Apple Silicon Mac 使用同一套 CLI 和导出格式

## 支持的版本

| 平台 | 来源 / 实测客户端 | page-key 派生 | 取 key 方式 |
|---|---|---|---|
| Windows | 微信 ≤ 4.0.x | raw-key（`enc_key` 直接用） | 被动内存扫描 |
| Windows | 微信 4.1.10.31+ | password 模式 —— `PBKDF2-HMAC-SHA512(enc_key, salt, 256000)` | 一次性调试器 |
| Windows | QQ NTQQ 9.9.x | 每库口令 | 被动扫描或一次性调试器 |
| macOS arm64 | 微信 4.1.9（build 268575） | 由 page-1 HMAC 自动选择 raw/password 模式 | 被动扫描；主动流程仅在签名预检通过时可用 |
| macOS arm64 | QQ 6.9.95（build 36385） | 每库口令 | 被动扫描；主动流程仅在签名预检通过时可用 |

**微信 4.1.10.31**（2026-05-27 发布）把明文 key 移出了进程堆，因此被动内存扫描
——多数现有工具依赖的方式——在这些版本上**取不到 key**。chatlog-keeper 会对这些
版本自动回退到“取一次”的调试器方式（见[封号风险](#封号风险)）。

## 与同类工具对比

一份客观的快照（**截至 2026-06**；star 数与维护状态会随时间变化，请以各仓库实际为准）：

| 工具 | Star | 最近更新 | 微信 | QQ | 平台 | 备注 |
|---|---|---|---|---|---|---|
| **chatlog-keeper**（本项目） | — | 2026-07 | ≤4.0 **+ 4.1.x** | ✅ NTQQ | Windows + macOS arm64 | 被动扫描 + 带签名门禁的主动流程 |
| [WeChatMsg / 留痕](https://github.com/LC044/WeChatMsg) | 41k+ | 2025-12 | ≤4.0 | ❌ | Windows | 功能丰富的 GUI；作者声明**不再更新** |
| [PyWxDump](https://github.com/xaoyaoo/PyWxDump) | 9k+ | 2025-10 | 3.x–4.0 | ❌ | Windows | 仓库描述现为“删库”；已停更 |
| [chatlog](https://github.com/sjzar/chatlog) | 9k+ | 2025-10 | ≤4.0 | ❌ | 跨平台 | Go；提供 HTTP/MCP API |
| [ylytdeng/wechat-decrypt](https://github.com/ylytdeng/wechat-decrypt) | 4k+ | 2026-06 | 4.0 | ❌ | Win/macOS/Linux | 活跃；仅内存扫描 |

chatlog-keeper 的不同之处：它是这里唯一能处理 **微信 4.1.10.31+**（key 已离开
明文内存）、并且**同时导出 QQ（NTQQ）**而不只是微信的工具。

它仍是一个新项目，并且刻意以 CLI 为先（JSON/HTML，无内置分析）；macOS 独立包目前
只覆盖 Apple Silicon。本项目的定位是*在两个桌面平台兼容当前微信 + QQ，且本地与法律
边界清晰*。

## 安装

需要 **Python 3.9+**。

```bash
git clone https://github.com/labazhou2024/chatlog-keeper.git
cd chatlog-keeper
python -m pip install .
```

正式 tag 还提供 Windows `chatlog-keeper.exe` 和 Apple Silicon
`chatlog-keeper-macos-arm64` 独立文件。Mac 独立包已经内置只读 Mach helper；源码安装
会在首次取 key 时编译这段可审计的 C helper，因此需要 Xcode Command Line Tools。

请从同一个 [GitHub Release](https://github.com/labazhou2024/chatlog-keeper/releases)
下载可执行文件及其对应的 `.sha256`，保留原始文件名并在运行前校验：

```powershell
# Windows PowerShell
$expected = (Get-Content .\chatlog-keeper.exe.sha256).Split()[0]
$actual = (Get-FileHash .\chatlog-keeper.exe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "chatlog-keeper checksum mismatch" }
.\chatlog-keeper.exe --help
.\chatlog-keeper.exe message-stream-v1 --capabilities
.\chatlog-keeper.exe participant-directory-v1 --capabilities
```

```bash
# Apple Silicon macOS
shasum -a 256 -c chatlog-keeper-macos-arm64.sha256
chmod 755 chatlog-keeper-macos-arm64
./chatlog-keeper-macos-arm64 --help
./chatlog-keeper-macos-arm64 message-stream-v1 --capabilities
./chatlog-keeper-macos-arm64 participant-directory-v1 --capabilities
```

每个 Release 还包含从对应 tag commit 确定性生成的
`chatlog-keeper-v*-source.tar.gz`，以及 Windows、macOS 各自的 canonical approved
artifact descriptor；它们旁边都有独立 `.sha256`，校验方式相同。两个 descriptor
引用同一个 source bundle，并同时声明两个冻结的本机 IPC 协议，使宿主能够把下载的
可执行文件与精确源码绑定。

## 使用

> 前提：在本机登录**你自己**的 QQ / 微信，工具才能读到属于你自己的本地数据。

```bash
# 1) 看看本机能导出什么、密钥拿到了没
python -m chatlog_keeper.cli probe

# 2) 导出最近 30 天的 QQ 聊天 → ./out/qq_messages.{json,html}
python -m chatlog_keeper.cli qq --days 30 --out ./out

# 3) 导出最近 30 天的微信聊天
python -m chatlog_keeper.cli wechat --days 30 --out ./out

# 4) 解密一批微信图片 .dat → jpg/png
python -m chatlog_keeper.cli images --src "<微信图片所在目录>" --out ./out/images
```

导出完，用浏览器打开 `out/*_messages.html`，就能像翻聊天记录一样，慢慢回看。

### 拿到解密 key（多数情况自动完成）

导出时，工具会自动从你**正在运行、已登录**的客户端被动读取解密 key（只读内存，不注入、不 hook、不附加调试器），取到后缓存在本机、之后直接复用——多数情况你**什么都不用做**。

只有自动取 key 失败时（常见于新版微信 4.1.10.31+，key 不再以明文留在内存），才需要手动取一次：

```bash
# 一键自动（默认）：先被动扫描（低风险），取不到再自动转调试器取 key
python -m chatlog_keeper.cli extract-key --source wechat

# 只用被动扫描（封号风险最低；新版微信 4.1.10.31+ 可能取不到）
python -m chatlog_keeper.cli extract-key --source wechat --method passive

# 只走主动流程（新版；macOS 微信自动复用当前会话，无需切换账号）
python -m chatlog_keeper.cli extract-key --source wechat --method active

# Windows 只以当前用户身份启动并调试一个新子进程，不请求 UAC/管理员权限；
# 内置脚本固定校验 SHA-256，微信/QQ 可执行文件与模块必须通过腾讯 Authenticode 签名校验。

# 如果移动过微信数据目录，可显式指定 xwechat_files 文件夹（Windows 示例）
python -m chatlog_keeper.cli extract-key --source wechat --method active --data-root "E:\xwechat_files"

# macOS 示例
python -m chatlog_keeper.cli extract-key --source wechat --method active \
  --data-root "$HOME/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files"

# 推荐的手动兜底：从 stdin 仅读取一行 key。运行后粘贴 key，再发送 EOF
#（Windows 按 Ctrl+Z 后回车；macOS 按 Ctrl+D）。
python -m chatlog_keeper.cli set-key --source wechat --key-stdin
python -m chatlog_keeper.cli set-key --source qq --key-stdin

# 仅兼容旧用法：--key 会把密钥暴露在进程参数和 shell 历史中。
python -m chatlog_keeper.cli set-key --source wechat --key <64位十六进制>
python -m chatlog_keeper.cli set-key --source qq --key <16位口令>
```

取到的 key 会缓存在本机，之后导出直接复用：

- Windows：`%LOCALAPPDATA%\chatlog-keeper\data\secrets\`
- macOS：`~/Library/Application Support/chatlog-keeper/secrets/`

macOS 上 secrets 目录权限为 `0700`，每个 key 文件为 `0600`。Windows 上使用
受保护 ACL，只允许当前用户和 LocalSystem 访问；ACL 收紧或复核失败时拒绝读取。
详细见
[macOS 安全与排障说明](docs/macos.zh.md)。

## 封号风险

一句话：**导出自己本地的聊天记录，封号风险很低**——它不与服务器发生异常交互。腾讯的封号风控主要针对“服务器侧的异常行为”（自动登录、批量加好友、模拟点击发消息、改包多开、外挂插件、虚拟定位），而不是“在本地读自己的数据”。

实际风险**取决于取 key 的方式**：

| 操作 | 封号风险 | 说明 |
|---|---|---|
| 读本地数据库文件 | 极低（≈0） | 纯文件读取，不碰网络，服务器无从感知 |
| 被动内存扫描取 key（默认） | 低 | 只读进程内存（不注入、不 hook、不附加调试器）；社区主流工具长期采用，未见因此被封的实证 |
| Windows 主动取 key | 中–偏高 | 启动独立受调试客户端，在密码边界读取 key；仅在被动方式失败时使用 |
| macOS 主动取 key | 兼容性敏感 | 不修改原应用、不关闭 SIP；微信显式主动模式只在私有兼容副本启动前载入固定捕获器，自动登录无需切号，所有候选仍必须通过数据库 HMAC 验证 |

降低风险：优先用默认的被动方式；能用缓存就不重复取 key；取到 key 后甚至可以退出客户端、离线解密；**绝不**用本工具做任何服务器侧自动化操作（那才是真正的封号高发区）。

> 注：腾讯对这类工具的实际处置，主要是要求代码托管平台**下架工具仓库**（DMCA），而非封禁使用者个人账号——这是**项目层面**的风险，与你个人导出自己数据的封号风险是两回事。

## 工作原理（简述）

聊天软件会把你的消息存在本机一个加密的小型数据库里，而打开它所需的密钥，在你
自己登录之后就在你自己的机器上。本工具做的事很简单：读取**你本机**的这个数据库，
用**你机器上**的密钥把它打开，再把消息整理、导出。全程只接触**你自己电脑上、你本就
有权访问**的文件，不连任何网络。

> 解密采用逐页流式处理（峰值内存约等于一个 4 KB 内存页），即使是好几个 GB 的数据库，
> 也不会被整个读进内存。

对正在使用的数据库，工具会先一致性快照 `db`、`-wal`、`-shm` 文件族；APFS 上使用
clone-copy。微信已提交的 WAL frame 会先逐页通过 HMAC 校验，再写入解密副本。

## 法律与免责

使用前请先阅读 **[DISCLAIMER.zh.md](DISCLAIMER.zh.md)**。

一句话：本工具仅用于导出、备份**你本人**的聊天数据，用于个人留存与怀旧；仅限本地、
绝不外传；是否使用、如何使用由你自行判断并自行承担，且应遵守你所在地区的法律法规与
相关服务条款。若相关权利方有任何疑虑，欢迎通过 issue 联系，作者会积极配合处理。

## 许可

本项目以 **[MIT 协议](LICENSE)** 开源——宽松自由，任何人都可使用，包括用于自己的项目。
