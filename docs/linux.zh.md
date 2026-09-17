# Linux 设置、安全模型与排障

chatlog-keeper 为 Debian 系桌面（以 Ubuntu 为主）上的官方 Linux 微信 4.x 与
QQ NT 增加原生支持。命令名以及 JSON/HTML 导出格式与 Windows、macOS 完全一致。

Wine / deepin-wine 里的 Windows 客户端不在支持范围。

## 工具会改什么

普通导出对两个聊天客户端都是只读的：

1. 定位当前用户的 XDG / 官方数据目录；
2. 把加密数据库及 `-wal`、`-shm` 一致性快照到私有临时目录；
3. 用数据库第一页验证缓存或新发现的 key；
4. 仅在本机解密快照和已提交 WAL；
5. 只写用户指定的 JSON/HTML 导出目录。

普通导出和被动取钥不会注入代码。显式的微信主动取钥只会把下文所述的固定观察器
通过 `LD_PRELOAD` 载入**由本工具启动的子进程**。工具自身不会发消息或调用腾讯
接口，也不会修改 `/opt/wechat` 或 `/opt/QQ` 下的已安装包。被启动的官方客户端
仍可能执行它正常的会话认证和联网行为。

## 数据位置

官方 Linux 微信 4.x 的聊天库在用户的「文档」目录下，而不是 `~/.xwechat`
（后者只是运行时配置）：

```text
$XDG_DOCUMENTS_DIR/xwechat_files/<wxid_...>/db_storage/message/message_*.db
```

常见文档路径是 `~/Documents` 或 `~/文档`。Flatpak 安装可能把副本放在
`~/.var/app/com.tencent.WeChat/`。

官方 Linux QQ NT 使用哈希账号目录：

```text
~/.config/QQ/nt_qq_<hash>/nt_db/nt_msg.db
```

可用 `--data-root` 或 `CHATLOG_WECHAT_DATA_ROOT` / `CHATLOG_QQ_DATA_ROOT` 覆盖。

## 取 key

Ubuntu 默认 `kernel.yama.ptrace_scope=1`，对**已经在跑**的微信 / QQ 做
`process_vm_readv` 通常会被拒绝。这会报 `process_access_denied`，而不是“没有
key”。

`extract-key --method passive` 尝试读日常客户端。在默认 Ubuntu 桌面上通常会
fail closed。

`extract-key --method active` 是显式、可见的交互流程：

- 先正常退出日常微信或 QQ，并等待进程结束；
- 工具把官方二进制（`/opt/wechat/wechat` 或 `/opt/QQ/qq`）作为自己的子进程启动，
  因此 Yama 仍允许父进程读取它；
- 若微信动态解析了 `sqlite3_key` / OpenSSL PBKDF2，工具可能通过 `LD_PRELOAD`
  载入本地编译的观察器；候选只走当前用户的 `0600` FIFO，不写日志；
- 若这些符号未导出，则扫描子进程堆，必要时再走编译好的
  `process_vm_readv` / ptrace helper；
- 任何未通过真实数据库 HMAC oracle 的候选都会被 Python 丢弃。

不要为了绕过 Yama 而以 root 运行本工具。请用主动取钥或 `set-key`。

官方 Linux 微信目前是 4.1.x，堆里往往不再保留旧的 `x'<64hex>...'` raw-key。
若主动取钥得不到能通过 HMAC 的候选，请用 `set-key` 写入已验证的 key。尚未在
真实 Ubuntu 环境测过的版本不会写进 README 的「已验证」表。

Flatpak：可以发现数据目录，`set-key` 与缓存导出可用。读取沙箱进程通常会
fail closed；主动取钥请改用官方 `.deb`，或对 Flatpak 数据目录使用 `set-key`。

## 文件与权限

```text
$XDG_DATA_HOME/chatlog-keeper/   # 通常是 ~/.local/share/chatlog-keeper
├── bin/          # 私有内存扫描 helper 与微信观察器
└── secrets/      # 已缓存数据库 key
```

`secrets/` 权限为 `0700`；key 文件采用原子写入且权限为 `0600`。成功 key 不会
出现在 JSON 返回值或诊断日志中。

## 命令

```bash
chatlog-keeper probe
chatlog-keeper extract-key --source wechat --method active
chatlog-keeper extract-key --source qq --method active
chatlog-keeper wechat --days 7 --out ./out
chatlog-keeper qq --days 7 --out ./out
```

源码安装会在首次使用时编译这段可审计的 C helper，因此需要 `gcc` 或 `clang`
（`sudo apt install build-essential`）。独立包
`chatlog-keeper-linux-x86_64` 已经内置编译后的 helper。

## 常见问题

- `process_access_denied`：Yama 拒绝读取已在运行的客户端。先退出再试主动取钥，
  或使用 `set-key`。
- `daily_client_single_instance_conflict`：先正常退出日常客户端并等待进程结束。
- `official_client_not_found`：安装腾讯官方 `.deb`，或传入 `--data-root` 后用
  `set-key`。
- `helper_compile_failed` / `capture_compile_failed`：安装 `build-essential`
  后重试；独立包不需要编译器。
- 找不到数据目录：用 `--data-root` 传入 `xwechat_files` 或 `~/.config/QQ`。
- Flatpak 取钥失败：改用 `.deb` 客户端，或对 Flatpak 数据目录使用 `set-key`。

## 当前发布边界

Linux 独立资产目前只提供 x86_64。aarch64 Ubuntu 可以运行 Python 源码版，但不在
冻结 GitHub Release 验收范围内。Wine / deepin-wine 不受支持。
