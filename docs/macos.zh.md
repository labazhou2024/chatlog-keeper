# macOS 设置、安全模型与排障

chatlog-keeper 0.2 为当前沙盒版微信和 QQ 增加 Apple Silicon 原生支持。命令名以及
JSON/HTML 导出格式与 Windows 完全一致。

## 工具会改什么

普通导出对两个聊天客户端都是只读的：

1. 定位当前用户的 sandbox container；
2. 把加密数据库及 `-wal`、`-shm` 一致性快照到私有临时目录；
3. 用数据库第一页验证缓存或新发现的 key；
4. 仅在本机解密快照和已提交 WAL；
5. 只写用户指定的 JSON/HTML 导出目录。

工具不会注入代码、不会发消息、不会连接腾讯服务器、不会关闭 SIP，也不会修改
`/Applications` 下的原应用。

## 取 key

`extract-key --method passive` 用当前普通用户身份请求只读 Mach 访问。现代 hardened
客户端通常会拒绝。

`extract-key --method active` 是显式、可见的交互流程：

- 在 `~/Library/Application Support/chatlog-keeper/debug-apps/` 创建隔离副本；
- 保留原 entitlements，只增加 `com.apple.security.get-task-allow`；
- ad-hoc 签名并验证通过后才启动；
- macOS 自己弹出管理员认证框；
- 内置 helper 只读候选字节，不向客户端写入；
- 任何未通过真实数据库 HMAC oracle 的候选都会被 Python 丢弃。

原应用保持不变。客户端升级后会按新内容身份创建新的隔离副本，不会静默复用旧副本。

## 文件与权限

```text
~/Library/Application Support/chatlog-keeper/
├── bin/          # 私有 Mach helper
├── debug-apps/   # 主动流程的隔离应用副本
└── secrets/      # 已缓存数据库 key
```

`secrets/` 权限为 `0700`；key 文件采用原子写入且权限为 `0600`。成功 key 不会出现在
JSON 返回值或诊断日志中。

## 命令

```bash
chatlog-keeper probe
chatlog-keeper extract-key --source wechat --method active
chatlog-keeper extract-key --source qq --method active
chatlog-keeper wechat --days 7 --out ./out
chatlog-keeper qq --days 7 --out ./out
```

主动流程可能打开独立微信或 QQ 窗口；只有客户端确实要求时才登录。管理员凭据只能输入
macOS 自己的认证框，不要输入终端或第三方界面。

## 常见问题

- `administrator username or password was not accepted`：从当前已登录的桌面会话重跑，
  并完成 macOS 认证框；SSH 不能安全代替这一步人工操作。
- `process_access_denied`：taskgated 没接受隔离副本。保持 SIP 开启，不要降低系统保护；
  客户端升级后重建隔离副本再试。
- 找不到数据目录：用 `--data-root` 显式传入微信 `xwechat_files` 或 QQ Application
  Support 目录。
- 源码安装报 `helper_compile_failed`：安装 Xcode Command Line Tools；arm64 独立包已
  内置编译后的 helper。
- container 拒绝访问：在系统设置中给实际调用者（Terminal 或桌面宿主）开启“完全磁盘
  访问权限”，然后重启调用者。

## 当前发布边界

macOS 独立资产目前只提供 arm64。Intel Mac 可以运行 Python 源码版，但不在 0.2 的发布
验收范围内。
