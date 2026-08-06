# macOS 设置、安全模型与排障

chatlog-keeper 0.3 为当前沙盒版微信和 QQ 增加 Apple Silicon 原生支持。命令名以及
JSON/HTML 导出格式与 Windows 完全一致。

## 工具会改什么

普通导出对两个聊天客户端都是只读的：

1. 定位当前用户的 sandbox container；
2. 把加密数据库及 `-wal`、`-shm` 一致性快照到私有临时目录；
3. 用数据库第一页验证缓存或新发现的 key；
4. 仅在本机解密快照和已提交 WAL；
5. 只写用户指定的 JSON/HTML 导出目录。

普通导出和被动取钥不会注入代码。显式的微信主动取钥只会把下文所述的固定捕获器
载入隔离副本；工具自身不会发消息或调用腾讯接口，也不会关闭 SIP、修改 `/Applications`
下的原应用。被启动的官方客户端仍可能执行它正常的会话认证和联网行为。

## 取 key

`extract-key --method passive` 用当前普通用户身份请求只读 Mach 访问。现代 hardened
客户端通常会拒绝。

`extract-key --method active` 是显式、可见的交互流程：

- 在 `~/Library/Application Support/chatlog-keeper/debug-apps/` 创建隔离副本；
- 保留原 entitlements，只增加 `com.apple.security.get-task-allow`；
- QQ 副本保留 Hardened Runtime，并在验证签名、精确 entitlement 差异以及直接依赖的
  Team-ID 关系后才启动；
- 微信采用上游 v0.2 的兼容签名：私有副本不启用 Hardened Runtime，因为 ad-hoc 主程序
  否则无法加载当前仍由腾讯签名的内嵌 framework；已安装原应用的保护不会改变；
- 微信副本启动前，把本地构建、签名并校验过的固定 PBKDF2 捕获器临时复制到微信自身
  sandbox 的 `Data/tmp`；LaunchServices 只给这个进程传入固定 dylib 和 FIFO 路径；
- 捕获器在自动登录之前生效，只接受符合微信 4.x 参数形状的 32 字节候选；候选只通过
  当前用户的 `0600` FIFO 返回，不写日志或临时文件；
- helper 以当前用户身份运行，不提权，也不会请求管理员密码；
- helper 在取得 task port 前后核对精确可执行路径和内核进程启动代际；
- 内置 helper 只读候选字节，不向客户端写入；
- 任何未通过真实数据库 HMAC oracle 的候选都会被 Python 丢弃。

原应用保持不变。客户端升级后会按新内容身份创建新的隔离副本，不会静默复用旧副本。
微信仍是单实例应用：运行主动流程前，请从微信菜单正常退出日常客户端并等待它完全关闭；
工具不会强制退出日常微信。私有副本会直接复用当前登录会话并自动捕获 key，用户无需
切换账号；只有登录会话确实失效时，才需要在命令等待期间扫描微信显示的官方登录二维码。
命令会在有界时间内保持该精确进程，使用数据库验证候选 key，最后只关闭自己启动的那个
进程代际，并按 inode 清理本次 FIFO 与临时 dylib。

这个兼容副本的运行时保护低于已安装微信。它仅对当前用户可见，只在用户明确请求主动取
key 时使用，不能替代日常客户端。SIP 始终开启，不使用管理员进程，不重签原应用，任何候选
还必须通过真实数据库 HMAC oracle。QQ 以及未来仍保留 Hardened Runtime 的副本，如果无法
证明签名关系，仍会以 `debug_copy_library_validation_incompatible` 或
`debug_copy_library_validation_unverifiable` fail closed。

## 文件与权限

```text
~/Library/Application Support/chatlog-keeper/
├── bin/          # 私有 Mach helper 与已签名捕获器
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

主动流程可能打开独立微信或 QQ 窗口。微信会先复用现有会话，不需要切换账号；只有会话
失效时，才在命令仍等待期间完成微信官方二维码登录。
macOS 流程不会索取管理员凭据；若出现任何要求把系统密码输入终端或第三方界面的提示，
请停止操作。

## 常见问题

- `daily_client_single_instance_conflict`：从微信菜单正常退出日常客户端，等待进程完全关闭
  后重试；不要强制退出。
- `debug_copy_busy`：已有一个主动流程在运行，等待它结束后重试。
- `debug_copy_cleanup_failed`：仅关闭工具启动的隔离客户端，再重试；不要终止日常客户端。
- `capture_launch_configuration_invalid`：临时捕获器或 FIFO 在启动前身份发生变化，工具没有
  启动副本；直接重试。
- `capture_channel_*` / `capture_library_*`：临时通道未通过权限、签名、哈希或清理校验；
  更新或重装 connector 后重试。
- `debug_copy_library_validation_incompatible`：保留 Hardened Runtime 的隔离主程序与必需
  内嵌库的 Team ID 不满足
  运行时要求；工具不会启动它，请使用经数据库验证的手动 key。
- `debug_copy_library_validation_unverifiable`：工具无法安全证明必需依赖的签名关系；
  工具不会启动副本，请更新 connector/client，或使用经数据库验证的手动 key。
- `process_access_denied`：taskgated 没接受隔离副本。保持 SIP 开启，不要降低系统保护；
  客户端升级后重建隔离副本再试。
- 找不到数据目录：用 `--data-root` 显式传入微信 `xwechat_files` 或 QQ Application
  Support 目录。
- 源码安装报 `helper_compile_failed`：安装 Xcode Command Line Tools；arm64 独立包已
  内置编译后的 helper。
- container 拒绝访问：在系统设置中给实际调用者（Terminal 或桌面宿主）开启“完全磁盘
  访问权限”，然后重启调用者。

## 当前发布边界

macOS 独立资产目前只提供 arm64。Intel Mac 可以运行 Python 源码版，但不在 0.3 的发布
验收范围内。
