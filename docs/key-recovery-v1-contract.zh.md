# Key Recovery v1 私有生命周期合同

本文冻结桌面宿主与 ChatLog Keeper 主动取钥流程之间的本机合同。目标是让宿主在不接触
key、账号、数据库路径、PID 或 helper 原始输出的前提下，可靠地启动、查询、取消和清理
一次 QQ/微信取钥操作。普通 `extract-key`、`probe` 和 Python API 不属于本合同。

## 1. 边界与前置条件

- v1 仅用于 `extract-key --method active`。
- `source` 只能是 `qq` 或 `wechat`。
- 每次操作必须使用新的 256 位随机 `operation_id`，编码为 64 个小写十六进制字符。宿主
  不得复用 ID；仍有 operation 或 cleanup receipt 时，Keeper 也会拒绝重放。
- `confirmed=true` 表示用户已经同意打开本次隔离客户端，并了解隔离客户端可能执行正常的
  官方会话认证和联网。未确认时不得准备 helper 或启动客户端。
- 日常 QQ/微信必须先正常退出。只要前置检查发现日常客户端仍在运行，操作返回
  `client_running`。所有清理都按本次记录的精确进程代际进行，禁止按进程名终止日常客户端。
- 同一 OS 用户、同一设备、同一 source 同时只允许一个取钥操作；QQ 和微信各有独立 lease。

## 2. 能力发现

```bash
python -m chatlog_keeper.cli key-recovery-v1 --capabilities
```

返回字段和值固定如下；数组顺序也是合同的一部分：

```json
{
  "schema": "chatlog-keeper.key-recovery-capabilities.v1",
  "version": 1,
  "operation_id_format": "lowercase-hex-64",
  "actions": ["start", "status", "cancel", "cleanup"],
  "phases": ["client_open", "preparing", "terminal_error", "verified", "waiting_key"],
  "error_codes": [
    "active_operation_exists",
    "cancelled",
    "cleanup_failed",
    "client_running",
    "confirmation_required",
    "helper_unavailable",
    "internal_error",
    "invalid_request",
    "not_found",
    "not_terminal",
    "operation_active",
    "operation_exists",
    "owner_lost",
    "source_unavailable",
    "status_unavailable",
    "timed_out",
    "verification_failed",
    "write_failed"
  ],
  "terminal_phases": ["terminal_error", "verified"]
}
```

## 3. 启动操作

命令：

```bash
python -m chatlog_keeper.cli extract-key \
  --source wechat \
  --method active \
  --key-recovery-v1-stdin
```

stdin 必须是一个不超过 1024 字节、无重复字段、无额外字段的 JSON：

```json
{
  "schema": "chatlog-keeper.key-recovery-request.v1",
  "operation_id": "<64 个小写十六进制字符>",
  "timeout_seconds": 600,
  "confirmed": true
}
```

`timeout_seconds` 必须是 1 至 3600 的整数，布尔值不视为整数。stdin 中不得放入 key、账号
或路径。启用 v1 后，stdout 只输出一次终态结果：

```json
{
  "schema": "chatlog-keeper.key-recovery-result.v1",
  "operation_id": "<同一 ID>",
  "ok": true,
  "terminal": true,
  "error_code": null
}
```

结果字段严格为 `schema`、`operation_id`、`ok`、`terminal`、`error_code`。请求尚未成功解析
时，`operation_id` 为 `null`。失败时 `ok=false` 且 `error_code` 必须是能力声明中的值。

## 4. 查询、取消和清理

三个控制动作都使用同一个 path-free 请求，不接受目录或文件路径：

```bash
python -m chatlog_keeper.cli key-recovery-v1 --request-stdin --action status
python -m chatlog_keeper.cli key-recovery-v1 --request-stdin --action cancel
python -m chatlog_keeper.cli key-recovery-v1 --request-stdin --action cleanup
```

stdin 严格为：

```json
{
  "schema": "chatlog-keeper.key-recovery-control-request.v1",
  "operation_id": "<64 个小写十六进制字符>"
}
```

### 4.1 status 成功结果

`status` 成功时直接返回 status schema，不套 control result：

```json
{
  "schema": "chatlog-keeper.key-recovery-status.v1",
  "operation_id": "<同一 ID>",
  "sequence": 4,
  "phase": "verified",
  "terminal": true,
  "error_code": null,
  "elapsed_ms": 1234,
  "lease_state": "terminal",
  "events": [
    {
      "sequence": 1,
      "phase": "preparing",
      "terminal": false,
      "error_code": null,
      "elapsed_ms": 1
    }
  ]
}
```

顶层字段严格为 `schema`、`operation_id`、`sequence`、`phase`、`terminal`、
`error_code`、`elapsed_ms`、`lease_state`、`events`。每个 event 严格为 `sequence`、
`phase`、`terminal`、`error_code`、`elapsed_ms`。`events` 是有界完整历史，最后一项必须与
顶层阶段字段一致。

`elapsed_ms` 必须是 `0` 至 `9007199254740991`（`2**53-1`）之间的整数，布尔值不视为
整数。它从 operation 创建时开始累计；owner 离线后直到恢复或查询发生的等待时间也计入，
因此延迟数小时或数十天恢复仍保持单调且可由 JSON/JavaScript 精确表示。

`lease_state` 只允许：

- `held`：启动进程仍持有 source lease；
- `released`：lease 已释放，但尚未形成其他外部状态；
- `orphaned_helper`：Windows Job 或 macOS memory helper 仍需精确回收；
- `orphaned_client`：macOS 隔离客户端仍需精确回收；
- `terminal`：不存在仍可写本操作状态的外部进程树，操作已终结。

### 4.2 cancel/cleanup 成功结果和统一失败结果

`cancel`、`cleanup` 成功，以及任一控制动作失败时，使用严格 control result：

```json
{
  "schema": "chatlog-keeper.key-recovery-control-result.v1",
  "operation_id": "<同一 ID或 null>",
  "action": "cancel",
  "ok": true,
  "terminal": true,
  "error_code": null,
  "lease_state": "terminal"
}
```

字段严格为 `schema`、`operation_id`、`action`、`ok`、`terminal`、`error_code`、
`lease_state`。语义冻结如下：

- `ok=true` 表示控制动作成功，此时 `error_code` 必须为 `null`；
- `ok=false` 表示控制动作失败，此时 `error_code` 必须非空；
- 生产者操作究竟是 `verified`、`cancelled` 还是其他 `terminal_error`，只能从 `status`
  读取，不能从成功的 cancel/cleanup 结果推断；
- 从未存在的 ID 返回 `not_found`；已 cleanup 且 receipt 尚在的 ID 仍可重复 status、cancel
  和 cleanup。

宿主不得直接读取或写入内部 `status.json`、`cancel.json`，也不得自行删除 operation 目录。

## 5. 阶段与错误

正常阶段含义：

1. `preparing`：验证数据库 oracle、helper、签名和私有通道；
2. `client_open`：本次隔离客户端已经打开；
3. `waiting_key`：等待自动登录、官方二维码认证或可由数据库验证的候选；
4. `verified`：候选已通过本地 DB HMAC 验证并成功写入私有缓存；
5. `terminal_error`：失败终态，原因仅由 `error_code` 表达。

允许的主要顺序是 `preparing -> client_open -> waiting_key -> verified|terminal_error`。
准备阶段可直接转为 `verified` 或 `terminal_error`；未确认请求可直接进入
`terminal_error/confirmation_required`。只有 `terminal_error` event 可携带非空
`error_code`。

能力中声明的错误码含义：

| 错误码 | 含义 |
|---|---|
| `active_operation_exists` | 同一 source 的 native lease 已被另一操作持有 |
| `cancelled` | 生产者操作按请求取消 |
| `cleanup_failed` | 无法证明精确进程或私有文件已安全清理 |
| `client_running` | 日常 QQ/微信仍在运行 |
| `confirmation_required` | 用户未明确确认主动流程 |
| `helper_unavailable` | 平台 helper 不可用或未得到已验证 key |
| `internal_error` | 未分类的内部失败；不携带原始诊断 |
| `invalid_request` | schema、字段、类型、范围或参数组合不合法 |
| `not_found` | operation 与 cleanup receipt 均不存在 |
| `not_terminal` | 非终态操作不允许 cleanup |
| `operation_active` | 外部进程树或 source lease 仍活跃，禁止 cleanup |
| `operation_exists` | operation ID 或同 ID receipt 已存在 |
| `owner_lost` | owner 崩溃且已证明没有外部进程树继续写入 |
| `source_unavailable` | 无法冻结或验证本机数据源 |
| `status_unavailable` | 状态、身份或系统枚举不确定；必须 fail closed |
| `timed_out` | monotonic deadline 到期 |
| `verification_failed` | 候选未通过本地数据库验证 |
| `write_failed` | 已验证 key 无法安全写入私有缓存 |

## 6. 固定运行时根和 native lease

Recovery 状态使用 OS-known 的当前用户目录，不跟随 `CHATLOG_KEEPER_DATA_DIR`、
`CHATLOG_QQ_DATA_ROOT`、`CHATLOG_WECHAT_DATA_ROOT` 或调用者环境变化：

- Windows：Known Folder `LocalAppData` 下的
  `chatlog-keeper\runtime\key-recovery-v1`；
- macOS：当前 UID 的 home 下
  `Library/Application Support/chatlog-keeper/runtime/key-recovery-v1`；
- 其他 POSIX：当前 UID 的 home 下
  `.local/share/chatlog-keeper/runtime/key-recovery-v1`。

内部根分为 `operations`、`leases` 和 `cleanup-receipts`。operation 内除状态外还可保存
metadata、精确 process/helper 代际、临时 transcript 或 capture artifact 的身份记录；这些
内部记录永不通过 stdout 暴露。

POSIX 使用当前 UID 私有文件和 `flock`；Windows 同时使用当前用户命名 mutex、
`LockFileEx` 和受保护 DACL。持有期间持续复核 lock 文件代际，配置覆盖不能创建第二个
lease 命名空间。

## 7. 崩溃一致性与精确清理

### Windows

- PowerShell 从 `GetSystemDirectoryW` 派生的绝对系统路径启动；拒绝 reparse point，
  `PATH` 和当前目录中的同名程序不能参与选择。
- 使用 `CreateProcessW + STARTUPINFOEX + PROC_THREAD_ATTRIBUTE_JOB_LIST` 在创建时原子加入
  本次命名 Job，同时以 `HANDLE_LIST` 限制继承句柄。进程先以 `CREATE_SUSPENDED` 创建，
  Job 设为 `KILL_ON_JOB_CLOSE`，成功绑定后才恢复主线程。
- 因此 owner 在 CreateProcess 返回前后硬崩，已创建子进程也属于本次 Job；关闭 owner
  句柄会终止 debugger-owned 完整子树。Job 查询只有明确的 `ERROR_FILE_NOT_FOUND` 才表示
  inactive；`ACCESS_DENIED` 和其他系统错误一律 fail closed。
- transcript 位于随机 owner-only 临时目录。启动前先持久化目录的 device/inode/owner PID；
  正常退出、取消、owner-loss 恢复以及每次 CLI 的 dead-owner scavenger 都按精确身份清理。

### macOS

- 只启动验证通过的隔离副本，不修改日常客户端；记录隔离可执行文件的绝对路径、PID 和
  kernel start generation。
- 启动隔离副本前先创建 owner-watchdog。watchdog 输出 `WATCH_ARMED` 后，Keeper 必须先将
  watchdog 的签名文件 digest/device/inode 与 PID/start generation 写入
  `macos-watchdog.json`，再发送单字节 `L`；未收到 `L` 时 watchdog 不得调用 LaunchServices。
- watchdog 冻结 App bundle、主可执行文件的 owner/device/inode/文件类型/非链接身份；微信
  capture 模式还冻结 dylib 与 FIFO 的同类身份和权限。在收到 `L` 后、`posix_spawn` 前再次
  `lstat` 精确比对，任一换代或类型漂移都拒绝启动。Python 参数、内部 journal、C watchdog
  和内核 `proc_pidpath` 一律使用同一 `realpath` 规范路径，不能把 `/tmp` 与 `/private/tmp`
  一类系统路径别名误判为不同目标；最终条目本身仍禁止为符号链接。
- `/usr/bin/open` 使用绝对、root-owned、不可写且非链接的系统文件，并以空的最小 `envp`
  启动，不继承 Keeper/宿主的 API key、数据库或会话环境；微信 capture 仅通过固定的两个
  `open --env` 参数注入隔离客户端。watchdog 的控制 fd 标为 `CLOEXEC`，不能被 open 或客户端
  继承。
- watchdog 自己调用 `/usr/bin/open` 并持续冻结新出现的精确客户端代际。Keeper 正常结束时
  发送 `C`；Keeper 被 `SIGKILL`、控制管道 EOF 或 watchdog 收到终止信号时，也由 watchdog
  在有界期限内按 PID/start/path/UID 复核后先 TERM、必要时 KILL，并证明目标完全消失。该
  路径从不按进程名终止日常 `/Applications` 客户端。
- memory helper 记录签名文件的 digest/device/inode 以及 helper PID/start generation；helper
  自身持续检查 owner PID 与目标进程代际，owner 或目标消失时退出并释放 task port。
- 崩溃恢复先严格验证记录结构。若内核已经明确证明记录 PID 不存在，即使旧 helper/cache
  已清理或官方客户端已经更新，也允许完成 cleanup；PID 存活、复用或身份不确定且 artifact
  漂移时保持 fail closed，不发送信号、不释放 source owner。
- 真正需要终止时，先复核记录 artifact 和精确进程代际，只终止 helper 与隔离副本；随后
  再次证明两者均不活跃，才允许写终态或清理 journal。

### status 损坏和 owner 丢失

- source lease 仍由 live owner 持有时，损坏或缺失的 status 返回 `status_unavailable`，不得
  覆盖 live owner 的状态或删除其文件。
- lease 可取得时，Keeper 才执行恢复：先判断精确 Windows Job、macOS helper/隔离客户端，
  存在时返回相应 orphan lease state；确认不存在时清理 transcript/capture artifact，并写入
  `terminal_error/owner_lost`。
- 任何路径、文件代际、ACL、进程代际或枚举结果不确定时，恢复与 cleanup 均 fail closed。

## 8. cleanup receipt 与保留期

- `cleanup` 只接受已终态且不存在外部进程树的 operation。
- 删除 owner/journal 之前，先原子写入 owner-only cleanup receipt；receipt 必须与同一
  `operation_id` 的 source 和完整 terminal status 精确一致。冲突 receipt 不会被接受。
- owner 或进程在 receipt 写入后崩溃，重复 cleanup 会先完成剩余精确删除；重复 status 返回
  receipt 中的原终态。
- 合法 terminal journal 保留 24 小时；自动 retention 也必须先写 receipt 再删 journal，写入
  失败则保留原件。
- cleanup receipt 保留 30 天。超过保留期后可删除；宿主仍必须保证自身永不复用 operation
  ID。损坏或身份不确定的 journal 不会被 retention 扩大删除范围，而是保留供显式审计。

## 9. 不披露与宿主收口规则

status、result、control result 和私有 stderr 不得包含 key、原生账号、昵称、数据库/缓存
路径、PID、helper 路径或原始诊断。候选只存在于有界进程内存，并且必须通过本机数据库
HMAC 验证后才可写缓存。

宿主应按以下顺序收口：

1. 先用 `probe` 判断缓存是否已可用。微信客户端已退出但本机存在数据库且没有验证通过的
   key 时，仍应视为 `needs_key=true`。
2. 展示主动流程影响并取得确认，要求用户正常退出日常客户端。
3. 生成新随机 ID，启动后只通过 path-free `status` 轮询完整 `events`。
4. 取消时调用 `cancel`，等待受控终态；不要先强杀 Keeper。
5. 只在 status 为 `verified` 或后续 `probe` 证明缓存可用后进入消息提取。
6. 读取终态后调用 `cleanup`；网络、GUI 或宿主崩溃后仍以同一 ID 恢复 status/cancel/cleanup，
   绝不自动重放 start。
