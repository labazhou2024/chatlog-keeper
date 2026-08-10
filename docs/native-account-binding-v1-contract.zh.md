# Native Account Binding v1 私有合同

本文冻结 ChatLog Keeper 与本机宿主之间的账号绑定合同。它用于在数据库 key 暂时不在
Connector 缓存时，仍能用稳定的匿名引用定位 OS 凭据；不得作为公开用户身份、云端账号或
跨设备身份使用。

## 1. 隐私与信任边界

- 跨进程只输出严格版本化的 opaque `account_ref`，不输出微信号、QQ号、数据库路径、key 或
  目录名。微信已有数据库 key 证明时沿用 `key-identity-v1` 的
  `chatlog-account-ref-v1:<摘要>`，这样宿主可以继续命中既有 OS 凭据；QQ 以及尚未证明 key 的
  本机候选使用 `chatlog-native-account-ref-v1:<摘要>`。
- native 候选 ref 使用本机 owner-only 随机 secret 对 `source + native account ID` 做
  HMAC-SHA256。不能用固定盐或普通摘要替代，否则低熵 QQ 号可被枚举。
- 持久化选择只保存 `account_ref`、native ID 的私有 routing HMAC、source 和 proof；不保存
  raw native ID、路径或 key。routing HMAC 使用同一 device secret 但独立 domain；secret
  丢失或不可读时禁止仅凭记录恢复，不能退回可枚举的普通摘要。
- 每次恢复都必须重新严格枚举本机账号。native ref 以 routing hash 和 HMAC ref 同时精确匹配；
  已证明的 key ref 以 owner-only 记录中的 routing hash 精确匹配，随后取回的 key 仍须重新通过
  完整数据库集合验证。零个或多个账号匹配都失败关闭。恢复出的 raw ID 只在 Connector 进程内
  用于路由。
- 微信 key 仍必须通过完整本机数据库集合的 HMAC 验证；本合同不能替代
  `key-identity-v1` 的数据库证明。

## 2. 能力发现

```bash
python -m chatlog_keeper.cli native-account-binding-v1 --capabilities
```

返回：

```json
{
  "capability": "native-account-binding-v1",
  "schema": "chatlog-keeper.native-account-binding.v1",
  "authority": "device-local-canonical-account-binding",
  "account_ref_formats": [
    "chatlog-account-ref-v1-sha256",
    "chatlog-native-account-ref-v1-hmac-sha256"
  ],
  "sources": ["qq", "wechat"],
  "states": [
    "verified",
    "verified_unpersisted",
    "restored",
    "single_account",
    "current_account",
    "selection_required",
    "unavailable"
  ]
}
```

能力命令不读取 stdin、不扫描数据库、不创建 secret 或选择文件。

## 3. Probe/普通取钥结果

普通 `probe`、`set-key` 和非 `key-recovery-v1` 的 `extract-key` 可加上固定形状的
`native_account_binding`：

```json
{
  "schema": "chatlog-keeper.native-account-binding.v1",
  "source": "wechat",
  "authority": "device-local-canonical-account-binding",
  "account_ref_format": "chatlog-account-ref-v1-sha256",
  "state": "restored",
  "account_ref": "chatlog-account-ref-v1:<摘要>",
  "account_refs": ["chatlog-account-ref-v1:<摘要>"],
  "account_selection_required": false
}
```

旧字段保持不变。严格的 `key-recovery-v1` status/result 字段不增加账号信息。
`account_ref_format` 必须与本次 envelope 中的 ref 一致；没有任何安全 ref 时为 `null`。同一
envelope 不混合两种格式。

状态语义：

- `verified`：本轮 key 已匹配数据库目标，并且选择已持久化。
- `verified_unpersisted`：数据库目标已确认，但本机选择文件无法写入；调用者不得把它当作可
  重启恢复完成。
- `restored`：已有选择与本轮完整账号枚举精确匹配。
- `single_account`：首次只发现一个规范账号，已建立一次性本机选择。
- `current_account`：QQ 现有 current-account 规则选中账号并持久化；微信不使用此状态。
- `selection_required`：首次发现多个微信账号且没有已验证选择。此时 `account_ref=null`，
  `account_refs` 给出全部匿名候选，禁止按目录顺序、mtime、昵称或路径伪造 scalar。
- `unavailable`：无法建立或恢复安全引用。

从 v0.3.4 升级时，如果只有 owner-only 的 `wechat_key_identity.ref` 而尚无 native binding
记录，`needs_key` 先以 `restored` 返回这个已经过历史数据库 key 证明的
`chatlog-account-ref-v1`。宿主用它读取 OS 凭据；key 再次通过完整数据库集合验证后，Connector
才把该 ref 与当前账号的私有 routing hash 绑定。升级过程不会把 raw wxid 暴露给宿主。

## 4. 首次微信恢复顺序

微信 `needs_key` 结果另带：

```json
{
  "schema": "chatlog-keeper.key-recovery-flow.v1",
  "source": "wechat",
  "sequence": ["passive", "active", "manual"],
  "active_authentication": ["saved_session", "qr"],
  "account_switch_required": false
}
```

语义固定为：先被动只读扫描；失败后由用户确认进入 Active，Active 使用官方客户端的已有会话
或二维码认证；仍未得到数据库验证 key 时才进入手动 key。二维码是 Active 的官方认证分支，
不是要求切换日常账号。后续运行优先恢复已持久化 `account_ref`，不要求重复选择账号。

## 5. 多账号安全例外

首次运行、本机有多个微信数据库、且没有缓存 key 或已绑定选择时，系统没有足够证据判断用户
要绑定哪个账号。此时必须返回 `selection_required`，不能返回 scalar `account_ref`。Active 或
手动 key 一旦对完整数据库集合证明唯一目标，立即持久化该目标，并沿用
`key-identity-v1` ref；之后重启均自动恢复。该例外是避免串号所必需的失败关闭行为。
