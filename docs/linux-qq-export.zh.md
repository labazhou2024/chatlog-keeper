# Linux QQ 会话导出

本文说明如何在官方 Linux QQ NT 客户端所在的本机读取一个会话，并将可用的媒体缓存打包成离线 HTML。所有聊天正文和媒体都保留在本机。

## 安装

需要 Python 3.9 及以上版本。Debian/Ubuntu 可在仓库根目录运行：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

如果源码安装首次需要编译 Linux 只读内存扫描 helper，还需要 `gcc` 或 `clang`。不需要以 root 运行。

## 找到会话 ID

先确认 QQ 数据是否可用，再列出本机已知账号和会话：

```bash
python -m chatlog_keeper.cli probe
python -m chatlog_keeper.cli directory --source qq
```

Linux QQ 的默认数据目录是 `~/.config/QQ`。如果使用了其他数据目录，可在两个命令中传入 `--data-root PATH`。从目录结果中找到需要导出的直接会话或群聊会话 ID。

## 准备解密密钥

导出使用保存在本机的、经过数据库验证的密钥缓存。先运行 `probe` 检查 QQ 是否显示为可用。

在 Ubuntu 等启用 Yama 的系统上，读取已经运行的 QQ 进程内存可能返回 `process_access_denied`。可先尝试只读被动获取：

```bash
python -m chatlog_keeper.cli extract-key --source qq --method passive
```

如果被动获取失败，项目提供显式的主动获取流程。先正常退出日常 QQ 并确认进程完全结束，再运行：

```bash
python -m chatlog_keeper.cli extract-key --source qq --method active
```

该命令会启动官方 QQ 子进程并在本机验证候选密钥。候选不通过数据库完整性校验时不会缓存。部分客户端构建或系统策略不兼容时会失败并给出错误；不要关闭 Yama、以 root 运行、安装来源不明的取钥工具，或把密钥粘贴到命令行参数中。

## 导出一个会话

在仓库根目录执行：

```bash
./scripts/export_qq_contact.sh \
  --conversation CONVERSATION_ID \
  --out ./out/conversation \
  --days 36500
```

脚本默认读取 `~/.config/QQ`，并使用很长的回看窗口覆盖现有本地历史。也可传 `--data-root PATH` 和 `--account ACCOUNT_ID` 指定数据目录或账号。若导出目录中已经存在本工具生成的 JSON/HTML，脚本会停止，避免无意覆盖；检查旧文件后可显式添加 `--overwrite`。

主命令会生成 `qq_messages.json` 和 `qq_messages.html`。JSON 保留时间、发送者、消息正文及解析到的附件元数据。数据库中缺失或无法安全解析的消息体不会被伪造成文本。

## 打包媒体并生成离线页面

主消息 JSON 包含附件元数据，但不一定内嵌媒体。可把指定 QQ 数据目录中按文件名精确匹配的缓存复制到导出目录：

```bash
python scripts/package_qq_media.py \
  --messages ./out/conversation/qq_messages.json \
  --data-root "$HOME/.config/QQ" \
  --out-dir ./out/conversation

python scripts/render_qq_chat_html.py \
  --messages ./out/conversation/qq_messages.json \
  --manifest ./out/conversation/media_manifest.json \
  --output ./out/conversation/qq_messages_with_media.html
```

媒体脚本仅复制名称精确匹配且来源位于指定数据目录中的文件。没有缓存的附件会在 `media_manifest.json` 标记为 `missing`；多个不同文件无法消歧时会标记为 `ambiguous`。它不会根据缩略图或近似名称猜测替代文件。

## 隐私与范围

- 导出文件包含私人对话，应存放在权限受控的目录。不要提交到公开仓库、工单、日志或云盘。
- 不要把数据库文件、密钥缓存、进程内存转储或临时明文数据库提交到 Git。
- 导出的内容仅限本机当前 QQ 数据库及本地媒体缓存实际保留的范围；这不证明服务器或其他设备没有更多历史。
- 本地媒体缓存可能不完整。查看媒体清单中的状态和路径确认实际复制结果。
