# 用法示例 / Usage Examples

> 前提 / Prerequisite：在本机登录**你自己**的 QQ / 微信。本工具只读取属于你自己的本地数据。
> Be logged into **your own** QQ / WeChat on this machine; the tool only reads data that belongs to you.

## 1. 先探测 / Probe first

```bash
python -m chatlog_keeper.cli probe
```

输出会告诉你 QQ / 微信是否被检测到、密钥是否已就绪（`key_present` / `enc_keys_present`）。
The output tells you whether QQ / WeChat were detected and whether the key is ready.

## 2. 导出 QQ / Export QQ

```bash
python -m chatlog_keeper.cli qq --days 90 --out ./out
# -> ./out/qq_messages.json  +  ./out/qq_messages.html
```

## 3. 导出微信 / Export WeChat

```bash
python -m chatlog_keeper.cli wechat --days 90 --out ./out
# -> ./out/wechat_messages.json  +  ./out/wechat_messages.html
```

用浏览器打开 `*.html` 即可像翻聊天记录一样回看。
Open the `*.html` in any browser to scroll back through your chats.

## 4. 解密微信图片 / Decrypt WeChat images

微信图片 `.dat` 通常位于 / WeChat image `.dat` files usually live under：

```
%APPDATA%\Tencent\xwechat_files\<your_wxid>\msg\attach\...\Image\
```

```bash
python -m chatlog_keeper.cli images --src "<上面的目录 / that folder>" --out ./out/images
```

## 常见问题 / FAQ

- **`key_present` / `enc_keys_present` 为 false**：确保对应客户端正在运行且你已登录——
  密钥要在登录之后才能从你自己机器上取得。
  *Make sure the client is running and you are logged in — the key is only obtainable after login.*
- **想换数据/缓存目录**：设置环境变量 `CHATLOG_KEEPER_DATA_DIR`。
  *Set `CHATLOG_KEEPER_DATA_DIR` to relocate the cache/data directory.*
- **微信图片是 wxgf 格式**：需要系统安装 `ffmpeg` 才能转成 jpg。
  *wxgf images need a system `ffmpeg` on PATH to transcode to jpg.*
- **一切都在本地**：以上命令都不联网，导出的文件只写到你指定的 `--out` 目录。
  *Everything is local: none of these commands touch the network.*
