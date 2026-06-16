# chatlog-keeper · Keep the stories behind every conversation

> Your QQ / WeChat chat history, kept on your own computer.
> *留住对话框背后的那些故事 —— 把属于你的聊天记录留在本地。*

English · [中文](README.zh.md)

---

What truly matters was never the app — it's the stories behind every
conversation: a late-night *"get some sleep"* from family, an inside joke with
an old friend, the small moments that are only yours. Those words were written
by you and sent to you; they belong to you. **chatlog-keeper** helps you take
them out of your local chat database and keep them as a backup you can revisit
any time — entirely on your own machine, never uploaded.

## What it is

A **local, offline** tool that exports **your own** logged-in QQ / WeChat chat
history into `JSON` plus a nostalgic, self-contained `HTML` page (chat bubbles,
grouped by conversation and day — the way you remember it).

## What it is NOT

- ❌ **Not** a tool for accessing **anyone else's** data — only your own account, on your own machine.
- ❌ **No** network, **no** upload, **no** telemetry — there is not a single line of network code in the decryption path.
- ❌ **Not** cracking anyone else's encryption, **not** intruding on any server — it reads local files **on your own computer that you already have the right to access**.

## Principles

| | |
|---|---|
| 🔒 Yourself only | Exports only **your own account's** data, on **your own device** |
| 🏠 Local only | Runs entirely on your computer — **never goes online** |
| 🚫 Nothing leaves | **No upload, no collection, zero telemetry** |
| 📖 Open & auditable | Fully open source — **read every line yourself** |

## Features

- **QQ** — export your local NTQQ chat history
- **WeChat** — export your local WeChat chat history
- **WeChat images** — restore local `.dat` images back to `jpg` / `png`

## Supported versions

| Source | Supported | Page-key derivation | How the key is obtained |
|---|---|---|---|
| WeChat ≤ 4.0.x | ✅ | raw-key (`enc_key` used directly) | passive memory scan |
| WeChat 4.1.10.31+ (2026-05) | ✅ | password mode — `PBKDF2-HMAC-SHA512(enc_key, salt, 256000)` | one-time debugger (key no longer kept in plaintext memory) |
| QQ NTQQ 9.9.x | ✅ | per-DB passphrase | passive scan |

On **WeChat 4.1.10.31** (released 2026-05-27) the plaintext key was moved out of
the process heap, so a passive memory scan — what most existing tools rely on —
no longer finds it on those builds. chatlog-keeper falls back to a one-time
debugger extraction for them (see [Account-ban risk](#account-ban-risk)).

## How it compares

A factual snapshot of similar open-source tools (**as of 2026-06**; star counts
and maintenance status change over time — please check each repo yourself):

| Tool | Stars | Last update | WeChat | QQ | Platform | Notes |
|---|---|---|---|---|---|---|
| **chatlog-keeper** (this) | — | 2026-06 | ≤4.0 **+ 4.1.10.31+** | ✅ NTQQ | Windows | passive scan + debugger fallback |
| [WeChatMsg / 留痕](https://github.com/LC044/WeChatMsg) | 41k+ | 2025-12 | ≤4.0 | ❌ | Windows | feature-rich GUI; author states it is **no longer updated** |
| [PyWxDump](https://github.com/xaoyaoo/PyWxDump) | 9k+ | 2025-10 | 3.x–4.0 | ❌ | Windows | repo description now reads "删库"; inactive |
| [chatlog](https://github.com/sjzar/chatlog) | 9k+ | 2025-10 | ≤4.0 | ❌ | cross-platform | Go; HTTP/MCP API |
| [ylytdeng/wechat-decrypt](https://github.com/ylytdeng/wechat-decrypt) | 4k+ | 2026-06 | 4.0 | ❌ | Win/macOS/Linux | active; memory-scan only |

Where chatlog-keeper differs: it is the one here that handles **WeChat
4.1.10.31+** (where the key left plaintext memory) and that also exports **QQ
(NTQQ)**, not just WeChat.

What it is **not**: it is **Windows-only**, a young project, and deliberately
CLI-first (JSON/HTML, no GUI or built-in analytics). If you want a polished GUI
or cross-platform support today, the tools above are more mature — this one's
niche is *newest-WeChat compatibility + QQ, with a clear legal stance*.

## Install

Requires **Python 3.9+**.

```bash
git clone <repo-url>
cd chatlog-keeper
pip install -r requirements.txt
```

## Usage

> Prerequisite: be logged into **your own** QQ / WeChat on this machine, so the
> tool can read the local data that belongs to you.

```bash
# 1) See what's available here and whether the key was obtained
python -m chatlog_keeper.cli probe

# 2) Export the last 30 days of QQ chats -> ./out/qq_messages.{json,html}
python -m chatlog_keeper.cli qq --days 30 --out ./out

# 3) Export the last 30 days of WeChat chats
python -m chatlog_keeper.cli wechat --days 30 --out ./out

# 4) Decrypt a folder of WeChat .dat images -> jpg/png
python -m chatlog_keeper.cli images --src "<folder of WeChat images>" --out ./out/images
```

When it's done, open `out/*_messages.html` in any browser and scroll back
through your memories.

### Getting the decryption key (usually automatic)

On export, the tool passively reads the key from your **running, logged-in**
client (read-only memory access — no injection, no hooks, no debugger attach),
caches it locally, and reuses it next time. Most of the time you do **nothing**.

Only when automatic extraction fails (common on newer WeChat 4.1.10.31+, where
the key is no longer kept in plaintext memory) do you fetch it once by hand:

```bash
# Auto (default): passive scan first (low ban risk); falls back to the debugger
# only if passive finds nothing.
python -m chatlog_keeper.cli extract-key --source wechat

# Passive only (lowest ban risk; may find nothing on WeChat 4.1.10.31+)
python -m chatlog_keeper.cli extract-key --source wechat --method passive

# Debugger only (gets the key on the newest builds; higher ban risk — see
#   "Account-ban risk"; needs Administrator + you log in once)
python -m chatlog_keeper.cli extract-key --source wechat --method active

# Paste it yourself (after obtaining the key with any tool)
python -m chatlog_keeper.cli set-key --source wechat --key <64-hex>
python -m chatlog_keeper.cli set-key --source qq --key <16-char passphrase>
```

The key is cached locally (`%LOCALAPPDATA%\chatlog-keeper\data\secrets\`) and
reused on later exports — no need to fetch it again.

## Account-ban risk

In short: **exporting your own local chat history carries low ban risk** — it
does not make any unusual interaction with the server. Tencent's ban controls
target *server-side* abnormal behavior (auto-login, bulk friend-adding,
simulated message sending, repacked multi-instance clients, plugins/cheats,
fake GPS), not "reading your own data locally".

The actual risk **depends on how the key is obtained**:

| Action | Ban risk | Notes |
|---|---|---|
| Reading the local database file | Negligible (≈0) | Pure file read; no network; the server cannot perceive it |
| Passive memory scan for the key (default) | Low | Read-only process memory (no injection, no hooks, no debugger); long used by mainstream tools with no reported bans |
| Debugger-breakpoint extraction (`--method active`) | Medium–high | Attaches a debugger to the client — the only path with a documented detection mechanism (a client may detect "being debugged / non-allowlisted module loaded"). Use only when passive fails, at your own discretion |

To minimize risk: prefer the default passive method; reuse the cache instead of
re-extracting; you can even quit the client and decrypt offline afterwards; and
**never** use this tool for any server-side automation (that is the real
ban-prone territory).

> Note: Tencent's actual enforcement against tools like these is mainly asking
> code-hosting platforms to **take the tool's repository down** (DMCA), not
> banning the individual user's account — that is a *project-level* risk,
> separate from your personal ban risk when exporting your own data.

## How it works (in brief)

A chat app stores your messages in a small encrypted database on your machine,
and the key needed to open it lives on your own computer once you've logged in.
This tool simply reads **your local** database, opens it with the key **on your
machine**, and exports the messages. It only ever touches files **on your own
computer that you already have the right to access**, and it never goes online.

> Decryption is page-by-page streaming (peak memory ≈ one 4 KB page), so even a
> multi-GB database is never loaded whole.

## Legal & Disclaimer

Please read **[DISCLAIMER.md](DISCLAIMER.md)** before use.

In one line: this tool is for exporting and backing up **your own** chat data
for personal preservation and nostalgia; local only, never transmitted; whether
and how you use it is your own decision and responsibility, and you must comply
with the laws of your jurisdiction and the relevant terms of service. If any
rights holder has concerns, please reach out via an issue and the author will
cooperate.

## License

Released under the **[MIT License](LICENSE)** — permissive, and free for anyone to use, including in their own projects.
