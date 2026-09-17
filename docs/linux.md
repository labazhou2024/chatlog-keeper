# Linux setup, security model, and troubleshooting

chatlog-keeper adds native support for the official Tencent Linux WeChat 4.x
and QQ NT clients on Debian-family desktops (Ubuntu first). The command names
and JSON/HTML export format are the same as on Windows and macOS.

Wine / deepin-wine Windows clients are out of scope.

## What the tool changes

The normal export path is read-only with respect to both chat clients. It:

1. locates the current user's XDG / official data directory;
2. snapshots the encrypted database family into a private temporary directory;
3. verifies a cached or newly observed key against database page 1;
4. decrypts the snapshot and committed WAL frames locally; and
5. writes only the requested JSON/HTML export.

Normal export and passive extraction do not inject code. Explicit WeChat active
extraction may load only the fixed LD_PRELOAD observer described below into a
child process that this tool launched. The tool itself does not send messages
or call Tencent APIs, and it does not modify the package under `/opt/wechat`
or `/opt/QQ`. The launched official client may still perform its normal session
authentication and network activity.

## Data locations

Official Linux WeChat 4.x stores chat databases under the user's Documents
directory, not under `~/.xwechat` (that directory is runtime config only):

```text
$XDG_DOCUMENTS_DIR/xwechat_files/<wxid_...>/db_storage/message/message_*.db
```

Typical Documents paths are `~/Documents` or `~/文档`. Flatpak installs may
keep a copy under `~/.var/app/com.tencent.WeChat/`.

Official Linux QQ NT uses hash-named account directories:

```text
~/.config/QQ/nt_qq_<hash>/nt_db/nt_msg.db
```

Override either root with `--data-root` or `CHATLOG_WECHAT_DATA_ROOT` /
`CHATLOG_QQ_DATA_ROOT`.

## Key acquisition

Ubuntu's default `kernel.yama.ptrace_scope=1` denies `process_vm_readv` against
an already-running WeChat or QQ process. That is reported as
`process_access_denied`, not as a missing key.

`extract-key --method passive` tries to read the daily client. On a default
Ubuntu desktop it usually fails closed with `process_access_denied`.

`extract-key --method active` is explicit and interactive:

- quit the daily WeChat or QQ client normally and wait for it to exit;
- the tool launches the official binary (`/opt/wechat/wechat` or `/opt/QQ/qq`)
  as its own child, so Yama still allows the parent to read that process;
- WeChat may also load a locally built observer through `LD_PRELOAD` when
  `sqlite3_key` / OpenSSL PBKDF2 are dynamically resolved; candidates go
  through a same-user `0600` FIFO and are never written to logs;
- if those symbols are not exported, the tool scans the child heap and, if
  needed, a small compiled `process_vm_readv` / ptrace helper;
- Python discards every candidate that fails the real database HMAC oracle.

Do not run the tool as root to bypass Yama. Use Active Key or `set-key`.

Official Linux WeChat is currently 4.1.x. Those builds often no longer keep the
legacy `x'<64hex>...'` raw-key blob in the heap. If Active Key cannot observe a
candidate that HMAC-verifies, paste a DB-verified key with `set-key`. Builds
that have not been exercised on a real Ubuntu install are not listed as
verified in the README.

Flatpak: data-root discovery and `set-key` / cached exports work. Reading a
sandboxed process usually fails closed; install the official `.deb` for Active
Key or pass `--data-root` and use `set-key`.

## Files and permissions

Writable state lives under:

```text
$XDG_DATA_HOME/chatlog-keeper/   # usually ~/.local/share/chatlog-keeper
├── bin/          # private memory-scan helper and WeChat observer
└── secrets/      # cached DB keys
```

`secrets/` is mode `0700`; key files are written atomically with mode `0600`.
The tool never prints a successful key in its JSON result or diagnostics.

## Commands

```bash
chatlog-keeper probe
chatlog-keeper extract-key --source wechat --method active
chatlog-keeper extract-key --source qq --method active
chatlog-keeper wechat --days 7 --out ./out
chatlog-keeper qq --days 7 --out ./out
```

A source install compiles the tiny C helpers on first use and therefore needs
`gcc` or `clang` (`sudo apt install build-essential`). The standalone
`chatlog-keeper-linux-x86_64` release already contains the compiled helpers.

## Troubleshooting

- `process_access_denied`: Yama blocked a read of the already-running client.
  Quit it, then retry Active Key, or use `set-key`.
- `daily_client_single_instance_conflict`: quit the daily client normally and
  wait for it to exit before retrying Active Key.
- `official_client_not_found`: install the official Tencent `.deb`, or pass
  `--data-root` and use `set-key`.
- `helper_compile_failed` / `capture_compile_failed`: install
  `build-essential` and retry. The standalone release does not need a compiler.
- data root not found: pass the `xwechat_files` folder or `~/.config/QQ` with
  `--data-root`.
- Flatpak extract-key failed: use the `.deb` client, or `set-key` against the
  Flatpak data directory.

## Current release boundary

The standalone Linux asset is x86_64-only. aarch64 Ubuntu can run the Python
source build, but it is not part of the frozen GitHub Release gate. Wine and
deepin-wine Windows clients are not supported.
