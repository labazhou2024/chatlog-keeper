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
extraction uses a GDB hardware breakpoint for a recognized internal WCDB KDF,
or may load the fixed LD_PRELOAD observer when dynamic symbols are available.
Both paths observe only a child process launched by this tool. It does not send messages
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
- if paired internal WCDB KDF instruction signatures match, GDB manages the
  child from startup and computes its hardware breakpoint from ELF mappings
  and ASLR, then checks the loaded instructions again;
- internal KDF candidates require a 32-byte password, 16-byte salt, 256000
  iterations, 32-byte output, and the SHA-512 algorithm parameter; they travel
  through a private `0600` FIFO to the existing HMAC verifier;
- WeChat may also load a locally built observer through `LD_PRELOAD` when
  `sqlite3_key` / OpenSSL PBKDF2 are dynamically resolved; candidates go
  through a same-user `0600` FIFO and are never written to logs;
- if internal signatures do not match and those symbols are not exported,
  the compatibility path for older builds scans the child heap and, if
  needed, a small compiled `process_vm_readv` / ptrace helper;
- Python discards every candidate that fails the real database HMAC oracle.

Do not run the tool as root to bypass Yama. Use Active Key or `set-key`.

Official native Linux WeChat **4.1.13.9 x86_64** was tested locally: the internal
KDF hardware breakpoint captured a 32-byte master key, and `_verify_key_v4`
passed for the target message database and all six message shards. Password
mode matched; raw-key mode did not. The integrated active flow also passed
capture, verification, account-cache storage, and child-exit checks. This does
not establish support for other 4.1.x builds.

The observation point is the main ELF's SQLCipher codec calling its crypto
provider KDF. The locator requires paired password-derivation and HMAC-key
derivation instruction sequences in executable segments and rejects ambiguous
matches. It does not depend on exported symbols, fixed RVAs, or legacy heap
hex strings. The tested binary has:

- ELF Build ID: `d16278a416e000526fd22aec59973e54f91291e4`
- ELF SHA-256: `91c2e3237ba69acadb23a84bdde360c714719889756aed92e9e45785c3d97010`

Untested builds are not marked verified. If signatures are incompatible or no
candidate HMAC-verifies, use `set-key` with an independently verified key.
The active flow exits its spawned client on completion or cancellation.

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
The internal KDF path additionally requires system `gdb` with Python support
(`sudo apt install gdb`), including for standalone releases. It does not use
Frida, change Yama, or require root.

## Troubleshooting

- `process_access_denied`: Yama blocked a read of the already-running client.
  Quit it, then retry Active Key, or use `set-key`.
- `daily_client_single_instance_conflict`: quit the daily client normally and
  wait for it to exit before retrying Active Key.
- `official_client_not_found`: install the official Tencent `.deb`, or pass
  `--data-root` and use `set-key`.
- `helper_compile_failed` / `capture_compile_failed`: install
  `build-essential` and retry. The standalone release does not need a compiler.
- `capture_debugger_missing`: install `gdb` with Python support and retry.
- `capture_image_changed`: the executable changed during startup or loaded
  instructions did not match; quit and retry without reusing old addresses.
- `capture_timeout`: no candidate HMAC-verified before the deadline; log in
  inside the tool-launched window instead of separately opening the daily client.
- data root not found: pass the `xwechat_files` folder or `~/.config/QQ` with
  `--data-root`.
- Flatpak extract-key failed: use the `.deb` client, or `set-key` against the
  Flatpak data directory.

## Current release boundary

The standalone Linux asset is x86_64-only. aarch64 Ubuntu can run the Python
source build, but it is not part of the frozen GitHub Release gate. Wine and
deepin-wine Windows clients are not supported.
