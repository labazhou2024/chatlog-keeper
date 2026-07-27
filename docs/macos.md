# macOS setup, security model, and troubleshooting

chatlog-keeper 0.2 adds native Apple Silicon support for the current sandboxed
WeChat and QQ desktop clients. The command names and JSON/HTML export format
are the same as on Windows.

## What the tool changes

The normal export path is read-only with respect to both chat clients. It:

1. locates the current user's sandbox container;
2. snapshots the encrypted database family into a private temporary directory;
3. verifies a cached or newly observed key against database page 1;
4. decrypts the snapshot and committed WAL frames locally; and
5. writes only the requested JSON/HTML export.

It does not inject code, send messages, contact Tencent, disable SIP, or modify
the app installed under `/Applications`.

## Key acquisition

`extract-key --method passive` asks the normal user process for read-only Mach
access. Modern hardened clients usually deny that request.

`extract-key --method active` is explicit and interactive:

- an isolated copy is created under
  `~/Library/Application Support/chatlog-keeper/debug-apps/`;
- the copy preserves the original entitlements and adds only
  `com.apple.security.get-task-allow`;
- the copy is ad-hoc signed and verified before launch;
- macOS displays its own administrator authentication dialog;
- a bundled helper reads candidate bytes without writing to the client; and
- Python discards every candidate that fails the real database HMAC oracle.

The original app remains unchanged. A client update creates a new
content-addressed isolated copy rather than silently reusing the previous one.

## Files and permissions

Writable state lives under:

```text
~/Library/Application Support/chatlog-keeper/
├── bin/          # private compiled/copied Mach helper
├── debug-apps/   # isolated active-extraction app copies
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

The active flow may open a separate WeChat or QQ window. Log into that isolated
window only if the client asks. Enter administrator credentials only into the
macOS-owned authentication dialog.

## Troubleshooting

- `administrator username or password was not accepted`: rerun the command
  from the logged-in desktop session and complete the macOS authentication
  dialog. SSH cannot safely substitute for that user interaction.
- `process_access_denied`: the isolated copy was not accepted by taskgated.
  Keep SIP enabled; remove no protections. Rebuild the isolated copy after a
  client update and retry.
- data root not found: pass the container's `xwechat_files` or QQ application
  support directory with `--data-root`.
- source install reports `helper_compile_failed`: install Xcode Command Line
  Tools. The standalone arm64 release already contains the compiled helper.
- container access denied: give the invoking host application (Terminal or the
  desktop host) Full Disk Access in System Settings, then relaunch it.

## Current release boundary

The standalone macOS asset is arm64-only. Intel Macs can run the Python source
build, but they are not part of the 0.2 release gate.
