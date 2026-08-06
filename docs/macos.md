# macOS setup, security model, and troubleshooting

chatlog-keeper 0.3 adds native Apple Silicon support for the current sandboxed
WeChat and QQ desktop clients. The command names and JSON/HTML export format
are the same as on Windows.

## What the tool changes

The normal export path is read-only with respect to both chat clients. It:

1. locates the current user's sandbox container;
2. snapshots the encrypted database family into a private temporary directory;
3. verifies a cached or newly observed key against database page 1;
4. decrypts the snapshot and committed WAL frames locally; and
5. writes only the requested JSON/HTML export.

Normal export and passive extraction do not inject code. Explicit WeChat active
extraction loads only the fixed observer described below into the isolated
copy. The tool itself does not send messages or call Tencent APIs, disable SIP,
or modify the app installed under `/Applications`. The launched official client
may still perform its normal session authentication and network activity.

## Key acquisition

`extract-key --method passive` asks the normal user process for read-only Mach
access. Modern hardened clients usually deny that request.

`extract-key --method active` is explicit and interactive:

- an isolated copy is created under
  `~/Library/Application Support/chatlog-keeper/debug-apps/`;
- the copy preserves the original entitlements and adds only
  `com.apple.security.get-task-allow`;
- QQ keeps Hardened Runtime and is launched only after its signature, exact
  entitlement delta, and direct-library Team-ID relation are verified;
- WeChat uses the upstream v0.2 compatibility signature: Hardened Runtime is
  not enabled on that private copy, because an ad-hoc main executable cannot
  otherwise load the current Tencent-signed embedded frameworks. The installed
  app keeps all of its original protections;
- before the WeChat copy starts, the locally built, signed, and verified PBKDF2
  observer is staged temporarily in WeChat's own sandbox `Data/tmp` directory;
  LaunchServices passes only that fixed dylib path and its FIFO path to the new
  process;
- the observer is active before automatic login, accepts only the narrow
  WeChat 4.x 32-byte candidate shape, and sends candidates through a same-user
  `0600` FIFO without writing them to logs or temporary files;
- the helper runs as the current user, without elevation or an administrator
  password prompt;
- the helper checks the exact executable path and kernel process generation
  before and after obtaining the task port;
- a bundled helper reads candidate bytes without writing to the client; and
- Python discards every candidate that fails the real database HMAC oracle.

The original app remains unchanged. A client update creates a new
content-addressed isolated copy rather than silently reusing the previous one.
WeChat remains single-instance: quit the daily client normally from its menu
and wait for it to close before starting the active flow. The tool does not
force-quit the daily client. The private copy reuses the current login session
and captures the key automatically; no account switching is required. Only an
expired session requires scanning WeChat's official login QR code while the
command waits. The command verifies the candidate against the database, closes
only the process generation it launched, and removes the exact FIFO and staged
dylib generations by inode.

This compatibility copy has fewer runtime protections than the installed
WeChat client. It is private to the current user, is used only after an explicit
active-key request, and is never a replacement for the daily client. SIP stays
enabled, no administrator process is used, the original app is not re-signed,
and every candidate must pass the real database HMAC oracle. QQ and any future
Hardened Runtime copy still fail closed with
`debug_copy_library_validation_incompatible` or
`debug_copy_library_validation_unverifiable` when their signing relationship
cannot be proved.

## Files and permissions

Writable state lives under:

```text
~/Library/Application Support/chatlog-keeper/
├── bin/          # private Mach helper and signed startup observer
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

The active flow may open a separate WeChat or QQ window. WeChat first reuses the
existing session and never requires account switching. Only an expired session
requires its official QR login while the command waits. The macOS flow never
asks for administrator credentials. Stop if any terminal or third-party prompt
asks for a system password.

## Troubleshooting

- `daily_client_single_instance_conflict`: quit the daily WeChat client normally
  from its menu, wait for it to close completely, and retry. Do not force-quit
  it.
- `debug_copy_busy`: another active flow is running; wait for it to finish and
  retry.
- `debug_copy_cleanup_failed`: close only the isolated client launched by the
  tool, then retry. Do not terminate the daily client.
- `capture_launch_configuration_invalid`: the staged observer or FIFO changed
  identity before launch; no copy was started, so retry.
- `capture_channel_*` / `capture_library_*`: the temporary channel failed a
  permission, signature, hash, or cleanup check; update or reinstall the
  connector and retry.
- `debug_copy_library_validation_incompatible`: a Hardened Runtime copy's required
  embedded libraries do not share a launch-compatible Team ID with the isolated
  main executable. The tool does not launch it; use a DB-verified manual key.
- `debug_copy_library_validation_unverifiable`: the tool could not safely prove
  the required dependency-signing relationship. It does not launch the copy;
  update the connector/client or use a DB-verified manual key.
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
build, but they are not part of the 0.3 release gate.
