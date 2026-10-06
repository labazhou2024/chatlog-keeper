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
- QQ preserves its original entitlements and adds
  `com.apple.security.get-task-allow`;
- only the inspected WeChat 4.1.11 (269136), 4.1.12 (269340/269364), 4.1.13
  (269579), and 4.1.15 (270100/270102) policies may remove Tencent signing-identity claims that
  an ad-hoc signature cannot assert; they require the exact Tencent
  application identifier/group allowlist and sandbox before preserving
  unrelated entitlements and adding the scoped Mach-registration exception
  required by PID-suffixed rendezvous services; 4.1.11/269136 and 4.1.12/269364
  must carry the exact Tencent Team ID, while 4.1.12/269340, 4.1.13/269579,
  and the listed 4.1.15 builds may omit that
  entitlement; other client builds and unknown developer, private, or keychain
  identity claims fail closed;
- the exact 4.1.15 (270100/270102) policies also permit the PID-suffixed XPlayer
  rendezvous service observed in 270100; 270102 has the same unsigned XPlayer
  payload, so its media thread can initialize
  without a sandbox registration denial terminating the private copy;
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
- the observer resolves PBKDF2 only from the exact system CommonCrypto image,
  verifies the final address owner, and terminates the private copy if that
  provenance cannot be proved; it never falls back to `RTLD_NEXT`;
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
force-quit the daily client. The private copy reuses the current login session;
no account switching is required. If the saved-session "Enter WeChat" window
appears, click it in the private copy and complete any phone confirmation while
the command waits. Remaining at that window may never open the message database
or produce a key. If macOS asks the isolated `WeChat-…` app to access other apps'
data, allow that system prompt; it can block startup before the observer loads.
An expired session requires WeChat's official QR login. The command
verifies the candidate against the database, closes every frozen process
generation executing inside its private bundle (including nested helpers,
never the installed client), and removes the exact FIFO and staged dylib
generations by inode.

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
existing session and never requires account switching. Complete any "Enter
WeChat", phone confirmation, or macOS app-data access prompt while it waits.
An expired session requires its official QR login. The macOS flow never
asks for administrator credentials. Stop if any terminal or third-party prompt
asks for a system password.

## Troubleshooting

- `debug_copy_unsupported_client`: this exact bundle version/build has no
  inspected policy. Update chatlog-keeper and compare the bundle pair with the
  list above. The official 270102 feed says `4.1.15.22`, but its signed bundle
  says `4.1.15`; the bundle's `Info.plist` determines support. Do not normalize
  versions or add builds manually.
- `debug_copy_entitlements_rejected`: the build is listed, but its signing
  entitlements failed the identity/sandbox checks. Use an unmodified official
  client; report the bundle pair and signing entitlements for review.
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
- `capture_library_not_loaded`: no startup acknowledgement arrived. Check for
  a macOS app-data access prompt for the isolated copy before retrying; a blocked
  launch and a missing observer can both cause this observation.
- `capture_environment_missing`: the observer reported missing FIFO environment.
- `capture_no_kdf_calls`: the observer loaded but saw no PBKDF2 calls. Complete
  login in the private copy; an unsupported native boundary is another possible
  cause, not a conclusion from this status alone.
- `capture_symbol_unresolved` / `capture_kdf_shape_unmatched`: the observer could
  not resolve system CommonCrypto or saw only unmatched PBKDF2 parameters.
  Report the error and client bundle version/build. Every candidate still
  requires local DB HMAC verification.
- `capture_native_write_failed`: the native observer could not write its private
  FIFO; retry after closing the isolated copy and check the container's Full
  Disk Access grant.
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

### Inspected builds and login-time failures

The 269340 and 270102 policies were derived from Tencent's official DMGs,
verified with `codesign --verify --deep --strict`, and checked against their
real bundle metadata and entitlements. Provenance checking normalizes signature
layout only on temporary executable copies; this handles the `__LINKEDIT`
virtual-size drift seen in 269340 after re-signing while still hashing client
code and nested signatures. Bundle inspection and private-copy preparation
do not verify login or DB-HMAC key capture. A matching
policy does not guarantee that recovery succeeds on every macOS/client pair.

One arm64 live run on the official `4.1.15 / 270102` bundle completed app-data
authorization and login, captured 24 candidates, and returned a 32-byte key
that passed an independent database HMAC check, without using the key cache.
Cleanup removed the private process and capture files; the installed app still
passed strict signature verification. This validates that scenario, not every
macOS permission or account state.

If a prepared copy exits or returns no verified key, first check that app-data
authorization and login completed in the private copy. A `crashpad_handler`
SIGTRAP alone does not identify why the main WeChat process exited. For a
report, include the exact attempt time, the CLI error, macOS version and the
following metadata from the original app:

```bash
/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' /Applications/WeChat.app/Contents/Info.plist
/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' /Applications/WeChat.app/Contents/Info.plist
codesign -d --verbose=4 /Applications/WeChat.app 2>&1 | grep -E '^(Identifier|Authority|TeamIdentifier)='
codesign -d --entitlements :- /Applications/WeChat.app
```

If available, add only the exception type and crashed thread's module/function
names from the main WeChat crash report, or the matching sandbox `mach-register`
denial. Redact home paths and PID suffixes; do not post full system logs, keys,
account identifiers or chat databases. This distinguishes an unsupported build,
a source-entitlement mismatch and a separate login-time failure.

## Current release boundary

The standalone macOS asset is arm64-only. Intel Macs can run the Python source
build, but they are not part of the 0.3 release gate.
