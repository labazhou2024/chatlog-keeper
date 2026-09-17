"""GDB-only startup observer. No attach, software KDF breakpoints, or key logging.

The parent locates the KDF instruction sequence in the ELF and verifies every
candidate with its existing page-1 HMAC. GDB owns the official child from exec
and kills only that child on completion, cancellation, or interrupt.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct

import gdb


def run():
    config = json.loads(os.environ.pop("CHATLOG_KEEPER_GDB_CONFIG"))
    state = {"hits": 0, "candidates": 0, "error": "", "child_pid": 0}
    status_path = Path(config["status_path"])

    def status(error=None):
        if error is not None:
            state["error"] = error
        # The parent created this empty file inside its private per-run dir.
        status_path.write_text(json.dumps(state), encoding="utf-8")

    fifo_fd = None
    try:
        for command in (
            "set pagination off", "set confirm off",
            "set print thread-events off", "set debuginfod enabled off",
            "set auto-load off", "set startup-with-shell off",
            "set disable-randomization off", "set detach-on-fork on",
            "set follow-fork-mode parent",
            "unset environment CHATLOG_KEEPER_GDB_CONFIG",
        ):
            gdb.execute(command, to_string=True)
        executable = Path(config["executable"]).resolve()
        if hashlib.sha256(executable.read_bytes()).hexdigest() != config["image_sha256"]:
            status("capture_image_changed")
            return
        if Path(gdb.current_progspace().filename).resolve() != executable:
            status("capture_image_changed")
            return
        fifo_fd = os.open(
            config["fifo"], os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW
        )
        info = os.fstat(fifo_fd)
        if (not stat.S_ISFIFO(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            status("capture_channel_prepare_failed")
            return
        gdb.execute("starti", to_string=True)
        inferior = gdb.selected_inferior()
        state["child_pid"] = inferior.pid
        status()
        bases = []
        for line in Path("/proc/%d/maps" % inferior.pid).read_text().splitlines():
            fields = line.split(maxsplit=5)
            if (len(fields) == 6 and fields[5] == str(executable)
                    and int(fields[2], 16) == 0):
                bases.append(int(fields[0].split("-")[0], 16))
        if len(bases) != 1:
            status("capture_image_mapping_failed")
            return
        base = bases[0]
        signature = bytes.fromhex(config["signature"])
        loaded = bytes(inferior.read_memory(base + config["signature_address"], len(signature)))
        if loaded != signature:
            status("capture_image_changed")
            return
        seen = set()

        class KDFBreakpoint(gdb.Breakpoint):
            def stop(self):
                state["hits"] += 1
                try:
                    frame = gdb.selected_frame()
                    reg = lambda name: int(frame.read_register(name))
                    # SysV arguments immediately BEFORE provider->kdf call:
                    # ctx, algorithm, pass, passlen, salt, saltlen;
                    # stack: iterations, output length, output pointer.
                    sp = reg("rsp")
                    iterations = struct.unpack("<I", bytes(inferior.read_memory(sp, 4)))[0]
                    length = struct.unpack("<I", bytes(inferior.read_memory(sp + 8, 4)))[0]
                    if (reg("ecx"), reg("r9d"), iterations, length, reg("esi")) != (
                        32, 16, 256000, 32, 2
                    ):
                        return False
                    candidate = bytes(inferior.read_memory(reg("rdx"), 32))
                    if candidate in seen:
                        return False
                    if len(seen) >= 64:
                        status("capture_candidate_limit")
                        return True
                    seen.add(candidate)
                    record = b"WXK1" + candidate
                    if os.write(fifo_fd, record) != len(record):
                        status("capture_channel_write_failed")
                        return True
                    state["candidates"] = len(seen)
                    status()
                    return False
                except Exception:
                    status("capture_observation_failed")
                    return True

        bp = KDFBreakpoint(
            "*%#x" % (base + config["virtual_address"]),
            type=gdb.BP_HARDWARE_BREAKPOINT, internal=True,
        )
        gdb.execute("continue", to_string=True)
        bp.delete()
    except KeyboardInterrupt:
        pass
    except Exception:
        status("capture_debugger_failed")
    finally:
        # SIGINT from the parent stops gdb.execute('continue'). Never leave an
        # interrupted client or a debug register behind after this session.
        try:
            if gdb.selected_inferior().pid:
                gdb.execute("kill", to_string=True)
        except Exception:
            pass
        if fifo_fd is not None:
            os.close(fifo_fd)


run()
