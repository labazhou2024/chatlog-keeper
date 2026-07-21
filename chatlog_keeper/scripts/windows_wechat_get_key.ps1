<#
.SYNOPSIS
    Extracts the WeChat (Weixin 4.x) SQLCipher master key from YOUR OWN running,
    logged-in WeChat, for decrypting YOUR OWN local chat database.

.DESCRIPTION
    Local-only, your-own-data tool. Mirrors the sibling windows_ntqq_get_key.ps1
    (QQ): a pure .NET/Win32 debugger (CreateProcessW DEBUG_ONLY_THIS_PROCESS +
    INT3 software breakpoint), no third-party binary, no DLL injection, nothing
    uploaded.

    WeChat 4.1.10.31 moved the key out of the heap as a plaintext x'..' blob, so
    the old passive memory scan finds nothing. Instead we:
      1. Locate WCDB's cipher-config function in Weixin.dll by the version-stable
         string "com.Tencent.WCDB.Config.Cipher" (find the RIP-relative LEA that
         references it, then the enclosing function via the exception directory).
      2. Launch Weixin.exe under our debugger, set an INT3 breakpoint at that
         function, and when it fires (WeChat opens its DB after you log in) read
         the registers.
      3. Identify WHICH register/stack slot holds the 32-byte master key WITHOUT
         hard-coding a register layout, using an HMAC cryptographic oracle: for
         each candidate 32 bytes, derive the page key (PBKDF2-HMAC-SHA512, 256000)
         and check it against message_0.db's page-1 HMAC. Only the real key
         verifies (collision-infeasible), so a wrong guess can never be returned.

    Compatible with Windows PowerShell 5.1 and PowerShell 7+.

.PARAMETER WeixinDllPath
    Path to Weixin.dll. Auto-detected from the installed WeChat if omitted.

.PARAMETER DbPath
    Path to a message_0.db used as the HMAC oracle. Auto-detected if omitted.

.PARAMETER NoDebugForKey
    Only do static analysis (print the function RVA), do not launch/debug WeChat.

.PARAMETER KillExisting
    Close any running WeChat first so our DEBUG instance is the one that opens the
    DB (WeChat is single-instance). Default $true.

.OUTPUTS
    On success prints a line:  master key: <64 hex chars>
    (the caller parses this line and caches it locally).

.NOTES
    Your-own-data, fully local. Uses Write-Host for interactive colored output.
#>
[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive script requiring colored console output')]
param(
    [Parameter()] [string]$WeixinDllPath,
    [Parameter()] [string]$DbPath,
    [Parameter()] [switch]$NoDebugForKey,
    [Parameter()] [bool]$KillExisting = $true
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

#region Console UTF-8
# This file is saved UTF-8 WITH BOM, so PowerShell 5.1+ parses its Chinese strings
# correctly with no re-read. We only force the console output to UTF-8 here so the
# `master key:` line and Chinese prompts render correctly when captured.
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
#endregion

#region P/Invoke + debugger (mirrors windows_ntqq_get_key.ps1; HMAC oracle is new)

$DebugApiCode = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace DebugApiWx
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct STARTUPINFOW
    {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public int dwX; public int dwY; public int dwXSize; public int dwYSize;
        public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute;
        public int dwFlags; public short wShowWindow; public short cbReserved2;
        public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct DEBUG_EVENT
    {
        public uint dwDebugEventCode;
        public uint dwProcessId;
        public uint dwThreadId;
        private uint _padding;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 160)]
        public byte[] u;
    }

    internal static class DebugEventParser
    {
        public static uint GetExceptionCode(byte[] u) { return BitConverter.ToUInt32(u, 0); }
        public static ulong GetExceptionAddress(byte[] u) { return BitConverter.ToUInt64(u, 16); }
        public static IntPtr GetFileHandle(byte[] u) { return (IntPtr)BitConverter.ToInt64(u, 0); }
        public static uint GetExitCode(byte[] u) { return BitConverter.ToUInt32(u, 0); }
        // CREATE_PROCESS_DEBUG_INFO: hFile(0) hProcess(8) hThread(16) lpBaseOfImage(24)…
        public static IntPtr GetCreateProcessHandle(byte[] u) { return (IntPtr)BitConverter.ToInt64(u, 8); }
        public static IntPtr GetCreateThreadHandle(byte[] u) { return (IntPtr)BitConverter.ToInt64(u, 16); }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct MODULEENTRY32W
    {
        public uint dwSize; public uint th32ModuleID; public uint th32ProcessID;
        public uint GlblcntUsage; public uint ProccntUsage; public IntPtr modBaseAddr;
        public uint modBaseSize; public IntPtr hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExePath;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 16)]
    internal struct CONTEXT64
    {
        public ulong P1Home; public ulong P2Home; public ulong P3Home; public ulong P4Home;
        public ulong P5Home; public ulong P6Home;
        public uint ContextFlags; public uint MxCsr;
        public ushort SegCs; public ushort SegDs; public ushort SegEs; public ushort SegFs;
        public ushort SegGs; public ushort SegSs; public uint EFlags;
        public ulong Dr0; public ulong Dr1; public ulong Dr2; public ulong Dr3; public ulong Dr6; public ulong Dr7;
        public ulong Rax; public ulong Rcx; public ulong Rdx; public ulong Rbx; public ulong Rsp; public ulong Rbp;
        public ulong Rsi; public ulong Rdi; public ulong R8; public ulong R9; public ulong R10; public ulong R11;
        public ulong R12; public ulong R13; public ulong R14; public ulong R15; public ulong Rip;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)] public byte[] FltSave;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)] public ulong[] VectorRegister;
        public ulong VectorControl; public ulong DebugControl; public ulong LastBranchToRip;
        public ulong LastBranchFromRip; public ulong LastExceptionToRip; public ulong LastExceptionFromRip;
    }

    internal static class Native
    {
        public const int DEBUG_PROCESS = 0x00000001;            // 调试整个进程树 (含子进程)
        public const int DEBUG_ONLY_THIS_PROCESS = 0x00000002;
        public const uint EXCEPTION_DEBUG_EVENT = 1;
        public const uint CREATE_PROCESS_DEBUG_EVENT = 3;
        public const uint EXIT_THREAD_DEBUG_EVENT = 4;
        public const uint EXIT_PROCESS_DEBUG_EVENT = 5;
        public const uint LOAD_DLL_DEBUG_EVENT = 6;
        public const uint UNLOAD_DLL_DEBUG_EVENT = 7;
        public const uint OUTPUT_DEBUG_STRING_EVENT = 8;
        public const uint EXCEPTION_BREAKPOINT = 0x80000003;
        public const uint EXCEPTION_SINGLE_STEP = 0x80000004;
        public const uint DBG_CONTINUE = 0x00010002;
        public const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
        public const uint CONTEXT_AMD64 = 0x00100000;
        public const uint CONTEXT_CONTROL = CONTEXT_AMD64 | 0x0001;
        public const uint CONTEXT_INTEGER = CONTEXT_AMD64 | 0x0002;
        public const uint CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | (CONTEXT_AMD64 | 0x0008);
        public const uint CONTEXT_ALL = CONTEXT_FULL | (CONTEXT_AMD64 | 0x0004) | (CONTEXT_AMD64 | 0x0010);
        public const uint TH32CS_SNAPMODULE = 0x00000008;
        public const uint TH32CS_SNAPMODULE32 = 0x00000010;
        public const uint THREAD_ALL_ACCESS = 0x1FFFFF;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessW(string lpApplicationName, IntPtr lpCommandLine,
            IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, int dwCreationFlags,
            IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFOW lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WaitForDebugEvent(out DEBUG_EVENT lpDebugEvent, uint dwMilliseconds);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ContinueDebugEvent(uint dwProcessId, uint dwThreadId, uint dwContinueStatus);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool TerminateProcess(IntPtr hProcess, int uExitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesRead);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool Module32FirstW(IntPtr hSnapshot, ref MODULEENTRY32W lpme);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool Module32NextW(IntPtr hSnapshot, ref MODULEENTRY32W lpme);
    }

    /// <summary>
    /// Debugger that breakpoints WCDB's cipher-config function and reads the
    /// 32-byte master key, identified by an HMAC oracle (no register hard-coding).
    /// </summary>
    public sealed class KeyExtractor
    {
        private readonly string _exePath;
        private readonly ulong[] _functionRvas;
        private readonly byte[] _dbPage1;
        private readonly Action<string> _log;
        private readonly Action<string> _logVerbose;

        // 多进程: 微信登录后 spawn 子进程, message 库的解密调用可能在子进程, 故用 DEBUG_PROCESS
        // 调试整个进程树, 每个加载 Weixin.dll 的进程独立维护断点 (per-process ProcCtx)。
        // 多断点: wx_key 签名命中 >=1 个候选函数, 每个进程对每个候选地址各设一个 INT3。
        private sealed class ProcCtx { public IntPtr hProcess; public ulong moduleBase; public Dictionary<ulong, byte> bps = new Dictionary<ulong, byte>(); public bool installed; }
        private readonly Dictionary<uint, ProcCtx> _procs = new Dictionary<uint, ProcCtx>();
        private uint _mainPid;
        private int _hitCount;
        private readonly byte[] _calibrateKey; // 校准诊断 (env CHATLOG_CALIBRATE_KEY): 已知标尺 key, 命中时定位其真实位置
        private Dictionary<uint, ulong> _steppingThreads = new Dictionary<uint, ulong>();

        public KeyExtractor(string exePath, ulong[] functionRvas, byte[] dbPage1, Action<string> log, Action<string> logVerbose)
        {
            _exePath = exePath; _functionRvas = functionRvas; _dbPage1 = dbPage1;
            _log = log ?? (s => { }); _logVerbose = logVerbose ?? (s => { });
            string ck = Environment.GetEnvironmentVariable("CHATLOG_CALIBRATE_KEY");
            if (ck != null && ck.Trim().Length == 64) { try { _calibrateKey = HexToBytes(ck.Trim()); } catch { _calibrateKey = null; } }
        }

        private static byte[] HexToBytes(string h) { byte[] b = new byte[h.Length / 2]; for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(h.Substring(i * 2, 2), 16); return b; }
        private static int IndexOfBytes(byte[] hay, byte[] needle)
        {
            if (hay == null || needle == null || needle.Length == 0 || hay.Length < needle.Length) return -1;
            for (int i = 0; i <= hay.Length - needle.Length; i++) { int j = 0; for (; j < needle.Length; j++) if (hay[i + j] != needle[j]) break; if (j == needle.Length) return i; }
            return -1;
        }

        // ── HMAC cryptographic oracle (SQLCipher 4.x raw-key page-key derivation) ──
        private static bool HmacCheck(byte[] pageKey, byte[] page1)
        {
            if (pageKey == null || pageKey.Length != 32 || page1 == null || page1.Length < 4096) return false;
            try
            {
                byte[] macSalt = new byte[16];
                for (int i = 0; i < 16; i++) macSalt[i] = (byte)(page1[i] ^ 0x3A);
                byte[] macKey;
                using (var kdf = new Rfc2898DeriveBytes(pageKey, macSalt, 2, HashAlgorithmName.SHA512))
                    macKey = kdf.GetBytes(32);
                using (var h = new HMACSHA512(macKey))
                {
                    h.TransformBlock(page1, 16, 4096 - 64 - 16, null, 0);
                    h.TransformFinalBlock(BitConverter.GetBytes((uint)1), 0, 4);
                    byte[] mac = h.Hash;
                    for (int i = 0; i < 64; i++) if (mac[i] != page1[4096 - 64 + i]) return false;
                    return true;
                }
            }
            catch { return false; }
        }

        // Returns the candidate IF it is a valid master key for this db (raw-key
        // <=4.0.x, OR 256000-derived 4.1.10.31+), else null. We always cache the
        // candidate (master); decryption derives each db's page key from it.
        private static bool IsValidMasterKey(byte[] cand, byte[] page1)
        {
            if (cand == null || cand.Length != 32) return false;
            // cheap entropy gate: skip all-zero / low-entropy buffers before PBKDF2
            int nz = 0; for (int i = 0; i < 32; i++) if (cand[i] != 0) nz++;
            if (nz < 8) return false;
            if (HmacCheck(cand, page1)) return true;               // raw-key mode
            try
            {
                byte[] salt = new byte[16]; Array.Copy(page1, 0, salt, 0, 16);
                byte[] derived;
                using (var kdf = new Rfc2898DeriveBytes(cand, salt, 256000, HashAlgorithmName.SHA512))
                    derived = kdf.GetBytes(32);
                return HmacCheck(derived, page1);                  // password mode (4.1.10.31+)
            }
            catch { return false; }
        }

        private byte[] Read(IntPtr hProcess, ulong addr, int n)
        {
            if (addr < 0x10000UL || addr > 0x7FFFFFFFFFFFUL) return null;
            byte[] b = new byte[n]; UIntPtr nr;
            if (Native.ReadProcessMemory(hProcess, (IntPtr)addr, b, new UIntPtr((uint)n), out nr) && (ulong)nr == (ulong)n)
                return b;
            return null;
        }
        private ulong ReadPtr(IntPtr hProcess, ulong addr)
        {
            byte[] b = Read(hProcess, addr, 8);
            return b == null ? 0UL : BitConverter.ToUInt64(b, 0);
        }

        public string ExtractKey()
        {
            _log("正在以调试方式启动微信 (Weixin.exe, DEBUG_PROCESS 调试整个进程树)…");
            _log("  EXE: " + _exePath);
            { var sb = new StringBuilder(); foreach (var r in _functionRvas) sb.Append("0x" + r.ToString("X") + " "); _log("  目标函数 RVA (" + _functionRvas.Length + "): " + sb.ToString().Trim()); }
            if (!StartDebugProcess())
                throw new Exception("CreateProcessW(DEBUG) 失败, 错误: " + Marshal.GetLastWin32Error());
            _log("微信主进程已启动, PID=" + _mainPid + " — 请在弹出的微信里扫码/登录目标账号。");
            try { return DebugLoop(); }
            finally { Cleanup(); }
        }

        private bool StartDebugProcess()
        {
            STARTUPINFOW si = new STARTUPINFOW();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFOW));
            PROCESS_INFORMATION pi;
            // DEBUG_PROCESS: 调试整个进程树 (含微信登录后 spawn 的子进程; message 库解密
            // 调用可能在子进程, DEBUG_ONLY_THIS_PROCESS 收不到子进程的调试事件)。
            bool ok = Native.CreateProcessW(_exePath, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, false,
                Native.DEBUG_PROCESS, IntPtr.Zero, null, ref si, out pi);
            if (ok)
            {
                _mainPid = (uint)pi.dwProcessId;
                _procs[_mainPid] = new ProcCtx { hProcess = pi.hProcess };
                if (pi.hThread != IntPtr.Zero) Native.CloseHandle(pi.hThread);
            }
            return ok;
        }

        private ulong GetModuleBaseAddress(uint pid, string moduleName)
        {
            IntPtr snap = Native.CreateToolhelp32Snapshot(Native.TH32CS_SNAPMODULE | Native.TH32CS_SNAPMODULE32, pid);
            if (snap == IntPtr.Zero || snap == new IntPtr(-1)) return 0;
            try
            {
                MODULEENTRY32W e = new MODULEENTRY32W();
                e.dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32W));
                if (Native.Module32FirstW(snap, ref e))
                {
                    do { if (string.Equals(e.szModule, moduleName, StringComparison.OrdinalIgnoreCase)) return (ulong)e.modBaseAddr; }
                    while (Native.Module32NextW(snap, ref e));
                }
            }
            finally { Native.CloseHandle(snap); }
            return 0;
        }

        // 给某进程设断点 (它刚加载 Weixin.dll 时调用; 幂等: installed 即已设)。对每个候选函数各设一个 INT3。
        private void TrySetBreakpoint(uint pid)
        {
            ProcCtx pc; if (!_procs.TryGetValue(pid, out pc)) return;
            if (pc.installed || pc.hProcess == IntPtr.Zero) return;
            ulong b = GetModuleBaseAddress(pid, "Weixin.dll");
            if (b == 0) return;
            pc.moduleBase = b; pc.installed = true;
            foreach (ulong rva in _functionRvas)
            {
                ulong addr = b + rva;
                byte[] one = Read(pc.hProcess, addr, 1);
                if (one == null) { _logVerbose("PID=" + pid + " 读断点原字节失败 @0x" + addr.ToString("X")); continue; }
                UIntPtr w;
                if (!Native.WriteProcessMemory(pc.hProcess, (IntPtr)addr, new byte[] { 0xCC }, new UIntPtr(1), out w) || w != new UIntPtr(1))
                { _logVerbose("PID=" + pid + " 写 INT3 失败 @0x" + addr.ToString("X")); continue; }
                Native.FlushInstructionCache(pc.hProcess, (IntPtr)addr, new UIntPtr(1));
                pc.bps[addr] = one[0];
                _log("断点已设 (PID=" + pid + ") 于 0x" + addr.ToString("X"));
            }
        }
        private void RestoreOriginalByte(ProcCtx pc, ulong addr)
        {
            byte orig; if (!pc.bps.TryGetValue(addr, out orig)) return;
            UIntPtr w;
            Native.WriteProcessMemory(pc.hProcess, (IntPtr)addr, new byte[] { orig }, new UIntPtr(1), out w);
            Native.FlushInstructionCache(pc.hProcess, (IntPtr)addr, new UIntPtr(1));
        }
        private void ReinstallBreakpoint(ProcCtx pc, ulong addr)
        {
            if (!pc.bps.ContainsKey(addr)) return;
            UIntPtr w;
            Native.WriteProcessMemory(pc.hProcess, (IntPtr)addr, new byte[] { 0xCC }, new UIntPtr(1), out w);
            Native.FlushInstructionCache(pc.hProcess, (IntPtr)addr, new UIntPtr(1));
        }

        private string DebugLoop()
        {
            DEBUG_EVENT ev; bool go = true; string foundKey = null;
            while (go)
            {
                if (!Native.WaitForDebugEvent(out ev, 10000)) { continue; } // timeout: 继续等登录
                uint pid = ev.dwProcessId;
                uint cont = Native.DBG_CONTINUE;
                switch (ev.dwDebugEventCode)
                {
                    case Native.CREATE_PROCESS_DEBUG_EVENT:
                        {
                            IntPtr hProc = DebugEventParser.GetCreateProcessHandle(ev.u);
                            IntPtr hThr  = DebugEventParser.GetCreateThreadHandle(ev.u);
                            IntPtr hFile = DebugEventParser.GetFileHandle(ev.u);
                            ProcCtx pc;
                            if (!_procs.TryGetValue(pid, out pc)) { _procs[pid] = new ProcCtx { hProcess = hProc }; if (pid != _mainPid) _logVerbose("子进程创建 PID=" + pid); }
                            else if (pc.hProcess == IntPtr.Zero) { pc.hProcess = hProc; }
                            TrySetBreakpoint(pid); // Weixin.dll 在 CREATE 时可能已加载
                            if (hThr != IntPtr.Zero && hThr != new IntPtr(-1)) Native.CloseHandle(hThr);
                            if (hFile != IntPtr.Zero && hFile != new IntPtr(-1)) Native.CloseHandle(hFile);
                        }
                        break;
                    case Native.LOAD_DLL_DEBUG_EVENT:
                        {
                            IntPtr h = DebugEventParser.GetFileHandle(ev.u); if (h != IntPtr.Zero && h != new IntPtr(-1)) Native.CloseHandle(h);
                            TrySetBreakpoint(pid); // 该进程加载新 dll, 试设断点 (含 Weixin.dll)
                        }
                        break;
                    case Native.EXCEPTION_DEBUG_EVENT:
                        {
                            uint code = DebugEventParser.GetExceptionCode(ev.u);
                            ulong addr = DebugEventParser.GetExceptionAddress(ev.u);
                            ProcCtx pc; bool known = _procs.TryGetValue(pid, out pc);
                            if (code == Native.EXCEPTION_BREAKPOINT && known && pc.bps.ContainsKey(addr))
                            {
                                RestoreOriginalByte(pc, addr);
                                string k = HandleBreakpoint(pc, pid, ev.dwThreadId);
                                if (k != null) { foundKey = k; go = false; }
                                else { SetSingleStepForRearm(pc, ev.dwThreadId, addr); }
                            }
                            else if (code == Native.EXCEPTION_SINGLE_STEP)
                            {
                                ulong rearmAddr; bool inStep = _steppingThreads.TryGetValue(ev.dwThreadId, out rearmAddr);
                                _logVerbose("[rearm] 单步异常 T=" + ev.dwThreadId + " inStep=" + inStep + " PID=" + pid);
                                if (inStep)
                                { ClearTrapFlag(ev.dwThreadId); if (known) { ReinstallBreakpoint(pc, rearmAddr); _logVerbose("[rearm] 已重装0xCC @0x" + rearmAddr.ToString("X") + " PID=" + pid); } _steppingThreads.Remove(ev.dwThreadId); }
                            }
                            else if (code != Native.EXCEPTION_BREAKPOINT) { cont = Native.DBG_EXCEPTION_NOT_HANDLED; } // 交给微信自己的 SEH
                        }
                        break;
                    case Native.EXIT_PROCESS_DEBUG_EVENT:
                        {
                            ProcCtx pc; if (_procs.TryGetValue(pid, out pc)) { if (pc.hProcess != IntPtr.Zero) Native.CloseHandle(pc.hProcess); _procs.Remove(pid); }
                            if (pid == _mainPid) go = false; // 主进程退出才结束
                        }
                        break;
                }
                Native.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
            }
            return foundKey;
        }

        // The HMAC oracle: collect every plausible 32-byte buffer reachable from the
        // registers/stack at the breakpoint and return the one that verifies. No
        // register layout is assumed; the [rdx+0x08] heuristic is just tried first.
        private string HandleBreakpoint(ProcCtx pc, uint pid, uint threadId)
        {
            _hitCount++;
            IntPtr hThread = Native.OpenThread(Native.THREAD_ALL_ACCESS, false, threadId);
            if (hThread == IntPtr.Zero) return null;
            try
            {
                CONTEXT64 ctx = new CONTEXT64();
                // 只取 整数+控制 寄存器, 绝不碰 FltSave/VectorRegister (结构 VectorRegister 定义为
                // ulong[26]=208B 但真实 M128A[26]=416B, CONTEXT_ALL 读写会损坏线程 FPU/SSE → 崩)。
                ctx.ContextFlags = Native.CONTEXT_INTEGER | Native.CONTEXT_CONTROL;
                ctx.FltSave = new byte[512];
                ctx.VectorRegister = new ulong[26];
                if (!Native.GetThreadContext(hThread, ref ctx)) return null;
                ctx.Rip = ctx.Rip - 1; // step back over the 0xCC
                ctx.ContextFlags = Native.CONTEXT_CONTROL; // 只写回 Rip/EFlags 控制寄存器
                Native.SetThreadContext(hThread, ref ctx);

                IntPtr hp = pc.hProcess;
                // ── 校准诊断 (env CHATLOG_CALIBRATE_KEY 控制): 用已知标尺 key 定位 cipher 命中时
                // master key 的真实位置, 据此修正下方扫描策略 → 对所有用户通用 (默认关, 不影响发行) ──
                if (_calibrateKey != null && _hitCount <= 4)
                {
                    _log("[校准] 第" + _hitCount + "次命中 (PID=" + pid + "), 搜标尺 key 位置…");
                    string[] rn = { "rdx","rcx","r8","r9","rax","rbx","rsi","rdi","rbp","rsp","r10","r11","r12","r13","r14","r15" };
                    ulong[] rvv = { ctx.Rdx,ctx.Rcx,ctx.R8,ctx.R9,ctx.Rax,ctx.Rbx,ctx.Rsi,ctx.Rdi,ctx.Rbp,ctx.Rsp,ctx.R10,ctx.R11,ctx.R12,ctx.R13,ctx.R14,ctx.R15 };
                    bool found = false;
                    for (int ci = 0; ci < rn.Length; ci++)
                    {
                        byte[] m1 = Read(hp, rvv[ci], 0x200);
                        if (m1 != null) { int idx = IndexOfBytes(m1, _calibrateKey); if (idx >= 0) { _log("[校准] ★ key 在 [" + rn[ci] + "]+0x" + idx.ToString("X")); found = true; } }
                        ulong pp = ReadPtr(hp, rvv[ci]);
                        if (pp != 0) { byte[] m2 = Read(hp, pp, 0x200); if (m2 != null) { int idx = IndexOfBytes(m2, _calibrateKey); if (idx >= 0) { _log("[校准] ★ key 在 [[" + rn[ci] + "]]+0x" + idx.ToString("X")); found = true; } } }
                    }
                    byte[] stk = Read(hp, ctx.Rsp, 0x2000);
                    if (stk != null) { int idx = IndexOfBytes(stk, _calibrateKey); if (idx >= 0) { _log("[校准] ★ key 在 [rsp]+0x" + idx.ToString("X")); found = true; } }
                    if (!found) _log("[校准] 本次命中未在 寄存器/一层间接/栈 找到标尺 key (此调用可能不传 master key)");
                }
                var tried = new HashSet<ulong>();
                Func<ulong, string> tryAddr = (addr) =>
                {
                    if (addr < 0x10000UL || addr > 0x7FFFFFFFFFFFUL) return null;
                    if (!tried.Add(addr)) return null;
                    byte[] b = Read(hp, addr, 32);
                    if (b != null && IsValidMasterKey(b, _dbPage1))
                    {
                        var sb = new StringBuilder(64);
                        for (int i = 0; i < 32; i++) sb.Append(b[i].ToString("x2"));
                        return sb.ToString();
                    }
                    return null;
                };

                ulong[] regs = { ctx.Rdx, ctx.Rcx, ctx.R8, ctx.R9, ctx.Rax, ctx.Rbx,
                                 ctx.Rsi, ctx.Rdi, ctx.Rbp, ctx.R10, ctx.R11, ctx.R12, ctx.R13, ctx.R14, ctx.R15 };
                ulong[] offs = { 0x0, 0x8, 0x10, 0x18, 0x20, 0x28, 0x30 };

                // 1. Heuristic first: key pointer at [rdx+0x08], size at [rdx+0x10]==32
                ulong sz = ReadPtr(hp, ctx.Rdx + 0x10);
                if (sz == 32)
                {
                    string k = tryAddr(ReadPtr(hp, ctx.Rdx + 0x08));
                    if (k != null) { _log("master key 命中 (PID=" + pid + " rdx+0x08, 第" + _hitCount + "次)"); return k; }
                }
                // 2. each register: as a direct pointer to the key, and via [reg+off] indirections
                foreach (ulong r in regs)
                {
                    string k = tryAddr(r);
                    if (k != null) { _log("master key 命中 (PID=" + pid + " 寄存器直指, 第" + _hitCount + "次)"); return k; }
                    foreach (ulong o in offs)
                    {
                        string k2 = tryAddr(ReadPtr(hp, r + o));
                        if (k2 != null) { _log("master key 命中 (PID=" + pid + " 寄存器间接, 第" + _hitCount + "次)"); return k2; }
                    }
                }
                // 3. stack: pointers in the first 0x200 bytes from rsp
                for (ulong off = 0; off <= 0x200; off += 8)
                {
                    string k = tryAddr(ReadPtr(hp, ctx.Rsp + off));
                    if (k != null) { _log("master key 命中 (PID=" + pid + " 栈指针, 第" + _hitCount + "次)"); return k; }
                }
                // not this hit; let the breakpoint re-arm and try the next call
                _logVerbose("第" + _hitCount + "次断点未命中 key (PID=" + pid + "), 继续等待…");
                return null;
            }
            finally { Native.CloseHandle(hThread); }
        }

        private void SetSingleStepForRearm(ProcCtx pc, uint threadId, ulong addr)
        {
            IntPtr hThread = Native.OpenThread(Native.THREAD_ALL_ACCESS, false, threadId);
            if (hThread == IntPtr.Zero) { _logVerbose("[rearm] OpenThread 失败 T=" + threadId); return; }
            try
            {
                CONTEXT64 ctx = new CONTEXT64();
                ctx.ContextFlags = Native.CONTEXT_CONTROL; ctx.FltSave = new byte[512]; ctx.VectorRegister = new ulong[26];
                if (Native.GetThreadContext(hThread, ref ctx))
                {
                    ctx.EFlags = ctx.EFlags | 0x100; // trap flag → 单步过被恢复的原指令
                    ctx.ContextFlags = Native.CONTEXT_CONTROL;
                    bool ok = Native.SetThreadContext(hThread, ref ctx);
                    _steppingThreads[threadId] = addr;
                    _logVerbose("[rearm] 设单步 T=" + threadId + " addr=0x" + addr.ToString("X") + " setctx=" + ok + " ef=0x" + ctx.EFlags.ToString("X"));
                }
                else { _logVerbose("[rearm] GetThreadContext 失败 T=" + threadId); }
            }
            finally { Native.CloseHandle(hThread); }
        }
        private void ClearTrapFlag(uint threadId)
        {
            IntPtr hThread = Native.OpenThread(Native.THREAD_ALL_ACCESS, false, threadId);
            if (hThread == IntPtr.Zero) return;
            try
            {
                CONTEXT64 ctx = new CONTEXT64();
                ctx.ContextFlags = Native.CONTEXT_CONTROL; ctx.FltSave = new byte[512]; ctx.VectorRegister = new ulong[26];
                if (Native.GetThreadContext(hThread, ref ctx)) { ctx.EFlags = ctx.EFlags & ~0x100u; Native.SetThreadContext(hThread, ref ctx); }
            }
            finally { Native.CloseHandle(hThread); }
        }
        private void Cleanup()
        {
            foreach (var kv in _procs) { if (kv.Value.hProcess != IntPtr.Zero) Native.CloseHandle(kv.Value.hProcess); }
            _procs.Clear();
        }
    }

    // Static locator: find WCDB cipher-config function RVA in Weixin.dll via the
    // version-stable string "com.Tencent.WCDB.Config.Cipher" (string -> RIP-relative
    // LEA -> enclosing function via the exception directory). In C# because scanning
    // a 100+MB .text in a PowerShell byte loop would take minutes.
    public static class Locator
    {
        private static int IndexOf(byte[] hay, byte[] needle)
        {
            int end = hay.Length - needle.Length;
            for (int i = 0; i <= end; i++) { bool ok = true; for (int j = 0; j < needle.Length; j++) if (hay[i + j] != needle[j]) { ok = false; break; } if (ok) return i; }
            return -1;
        }
        public static ulong FindCipherFunctionRva(byte[] d, Action<string> log)
        {
            if (BitConverter.ToUInt16(d, 0) != 0x5A4D) throw new Exception("not a PE (DOS header)");
            int pe = BitConverter.ToInt32(d, 0x3C);
            if (BitConverter.ToUInt32(d, pe) != 0x00004550) throw new Exception("not a PE (PE signature)");
            int coff = pe + 4;
            int numSec = BitConverter.ToUInt16(d, coff + 2);
            int sizeOpt = BitConverter.ToUInt16(d, coff + 16);
            int opt = coff + 20;
            if (BitConverter.ToUInt16(d, opt) != 0x20B) throw new Exception("only PE32+ supported");
            uint excRVA = BitConverter.ToUInt32(d, opt + 112 + 3 * 8);
            uint excSize = BitConverter.ToUInt32(d, opt + 112 + 3 * 8 + 4);
            int secOff = opt + sizeOpt;
            int N = numSec;
            string[] nm = new string[N]; long[] va = new long[N]; long[] vs = new long[N]; int[] rp = new int[N]; int[] rs = new int[N];
            for (int i = 0; i < N; i++)
            {
                int so = secOff + i * 40;
                nm[i] = Encoding.ASCII.GetString(d, so, 8).TrimEnd('\0');
                vs[i] = BitConverter.ToUInt32(d, so + 8);
                va[i] = BitConverter.ToUInt32(d, so + 12);
                rs[i] = (int)BitConverter.ToUInt32(d, so + 16);
                rp[i] = (int)BitConverter.ToUInt32(d, so + 20);
            }
            byte[] needle = Encoding.ASCII.GetBytes("com.Tencent.WCDB.Config.Cipher");
            int strFo = IndexOf(d, needle);
            if (strFo < 0) throw new Exception("WCDB cipher string not found in Weixin.dll (incompatible version?)");
            long strRva = -1;
            for (int i = 0; i < N; i++) if (strFo >= rp[i] && strFo < rp[i] + rs[i]) { strRva = va[i] + (strFo - rp[i]); break; }
            if (strRva < 0) throw new Exception("string RVA resolve failed");
            if (log != null) log("  string RVA=0x" + strRva.ToString("X"));
            int ti = -1; for (int i = 0; i < N; i++) if (nm[i] == ".text") { ti = i; break; }
            if (ti < 0) throw new Exception(".text section not found");
            int tStart = rp[ti]; int tEnd = rp[ti] + rs[ti]; long tVA = va[ti];
            long leaRva = -1;
            for (int i = tStart; i < tEnd - 7; i++)
            {
                if (d[i + 1] != 0x8D) continue;
                if ((d[i] & 0xF8) != 0x48) continue;
                if ((d[i + 2] & 0xC7) != 0x05) continue;
                int disp = BitConverter.ToInt32(d, i + 3);
                long instrRva = tVA + (i - tStart);
                if (instrRva + 7 + disp == strRva) { leaRva = instrRva; break; }
            }
            if (leaRva < 0) throw new Exception("no LEA referencing the string");
            if (log != null) log("  LEA RVA=0x" + leaRva.ToString("X"));
            int excFo = -1; for (int i = 0; i < N; i++) if (excRVA >= va[i] && excRVA < va[i] + vs[i]) { excFo = (int)(rp[i] + (excRVA - va[i])); break; }
            if (excFo < 0) throw new Exception("exception directory locate failed");
            int n = (int)(excSize / 12); uint t = (uint)leaRva;
            int lo = 0, hi = n - 1; long func = -1;
            while (lo <= hi)
            {
                int mid = (lo + hi) / 2; int eo = excFo + mid * 12;
                uint b = BitConverter.ToUInt32(d, eo); uint e = BitConverter.ToUInt32(d, eo + 4);
                if (t < b) hi = mid - 1; else if (t >= e) lo = mid + 1; else { func = b; break; }
            }
            if (func < 0) throw new Exception("enclosing function not found in exception directory");
            if (log != null) log("  function RVA=0x" + func.ToString("X"));
            return (ulong)func;
        }

        // PRIMARY anchor (2026-06-08): scan Weixin.dll .text for the empirically-proven
        // WCDB key-set prologue signature (the wx_key signature that captured the
        // 4.1.10.31 master key). Returns the enclosing-function RVAs (>=1). The old
        // com.Tencent.WCDB.Config.Cipher string anchor is DEAD: it points to a
        // config-NAME-string initializer (runs once at DLL load, never carries the
        // key). This prologue is the real key-set entry: at entry rdx -> a WCDB Data
        // blob {+0x08 = key ptr, +0x10 = key len == 0x20}. Sig (idx 5 = wildcard):
        //   24 50 48 C7 45 ?? FE FF FF FF 44 89 CF 44 89 C3 49 89 D6
        public static ulong[] FindKeySetFunctionRvas(byte[] d, Action<string> log)
        {
            if (BitConverter.ToUInt16(d, 0) != 0x5A4D) throw new Exception("not a PE (DOS header)");
            int pe = BitConverter.ToInt32(d, 0x3C);
            if (BitConverter.ToUInt32(d, pe) != 0x00004550) throw new Exception("not a PE (PE signature)");
            int coff = pe + 4;
            int numSec = BitConverter.ToUInt16(d, coff + 2);
            int sizeOpt = BitConverter.ToUInt16(d, coff + 16);
            int opt = coff + 20;
            if (BitConverter.ToUInt16(d, opt) != 0x20B) throw new Exception("only PE32+ supported");
            uint excRVA = BitConverter.ToUInt32(d, opt + 112 + 3 * 8);
            uint excSize = BitConverter.ToUInt32(d, opt + 112 + 3 * 8 + 4);
            int secOff = opt + sizeOpt;
            int N = numSec;
            string[] nm = new string[N]; long[] va = new long[N]; long[] vs = new long[N]; int[] rp = new int[N]; int[] rs = new int[N];
            for (int i = 0; i < N; i++)
            {
                int so = secOff + i * 40;
                nm[i] = Encoding.ASCII.GetString(d, so, 8).TrimEnd('\0');
                vs[i] = BitConverter.ToUInt32(d, so + 8);
                va[i] = BitConverter.ToUInt32(d, so + 12);
                rs[i] = (int)BitConverter.ToUInt32(d, so + 16);
                rp[i] = (int)BitConverter.ToUInt32(d, so + 20);
            }
            int ti = -1; for (int i = 0; i < N; i++) if (nm[i] == ".text") { ti = i; break; }
            if (ti < 0) throw new Exception(".text section not found");
            int tStart = rp[ti]; int tEnd = rp[ti] + rs[ti]; long tVA = va[ti];
            int excFo = -1; for (int i = 0; i < N; i++) if (excRVA >= va[i] && excRVA < va[i] + vs[i]) { excFo = (int)(rp[i] + (excRVA - va[i])); break; }
            if (excFo < 0) throw new Exception("exception directory locate failed");
            int nExc = (int)(excSize / 12);
            byte[] sig = { 0x24,0x50,0x48,0xC7,0x45,0x00,0xFE,0xFF,0xFF,0xFF,0x44,0x89,0xCF,0x44,0x89,0xC3,0x49,0x89,0xD6 };
            bool[] wild = new bool[sig.Length]; wild[5] = true;
            var rvas = new List<ulong>(); var seen = new HashSet<ulong>();
            int limit = tEnd - sig.Length;
            for (int i = tStart; i <= limit; i++)
            {
                if (d[i] != 0x24) continue;
                bool ok = true;
                for (int j = 1; j < sig.Length; j++) { if (wild[j]) continue; if (d[i + j] != sig[j]) { ok = false; break; } }
                if (!ok) continue;
                long matchRva = tVA + (i - tStart);
                uint t = (uint)matchRva; int lo = 0, hi = nExc - 1; long func = -1;
                while (lo <= hi)
                {
                    int mid = (lo + hi) / 2; int eo = excFo + mid * 12;
                    uint b = BitConverter.ToUInt32(d, eo); uint e = BitConverter.ToUInt32(d, eo + 4);
                    if (t < b) hi = mid - 1; else if (t >= e) lo = mid + 1; else { func = b; break; }
                }
                ulong fr = func >= 0 ? (ulong)func : (ulong)(matchRva - 3);
                if (seen.Add(fr)) { rvas.Add(fr); if (log != null) log("  key-set sig @0x" + matchRva.ToString("X") + " -> func RVA=0x" + fr.ToString("X")); }
                if (rvas.Count >= 8) break;
            }
            if (rvas.Count == 0) throw new Exception("wx_key 函数签名未在 Weixin.dll 找到 (微信版本变化, 需重新取证)");
            return rvas.ToArray();
        }
    }
}
'@

#endregion

#region Helper functions

function Read-UInt16 { param([byte[]]$B, [int]$O) [BitConverter]::ToUInt16($B, $O) }
function Read-UInt32 { param([byte[]]$B, [int]$O) [BitConverter]::ToUInt32($B, $O) }
function Read-Int32  { param([byte[]]$B, [int]$O) [BitConverter]::ToInt32($B, $O) }

function Find-AsciiString {
    param([byte[]]$Data, [string]$Text)
    $needle = [System.Text.Encoding]::ASCII.GetBytes($Text)
    $end = $Data.Length - $needle.Length
    for ($i = 0; $i -le $end; $i++) {
        $ok = $true
        for ($j = 0; $j -lt $needle.Length; $j++) { if ($Data[$i + $j] -ne $needle[$j]) { $ok = $false; break } }
        if ($ok) { return $i }
    }
    return -1
}

# Static analysis: find the WCDB cipher-config function RVA in Weixin.dll via the
# version-stable string "com.Tencent.WCDB.Config.Cipher".
function Get-WeixinCipherFunctionRva {
    param([string]$DllPath)
    $bytes = [System.IO.File]::ReadAllBytes($DllPath)
    if ((Read-UInt16 $bytes 0) -ne 0x5A4D) { throw "不是有效 PE (DOS header)" }
    $peOff = Read-UInt32 $bytes 0x3C
    if ((Read-UInt32 $bytes $peOff) -ne 0x00004550) { throw "不是有效 PE (PE signature)" }
    $coff = $peOff + 4
    $numSec = Read-UInt16 $bytes ($coff + 2)
    $sizeOpt = Read-UInt16 $bytes ($coff + 16)
    $optOff = $coff + 20
    if ((Read-UInt16 $bytes $optOff) -ne 0x20B) { throw "仅支持 PE32+ (64 位)" }
    # data directory index 3 = exception directory (PE32+ data dirs at optOff+112)
    $excRVA = Read-UInt32 $bytes ($optOff + 112 + 3 * 8)
    $excSize = Read-UInt32 $bytes ($optOff + 112 + 3 * 8 + 4)
    $secOff = $optOff + $sizeOpt
    $secs = @()
    for ($i = 0; $i -lt $numSec; $i++) {
        $so = $secOff + $i * 40
        $name = [System.Text.Encoding]::ASCII.GetString($bytes, $so, 8).TrimEnd([char]0)
        $vsize = Read-UInt32 $bytes ($so + 8)
        $va = Read-UInt32 $bytes ($so + 12)
        $rawsize = Read-UInt32 $bytes ($so + 16)
        $rawptr = Read-UInt32 $bytes ($so + 20)
        $secs += [pscustomobject]@{ Name = $name; VA = [uint64]$va; VSize = [uint64]$vsize; RawPtr = [int]$rawptr; RawSize = [int]$rawsize }
    }
    function FO2RVA([int]$fo) { foreach ($s in $secs) { if ($fo -ge $s.RawPtr -and $fo -lt ($s.RawPtr + $s.RawSize)) { return $s.VA + ($fo - $s.RawPtr) } } return $null }
    function RVA2FO([uint64]$rva) { foreach ($s in $secs) { if ($rva -ge $s.VA -and $rva -lt ($s.VA + $s.VSize)) { return [int]($s.RawPtr + ($rva - $s.VA)) } } return $null }

    $strFo = Find-AsciiString -Data $bytes -Text 'com.Tencent.WCDB.Config.Cipher'
    if ($strFo -lt 0) { throw "Weixin.dll 内未找到 'com.Tencent.WCDB.Config.Cipher' 字符串 (版本不兼容?)" }
    $strRva = FO2RVA $strFo
    Write-Host ("  字符串 RVA: 0x{0:X}" -f $strRva) -ForegroundColor Cyan

    $text = $secs | Where-Object { $_.Name -eq '.text' } | Select-Object -First 1
    if (-not $text) { throw ".text section 未找到" }
    $tStart = $text.RawPtr; $tEnd = $text.RawPtr + $text.RawSize; $tVA = $text.VA
    $leaRva = $null
    for ($i = $tStart; $i -lt $tEnd - 7; $i++) {
        if ($bytes[$i + 1] -ne 0x8D) { continue }            # LEA opcode
        $rex = $bytes[$i]; if (($rex -band 0xF8) -ne 0x48) { continue }   # REX.W
        $modrm = $bytes[$i + 2]; if (($modrm -band 0xC7) -ne 0x05) { continue }  # mod=00 rm=101 (RIP-relative)
        $disp = Read-Int32 $bytes ($i + 3)
        $instrRva = $tVA + ($i - $tStart)
        $target = $instrRva + 7 + $disp
        if ($target -eq $strRva) { $leaRva = $instrRva; break }
    }
    if ($null -eq $leaRva) { throw "未找到引用该字符串的 LEA 指令" }
    Write-Host ("  LEA RVA: 0x{0:X}" -f $leaRva) -ForegroundColor Cyan

    # exception directory binary search for the enclosing function
    $excFo = RVA2FO $excRVA
    $nEntries = [int]($excSize / 12)
    $target32 = [uint32]$leaRva
    $lo = 0; $hi = $nEntries - 1; $funcRva = $null
    while ($lo -le $hi) {
        $mid = [int][Math]::Floor(($lo + $hi) / 2)
        $eo = $excFo + $mid * 12
        $begin = Read-UInt32 $bytes $eo
        $endA = Read-UInt32 $bytes ($eo + 4)
        if ($target32 -lt $begin) { $hi = $mid - 1 }
        elseif ($target32 -ge $endA) { $lo = $mid + 1 }
        else { $funcRva = $begin; break }
    }
    if ($null -eq $funcRva) { throw "exception directory 未找到包含该 LEA 的函数" }
    Write-Host ("  函数 RVA: 0x{0:X}" -f $funcRva) -ForegroundColor Green
    return [uint64]$funcRva
}

function Get-InstalledWeixinInfo {
    [CmdletBinding()] [OutputType([hashtable])] param()
    $installPath = $null
    foreach ($rp in @('HKCU:\Software\Tencent\Weixin', 'HKLM:\SOFTWARE\WOW6432Node\Tencent\Weixin', 'HKLM:\SOFTWARE\Tencent\Weixin')) {
        try { if (Test-Path $rp) { $r = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue; if ($r -and $r.InstallPath) { $installPath = $r.InstallPath; break } } } catch {}
    }
    if (-not $installPath) {
        foreach ($c in @('C:\Program Files\Tencent\Weixin', 'C:\Program Files (x86)\Tencent\Weixin')) { if (Test-Path $c) { $installPath = $c; break } }
    }
    if (-not $installPath -or -not (Test-Path $installPath)) { throw "未找到微信安装目录 (Weixin)" }
    $exe = Join-Path $installPath 'Weixin.exe'
    if (-not (Test-Path $exe)) { throw "未找到 Weixin.exe: $exe" }
    # version subdir (e.g. 4.1.10.31) holding Weixin.dll
    $verDir = Get-ChildItem -Path $installPath -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } | Sort-Object Name -Descending | Select-Object -First 1
    $dll = $null
    if ($verDir) { $cand = Join-Path $verDir.FullName 'Weixin.dll'; if (Test-Path $cand) { $dll = $cand } }
    if (-not $dll) { $cand = Join-Path $installPath 'Weixin.dll'; if (Test-Path $cand) { $dll = $cand } }
    if (-not $dll) { throw "未找到 Weixin.dll (安装目录或版本子目录)" }
    return @{ InstallPath = $installPath; WeixinExe = $exe; WeixinDll = $dll; Version = $(if ($verDir) { $verDir.Name } else { '' }) }
}

# Read a message_0.db page-1 (4096 bytes) with FILE_SHARE_READ|WRITE|DELETE so a
# locked db can still be read for the HMAC oracle.
function Get-DbPage1 {
    param([string]$Path)
    # PS 5.1: System.IO.File 是静态类无构造函数, [System.IO.File]::new(4参数) 不存在
    # ("找不到 new 的重载, 参数计数 4") → 必须用 FileStream。FILE_SHARE_READ|WRITE|DELETE
    # 让被微信锁定的 db 仍可读 page1 做 HMAC oracle。
    $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
    try { $buf = New-Object byte[] 4096; [void]$fs.Read($buf, 0, 4096); return $buf } finally { $fs.Close() }
}

function Find-WeixinMessageDb {
    $roots = @()
    foreach ($drive in (Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) {
        $roots += (Join-Path $drive.Root 'wechat files\xwechat_files')
        $roots += (Join-Path $drive.Root 'xwechat_files')
        $roots += (Join-Path $drive.Root 'WeChat Files')
    }
    $roots += (Join-Path $env:USERPROFILE 'Documents\xwechat_files')
    $roots += (Join-Path $env:USERPROFILE 'Documents\WeChat Files')
    $roots = @($roots | Select-Object -Unique)
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($wx in (Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue)) {
            $db = Join-Path $wx.FullName 'db_storage\message\message_0.db'
            if (Test-Path $db) { return $db }
        }
    }
    return $null
}

#endregion

#region Main

Write-Host "=== 微信 master key 自动提取 (本人数据, 全本地) ===" -ForegroundColor Yellow

$info = $null
if (-not $WeixinDllPath) {
    $info = Get-InstalledWeixinInfo
    $WeixinDllPath = $info.WeixinDll
    Write-Host ("微信安装: {0}  (版本 {1})" -f $info.InstallPath, $info.Version) -ForegroundColor Cyan
    Write-Host ("  Weixin.dll: {0}" -f $WeixinDllPath) -ForegroundColor Cyan
}
if (-not (Test-Path $WeixinDllPath)) { throw "Weixin.dll 不存在: $WeixinDllPath" }

Write-Host "`n=== 静态定位 WCDB key-set 函数 (wx_key 签名) ===" -ForegroundColor Yellow
if (-not ([System.Management.Automation.PSTypeName]'DebugApiWx.KeyExtractor').Type) {
    Add-Type -TypeDefinition $DebugApiCode -Language CSharp
}
$locLog = [Action[string]] { param($m) Write-Host $m -ForegroundColor Cyan }
# PRIMARY: wx_key 签名定位真正的 key-set 函数 (>=1 个候选); 旧的 config-name 字符串锚已废弃 (指向死的 config-name 初始化器)。
$funcRvas = [uint64[]]([DebugApiWx.Locator]::FindKeySetFunctionRvas([System.IO.File]::ReadAllBytes($WeixinDllPath), $locLog))
Write-Host ("命中 key-set 候选函数 {0} 个: {1}" -f $funcRvas.Count, (($funcRvas | ForEach-Object { '0x{0:X}' -f $_ }) -join ', ')) -ForegroundColor Green

if ($NoDebugForKey) {
    return [pscustomobject]@{ FunctionRVA = $funcRvas[0]; FunctionRVAs = $funcRvas; Key = $null }
}

if (-not $DbPath) { $DbPath = Find-WeixinMessageDb }
if (-not $DbPath -or -not (Test-Path $DbPath)) { throw "未找到 message_0.db 作 HMAC 校验 (用 -DbPath 指定)" }
Write-Host ("HMAC 校验库: {0}" -f $DbPath) -ForegroundColor Cyan
$page1 = Get-DbPage1 -Path $DbPath

if (-not $info) { try { $info = Get-InstalledWeixinInfo } catch {} }
$weixinExe = if ($info) { $info.WeixinExe } else { (Join-Path (Split-Path -Parent (Split-Path -Parent $WeixinDllPath)) 'Weixin.exe') }
if (-not (Test-Path $weixinExe)) { throw "未找到 Weixin.exe: $weixinExe" }

if ($KillExisting) {
    $running = @(Get-Process -Name 'Weixin' -ErrorAction SilentlyContinue)
    if ($running.Count -gt 0) {
        Write-Host ("检测到微信正在运行 (PID: {0}) — 临时关闭以便调试实例接管…" -f ($running.Id -join ', ')) -ForegroundColor Yellow
        foreach ($p in $running) { try { Stop-Process -Id $p.Id -Force -ErrorAction Stop } catch {} }
        $deadline = (Get-Date).AddSeconds(6)
        while ((Get-Date) -lt $deadline) { if (@(Get-Process -Name 'Weixin' -ErrorAction SilentlyContinue).Count -eq 0) { break }; Start-Sleep -Milliseconds 250 }
    }
}

Write-Host "`n=== 启动调试实例并等待登录 ===" -ForegroundColor Yellow
if (-not ([System.Management.Automation.PSTypeName]'DebugApiWx.KeyExtractor').Type) {
    Add-Type -TypeDefinition $DebugApiCode -Language CSharp
}
$logA = [Action[string]] { param($m) Write-Host $m -ForegroundColor Cyan }
$logV = [Action[string]] { param($m) Write-Verbose $m }
$extractor = New-Object DebugApiWx.KeyExtractor($weixinExe, [uint64[]]$funcRvas, $page1, $logA, $logV)

$result = [pscustomobject]@{ FunctionRVA = $funcRvas[0]; FunctionRVAs = $funcRvas; Key = $null }
try {
    $key = $extractor.ExtractKey()
    if ($key) {
        $result.Key = $key
        Write-Host "`n========================================" -ForegroundColor Green
        Write-Host ("master key: {0}" -f $key) -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "(已校验: 该 key 能解出你的 message_0.db; 仅本地, 未上传)" -ForegroundColor Green
    } else {
        Write-Host "未提取到 master key (未在弹出的微信里登录 / 版本不兼容)。" -ForegroundColor Red
    }
}
catch { Write-Host ("提取出错: {0}" -f $_) -ForegroundColor Red }

return $result
#endregion
