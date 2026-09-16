import re
import shutil
import subprocess
from pathlib import Path

import pytest


SCRIPT = (
    Path(__file__).parents[1]
    / "chatlog_keeper"
    / "scripts"
    / "windows_wechat_get_key.ps1"
)


def _method_body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1 : index]
    raise AssertionError(f"unterminated method: {signature}")


def _embedded_csharp(source: str) -> str:
    match = re.search(r"\$DebugApiCode = @'\r?\n(.*?)\r?\n'@", source, re.DOTALL)
    assert match is not None
    return match.group(1)


def test_breakpoint_events_resume_before_bounded_cooperative_verification():
    source = SCRIPT.read_text(encoding="utf-8-sig")
    csharp = _embedded_csharp(source)
    debug_loop = _method_body(csharp, "private string DebugLoop()")
    capture = _method_body(csharp, "private void CaptureBreakpointCandidates(")
    verifier = _method_body(csharp, "private void ProcessCandidateVerificationSlice()")

    # Register/process-memory capture is cheap; the 256,000-round PBKDF2 is
    # advanced only in fixed slices after each received event has been continued.
    assert "QueueCandidateBatch" in capture
    assert "HmacCheck" not in capture
    assert "VerificationIterationsPerSlice = 1024" in csharp
    assert ".Advance(VerificationIterationsPerSlice)" in verifier
    assert debug_loop.count("Native.ContinueDebugEvent") == 1
    assert debug_loop.index("finally") < debug_loop.index("Native.ContinueDebugEvent")

    # Copied candidates remain drainable after main-process exit, but the same
    # absolute deadline still bounds shutdown.  No worker or wait handle survives.
    assert "while (debuggeeRunning || HasCandidateWork())" in debug_loop
    assert "if (!debuggeeRunning) continue;" in debug_loop
    assert "ClearCandidateVerifier();" in debug_loop
    assert "new Thread" not in csharp
    assert "AutoResetEvent" not in csharp


def test_candidate_backlog_declares_bounds_and_strict_round_robin():
    source = SCRIPT.read_text(encoding="utf-8-sig")
    csharp = _embedded_csharp(source)
    enqueue = _method_body(csharp, "private void QueueCandidateBatch(")
    take = _method_body(csharp, "private byte[] TakeNextCandidate()")

    assert "MaxPendingCandidateSources = 32" in csharp
    assert "MaxCandidatesPerSource = 192" in csharp
    assert "EvictOldestCandidateBatch" in enqueue
    assert "DropCandidate(batch.candidates.Dequeue())" in enqueue
    # Requeue happens synchronously while taking one candidate; later arrivals
    # append behind it and therefore cannot starve an admitted source.
    assert take.index("_candidateSchedule.Enqueue(batch)") < take.index(
        "return candidate"
    )


def test_embedded_csharp_queue_bounds_fairness_and_shutdown(tmp_path):
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if powershell is None:
        pytest.skip("PowerShell is required to compile the embedded C# harness")

    source = SCRIPT.read_text(encoding="utf-8-sig")
    harness = r'''

namespace DebugApiWx
{
    using System.Reflection;

    public static class QueueLifecycleHarness
    {
        private const BindingFlags PrivateInstance = BindingFlags.Instance | BindingFlags.NonPublic;
        private const BindingFlags PrivateStatic = BindingFlags.Static | BindingFlags.NonPublic;

        private static MethodInfo Method(string name)
        {
            MethodInfo method = typeof(KeyExtractor).GetMethod(name, PrivateInstance);
            if (method == null) throw new Exception("missing method: " + name);
            return method;
        }

        private static object Field(KeyExtractor extractor, string name)
        {
            FieldInfo field = typeof(KeyExtractor).GetField(name, PrivateInstance);
            if (field == null) throw new Exception("missing field: " + name);
            return field.GetValue(extractor);
        }

        private static int Count(KeyExtractor extractor, string name)
        {
            object value = Field(extractor, name);
            return (int)value.GetType().GetProperty("Count").GetValue(value, null);
        }

        private static int Constant(string name)
        {
            FieldInfo field = typeof(KeyExtractor).GetField(name, PrivateStatic);
            if (field == null) throw new Exception("missing constant: " + name);
            return (int)field.GetRawConstantValue();
        }

        private static byte[] Candidate(int id)
        {
            byte[] value = new byte[32];
            for (int i = 0; i < value.Length; i++) value[i] = (byte)(1 + ((id * 37 + i * 11) % 251));
            Array.Copy(BitConverter.GetBytes(id), value, 4);
            return value;
        }

        private static void Queue(KeyExtractor extractor, uint pid, ulong address, params byte[][] values)
        {
            Method("QueueCandidateBatch").Invoke(
                extractor,
                new object[] { pid, address, new List<byte[]>(values) }
            );
        }

        private static byte[] Take(KeyExtractor extractor)
        {
            return (byte[])Method("TakeNextCandidate").Invoke(extractor, null);
        }

        private static int CandidateId(byte[] candidate)
        {
            return BitConverter.ToInt32(candidate, 0);
        }

        private static byte[] BuildPasswordModePage(byte[] master)
        {
            byte[] page = new byte[4096];
            for (int i = 0; i < page.Length - 64; i++) page[i] = (byte)((i * 29 + 7) % 251);
            byte[] salt = new byte[16]; Array.Copy(page, salt, 16);
            byte[] pageKey;
            using (var derive = new Rfc2898DeriveBytes(master, salt, 256000, HashAlgorithmName.SHA512))
                pageKey = derive.GetBytes(32);
            byte[] macSalt = new byte[16];
            for (int i = 0; i < 16; i++) macSalt[i] = (byte)(page[i] ^ 0x3A);
            byte[] macKey;
            using (var derive = new Rfc2898DeriveBytes(pageKey, macSalt, 2, HashAlgorithmName.SHA512))
                macKey = derive.GetBytes(32);
            using (var hmac = new HMACSHA512(macKey))
            {
                hmac.TransformBlock(page, 16, 4096 - 64 - 16, null, 0);
                hmac.TransformFinalBlock(BitConverter.GetBytes((uint)1), 0, 4);
                Array.Copy(hmac.Hash, 0, page, 4096 - 64, 64);
            }
            return page;
        }

        private static KeyExtractor NewExtractor(byte[] page)
        {
            return new KeyExtractor("unused", new ulong[] { 1 }, page, null, null, 120);
        }

        public static string Run()
        {
            byte[] blankPage = new byte[4096];

            // Reflection drives the real scheduler: admitted sources alternate.
            KeyExtractor fair = NewExtractor(blankPage);
            Queue(fair, 1, 0x1000, Candidate(11), Candidate(12));
            Queue(fair, 2, 0x2000, Candidate(21), Candidate(22));
            int[] order = { CandidateId(Take(fair)), CandidateId(Take(fair)), CandidateId(Take(fair)), CandidateId(Take(fair)) };
            int[] expected = { 11, 21, 12, 22 };
            for (int i = 0; i < order.Length; i++) if (order[i] != expected[i]) throw new Exception("round-robin failed");
            Method("ClearCandidateVerifier").Invoke(fair, null);

            // Per-source overflow retains exactly the declared bound.
            int maxPerSource = Constant("MaxCandidatesPerSource");
            KeyExtractor perSource = NewExtractor(blankPage);
            var many = new List<byte[]>();
            for (int i = 0; i < maxPerSource + 9; i++) many.Add(Candidate(1000 + i));
            Method("QueueCandidateBatch").Invoke(perSource, new object[] { (uint)1, (ulong)0x3000, many });
            if (Count(perSource, "_candidateDigests") != maxPerSource) throw new Exception("per-source bound failed");
            Method("ClearCandidateVerifier").Invoke(perSource, null);

            // Source overflow evicts the oldest source and admits the newest.
            int maxSources = Constant("MaxPendingCandidateSources");
            KeyExtractor sources = NewExtractor(blankPage);
            for (int i = 0; i < maxSources + 1; i++) Queue(sources, (uint)(i + 1), (ulong)0x4000, Candidate(2000 + i));
            if (Count(sources, "_candidateBatches") != maxSources) throw new Exception("source bound failed");
            object batches = Field(sources, "_candidateBatches");
            string newest = ((uint)(maxSources + 1)).ToString("X8") + ":" + ((ulong)0x4000).ToString("X16");
            bool admitted = (bool)batches.GetType().GetMethod("ContainsKey").Invoke(batches, new object[] { newest });
            if (!admitted) throw new Exception("new source was starved");
            Method("ClearCandidateVerifier").Invoke(sources, null);

            // Exercise the incremental PBKDF2/HMAC path, then clean it.  The
            // verified result survives cleanup while all copied byte queues vanish.
            byte[] master = Candidate(4242);
            KeyExtractor lifecycle = NewExtractor(BuildPasswordModePage(master));
            Queue(lifecycle, 9, 0x9000, (byte[])master.Clone());
            MethodInfo process = Method("ProcessCandidateVerificationSlice");
            MethodInfo getKey = Method("GetVerifiedKey");
            string key = null;
            for (int i = 0; i < 300 && key == null; i++)
            {
                process.Invoke(lifecycle, null);
                key = (string)getKey.Invoke(lifecycle, null);
            }
            string expectedKey = BitConverter.ToString(master).Replace("-", "").ToLowerInvariant();
            if (key != expectedKey) throw new Exception("incremental HMAC verification failed");
            Method("ClearCandidateVerifier").Invoke(lifecycle, null);
            if ((string)getKey.Invoke(lifecycle, null) != expectedKey) throw new Exception("verified result was discarded");
            if (Field(lifecycle, "_activeVerification") != null) throw new Exception("active verifier survived cleanup");
            if (Count(lifecycle, "_candidateDigests") != 0 || Count(lifecycle, "_candidateSchedule") != 0)
                throw new Exception("candidate backlog survived cleanup");

            return "HARNESS_OK";
        }
    }
}
'''

    csharp_path = tmp_path / "windows_wechat_harness.cs"
    csharp_path.write_text(_embedded_csharp(source) + harness, encoding="utf-8")
    runner = tmp_path / "run_harness.ps1"
    runner.write_text(
        "param([string]$SourcePath)\n"
        "Add-Type -Path $SourcePath -ErrorAction Stop\n"
        "[DebugApiWx.QueueLifecycleHarness]::Run()\n",
        encoding="utf-8-sig",
    )
    completed = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(runner),
            str(csharp_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=120,
        check=False,
    )
    output = completed.stdout.decode(errors="replace")
    assert completed.returncode == 0, output
    assert "HARNESS_OK" in output
