from pathlib import Path


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


def test_non_verifying_breakpoint_resumes_before_background_verification():
    source = SCRIPT.read_text(encoding="utf-8-sig")
    debug_loop = _method_body(source, "private string DebugLoop()")
    capture = _method_body(source, "private void CaptureBreakpointCandidates(")
    verifier = _method_body(source, "private void VerifyCandidateQueue()")

    # Capturing registers and process memory is cheap.  The 256,000-round PBKDF2
    # oracle must not run while Windows is waiting for ContinueDebugEvent.
    assert "QueueCandidate" in capture
    assert "IsValidMasterKey" not in capture
    assert "IsValidMasterKey" in verifier
    assert "if (verified)" in verifier
    assert verifier.index("if (verified)") < verifier.index(
        "_verifiedKey = BytesToHex(candidate)"
    )

    # Every event returned by WaitForDebugEvent is continued exactly once, even
    # if candidate capture/re-arm fails.  That lets a later candidate breakpoint
    # run while the first hit's copied bytes are verified in the background.
    assert debug_loop.count("Native.ContinueDebugEvent") == 1
    assert "finally" in debug_loop
    assert debug_loop.index("finally") < debug_loop.index("Native.ContinueDebugEvent")
    assert "CaptureBreakpointCandidates" in debug_loop
    assert debug_loop.index("CaptureBreakpointCandidates") < debug_loop.index(
        "SetSingleStepForRearm"
    )
    assert "throw new Exception(\"ContinueDebugEvent 失败" in debug_loop


def test_candidate_verifier_runs_on_a_background_thread():
    source = SCRIPT.read_text(encoding="utf-8-sig")
    starter = _method_body(source, "private void StartCandidateVerifier()")
    debug_loop = _method_body(source, "private string DebugLoop()")
    verifier = _method_body(source, "private void VerifyCandidateQueue()")

    assert "new Thread(VerifyCandidateQueue)" in starter
    assert "IsBackground = true" in starter
    assert "StartCandidateVerifier();" in debug_loop
    assert "StopCandidateVerifier();" in debug_loop

    # A false hit can contain hundreds of expensive candidates.  Requeue its
    # remaining batch only after one verification, allowing a later breakpoint
    # batch (including the second located function) to be considered next.
    assert verifier.index("candidate = batch.candidates.Dequeue()") < verifier.index(
        "bool verified = IsValidMasterKey"
    )
    assert verifier.index("bool verified = IsValidMasterKey") < verifier.index(
        "_candidateBatches.Enqueue(batch)"
    )
