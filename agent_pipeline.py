"""
agent_pipeline.py
AI-based Multi-Agent SAST pipeline for raspberrypi/userland

Roles:
  1. Repository Explorer + Chunker -> batch_manifest.json (already built by chunker.py)
  2. Rule Engine (Cppcheck)        -> static pre-filter, cheap, runs before any LLM call
  3. Analyzer Agent (Gemini)       -> proposes candidate findings, scoped CWE list
  4. Verifier / Critic Agent (Gemini) -> confirms/rejects each candidate against the code
  5. Report                        -> writes per-batch JSON + a run summary with token usage

Setup:
    pip install google-genai
    (PowerShell) $env:GEMINI_API_KEY = "your-key-here"

Usage (run from the folder that contains both userland/ and batch_manifest.json):
    python agent_pipeline.py                # process every batch in the manifest
    python agent_pipeline.py B083 B097 B011  # process only these batch IDs

Before first run, list the models your key can actually use and pick a
free-tier-eligible flash/flash-lite model (model names change over time,
so this script deliberately does NOT hardcode one silently):

    python -c "from google import genai; c = genai.Client(); [print(m.name) for m in c.models.list()]"

Then set MODEL_NAME below to whatever the free-tier flash-lite model is
called on your key (check https://aistudio.google.com/app/apikey for which
models are marked free).
"""

import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from google import genai
from google.genai import types

# ---------------------------------------------------------------------------
# Config — adjust these three if your setup differs
# ---------------------------------------------------------------------------
REPO_ROOT = Path("userland")                 # relative to where you run this script
MANIFEST_PATH = Path("batch_manifest.json")  # output of chunker.py
OUTPUT_DIR = Path("agent_results")

MODEL_NAME = "gemini-flash-lite-latest"      # gemini-2.5-flash returned 404 (blocked for new accounts) -
                                              # pinned older-gen models risk the same. This alias is
                                              # confirmed present on this key, and lite tiers generally
                                              # carry a more generous free daily quota than full flash.

# Full path used because the temporary `function cppcheck {...}` PowerShell
# trick only exists in that one interactive session — a fresh Python
# subprocess will NOT see it. If you did the permanent PATH fix, "cppcheck"
# alone will also work.
CPPCHECK_EXE = r"C:\Program Files\Cppcheck\cppcheck.exe"

# ---------------------------------------------------------------------------
# Agent prompts (v1) — these are the *actual* prompts used, keep them
# unmodified here for the report's "prompt history" section; make edits as
# v2/v3 in report.md, not silently in this file.
# ---------------------------------------------------------------------------

ANALYZER_SYSTEM_PROMPT = """You are a static analysis agent specialized in memory-safety vulnerabilities
in embedded C code (Raspberry Pi GPU userland libraries).

Scope: analyze ONLY the following CWE classes, since this codebase is a
low-level C library, not a web application:
- CWE-787 / CWE-120: Out-of-bounds Write / Buffer Overflow
- CWE-125: Out-of-bounds Read
- CWE-416: Use After Free
- CWE-415: Double Free
- CWE-476: NULL Pointer Dereference
- CWE-190: Integer Overflow/Wraparound
- CWE-362: Race Condition (concurrency)
- CWE-78: OS Command Injection (system/popen/exec)
- CWE-401: Memory Leak

Do NOT report web-related classes (XSS, SQLi, CSRF) - they do not apply here.

You will receive:
1. Cppcheck static-analysis hints for the batch (may be empty - Cppcheck
   frequently misses issues in this codebase because it cannot resolve all
   macros/headers; an empty hint list does NOT mean the code is clean)
2. One or more C source files, each preceded by a "// ===== FILE: path =====" marker

Rules:
- Only report findings with a concrete code-level basis. Do not invent
  functions, variables, or line numbers that are not present in the input.
- If Cppcheck already flagged something, cross-check it - confirm, refine,
  or explicitly reject it with a reason.
- Trace the actual call chain for anything you flag (who calls this
  function, where does the tainted value ultimately get validated or not).
- If a finding's certainty depends on runtime behavior you cannot verify
  statically (e.g., actual thread interleaving, actual input length at
  runtime), mark "runtime_dependent": true instead of guessing.
- Output ONLY a JSON array, no prose, no markdown fences.

Output schema per finding:
{
  "cwe": "CWE-xxx",
  "file": "relative/path.c",
  "function": "function_name",
  "line": 0,
  "source": "description of untrusted/tainted origin",
  "sink": "description of dangerous operation",
  "evidence": "short paraphrase of the relevant code logic (max 2 sentences, no verbatim code >5 lines)",
  "cppcheck_correlation": "confirmed | refined | rejected | not_flagged",
  "confidence": 0.0,
  "runtime_dependent": false
}
If there are no findings in scope, output an empty JSON array: []
"""

VERIFIER_SYSTEM_PROMPT = """You are a skeptical verification agent. You receive candidate findings from
an Analyzer agent and the original source code. Your job is to catch
hallucinations, not to find new vulnerabilities.

For each candidate finding, check:
1. Does the referenced file/function/line actually exist in the provided code?
2. Is the described source->sink data flow actually present, or assumed?
3. Is there existing bounds-checking/validation/clamping logic elsewhere in
   the provided code that the Analyzer missed? Trace it before deciding.
4. If the finding depends on runtime conditions not visible in static code,
   it cannot be CONFIRMED regardless of how plausible it sounds.

Assign exactly one status:
- CONFIRMED: code-level evidence is verifiable and sufficient
- LIKELY: evidence is plausible but incomplete (e.g., missing caller context)
- UNCERTAIN: cannot be verified with the code provided
- REJECTED: finding is factually wrong (function/line doesn't exist, or
  contradicted by code) - state the specific reason
- RUNTIME_VALIDATION_REQUIRED: static analysis alone cannot confirm this
  class of issue (e.g., actual race condition triggering)

Output ONLY a JSON array. Each element must contain all original finding
fields plus:
  "verifier_status": "...",
  "verifier_reason": "..."
If the candidate list is empty, output an empty JSON array: []
"""

# ---------------------------------------------------------------------------
# Plumbing
# ---------------------------------------------------------------------------

client = genai.Client()  # picks up GEMINI_API_KEY from the environment


def run_cppcheck(files):
    """Run cppcheck on a list of file paths (relative to REPO_ROOT).
    Cppcheck writes its XML report to stderr, not stdout.
    Returns (xml_text, status) where status distinguishes a real scan
    from a failed one -- see report.md 14.6 for why this distinction
    matters (a failure that looks like "0 hits" is a safety problem)."""
    cmd = [CPPCHECK_EXE, "--enable=warning,portability,performance",
           "--xml", "--xml-version=2"] + files
    try:
        result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True,
                                 text=True, encoding="utf-8", errors="ignore",
                                 timeout=120)
        # cppcheck returns 0 on a clean run even with findings; nonzero
        # generally means a real execution problem (bad args, crash, etc.),
        # not "the code has issues". Surface that distinction instead of
        # silently treating stderr as valid hint XML either way.
        if result.returncode != 0:
            return (result.stderr, "CPPCHECK_NONZERO_EXIT")
        return (result.stderr, "OK")
    except FileNotFoundError:
        return ("<!-- cppcheck not found at CPPCHECK_EXE, skipping rule-engine pre-filter -->",
                "CPPCHECK_NOT_FOUND")
    except subprocess.TimeoutExpired:
        return ("<!-- cppcheck timed out, skipping rule-engine pre-filter -->",
                "CPPCHECK_TIMEOUT")


def read_batch_code(batch):
    """Concatenate the batch's files with clear file-boundary markers."""
    parts = []
    for rel_path in batch["files"]:
        full_path = REPO_ROOT / rel_path
        try:
            text = full_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            text = f"/* ERROR READING FILE: {e} */"
        parts.append(f"// ===== FILE: {rel_path} =====\n{text}")
    return "\n\n".join(parts)


def load_file_lines(batch):
    """Per-file line lists, used by grounding_check (separate from the
    single concatenated string read_batch_code builds for the LLM prompt)."""
    result = {}
    for rel_path in batch["files"]:
        full_path = REPO_ROOT / rel_path
        try:
            result[rel_path.replace("\\", "/")] = full_path.read_text(
                encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            result[rel_path.replace("\\", "/")] = []
    return result


def grounding_check(finding, file_lines, window=20):
    """v2 addition: cross-reference a finding's claimed file/line/function
    against the actual file content in Python, independent of any LLM
    judgement. Added after testing showed the LLM Verifier confirmed two
    findings that did not correspond to real code (wrong function name at
    the claimed line; a finding placed on a comment line with an invented
    sink function that was not present). This does not replace the
    Verifier agent - it catches the specific failure mode the Verifier
    missed: line/function attribution that does not match the file."""
    file_key = str(finding.get("file", "")).replace("\\", "/")
    lines = None
    for key, val in file_lines.items():
        if file_key.endswith(key) or key.endswith(file_key):
            lines = val
            break
    if lines is None:
        return False, f"file '{file_key}' not in this batch"

    line_no = finding.get("line")
    if not isinstance(line_no, int) or not (1 <= line_no <= len(lines)):
        return False, f"line {line_no} out of range (file has {len(lines)} lines)"

    lo = max(0, line_no - window - 1)
    hi = min(len(lines), line_no + window)
    window_text = "\n".join(lines[lo:hi])

    func = str(finding.get("function", "")).strip()
    if func and func not in window_text:
        return False, f"function name '{func}' not found within +/-{window} lines of claimed line"

    return True, "ok"


def call_gemini(system_prompt, user_content):
    base_kwargs = dict(
        system_instruction=system_prompt,
        temperature=0.1,
        max_output_tokens=8192,
        response_mime_type="application/json",
    )
    # Which parameter controls "thinking" depends on the model generation
    # MODEL_NAME currently resolves to, and that changes over time since
    # "-latest" aliases move forward:
    #   - Gemini <=2.5 style: thinking_config=ThinkingConfig(thinking_budget=0)
    #   - Gemini 3.x style:   thinking_config=ThinkingConfig(thinking_level="minimal")
    # NOTE (corrected after review, see report.md §6.2/§11.4): Gemini 3
    # Flash/Flash-Lite do NOT support fully disabling thinking. "minimal" is
    # documented as "as close to zero as possible", not a guaranteed zero.
    # Try both; if neither is accepted, fall back to leaving thinking on
    # (the large max_output_tokens above still leaves room for the answer).
    thinking_attempts = [
        types.ThinkingConfig(thinking_budget=0),
        types.ThinkingConfig(thinking_level="minimal"),
        None,
    ]

    response = None
    last_error = None
    for thinking_cfg in thinking_attempts:
        kwargs = dict(base_kwargs)
        if thinking_cfg is not None:
            kwargs["thinking_config"] = thinking_cfg
        try:
            response = client.models.generate_content(
                model=MODEL_NAME,
                contents=user_content,
                config=types.GenerateContentConfig(**kwargs),
            )
            break
        except Exception as e:
            last_error = e
            continue
    if response is None:
        raise last_error
    usage = getattr(response, "usage_metadata", None)
    prompt_tok = getattr(usage, "prompt_token_count", None) if usage else None
    candidates_tok = getattr(usage, "candidates_token_count", None) if usage else None
    total_tok = getattr(usage, "total_token_count", None) if usage else None
    # FIX (post-review, see report.md §14.5): read the API's own
    # thoughts_token_count field directly instead of only inferring an
    # "invisible token" count as total - input - output. The inferred value
    # is kept as invisible_tokens_inferred for backward comparison with the
    # earlier run's numbers, but thoughts_token_count is the precise figure
    # when the API actually returns it.
    thoughts_tok = getattr(usage, "thoughts_token_count", None) if usage else None
    inferred_invisible = None
    if all(v is not None for v in (prompt_tok, candidates_tok, total_tok)):
        inferred_invisible = total_tok - prompt_tok - candidates_tok
    token_info = {
        "input_tokens": prompt_tok,
        "output_tokens": candidates_tok,
        "total_tokens": total_tok,
        "thoughts_token_count": thoughts_tok,
        "invisible_tokens_inferred": inferred_invisible,
    }
    return response.text or "", token_info


def extract_json(text):
    """Strip markdown code fences if the model added them, then parse JSON."""
    cleaned = re.sub(r"^```(json)?|```$", "", text.strip(), flags=re.MULTILINE).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return {"parse_error": True, "raw_text": text}


def process_batch(batch):
    print(f"\n=== {batch['batch_id']}  ({batch['dir']}, tier {batch['tier']}) ===")

    cppcheck_xml, cppcheck_status = run_cppcheck(batch["files"])
    if cppcheck_status != "OK":
        print(f"  [WARN] Cppcheck did not complete normally: {cppcheck_status}")
    code = read_batch_code(batch)

    analyzer_input = (
        f"[Cppcheck hints]\n{cppcheck_xml}\n\n"
        f"[Code batch: {batch['batch_id']} - {batch['dir']}]\n{code}"
    )
    analyzer_text, analyzer_tokens = call_gemini(ANALYZER_SYSTEM_PROMPT, analyzer_input)
    findings_raw = extract_json(analyzer_text)
    # FIX (post-review, see report.md §14.6): a JSON-parse failure and a
    # genuine "no findings" result used to both collapse to raw_findings=[],
    # which is indistinguishable downstream. Track the real reason via an
    # explicit status field instead of silently coercing to [].
    # Named CANDIDATES_FOUND (not FINDINGS_FOUND) on purpose: at this stage
    # these are unverified candidates. A batch can be CANDIDATES_FOUND while
    # every candidate is later REJECTED -- "finding" would read as a
    # confirmed issue in a delivered report. See report.md 14.6.
    status = "CANDIDATES_FOUND"
    if isinstance(findings_raw, list):
        findings = findings_raw
        if not findings:
            status = "CLEAN"
    else:
        print(f"  [WARN] Analyzer output did not parse as JSON list: {findings_raw}")
        findings = []
        status = "ANALYZER_PARSE_FAILED"

    verified = []
    verifier_tokens = {
        "input_tokens": 0, "output_tokens": 0, "total_tokens": 0,
        "thoughts_token_count": 0, "invisible_tokens_inferred": 0,
    }
    if findings:
        verifier_input = (
            f"[Candidate findings]\n{json.dumps(findings, ensure_ascii=False)}\n\n"
            f"[Original code]\n{code}"
        )
        verifier_text, v_tokens = call_gemini(VERIFIER_SYSTEM_PROMPT, verifier_input)
        parsed = extract_json(verifier_text)
        if isinstance(parsed, list):
            verified = parsed
        else:
            print(f"  [WARN] Verifier output did not parse as JSON list: {parsed}")
            verified = findings  # fall back to unverified candidates, but flag it
            status = "VERIFIER_PARSE_FAILED"
        for k in verifier_tokens:
            verifier_tokens[k] = v_tokens.get(k) or 0

        # v2: programmatic grounding check overrides the LLM verifier when
        # the claimed file/line/function does not match real file content.
        # NOTE (post-review, see report.md §10.7): this only checks
        # *existence* (file/line/function), not whether the claimed guard
        # logic actually matches the code's real control flow. A finding
        # whose function/line are real but whose conclusion is wrong (a
        # "semantic hallucination", see report.md §10.3 / B011 CWE-416)
        # will pass this check. Treat GROUNDING_CHECK-passed findings as
        # "not yet disproven", not as independently confirmed.
        file_lines = load_file_lines(batch)
        for f in verified:
            if not isinstance(f, dict):
                continue
            ok, reason = grounding_check(f, file_lines)
            if not ok:
                f["llm_verifier_status"] = f.get("verifier_status")  # keep original for comparison
                f["verifier_status"] = "REJECTED_BY_GROUNDING_CHECK"
                f["verifier_reason"] = f"[automated] {reason}"

    return {
        "batch_id": batch["batch_id"],
        "dir": batch["dir"],
        "tier": batch["tier"],
        "files": batch["files"],
        "status": status,
        "cppcheck_status": cppcheck_status,
        "raw_findings": findings,
        "verified_findings": verified,
        "token_usage": {"analyzer": analyzer_tokens, "verifier": verifier_tokens},
        "timestamp": datetime.now().isoformat(),
    }


def main():
    if not os.environ.get("GEMINI_API_KEY") and not os.environ.get("GOOGLE_API_KEY"):
        print("[ERROR] GEMINI_API_KEY (or GOOGLE_API_KEY) 환경변수가 설정되어 있지 않습니다.")
        print('  PowerShell: $env:GEMINI_API_KEY = "your-key-here"')
        sys.exit(1)

    OUTPUT_DIR.mkdir(exist_ok=True)
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    target_ids = sys.argv[1:] if len(sys.argv) > 1 else None
    batches = [b for b in manifest if target_ids is None or b["batch_id"] in target_ids]

    if not batches:
        print("처리할 배치가 없습니다. 배치 ID를 확인하세요.")
        return

    all_results = []
    total_tokens = 0
    for batch in batches:
        try:
            result = process_batch(batch)
            all_results.append(result)
            total_tokens += result["token_usage"]["analyzer"].get("total_tokens") or 0
            total_tokens += result["token_usage"]["verifier"].get("total_tokens") or 0
            out_path = OUTPUT_DIR / f"{batch['batch_id']}.json"
            # FIX (post-review, see report.md §14.7): the previous behavior
            # silently overwrote any prior run's output for this batch_id,
            # which is exactly how Run A's original findings disappeared
            # from agent_results/ before the run_A/run_B/manual_ground_truth
            # restructuring. Back up an existing file before replacing it
            # instead of relying on the operator to remember to move it.
            if out_path.exists():
                backup_path = out_path.with_name(
                    f"{batch['batch_id']}.prev-{datetime.now().strftime('%Y%m%dT%H%M%S')}.json"
                )
                out_path.replace(backup_path)
                print(f"  [INFO] Existing {out_path.name} backed up to {backup_path.name}")
            out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
            n_confirmed = sum(1 for f in result["verified_findings"]
                               if isinstance(f, dict) and f.get("verifier_status") == "CONFIRMED")
            print(f"  -> [{result['status']}] {len(result['verified_findings'])}건 검증 완료 "
                  f"(CONFIRMED {n_confirmed}건) | 저장: {out_path}")
        except Exception as e:
            print(f"  [ERROR] {batch['batch_id']} 처리 실패: {e}")

    # FIX (post-review, see report.md §14.6): surface parse-failure counts
    # in the run summary so a failed run can't be mistaken for a clean scan
    # just by glancing at _summary.json.
    status_counts = {}
    for r in all_results:
        s = r.get("status", "UNKNOWN")
        status_counts[s] = status_counts.get(s, 0) + 1

    summary_path = OUTPUT_DIR / "_summary.json"
    summary_path.write_text(json.dumps({
        "run_timestamp": datetime.now().isoformat(),
        "model": MODEL_NAME,
        "processed_batches": len(all_results),
        "status_counts": status_counts,
        "total_tokens_used": total_tokens,
        "batch_ids": [r["batch_id"] for r in all_results],
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\n완료: {len(all_results)}개 배치, 총 {total_tokens} 토큰 사용 (실측)")
    print(f"상태 집계: {status_counts}")
    print(f"요약 파일: {summary_path}")



if __name__ == "__main__":
    main()