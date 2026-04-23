"""
AuditPal Miner Agent — Gemini-powered Smart Contract Auditor
============================================================
Reads challenge codebases from /challenge/<codebase_id>/*.sol
Outputs a single JSON AuditReport to stdout (via runner.py).

Environment variables injected by the validator sandbox:
  CHALLENGE_ID   CHALLENGE_NAME   PROJECT_ID   PLATFORM   GEMINI_API_KEY
"""

from __future__ import annotations

import json
import os
import signal
import sys
import time
import traceback
from pathlib import Path
from typing import Any

import google.generativeai as genai
from google.generativeai.types import FunctionDeclaration, Tool

# ── Constants ─────────────────────────────────────────────────────────────────

CHALLENGE_ID   = os.environ.get("CHALLENGE_ID",   "unknown")
PROJECT_ID     = os.environ.get("PROJECT_ID",     "unknown")
CHALLENGE_NAME = os.environ.get("CHALLENGE_NAME", "unknown")
PLATFORM       = os.environ.get("PLATFORM",       "unknown")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

CHALLENGE_DIR  = Path("/challenge")
MAX_FILE_CHARS = 40_000
MODEL_NAME     = "gemini-2.0-flash"
MAX_TURNS      = 20
# Leave a buffer before the sandbox's 100 s hard kill
GEMINI_TIMEOUT_S = int(os.getenv("GEMINI_TIMEOUT", "85"))

VALID_SEVERITIES = {"high", "medium", "low", "info"}

# ── Logging (stderr only — never pollute stdout JSON) ─────────────────────────

def _log(level: str, msg: str) -> None:
    print(f"[{level}] {msg}", file=sys.stderr, flush=True)

# ── Gemini setup ──────────────────────────────────────────────────────────────

def _configure_gemini() -> None:
    if not GEMINI_API_KEY:
        _log("ERR", "GEMINI_API_KEY is not set — Gemini calls will fail")
    else:
        _log("INFO", f"GEMINI_API_KEY set ✓ (length={len(GEMINI_API_KEY)})")
    genai.configure(api_key=GEMINI_API_KEY)

# ── Tool declarations ─────────────────────────────────────────────────────────

REPORT_FINDING_DECL = FunctionDeclaration(
    name="report_finding",
    description=(
        "Report a confirmed vulnerability or security issue found in the audited Solidity codebase. "
        "Call this once for EACH distinct finding. Be precise about file, line numbers, and root cause."
    ),
    parameters={
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": "Short, descriptive title of the vulnerability (≤ 80 chars).",
            },
            "vulnerability_type": {
                "type": "string",
                "description": (
                    "Canonical vulnerability category, e.g. "
                    "Reentrancy, Integer Overflow, Access Control, "
                    "Front-Running, Unchecked Return Value, Price Manipulation, "
                    "Flash Loan Attack, Denial of Service, Logic Error, etc."
                ),
            },
            "severity": {
                "type": "string",
                "enum": ["high", "medium", "low", "info"],
                "description": "Severity level of the finding.",
            },
            "file": {
                "type": "string",
                "description": "Filename (basename only) where the vulnerability is located.",
            },
            "line_start": {
                "type": "integer",
                "description": "First line number of the vulnerable code block.",
            },
            "line_end": {
                "type": "integer",
                "description": "Last line number of the vulnerable code block.",
            },
            "description": {
                "type": "string",
                "description": (
                    "Detailed explanation: what the vulnerability is, why it is dangerous, "
                    "and a concrete attack scenario (2–5 sentences)."
                ),
            },
            "recommendation": {
                "type": "string",
                "description": "Concrete, actionable fix or mitigation (1–3 sentences).",
            },
        },
        "required": [
            "title", "vulnerability_type", "severity",
            "file", "line_start", "line_end",
            "description", "recommendation",
        ],
    },
)

AUDIT_COMPLETE_DECL = FunctionDeclaration(
    name="audit_complete",
    description=(
        "Signal that the audit is finished. Call this ONCE after all report_finding calls "
        "are done (or immediately if no vulnerabilities were found)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "description": "1–3 sentence overall audit summary.",
            },
            "files_reviewed": {
                "type": "integer",
                "description": "Number of Solidity files reviewed.",
            },
        },
        "required": ["summary", "files_reviewed"],
    },
)

AUDIT_TOOL = Tool(function_declarations=[REPORT_FINDING_DECL, AUDIT_COMPLETE_DECL])

# ── File helpers ──────────────────────────────────────────────────────────────

def _load_codebase_from_disk() -> dict[str, str]:
    """Walk /challenge/<codebase_id>/*.sol and return {filename: content}."""
    sources: dict[str, str] = {}

    if not CHALLENGE_DIR.exists():
        _log("WARN", f"{CHALLENGE_DIR} does not exist")
        return sources

    _log("INFO", f"Scanning {CHALLENGE_DIR} for .sol files:")
    for sol_file in sorted(CHALLENGE_DIR.rglob("*.sol")):
        try:
            text = sol_file.read_text(encoding="utf-8", errors="replace")
            if len(text) > MAX_FILE_CHARS:
                _log("WARN", f"{sol_file.name}: {len(text):,} chars — truncated to {MAX_FILE_CHARS:,}")
                text = text[:MAX_FILE_CHARS] + "\n// [TRUNCATED]\n"
            sources[sol_file.name] = text
            _log("INFO", f"  Loaded {sol_file.name}  ({len(text):,} chars)")
        except Exception as exc:
            _log("ERR", f"  Could not read {sol_file}: {exc}")

    _log("INFO", f"Total from disk: {len(sources)} file(s)")
    return sources


def _load_codebase(task: dict | None) -> dict[str, str]:
    """
    Primary source: disk (/challenge/**/*.sol).
    Fallback: contracts dict passed in task by runner.py.
    This handles both direct invocation and runner-mediated invocation.
    """
    sources = _load_codebase_from_disk()

    if not sources and task and task.get("contracts"):
        _log("WARN", "Disk empty — falling back to contracts from task dict")
        sources = task["contracts"]
        for name, content in sources.items():
            _log("INFO", f"  (task) {name}  ({len(content):,} chars)")

    if not sources:
        _log("ERR", "No .sol source files found from disk or task — audit will be empty")

    return sources


def _build_prompt(sources: dict[str, str]) -> str:
    files_block = "\n\n".join(
        f"=== FILE: {name} ===\n```solidity\n{content}\n```"
        for name, content in sources.items()
    )
    return f"""You are an expert smart-contract security auditor specialising in Solidity / EVM.

## Challenge
- Challenge ID : {CHALLENGE_ID}
- Project ID   : {PROJECT_ID}
- Name         : {CHALLENGE_NAME}
- Platform     : {PLATFORM}

## Task
Perform a thorough security audit of the following Solidity source file(s).
For every confirmed vulnerability call `report_finding` with full details.
When you have reported all findings (or found none), call `audit_complete`.

### Vulnerability checklist (non-exhaustive)
- Reentrancy (cross-function, cross-contract, read-only)
- Integer overflow / underflow (pre-0.8 or unchecked blocks)
- Access-control flaws (missing onlyOwner, wrong msg.sender checks)
- Unprotected initializer / upgradeable proxy pitfalls
- Flash-loan / price-oracle manipulation
- Front-running / MEV exposure
- Unchecked external call return values
- Denial-of-service (block gas limit, push vs pull)
- Logic errors / incorrect accounting
- Unsafe delegatecall / low-level calls
- Storage collision in proxies
- Signature replay / missing nonce
- Timestamp / block-number dependence
- Centralization / admin key risks
- Missing event emissions for critical state changes
- Gas-limit issues in loops

## Source files

{files_block}

Begin the audit now. Call `report_finding` for each issue, then call `audit_complete`.
"""

# ── Gemini agentic loop ───────────────────────────────────────────────────────

def _run_audit(sources: dict[str, str]) -> list[dict[str, Any]]:
    """
    Drive Gemini in a function-calling loop until audit_complete is called
    or we run out of turns. Returns raw list of finding dicts.
    """
    # ── Fix: hard timeout via SIGALRM so we always produce output ────────────
    def _handle_timeout(signum, frame):
        raise TimeoutError(f"Gemini audit exceeded {GEMINI_TIMEOUT_S}s hard limit")

    signal.signal(signal.SIGALRM, _handle_timeout)
    signal.alarm(GEMINI_TIMEOUT_S)

    findings: list[dict[str, Any]] = []

    try:
        model = genai.GenerativeModel(
            model_name=MODEL_NAME,
            tools=[AUDIT_TOOL],
            system_instruction=(
                "You are a senior smart-contract security researcher. "
                "Use the provided tools to report every vulnerability you find. "
                "Be thorough but precise — do NOT fabricate issues that aren't present."
            ),
        )

        chat   = model.start_chat(history=[])
        prompt = _build_prompt(sources)

        _log("INFO", f"Starting Gemini loop | model={MODEL_NAME} | max_turns={MAX_TURNS} | prompt={len(prompt):,} chars")

        t0       = time.time()
        response = chat.send_message(prompt)
        _log("INFO", f"Initial response in {time.time()-t0:.1f}s")

        turn = 0
        while turn < MAX_TURNS:
            turn += 1
            _log("INFO", f"── Turn {turn}/{MAX_TURNS} ──────────────────────────────")

            any_function_call = False

            for candidate in response.candidates:
                finish_reason = str(candidate.finish_reason)
                _log("INFO", f"  finish_reason={finish_reason}  parts={len(candidate.content.parts)}")

                for pi, part in enumerate(candidate.content.parts):

                    if hasattr(part, "text") and part.text:
                        preview = part.text.replace("\n", " ")[:200]
                        _log("INFO", f"  [part {pi}] text ({len(part.text)} chars): {preview}")

                    if not (hasattr(part, "function_call") and part.function_call):
                        continue

                    fc    = part.function_call
                    fname = fc.name
                    args  = dict(fc.args)
                    any_function_call = True

                    _log("INFO", f"  [part {pi}] function_call → {fname}")

                    # ── report_finding ────────────────────────────────────────
                    if fname == "report_finding":
                        sev   = args.get("severity", "?").upper()
                        title = args.get("title", "?")
                        file_ = args.get("file", "?")
                        lines = f"{args.get('line_start','?')}-{args.get('line_end','?')}"
                        _log("INFO", f"    FINDING [{sev}] {title}  ({file_}:{lines})")
                        findings.append(args)

                        t_ack  = time.time()
                        # ── Fix: update `response` so next loop iteration uses
                        #        the NEW response, not re-processes old parts ──
                        response = chat.send_message(
                            genai.protos.Content(
                                role="user",
                                parts=[genai.protos.Part(
                                    function_response=genai.protos.FunctionResponse(
                                        name=fname,
                                        response={"result": "finding_recorded"},
                                    )
                                )],
                            )
                        )
                        _log("INFO", f"    ack sent in {time.time()-t_ack:.1f}s")
                        # Break inner loops so the while re-evaluates with the
                        # fresh response rather than continuing stale iteration
                        break

                    # ── audit_complete ────────────────────────────────────────
                    elif fname == "audit_complete":
                        summary = args.get("summary", "")
                        _log("INFO", f"    AUDIT COMPLETE — findings={len(findings)}")
                        _log("INFO", f"    summary: {summary[:200]}")
                        try:
                            chat.send_message(
                                genai.protos.Content(
                                    role="user",
                                    parts=[genai.protos.Part(
                                        function_response=genai.protos.FunctionResponse(
                                            name=fname,
                                            response={"result": "acknowledged"},
                                        )
                                    )],
                                )
                            )
                        except Exception:
                            pass  # final ack failure is non-critical
                        signal.alarm(0)  # cancel timeout
                        return findings

                    else:
                        _log("WARN", f"  [part {pi}] unknown function: {fname} — ignoring")

                else:
                    # inner for-part loop finished without a break (no function call hit)
                    continue
                break  # propagate break from part loop to candidate loop

            if not any_function_call:
                _log("WARN", f"Turn {turn}: no function calls — model returned text only, treating as done")
                break

        _log("WARN", f"Loop ended after {turn} turn(s) — collected {len(findings)} finding(s)")

    except TimeoutError as exc:
        _log("ERR", f"TIMEOUT: {exc} — returning {len(findings)} partial finding(s)")

    except Exception as exc:
        _log("ERR", f"Gemini call failed: {type(exc).__name__}: {exc}")
        _log("ERR", traceback.format_exc())

    finally:
        signal.alarm(0)  # always cancel the alarm

    return findings

# ── Report builder ────────────────────────────────────────────────────────────

def _make_report(findings_raw: list[dict[str, Any]]) -> dict[str, Any]:
    formatted = []
    for i, f in enumerate(findings_raw):
        sev = f.get("severity", "info").lower()
        if sev not in VALID_SEVERITIES:
            sev = "info"
        formatted.append({
            "id":                 f"finding-{i+1:03d}",
            "title":              f.get("title", "Untitled"),
            "vulnerability_type": f.get("vulnerability_type", "Unknown"),
            "severity":           sev,
            "file":               f.get("file", "unknown.sol"),
            "line_start":         int(f.get("line_start", 0)),
            "line_end":           int(f.get("line_end", 0)),
            "description":        f.get("description", ""),
            "recommendation":     f.get("recommendation", ""),
        })
    return {
        "challenge_id": CHALLENGE_ID,
        "project_id":   PROJECT_ID,
        "findings":     formatted,
    }

# ── Public entry point (called by runner.py) ──────────────────────────────────

def agent_main(task: dict | None = None) -> dict:
    _log("INFO", "════════════════════════════════════════════════════")
    _log("INFO", "AuditPal Gemini Agent starting (agent_main)")
    _log("INFO", f"Challenge : {CHALLENGE_NAME} ({CHALLENGE_ID})")
    _log("INFO", f"Project   : {PROJECT_ID}  Platform: {PLATFORM}")
    _log("INFO", f"task keys : {list(task.keys()) if task else 'none'}")
    _log("INFO", f"contracts in task: {len(task.get('contracts', {})) if task else 0}")
    _log("INFO", "════════════════════════════════════════════════════")

    _configure_gemini()

    sources = _load_codebase(task)

    if not sources:
        _log("WARN", "No source files — returning empty report")
        return _make_report([])

    _log("INFO", f"Auditing {len(sources)} file(s): {list(sources.keys())}")

    t0           = time.time()
    findings_raw = _run_audit(sources)
    elapsed      = time.time() - t0

    _log("INFO", f"Audit finished in {elapsed:.1f}s — {len(findings_raw)} raw finding(s)")

    report = _make_report(findings_raw)

    _log("INFO", f"Report: challenge_id={report['challenge_id']} findings={len(report['findings'])}")
    _log("INFO", "AuditPal Gemini Agent done ✓")

    return report


# ── Standalone entrypoint (python agent.py) ───────────────────────────────────

def main() -> None:
    _log("INFO", "Running in standalone mode (no runner.py)")
    report = agent_main(task=None)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()