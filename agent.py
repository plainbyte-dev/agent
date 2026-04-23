# """
# Static test agent — no Gemini, no network, no dependencies.
# Just proves the container → runner → agent_main → JSON pipeline works.
# """
# import json
# import os
# import sys


# def _log(msg):
#     print(f"[agent] {msg}", file=sys.stderr, flush=True)


# def agent_main(task=None):
#     _log("agent_main() called ✓")
#     _log(f"CHALLENGE_ID  = {os.environ.get('CHALLENGE_ID', 'NOT SET')}")
#     _log(f"PROJECT_ID    = {os.environ.get('PROJECT_ID',   'NOT SET')}")
#     _log(f"task type     = {type(task)}")
#     _log(f"contracts     = {list(task['contracts'].keys()) if task and task.get('contracts') else 'none'}")

#     report = {
#         "challenge_id": os.environ.get("CHALLENGE_ID", "unknown"),
#         "project_id":   os.environ.get("PROJECT_ID",   "unknown"),
#         "findings": [
#             {
#                 "id":                 "finding-001",
#                 "title":              "TEST: Static finding from test agent",
#                 "vulnerability_type": "Test",
#                 "severity":           "info",
#                 "file":               "test.sol",
#                 "line_start":         1,
#                 "line_end":           1,
#                 "description":        "Static test finding to verify the full pipeline works end to end.",
#                 "recommendation":     "No action needed — this is a test.",
#             }
#         ],
#     }

#     _log(f"Returning report with {len(report['findings'])} finding(s) ✓")
#     return report


# def main():
#     report = agent_main()
#     print(json.dumps(report, indent=2))


# if __name__ == "__main__":
#     main()

"""
Minimal LLM test agent — single Gemini call, no function-calling loop.
Proves: network works, API key works, LLM responds, JSON reaches validator.

Dependencies (requirements.txt must include):
    google-generativeai>=0.8.0
"""
import json
import os
import sys
import time

import google.generativeai as genai


# ── Config ────────────────────────────────────────────────────────────────────

CHALLENGE_ID   = os.environ.get("CHALLENGE_ID",   "unknown")
PROJECT_ID     = os.environ.get("PROJECT_ID",     "unknown")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
MODEL_NAME     = "gemini-2.5-pro"

# ── Logging ───────────────────────────────────────────────────────────────────

def _log(msg):
    print(f"[agent] {msg}", file=sys.stderr, flush=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_one_contract(task: dict | None) -> tuple[str, str]:
    """Return (filename, content) for the first .sol file found."""

    # Try task dict first (passed by runner.py)
    if task and task.get("contracts"):
        name, content = next(iter(task["contracts"].items()))
        _log(f"Using contract from task: {name} ({len(content):,} chars)")
        return name, content

    # Fall back to disk
    from pathlib import Path
    for sol in sorted(Path("/challenge").rglob("*.sol")):
        content = sol.read_text(encoding="utf-8", errors="replace")
        _log(f"Using contract from disk: {sol.name} ({len(content):,} chars)")
        return sol.name, content[:8_000]   # keep prompt small for test

    return "none.sol", "// no contract found"


def _call_gemini(filename: str, content: str) -> list[dict]:
    """Single Gemini call — ask for reentrancy issues only, return as list."""

    if not GEMINI_API_KEY:
        raise ValueError("GEMINI_API_KEY is not set")

    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel(model_name=MODEL_NAME)

    prompt = f"""You are a smart contract security auditor.

Analyze the following Solidity file for REENTRANCY vulnerabilities ONLY.
Respond with a JSON array (and nothing else — no markdown, no explanation).
Each element must have exactly these fields:
  title, severity (high/medium/low/info), line_start, line_end, description, recommendation

If no reentrancy issues exist, return an empty array: []

File: {filename}
```solidity
{content[:6_000]}
```
"""

    _log(f"Sending prompt to Gemini ({len(prompt):,} chars)...")
    t0 = time.time()
    response = model.generate_content(prompt)
    _log(f"Gemini responded in {time.time() - t0:.1f}s")

    raw = response.text.strip()
    _log(f"Raw response ({len(raw)} chars): {raw[:300]}")

    # Strip markdown fences if Gemini added them anyway
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()

    findings = json.loads(raw)
    if not isinstance(findings, list):
        findings = [findings]

    _log(f"Parsed {len(findings)} finding(s) from Gemini response")
    return findings


def _format_findings(raw_findings: list[dict], filename: str) -> list[dict]:
    formatted = []
    valid_sev = {"high", "medium", "low", "info"}
    for i, f in enumerate(raw_findings):
        sev = str(f.get("severity", "info")).lower()
        if sev not in valid_sev:
            sev = "info"
        formatted.append({
            "id":                 f"finding-{i+1:03d}",
            "title":              f.get("title", "Untitled"),
            "vulnerability_type": "Reentrancy",
            "severity":           sev,
            "file":               f.get("file", filename),
            "line_start":         int(f.get("line_start", 0)),
            "line_end":           int(f.get("line_end",   0)),
            "description":        f.get("description", ""),
            "recommendation":     f.get("recommendation", ""),
        })
    return formatted


# ── Entry point ───────────────────────────────────────────────────────────────

def agent_main(task: dict | None = None) -> dict:
    _log("════════════════════════════════════════")
    _log("LLM test agent starting")
    _log(f"CHALLENGE_ID  = {CHALLENGE_ID}")
    _log(f"PROJECT_ID    = {PROJECT_ID}")
    _log(f"API key set   = {'yes ✓' if GEMINI_API_KEY else 'NO ✗'}")
    _log("════════════════════════════════════════")

    filename, content = _load_one_contract(task)

    try:
        raw_findings = _call_gemini(filename, content)
    except Exception as exc:
        _log(f"Gemini call FAILED: {type(exc).__name__}: {exc}")
        # Return a valid report so the validator doesn't get nothing
        raw_findings = [{
            "title":          f"LLM call failed: {type(exc).__name__}",
            "severity":       "info",
            "line_start":     0,
            "line_end":       0,
            "description":    str(exc),
            "recommendation": "Check GEMINI_API_KEY and network access.",
        }]

    findings = _format_findings(raw_findings, filename)

    report = {
        "challenge_id": CHALLENGE_ID,
        "project_id":   PROJECT_ID,
        "findings":     findings,
    }

    _log(f"Done — {len(findings)} finding(s) in report")
    return report


def main():
    report = agent_main()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()