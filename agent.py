"""
Static test agent — no Gemini, no network, no dependencies.
Just proves the container → runner → agent_main → JSON pipeline works.
"""
import json
import os
import sys


def _log(msg):
    print(f"[agent] {msg}", file=sys.stderr, flush=True)


def agent_main(task=None):
    _log("agent_main() called ✓")
    _log(f"CHALLENGE_ID  = {os.environ.get('CHALLENGE_ID', 'NOT SET')}")
    _log(f"PROJECT_ID    = {os.environ.get('PROJECT_ID',   'NOT SET')}")
    _log(f"task type     = {type(task)}")
    _log(f"contracts     = {list(task['contracts'].keys()) if task and task.get('contracts') else 'none'}")

    report = {
        "challenge_id": os.environ.get("CHALLENGE_ID", "unknown"),
        "project_id":   os.environ.get("PROJECT_ID",   "unknown"),
        "findings": [
            {
                "id":                 "finding-001",
                "title":              "TEST: Static finding from test agent",
                "vulnerability_type": "Test",
                "severity":           "info",
                "file":               "test.sol",
                "line_start":         1,
                "line_end":           1,
                "description":        "Static test finding to verify the full pipeline works end to end.",
                "recommendation":     "No action needed — this is a test.",
            }
        ],
    }

    _log(f"Returning report with {len(report['findings'])} finding(s) ✓")
    return report


def main():
    report = agent_main()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()