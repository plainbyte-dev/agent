"""
Agent interface for ScaBench-style auditing.
Validator will import this file and call main(tasks).
"""

from typing import Dict, List, Any

def main(tasks: Dict[str, Any]) -> Dict[str, Any]:
    """
    Args:
        tasks (dict): Challenge input provided by validator

    Returns:
        dict: Structured findings
    """

    results = []

    for task in tasks["challenges"]:
        contract = task["contract"]
        challenge_id = task["challenge_id"]

        findings = []

        # Example naive heuristic
        if "call.value" in contract or "call{" in contract:
            findings.append({
                "type": "reentrancy",
                "severity": "high",
                "confidence": 0.7
            })

        results.append({
            "challenge_id": challenge_id,
            "findings": findings
        })

    return {
        "agent_name": "example-miner-agent",
        "version": "0.1.0",
        "results": results
    }
