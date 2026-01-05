"""
Agent interface for ScaBench-style auditing using LLM.
Validator will call main(tasks) and receive structured findings.
"""

from typing import Dict, List, Any
from openai import OpenAI
import json

MODEL_ID = "gpt-3.5-turbo"

def analyze_contract(code: str, client: OpenAI) -> List[Dict[str, Any]]:
    """
    Analyze smart contract code and return a list of findings.
    """
    system_prompt = """You are a security auditor analyzing smart contract code for vulnerabilities.
For each vulnerability, provide:
- title
- description
- vulnerability_type
- severity (critical, high, medium, low)
- confidence (0.0 to 1.0)
Return as JSON {"findings": [...]}."""

    user_prompt = f"Analyze this contract for security vulnerabilities:\n```solidity\n{code}\n```"

    try:
        completion = client.chat.completions.create(
            model=MODEL_ID,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        )

        result_text = completion.choices[0].message.content
        result = json.loads(result_text) if result_text else {}
        return result.get("findings", [])

    except Exception as e:
        # fallback: empty findings if error
        return []

def main(tasks: Dict[str, Any], api_key: str = None) -> Dict[str, Any]:
    """
    Args:
        tasks (dict): Input from validator
        api_key (str): Optional OpenAI API key

    Returns:
        dict: Structured findings
    """
    client = OpenAI(api_key=api_key) if api_key else OpenAI()
    results = []

    for task in tasks.get("challenges", []):
        contract_code = task.get("contract", "")
        challenge_id = task.get("challenge_id", "")

        findings = analyze_contract(contract_code, client)

        results.append({
            "challenge_id": challenge_id,
            "findings": findings
        })

    return {
        "agent_name": "llm-audit-agent",
        "version": "1.0.0",
        "results": results
    }
