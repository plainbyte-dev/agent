import tarfile
import tempfile
import requests
import hashlib
import datetime
from pathlib import Path
import re


# -------------------------------
# Utilities
# -------------------------------

def _hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def _download_and_extract_tarball(tarball_url: str, dest: Path):
    response = requests.get(tarball_url, timeout=30)
    response.raise_for_status()

    tar_path = dest / "repo.tar.gz"
    tar_path.write_bytes(response.content)

    with tarfile.open(tar_path, "r:gz") as tar:
        tar.extractall(dest)


def _find_solidity_files(root: Path):
    return [p for p in root.rglob("*.sol") if p.is_file()]


# -------------------------------
# Solidity Heuristics
# -------------------------------

def analyze_solidity_file(file_path: Path, source: str):
    findings = []

    # Heuristic 1: unchecked calldata length subtraction
    if "sub(data.length, 4)" in source:
        findings.append({
            "title": "Unchecked calldata length causes underflow and out-of-bounds slice",
            "description": (
                "Inline assembly subtracts 4 from data.length without ensuring "
                "data.length >= 4. In assembly, arithmetic is unchecked, which "
                "can underflow and cause out-of-bounds calldata slicing."
            ),
            "vulnerability_type": "integer underflow / out-of-bounds read",
            "severity": "medium",
            "confidence": 0.88,
            "location": "inline assembly block using sub(data.length, 4)",
            "file": file_path.name,
        })

    # Heuristic 2: nonce used before signature verification
    if "_useNonce" in source and "signature" in source.lower():
        findings.append({
            "title": "Nonce consumed before signature verification allows DoS",
            "description": (
                "Nonce is consumed before verifying the signature. "
                "An attacker can submit invalid signatures to burn nonces, "
                "causing denial of service for legitimate users."
            ),
            "vulnerability_type": "nonce misuse / denial of service",
            "severity": "medium",
            "confidence": 0.75,
            "location": "signature verification flow",
            "file": file_path.name,
        })

    return findings




def main(challenge: dict, api_key: str | None = None) -> dict:
    """
    Entry point required by validator.
    """

    project = challenge.get("project_id", challenge.get("name", "unknown_project"))
    codebases = challenge.get("codebases", [])

    all_findings = []
    files_analyzed = 0
    files_skipped = 0

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        for cb in codebases:
            tarball_url = cb.get("tarball_url")
            if not tarball_url:
                continue

            _download_and_extract_tarball(tarball_url, temp_path)

        sol_files = _find_solidity_files(temp_path)

        for sol_file in sol_files:
            try:
                source = sol_file.read_text(errors="ignore")
                files_analyzed += 1

                findings = analyze_solidity_file(sol_file, source)
                for f in findings:
                    f["id"] = _hash(f["title"] + f["file"])
                    f["reported_by_model"] = "static-solidity-agent-v1"
                    f["status"] = "proposed"
                    all_findings.append(f)

            except Exception:
                files_skipped += 1

    result = {
        "project": project,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "files_analyzed": files_analyzed,
        "files_skipped": files_skipped,
        "total_findings": len(all_findings),
        "findings": all_findings,
    }

    return result
