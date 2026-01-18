#!/usr/bin/env python3
"""
Gemini-Powered Code Audit Agent
Uses Google's Gemini API to analyze smart contract audit challenges
"""

import os
import json
import hashlib
import re
import tarfile
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging
import requests

try:
    import google.generativeai as genai
except ImportError:
    print("Install Gemini: pip install google-generativeai")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class GeminiAuditAnalyzer:
    """Uses Gemini API to analyze Solidity contracts"""

    def __init__(self, api_key: str):
        """Initialize Gemini analyzer with API key"""
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-2.5-flash')
        self.findings = []
        self.files_analyzed = 0
        self.files_skipped = 0

    def analyze_file(self, file_path: str) -> bool:
        """Analyze a single Solidity file using Gemini"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if not content.strip() or not file_path.endswith('.sol'):
                self.files_skipped += 1
                return False

            self.files_analyzed += 1
            
            # Prepare prompt for Gemini
            prompt = self._prepare_analysis_prompt(file_path, content)
            
            # Call Gemini API
            generation_config = {"response_mime_type": "application/json"}
            response = self.model.generate_content(prompt, generation_config=generation_config)
            analysis_result = response.text
            
            # Parse Gemini response
            self._parse_gemini_findings(file_path, content, analysis_result)
            
            logger.info(f"Analyzed {file_path}")
            return True
            
        except Exception as e:
            logger.warning(f"Error analyzing {file_path}: {str(e)}")
            self.files_skipped += 1
            return False

    def _prepare_analysis_prompt(self, file_path: str, content: str) -> str:
        """Prepare analysis prompt for Gemini"""
        prompt = f"""Analyze this Solidity smart contract for security vulnerabilities and code issues.

File: {file_path}

Code:
```solidity
{content}
```

For each issue found, provide the following in JSON format:
{{
  "issues": [
    {{
      "title": "Issue title",
      "description": "Detailed description",
      "vulnerability_type": "Type of vulnerability",
      "severity": "critical|high|medium|low",
      "confidence": 0.0-1.0,
      "line_number": line_number,
      "code_snippet": "relevant code",
      "recommendation": "How to fix"
    }}
  ]
}}

Focus on:
1. Reentrancy vulnerabilities
2. Unchecked external calls
3. TX.origin usage
4. Weak randomness
5. Missing validations
6. Integer overflow/underflow
7. Access control issues
8. Logic errors
9. Gas optimization issues
10. Best practice violations

Be thorough but realistic. Only report actual issues you can identify."""

        return prompt

    def _parse_gemini_findings(self, file_path: str, content: str, response_text: str) -> None:
        """Parse Gemini response and extract findings"""
        try:
            # Extract JSON from response
            json_match = re.search(r'\{[\s\S]*"issues"[\s\S]*\}', response_text)
            
            if not json_match:
                logger.warning(f"Could not extract JSON from Gemini response for {file_path}")
                return
            
            json_str = json_match.group(0)
            data = json.loads(json_str)
            
            lines = content.split('\n')
            
            for issue in data.get('issues', []):
                line_number = issue.get('line_number', 1)
                
                # Get code snippet context
                start_line = max(0, line_number - 2)
                end_line = min(len(lines), line_number + 2)
                snippet = '\n'.join(lines[start_line:end_line])
                
                # Generate unique ID
                finding_id = hashlib.sha256(
                    f"{file_path}{line_number}{issue.get('title')}".encode()
                ).hexdigest()[:16]
                
                finding = {
                    'title': issue.get('title', 'Security Issue'),
                    'description': issue.get('description', ''),
                    'vulnerability_type': issue.get('vulnerability_type', 'unknown'),
                    'severity': issue.get('severity', 'medium').lower(),
                    'confidence': float(issue.get('confidence', 0.8)),
                    'location': f"{file_path}:{line_number}",
                    'file': file_path,
                    'line': line_number,
                    'code_snippet': snippet.strip(),
                    'recommendation': issue.get('recommendation', ''),
                    'id': finding_id,
                    'reported_by_model': 'gemini-1.5-flash',
                    'status': 'identified'
                }
                
                self.findings.append(finding)
                
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON from Gemini response: {str(e)}")
        except Exception as e:
            logger.error(f"Error parsing Gemini findings: {str(e)}")

    def analyze_directory(self, directory: str) -> None:
        """Analyze all Solidity files in directory"""
        sol_files = list(Path(directory).rglob('*.sol'))
        logger.info(f"Found {len(sol_files)} Solidity files to analyze")
        
        for sol_file in sol_files:
            self.analyze_file(str(sol_file))


class GeminiAuditAgent:
    """Audit agent powered by Gemini API"""

    def __init__(self, api_key: str):
        """Initialize the audit agent with Gemini API key"""
        self.api_key = api_key
        logger.info("Gemini Audit Agent initialized")

    def download_codebase(self, tarball_url: str, temp_dir: str) -> Optional[str]:
        """Download and extract codebase from tarball URL"""
        try:
            logger.info(f"Downloading codebase from {tarball_url}")
            response = requests.get(tarball_url, timeout=120, stream=True)
            response.raise_for_status()
            
            tarball_path = os.path.join(temp_dir, "codebase.tar.gz")
            with open(tarball_path, 'wb') as f:
                f.write(response.content)
            
            extract_dir = os.path.join(temp_dir, "extracted")
            os.makedirs(extract_dir, exist_ok=True)
            
            with tarfile.open(tarball_path, 'r:gz') as tar:
                tar.extractall(extract_dir)
            
            subdirs = os.listdir(extract_dir)
            code_dir = os.path.join(extract_dir, subdirs[0]) if subdirs else extract_dir
            
            logger.info(f"Codebase extracted successfully")
            return code_dir
        except Exception as e:
            logger.error(f"Error downloading codebase: {str(e)}")
            return None

    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """Solve an audit challenge using Gemini API"""
        temp_dir = None
        try:
            project_id = challenge.get('project_id', 'unknown')
            project_name = challenge.get('name', 'unknown')
            platform = challenge.get('platform', 'unknown')
            
            logger.info(f"Processing challenge: {project_name} ({project_id})")
            
            temp_dir = tempfile.mkdtemp()
            
            total_files_analyzed = 0
            total_files_skipped = 0
            all_findings = []
            repo_urls = []
            
            codebases = challenge.get('codebases', [])
            logger.info(f"Processing {len(codebases)} codebase(s)")
            
            for idx, codebase in enumerate(codebases, 1):
                tarball_url = codebase.get('tarball_url')
                repo_url = codebase.get('repo_url')
                codebase_id = codebase.get('codebase_id', f'codebase_{idx}')
                
                if not tarball_url:
                    logger.warning(f"No tarball URL for {codebase_id}")
                    continue
                
                if repo_url:
                    repo_urls.append(repo_url)
                
                code_dir = self.download_codebase(tarball_url, temp_dir)
                if not code_dir:
                    continue
                
                # Create analyzer with Gemini API
                analyzer = GeminiAuditAnalyzer(self.api_key)
                analyzer.analyze_directory(code_dir)
                
                total_files_analyzed += analyzer.files_analyzed
                total_files_skipped += analyzer.files_skipped
                all_findings.extend(analyzer.findings)
                
                logger.info(f"  Analyzed {analyzer.files_analyzed} files, found {len(analyzer.findings)} issues")
            
            # Generate final report
            report = self._generate_report(
                project_name=project_name,
                repo_urls=repo_urls,
                files_analyzed=total_files_analyzed,
                files_skipped=total_files_skipped,
                findings=all_findings
            )
            
            logger.info(f"Challenge completed. Total findings: {len(all_findings)}")
            return report
            
        except Exception as e:
            logger.error(f"Error solving challenge: {str(e)}")
            return {
                'error': str(e),
                'project': challenge.get('name', 'unknown'),
                'timestamp': datetime.utcnow().isoformat(),
                'files_analyzed': 0,
                'files_skipped': 0,
                'total_findings': 0,
                'findings': []
            }
        finally:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)

    def _generate_report(self, project_name: str, repo_urls: List[str],
                        files_analyzed: int, files_skipped: int,
                        findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate audit report in required format"""
        timestamp = datetime.utcnow().isoformat()
        
        # Generate agent hash
        hash_input = f"{project_name}{files_analyzed}{len(findings)}{timestamp}"
        agent_hash = hashlib.sha256(hash_input.encode()).hexdigest()
        
        return {
            'project': project_name,
            'timestamp': timestamp,
            'files_analyzed': files_analyzed,
            'files_skipped': files_skipped,
            'total_findings': len(findings),
            'findings': findings,
            '_agent_hash': agent_hash,
            '_repo_url': repo_urls[0] if repo_urls else '',
            '_validated_at': datetime.utcnow().isoformat()
        }


def main(tasks: Dict[str, Any], api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Main entry point for validator-agent communication.
    Uses Gemini API to analyze smart contract audit challenges.
    
    Args:
        tasks: Dictionary containing audit challenge details from validator
        api_key: Gemini API key (from environment if not provided)
    
    Returns:
        Audit report with findings in required format
    """
    # Get API key from parameter or environment
    gemini_key = api_key or os.getenv('GEMINI_API_KEY')
    
    if not gemini_key:
        logger.error("GEMINI_API_KEY not provided or set in environment")
        return {
            'error': 'GEMINI_API_KEY not provided',
            'project': tasks.get('name', 'unknown'),
            'timestamp': datetime.utcnow().isoformat(),
            'files_analyzed': 0,
            'files_skipped': 0,
            'total_findings': 0,
            'findings': []
        }
    
    try:
        agent = GeminiAuditAgent(gemini_key)
        result = agent.solve_challenge(tasks)
        
        logger.info(f"Task completed with {result.get('total_findings', 0)} findings")
        return result
        
    except Exception as e:
        logger.error(f"Fatal error in main: {str(e)}")
        return {
            'error': str(e),
            'project': tasks.get('name', 'unknown'),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'files_analyzed': 0,
            'files_skipped': 0,
            'total_findings': 0,
            'findings': []
        }



run = main

if __name__ == "__main__":
    # For local testing
    import sys
    
    if len(sys.argv) > 1:
        challenge_file = sys.argv[1]
        with open(challenge_file, 'r') as f:
            challenge = json.load(f)
        
        api_key = os.getenv('GEMINI_API_KEY')
        result = main(challenge, api_key)
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python agent.py <challenge_file.json>")
        print("Requires GEMINI_API_KEY environment variable")