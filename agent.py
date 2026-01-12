#!/usr/bin/env python3
"""
Bittensor Subnet Miner Agent
Solves smart contract audit challenges sent by validators
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
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import logging
import subprocess
import sys

try:
    import requests
    import bittensor as bt
except ImportError:
    print("Install dependencies: pip install bittensor requests")


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """Represents a security finding"""
    file: str
    line_number: int
    severity: str
    issue_type: str
    description: str
    code_snippet: str
    recommendation: str


class SolidityAuditAnalyzer:
    """Analyzes Solidity contracts for security vulnerabilities"""

    def __init__(self):
        self.findings: List[Finding] = []
        self.files_analyzed = 0
        self.files_skipped = 0
        
        # Comprehensive security patterns
        self.patterns = {
            'reentrancy': {
                'regex': r'\.call\s*\{[^}]*\}\s*\(\s*\)',
                'severity': 'critical',
                'description': 'Potential reentrancy vulnerability detected',
                'recommendation': 'Use checks-effects-interactions pattern or reentrancy guard'
            },
            'unchecked_call': {
                'regex': r'(\.call|\.delegatecall|\.staticcall)\s*\(\s*\)',
                'severity': 'high',
                'description': 'Unchecked external call may fail silently',
                'recommendation': 'Always check return value of external calls'
            },
            'tx_origin': {
                'regex': r'\btx\.origin\b',
                'severity': 'high',
                'description': 'Use of tx.origin for authorization',
                'recommendation': 'Use msg.sender instead of tx.origin'
            },
            'weak_randomness': {
                'regex': r'block\.(timestamp|number|difficulty)',
                'severity': 'medium',
                'description': 'Weak randomness source detected',
                'recommendation': 'Use Chainlink VRF or similar service'
            },
            'missing_zero_check': {
                'regex': r'require\s*\(\s*\w+\s*!=\s*address\(0\)\s*\)',
                'severity': 'medium',
                'inverse': True,
                'description': 'Missing zero address validation',
                'recommendation': 'Validate address parameters are not zero address'
            },
            'unchecked_transfer': {
                'regex': r'\.transfer\s*\(',
                'severity': 'medium',
                'description': 'Direct transfer call without return check',
                'recommendation': 'Use safeTransfer from SafeERC20'
            },
            'arbitrary_delegatecall': {
                'regex': r'delegatecall\s*\(',
                'severity': 'critical',
                'description': 'Arbitrary delegatecall detected',
                'recommendation': 'Restrict delegatecall targets carefully'
            },
            'missing_event': {
                'regex': r'function\s+\w+.*\{[^}]*state[^}]*\}',
                'severity': 'low',
                'description': 'State-changing function may lack event emission',
                'recommendation': 'Emit events for all state changes'
            },
            'floating_pragma': {
                'regex': r'pragma\s+solidity\s+\^',
                'severity': 'medium',
                'description': 'Floating pragma version detected',
                'recommendation': 'Lock pragma to specific version'
            },
            'unchecked_arithmetic': {
                'regex': r'(?<!SafeMath)[\+\-\*](\s*=)?(?!\s*SafeMath)',
                'severity': 'low',
                'description': 'Direct arithmetic without SafeMath (Solidity <0.8)',
                'recommendation': 'Use SafeMath library or ensure Solidity >=0.8'
            }
        }

    def analyze_file(self, file_path: str) -> bool:
        """Analyze a single Solidity file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if not content.strip() or not file_path.endswith('.sol'):
                self.files_skipped += 1
                return False

            self.files_analyzed += 1
            lines = content.split('\n')

            # Run all security checks
            for pattern_name, pattern_data in self.patterns.items():
                self._check_pattern(file_path, content, lines, pattern_name, pattern_data)

            return True
        except Exception as e:
            logger.error(f"Error analyzing {file_path}: {str(e)}")
            self.files_skipped += 1
            return False

    def _check_pattern(self, file_path: str, content: str, lines: List[str],
                      pattern_name: str, pattern_data: Dict[str, Any]) -> None:
        """Check content against a security pattern"""
        regex = pattern_data['regex']
        inverse = pattern_data.get('inverse', False)
        
        matches = list(re.finditer(regex, content, re.MULTILINE | re.DOTALL))
        
        if inverse and not matches:
            # Pattern not found but it should be - this is the issue
            line_number = 1
            snippet = lines[0] if lines else ""
        else:
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                # Get code snippet
                start_line = max(0, line_number - 2)
                end_line = min(len(lines), line_number + 2)
                snippet = '\n'.join(lines[start_line:end_line])

                finding = Finding(
                    file=file_path,
                    line_number=line_number,
                    severity=pattern_data['severity'],
                    issue_type=pattern_name,
                    description=pattern_data['description'],
                    code_snippet=snippet.strip(),
                    recommendation=pattern_data['recommendation']
                )
                
                self.findings.append(finding)

    def analyze_directory(self, directory: str) -> None:
        """Analyze all Solidity files in directory"""
        sol_files = list(Path(directory).rglob('*.sol'))
        
        logger.info(f"Found {len(sol_files)} Solidity files to analyze")
        
        for sol_file in sol_files:
            self.analyze_file(str(sol_file))

    def get_findings(self) -> List[Dict[str, Any]]:
        """Return findings as list of dicts"""
        return [
            {
                'file': f.file,
                'line': f.line_number,
                'severity': f.severity,
                'type': f.issue_type,
                'description': f.description,
                'snippet': f.code_snippet,
                'recommendation': f.recommendation
            }
            for f in self.findings
        ]


class AuditMinerAgent:
    """Bittensor subnet miner agent for solving audit challenges"""

    def __init__(self, wallet_name: str = "default", hotkey_name: str = "default"):
        """Initialize miner agent"""
        self.wallet_name = wallet_name
        self.hotkey_name = hotkey_name
        self.analyzer = SolidityAuditAnalyzer()
        logger.info("Audit Miner Agent initialized")

    def download_codebase(self, tarball_url: str, temp_dir: str) -> str:
        """Download and extract codebase from tarball"""
        try:
            logger.info(f"Downloading codebase from {tarball_url}")
            response = requests.get(tarball_url, timeout=60)
            response.raise_for_status()
            
            tarball_path = os.path.join(temp_dir, "codebase.tar.gz")
            with open(tarball_path, 'wb') as f:
                f.write(response.content)
            
            extract_dir = os.path.join(temp_dir, "extracted")
            os.makedirs(extract_dir, exist_ok=True)
            
            with tarfile.open(tarball_path, 'r:gz') as tar:
                tar.extractall(extract_dir)
            
            # Find the actual code directory
            subdirs = os.listdir(extract_dir)
            if subdirs:
                code_dir = os.path.join(extract_dir, subdirs[0])
            else:
                code_dir = extract_dir
            
            logger.info(f"Codebase extracted to {code_dir}")
            return code_dir
        except Exception as e:
            logger.error(f"Error downloading codebase: {str(e)}")
            raise

    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """Solve an audit challenge"""
        temp_dir = None
        try:
            project_id = challenge.get('project_id', 'unknown')
            platform = challenge.get('platform', 'unknown')
            project_name = challenge.get('name', 'unknown')
            
            logger.info(f"Solving challenge for project: {project_name}")
            
            # Create temporary directory
            temp_dir = tempfile.mkdtemp()
            
            # Process each codebase
            total_findings = 0
            all_findings = []
            total_files_analyzed = 0
            total_files_skipped = 0
            repo_urls = []
            
            codebases = challenge.get('codebases', [])
            
            for codebase in codebases:
                tarball_url = codebase.get('tarball_url')
                repo_url = codebase.get('repo_url')
                
                if not tarball_url:
                    logger.warning(f"No tarball URL for codebase {codebase.get('codebase_id')}")
                    continue
                
                repo_urls.append(repo_url)
                
                # Download and analyze
                code_dir = self.download_codebase(tarball_url, temp_dir)
                
                # Analyze codebase
                self.analyzer.analyze_directory(code_dir)
                
                total_files_analyzed += self.analyzer.files_analyzed
                total_files_skipped += self.analyzer.files_skipped
                all_findings.extend(self.analyzer.get_findings())
            
            total_findings = len(all_findings)
            
            # Generate report in specified format
            report = self._generate_report(
                project_name=project_name,
                repo_urls=repo_urls,
                files_analyzed=total_files_analyzed,
                files_skipped=total_files_skipped,
                findings=all_findings
            )
            
            logger.info(f"Challenge solved. Found {total_findings} issues")
            return report
            
        except Exception as e:
            logger.error(f"Error solving challenge: {str(e)}")
            raise
        finally:
            # Cleanup
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)

    def _generate_report(self, project_name: str, repo_urls: List[str],
                        files_analyzed: int, files_skipped: int,
                        findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate audit report in specified format"""
        timestamp = datetime.utcnow().isoformat()
        
        # Generate agent hash
        hash_input = f"{project_name}{files_analyzed}{len(findings)}{timestamp}"
        agent_hash = hashlib.sha256(hash_input.encode()).hexdigest()
        
        report = {
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
        
        return report

    def process_challenge_request(self, challenge_json: str) -> Dict[str, Any]:
        """Process incoming challenge request"""
        try:
            challenge = json.loads(challenge_json)
            return self.solve_challenge(challenge)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON challenge: {str(e)}")
            return {'error': 'Invalid JSON format'}

    def start(self):
        """Start the miner agent (Bittensor integration)"""
        logger.info("Starting Audit Miner Agent on Bittensor subnet")
        # Bittensor registration and synapse handling would go here
        # This is a simplified version showing the core audit functionality


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Bittensor Audit Miner Agent')
    parser.add_argument('--challenge', type=str, help='Challenge JSON string')
    parser.add_argument('--challenge-file', type=str, help='Path to challenge JSON file')
    parser.add_argument('--output', '-o', type=str, help='Output file path')
    
    args = parser.parse_args()
    
    agent = AuditMinerAgent()
    
    if args.challenge:
        result = agent.process_challenge_request(args.challenge)
    elif args.challenge_file:
        with open(args.challenge_file, 'r') as f:
            challenge = json.load(f)
        result = agent.solve_challenge(challenge)
    else:
        logger.error("Please provide --challenge or --challenge-file")
        sys.exit(1)
    
    # Output result
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        logger.info(f"Report saved to {args.output}")
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()