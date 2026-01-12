#!/usr/bin/env python3
"""
Standalone Code Audit Agent
Solves smart contract audit challenges and generates reports
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

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SolidityAuditAnalyzer:
    """Analyzes Solidity contracts for security vulnerabilities"""

    def __init__(self):
        self.findings = []
        self.files_analyzed = 0
        self.files_skipped = 0
        
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
                'regex': r'address\s+\w+\s*=',
                'severity': 'medium',
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
            'floating_pragma': {
                'regex': r'pragma\s+solidity\s+\^',
                'severity': 'medium',
                'description': 'Floating pragma version detected',
                'recommendation': 'Lock pragma to specific version'
            },
            'unsafe_math': {
                'regex': r'(?<!SafeMath)\s+\+\s+(?!.*SafeMath)',
                'severity': 'low',
                'description': 'Arithmetic without SafeMath (Solidity <0.8)',
                'recommendation': 'Use SafeMath library or ensure Solidity >=0.8'
            },
            'missing_event': {
                'regex': r'function\s+\w+.*public.*\{[^}]*\s+(balance|amount|state)[^}]*\}',
                'severity': 'low',
                'description': 'State-changing function may lack event emission',
                'recommendation': 'Emit events for all state changes'
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

            for pattern_name, pattern_data in self.patterns.items():
                self._check_pattern(file_path, content, lines, pattern_name, pattern_data)

            return True
        except Exception as e:
            logger.warning(f"Error analyzing {file_path}: {str(e)}")
            self.files_skipped += 1
            return False

    def _check_pattern(self, file_path: str, content: str, lines: List[str],
                      pattern_name: str, pattern_data: Dict[str, Any]) -> None:
        """Check content against a security pattern"""
        regex = pattern_data['regex']
        
        try:
            for match in re.finditer(regex, content, re.MULTILINE | re.DOTALL):
                line_number = content[:match.start()].count('\n') + 1
                
                start_line = max(0, line_number - 2)
                end_line = min(len(lines), line_number + 2)
                snippet = '\n'.join(lines[start_line:end_line])

                self.findings.append({
                    'file': file_path,
                    'line': line_number,
                    'severity': pattern_data['severity'],
                    'type': pattern_name,
                    'description': pattern_data['description'],
                    'snippet': snippet.strip(),
                    'recommendation': pattern_data['recommendation']
                })
        except re.error:
            pass

    def analyze_directory(self, directory: str) -> None:
        """Analyze all Solidity files in directory"""
        sol_files = list(Path(directory).rglob('*.sol'))
        logger.info(f"Found {len(sol_files)} Solidity files")
        
        for sol_file in sol_files:
            self.analyze_file(str(sol_file))


class AuditAgent:
    """Standalone audit agent for solving code audit challenges"""

    def __init__(self):
        """Initialize the audit agent"""
        self.analyzer = SolidityAuditAnalyzer()
        logger.info("Audit Agent initialized")

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
        """Solve an audit challenge and return report"""
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
                
                # Reset analyzer for fresh analysis
                analyzer = SolidityAuditAnalyzer()
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
                'timestamp': datetime.utcnow().isoformat()
            }
        finally:
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

    def process_json_challenge(self, challenge_json: str) -> Dict[str, Any]:
        """Process a JSON challenge string"""
        try:
            challenge = json.loads(challenge_json)
            return self.solve_challenge(challenge)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON: {str(e)}")
            return {'error': 'Invalid JSON format'}

    def process_file_challenge(self, file_path: str) -> Dict[str, Any]:
        """Process a challenge from a JSON file"""
        try:
            with open(file_path, 'r') as f:
                challenge = json.load(f)
            return self.solve_challenge(challenge)
        except Exception as e:
            logger.error(f"Error reading challenge file: {str(e)}")
            return {'error': str(e)}


def main():
    """Main entry point"""
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Standalone Code Audit Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python agent.py --file challenge.json
  python agent.py --file challenge.json --output report.json
  python agent.py --json '{"project_id":"code4rena_iq-ai_2025_03",...}'
        '''
    )
    parser.add_argument('--file', '-f', help='Challenge JSON file path')
    parser.add_argument('--json', '-j', help='Challenge as JSON string')
    parser.add_argument('--output', '-o', help='Output report file path')
    
    args = parser.parse_args()
    
    agent = AuditAgent()
    
    if args.file:
        logger.info(f"Loading challenge from file: {args.file}")
        result = agent.process_file_challenge(args.file)
    elif args.json:
        logger.info("Processing JSON challenge")
        result = agent.process_json_challenge(args.json)
    else:
        parser.print_help()
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