#!/usr/bin/env python3
"""
SAFE-T1002: Supply Chain Compromise - Detection Implementation
This script detects supply chain compromise indicators in MCP server packages.
"""

import json
import re
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from urllib.parse import urlparse

class SupplyChainDetector:
    """Detector for Supply Chain Compromise in MCP packages"""
    
    def __init__(self):
        # Known legitimate package names for comparison
        self.legitimate_packages = [
            "mcp-github-tools",
            "mcp-slack",
            "mcp-filesystem",
            "mcp-aws",
            "mcp-google",
        ]
        
        # Typosquatting patterns
        self.typosquat_patterns = [
            (r'githab', 'github'),
            (r'slackk', 'slack'),
            (r'filesys', 'filesystem'),
            (r'awss', 'aws'),
            (r'gooogle', 'google'),
        ]
        
        # Suspicious script patterns
        self.suspicious_script_patterns = [
            r'fetch\s*\([^)]*http',
            r'curl\s+[^|]*http',
            r'wget\s+[^|]*http',
            r'exec\s*\(',
            r'eval\s*\(',
            r'child_process',
            r'fs\.writeFile',
            r'fs\.appendFile',
            r'crontab',
            r'setInterval',
            r'setTimeout',
        ]
        
        # Suspicious domains
        self.suspicious_domains = [
            r'\.tk$',
            r'\.ml$',
            r'\.ga$',
            r'pastebin',
            r'discord',
            r'analytics',
            r'metrics',
            r'backup-service',
            r'health-check',
        ]
    
    def detect_typosquatting(self, package_name: str) -> List[Dict[str, Any]]:
        """Detect typosquatting in package name"""
        findings = []
        
        for pattern, legitimate in self.typosquat_patterns:
            if re.search(pattern, package_name, re.IGNORECASE):
                # Check if similar legitimate package exists
                for legit in self.legitimate_packages:
                    if legitimate.lower() in legit.lower():
                        findings.append({
                            "severity": "high",
                            "type": "typosquatting",
                            "message": f"Package name '{package_name}' appears to typosquat '{legit}'",
                            "pattern": pattern,
                            "legitimate": legit
                        })
        
        return findings
    
    def analyze_metadata(self, package_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze package metadata for suspicious indicators"""
        findings = []
        
        # Check maintainer account age
        if "maintainer" in package_data:
            maintainer = package_data["maintainer"]
            if "created" in maintainer:
                try:
                    created_date = datetime.fromisoformat(maintainer["created"].replace('Z', '+00:00'))
                    days_old = (datetime.now(created_date.tzinfo) - created_date).days
                    
                    if days_old < 7:
                        findings.append({
                            "severity": "medium",
                            "type": "suspicious_metadata",
                            "message": f"Maintainer account created {days_old} days ago (very recent)",
                            "account_age_days": days_old
                        })
                except (ValueError, AttributeError):
                    pass
        
        # Check for generic descriptions
        description = package_data.get("description", "").lower()
        generic_terms = ["enhanced", "improved", "better", "new version", "updated"]
        if any(term in description for term in generic_terms):
            if len(description) < 50:  # Very short generic description
                findings.append({
                    "severity": "low",
                    "type": "suspicious_metadata",
                    "message": "Generic or vague package description",
                    "description": package_data.get("description", "")
                })
        
        return findings
    
    def analyze_scripts(self, package_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze preinstall/postinstall scripts for malicious patterns"""
        findings = []
        
        scripts = package_data.get("scripts", {})
        
        for script_name, script_content in scripts.items():
            if script_name in ["preinstall", "postinstall", "install"]:
                for pattern in self.suspicious_script_patterns:
                    if re.search(pattern, script_content, re.IGNORECASE):
                        findings.append({
                            "severity": "critical",
                            "type": "malicious_script",
                            "message": f"Suspicious pattern in {script_name} script",
                            "script": script_name,
                            "pattern": pattern,
                            "snippet": script_content[:200]
                        })
        
        return findings
    
    def check_network_indicators(self, package_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for suspicious network-related indicators"""
        findings = []
        
        # Check dependencies for suspicious packages
        dependencies = package_data.get("dependencies", {})
        for dep_name, dep_version in dependencies.items():
            for domain_pattern in self.suspicious_domains:
                if re.search(domain_pattern, dep_name, re.IGNORECASE):
                    findings.append({
                        "severity": "medium",
                        "type": "suspicious_dependency",
                        "message": f"Suspicious dependency name: {dep_name}",
                        "dependency": dep_name
                    })
        
        # Check repository URL
        repo = package_data.get("repository", {})
        if isinstance(repo, dict):
            repo_url = repo.get("url", "")
        else:
            repo_url = str(repo)
        
        if repo_url:
            parsed = urlparse(repo_url)
            for domain_pattern in self.suspicious_domains:
                if re.search(domain_pattern, parsed.netloc, re.IGNORECASE):
                    findings.append({
                        "severity": "high",
                        "type": "suspicious_repository",
                        "message": f"Suspicious repository domain: {parsed.netloc}",
                        "repository": repo_url
                    })
        
        return findings
    
    def scan_package(self, package_data: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """Scan a package for supply chain compromise indicators"""
        findings = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }
        
        package_name = package_data.get("name", "")
        
        # Check typosquatting
        typosquat_findings = self.detect_typosquatting(package_name)
        for finding in typosquat_findings:
            findings[finding["severity"]].append(finding)
        
        # Analyze metadata
        metadata_findings = self.analyze_metadata(package_data)
        for finding in metadata_findings:
            findings[finding["severity"]].append(finding)
        
        # Analyze scripts
        script_findings = self.analyze_scripts(package_data)
        for finding in script_findings:
            findings[finding["severity"]].append(finding)
        
        # Check network indicators
        network_findings = self.check_network_indicators(package_data)
        for finding in network_findings:
            findings[finding["severity"]].append(finding)
        
        return findings
    
    def generate_report(self, findings: Dict[str, List[Dict[str, Any]]], package_name: str) -> str:
        """Generate a human-readable report"""
        report = f"\n=== Supply Chain Compromise Detection Report for '{package_name}' ===\n"
        
        total_issues = sum(len(items) for items in findings.values())
        if total_issues == 0:
            report += "✓ No supply chain compromise indicators detected\n"
            return report
        
        report += f"Total issues found: {total_issues}\n\n"
        
        severity_order = ['critical', 'high', 'medium', 'low']
        icons = {
            'critical': '🚨',
            'high': '⚠️ ',
            'medium': '⚡',
            'low': '📌'
        }
        
        for severity in severity_order:
            if findings[severity]:
                report += f"{icons[severity]} {severity.upper()} ({len(findings[severity])} issues)\n"
                for finding in findings[severity]:
                    report += f"  - [{finding['type']}] {finding['message']}\n"
                report += "\n"
        
        return report


def scan_package_file(file_path: str):
    """Scan a package.json file for supply chain compromise"""
    detector = SupplyChainDetector()
    
    try:
        with open(file_path, 'r') as f:
            package_data = json.load(f)
    except Exception as e:
        print(f"Error loading package file: {e}")
        return
    
    findings = detector.scan_package(package_data)
    package_name = package_data.get("name", "unknown")
    report = detector.generate_report(findings, package_name)
    print(report)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        scan_package_file(sys.argv[1])
    else:
        print("Usage: python detection_implementation.py <package.json>")

