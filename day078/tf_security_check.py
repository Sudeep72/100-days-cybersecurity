#!/usr/bin/env python3
"""
Day 078 - Terraform Security Scanner
100 Days of Cybersecurity by Sudeep Ravichandran

Scans Terraform files for security misconfigurations.
Integrates with CI/CD pipelines (GitHub Actions, GitLab CI, etc.)

Usage:
    python3 tf_security_check.py --path ./terraform
    python3 tf_security_check.py --path ./terraform --format json --output report.json
"""

import os
import json
import argparse
import subprocess
import re
from pathlib import Path
from typing import Dict, List, Tuple

class TerraformSecurityScanner:
    def __init__(self, terraform_path: str):
        self.terraform_path = Path(terraform_path)
        self.findings = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "summary": {
                "total_files": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0
            }
        }

    def scan(self) -> Dict:
        """Run all security scans"""
        print("[*] Starting Terraform Security Scan...")
        
        # Find all .tf files
        tf_files = list(self.terraform_path.rglob("*.tf"))
        self.findings['summary']['total_files'] = len(tf_files)
        print(f"[*] Found {len(tf_files)} Terraform files")
        
        # Scan each file
        for tf_file in tf_files:
            self._scan_file(tf_file)
        
        return self.findings

    def _scan_file(self, filepath: Path):
        """Scan individual Terraform file"""
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            
            # Scan for various misconfigurations
            self._check_public_s3(content, filepath)
            self._check_unencrypted_database(content, filepath)
            self._check_public_security_group(content, filepath)
            self._check_hardcoded_secrets(content, filepath)
            self._check_no_logging(content, filepath)
            self._check_mfa_delete(content, filepath)
            self._check_backup_retention(content, filepath)
            self._check_public_database(content, filepath)
        
        except Exception as e:
            print(f"[!] Error scanning {filepath}: {str(e)}")

    def _check_public_s3(self, content: str, filepath: Path):
        """Check for public S3 buckets"""
        # Pattern: acl = "public-read" or similar
        patterns = [
            r'acl\s*=\s*"public-read"',
            r'acl\s*=\s*"public-read-write"',
            r'acl\s*=\s*"authenticated-read"'
        ]
        
        for pattern in patterns:
            if re.search(pattern, content):
                self.findings['critical'].append({
                    "severity": "CRITICAL",
                    "title": "S3 Bucket is publicly readable",
                    "file": str(filepath),
                    "pattern": pattern,
                    "remediation": "Set acl = \"private\" and enable block_public_access_block"
                })
                self.findings['summary']['critical_count'] += 1
                print(f"[!] CRITICAL: Public S3 bucket in {filepath}")

    def _check_unencrypted_database(self, content: str, filepath: Path):
        """Check for unencrypted RDS databases"""
        if 'aws_db_instance' in content:
            # Check for storage_encrypted = false
            if re.search(r'storage_encrypted\s*=\s*false', content):
                self.findings['critical'].append({
                    "severity": "CRITICAL",
                    "title": "RDS database is not encrypted",
                    "file": str(filepath),
                    "remediation": "Set storage_encrypted = true and specify kms_key_id"
                })
                self.findings['summary']['critical_count'] += 1
                print(f"[!] CRITICAL: Unencrypted database in {filepath}")
            
            # Check if encryption not specified (default is false)
            elif 'aws_db_instance' in content and 'storage_encrypted' not in content:
                self.findings['high'].append({
                    "severity": "HIGH",
                    "title": "RDS database encryption not explicitly configured",
                    "file": str(filepath),
                    "remediation": "Set storage_encrypted = true"
                })
                self.findings['summary']['high_count'] += 1
                print(f"[!] HIGH: Implicit unencrypted database in {filepath}")

    def _check_public_security_group(self, content: str, filepath: Path):
        """Check for overly permissive security groups"""
        # Check for 0.0.0.0/0 with no port restrictions
        if re.search(r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]', content):
            # Check if it's on restricted ports only (80, 443)
            if not re.search(r'from_port\s*=\s*(80|443)', content):
                self.findings['high'].append({
                    "severity": "HIGH",
                    "title": "Security group allows unrestricted ingress",
                    "file": str(filepath),
                    "remediation": "Restrict cidr_blocks to specific IPs or remove 0.0.0.0/0"
                })
                self.findings['summary']['high_count'] += 1
                print(f"[!] HIGH: Overly permissive security group in {filepath}")

    def _check_hardcoded_secrets(self, content: str, filepath: Path):
        """Check for hardcoded secrets"""
        patterns = [
            r'password\s*=\s*"[^"]+"',
            r'api_key\s*=\s*"[^"]+"',
            r'secret\s*=\s*"[^"]+"',
            r'token\s*=\s*"[^"]+"',
            r'aws_secret_access_key\s*=\s*"[^"]+"'
        ]
        
        for pattern in patterns:
            if re.search(pattern, content):
                self.findings['critical'].append({
                    "severity": "CRITICAL",
                    "title": "Hardcoded secret detected",
                    "file": str(filepath),
                    "pattern": pattern,
                    "remediation": "Use aws_secretsmanager_secret or random_password resource"
                })
                self.findings['summary']['critical_count'] += 1
                print(f"[!] CRITICAL: Hardcoded secret in {filepath}")

    def _check_no_logging(self, content: str, filepath: Path):
        """Check for resources without logging"""
        if 'aws_s3_bucket' in content and 'logging' not in content:
            self.findings['medium'].append({
                "severity": "MEDIUM",
                "title": "S3 bucket does not have access logging enabled",
                "file": str(filepath),
                "remediation": "Add aws_s3_bucket_logging resource"
            })
            self.findings['summary']['medium_count'] += 1
            print(f"[!] MEDIUM: S3 bucket without logging in {filepath}")
        
        if 'aws_db_instance' in content and 'enabled_cloudwatch_logs_exports' not in content:
            self.findings['medium'].append({
                "severity": "MEDIUM",
                "title": "RDS database does not have CloudWatch logs enabled",
                "file": str(filepath),
                "remediation": "Add enabled_cloudwatch_logs_exports"
            })
            self.findings['summary']['medium_count'] += 1
            print(f"[!] MEDIUM: RDS without CloudWatch logs in {filepath}")

    def _check_mfa_delete(self, content: str, filepath: Path):
        """Check for MFA delete on S3"""
        if 'aws_s3_bucket' in content:
            if 'mfa_delete' not in content:
                self.findings['low'].append({
                    "severity": "LOW",
                    "title": "S3 bucket does not have MFA delete enabled",
                    "file": str(filepath),
                    "remediation": "Enable MFA delete for critical buckets"
                })
                self.findings['summary']['low_count'] += 1

    def _check_backup_retention(self, content: str, filepath: Path):
        """Check for backup retention"""
        if 'aws_db_instance' in content:
            if 'backup_retention_period' not in content:
                self.findings['high'].append({
                    "severity": "HIGH",
                    "title": "RDS database has no backup retention configured",
                    "file": str(filepath),
                    "remediation": "Set backup_retention_period >= 30"
                })
                self.findings['summary']['high_count'] += 1
                print(f"[!] HIGH: RDS without backup retention in {filepath}")

    def _check_public_database(self, content: str, filepath: Path):
        """Check for publicly accessible databases"""
        if re.search(r'publicly_accessible\s*=\s*true', content):
            self.findings['critical'].append({
                "severity": "CRITICAL",
                "title": "Database is publicly accessible",
                "file": str(filepath),
                "remediation": "Set publicly_accessible = false"
            })
            self.findings['summary']['critical_count'] += 1
            print(f"[!] CRITICAL: Publicly accessible database in {filepath}")

    def generate_report(self, format_type: str = "text") -> str:
        """Generate report in specified format"""
        if format_type == "json":
            return json.dumps(self.findings, indent=2)
        
        elif format_type == "text":
            report = "=" * 70 + "\n"
            report += "TERRAFORM SECURITY SCAN REPORT\n"
            report += "=" * 70 + "\n\n"
            
            report += f"Total Files Scanned: {self.findings['summary']['total_files']}\n"
            report += f"Critical Issues: {self.findings['summary']['critical_count']}\n"
            report += f"High Issues: {self.findings['summary']['high_count']}\n"
            report += f"Medium Issues: {self.findings['summary']['medium_count']}\n"
            report += f"Low Issues: {self.findings['summary']['low_count']}\n\n"
            
            if self.findings['critical']:
                report += "CRITICAL FINDINGS:\n"
                report += "-" * 70 + "\n"
                for finding in self.findings['critical']:
                    report += f"  ✗ {finding['title']}\n"
                    report += f"    File: {finding['file']}\n"
                    report += f"    Remediation: {finding.get('remediation', 'N/A')}\n\n"
            
            if self.findings['high']:
                report += "HIGH FINDINGS:\n"
                report += "-" * 70 + "\n"
                for finding in self.findings['high']:
                    report += f"  ⚠ {finding['title']}\n"
                    report += f"    File: {finding['file']}\n"
                    report += f"    Remediation: {finding.get('remediation', 'N/A')}\n\n"
            
            report += "=" * 70 + "\n"
            return report
        
        return ""

    def export_report(self, output_file: str, format_type: str = "json"):
        """Export report to file"""
        report = self.generate_report(format_type)
        with open(output_file, 'w') as f:
            f.write(report)
        print(f"[+] Report exported to {output_file}")


def main():
    parser = argparse.ArgumentParser(description='Terraform Security Scanner - Day 078')
    parser.add_argument('--path', default='.', help='Path to Terraform files')
    parser.add_argument('--format', choices=['text', 'json'], default='text', help='Output format')
    parser.add_argument('--output', help='Output file for report')
    parser.add_argument('--fail-on', choices=['critical', 'high', 'medium'], default='critical',
                       help='Fail if this severity level or higher found')
    
    args = parser.parse_args()
    
    print("[*] Terraform Security Scanner - Day 078")
    print(f"[*] Scanning: {args.path}")
    
    scanner = TerraformSecurityScanner(args.path)
    findings = scanner.scan()
    
    # Print report
    report = scanner.generate_report(args.format)
    print("\n" + report)
    
    # Export if requested
    if args.output:
        scanner.export_report(args.output, args.format)
    
    # Exit with appropriate code
    severity_counts = {
        'critical': findings['summary']['critical_count'],
        'high': findings['summary']['high_count'] + findings['summary']['critical_count'],
        'medium': findings['summary']['medium_count'] + findings['summary']['high_count'] + findings['summary']['critical_count']
    }
    
    if severity_counts.get(args.fail_on, 0) > 0:
        print(f"\n[!] Scan failed: {args.fail_on.upper()} severity issues found")
        exit(1)
    else:
        print("\n[+] Scan passed: No critical issues found")
        exit(0)


if __name__ == "__main__":
    main()