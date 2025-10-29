#!/usr/bin/env python3
import re
import sys
import argparse
import json
import shutil
import time
from pathlib import Path

class CFMLSASTScanner:
    def __init__(self):
        # Security and performance limits
        self.max_file_size = 5 * 1024 * 1024  # 5MB
        self.max_findings = 10000  # Prevent memory exhaustion
        self.scan_start_time = time.time()
        self.max_scan_time = 300  # 5 minutes timeout
        
        # Load ignore patterns
        self.ignore_patterns = self.load_ignore_patterns()
        
        # Pre-compile regex patterns for performance
        self.rules = [
            {
                'id': 'CF-SQLI-001',
                'name': 'SQL Injection',
                'severity': 'HIGH',
                'pattern': re.compile(r'<cfquery[^>]*>.*?#[^#]+#.*?</cfquery>', re.IGNORECASE | re.DOTALL),
                'exclude': re.compile(r'<cfqueryparam', re.IGNORECASE),
                'description': 'Possible SQL Injection (<cfquery> without <cfqueryparam>)'
            },
            {
                'id': 'CF-XSS-001',
                'name': 'XSS',
                'severity': 'MEDIUM',
                'pattern': re.compile(r'#(form|url)\.[^#]+#', re.IGNORECASE),
                'exclude': re.compile(r'EncodeForHTML\(', re.IGNORECASE),
                'description': 'Potential XSS (form/url variable unencoded)'
            },
            {
                'id': 'CF-UPLOAD-001',
                'name': 'Unsafe Upload',
                'severity': 'HIGH',
                'pattern': re.compile(r'<cffile\s+action\s*=\s*["\']upload["\'][^>]*>', re.IGNORECASE),
                'exclude': re.compile(r'accept\s*=|nameconflict\s*=', re.IGNORECASE),
                'description': 'Unsafe file upload without validation'
            },
            {
                'id': 'CF-EXEC-001',
                'name': 'Command Execution',
                'severity': 'HIGH',
                'pattern': re.compile(r'(<cfexecute|Runtime\.exec)', re.IGNORECASE),
                'exclude': None,
                'description': 'Command execution detected'
            },
            {
                'id': 'CF-INCLUDE-001',
                'name': 'Dynamic Include',
                'severity': 'MEDIUM',
                'pattern': re.compile(r'<cfinclude\s+template\s*=\s*["\'][^"\']*#[^#]+#[^"\']*["\']', re.IGNORECASE),
                'exclude': None,
                'description': 'Dynamic include with user input'
            },
            {
                'id': 'CF-CRYPTO-001',
                'name': 'Weak Crypto',
                'severity': 'LOW',
                'pattern': re.compile(r'(MessageDigest|MD5|SHA1)', re.IGNORECASE),
                'exclude': None,
                'description': 'Weak cryptographic algorithm'
            },
            {
                'id': 'CF-EVAL-001',
                'name': 'Eval Abuse',
                'severity': 'MEDIUM',
                'pattern': re.compile(r'evaluate\s*\(', re.IGNORECASE),
                'exclude': None,
                'description': 'Dynamic code evaluation'
            },
            # CFScript patterns
            {
                'id': 'CF-SQLI-002',
                'name': 'CFScript SQL Injection',
                'severity': 'HIGH',
                'pattern': re.compile(r'queryExecute\s*\([^)]{0,100}[+&][^)]{0,100}\)', re.IGNORECASE),
                'exclude': re.compile(r'queryExecute\s*\([^,]+,\s*\[', re.IGNORECASE),
                'description': 'SQL Injection in queryExecute() without params'
            },
            {
                'id': 'CF-XSS-002',
                'name': 'CFScript XSS',
                'severity': 'MEDIUM',
                'pattern': re.compile(r'writeOutput\s*\(\s*(form|url|arguments)\.', re.IGNORECASE),
                'exclude': re.compile(r'encodeForHTML\(', re.IGNORECASE),
                'description': 'Unencoded output in CFScript'
            },
            {
                'id': 'CF-EXEC-002',
                'name': 'CFScript Command Execution',
                'severity': 'HIGH',
                'pattern': re.compile(r'cfexecute\s*\(', re.IGNORECASE),
                'exclude': None,
                'description': 'Command execution in CFScript'
            },
            {
                'id': 'CF-INCLUDE-002',
                'name': 'CFScript Dynamic Include',
                'severity': 'MEDIUM',
                'pattern': re.compile(r'include\s*\([^)]*[+&].*?\)', re.IGNORECASE),
                'exclude': None,
                'description': 'Dynamic include in CFScript'
            },
            {
                'id': 'CF-EVAL-002',
                'name': 'CFScript Eval',
                'severity': 'MEDIUM',
                'pattern': re.compile(r'evaluate\s*\([^)]*[+&].*?\)', re.IGNORECASE),
                'exclude': None,
                'description': 'Dynamic evaluation in CFScript'
            },
            # Additional security rules
            {
                'id': 'CF-LDAP-001',
                'name': 'LDAP Injection',
                'severity': 'HIGH',
                'pattern': re.compile(r'<cfldap[^>]*filter\s*=\s*["\'][^"\']*(#[^#]+#|\+|\&)', re.IGNORECASE),
                'exclude': None,
                'description': 'Potential LDAP injection vulnerability'
            },
            {
                'id': 'CF-XXE-001',
                'name': 'XXE Attack',
                'severity': 'HIGH',
                'pattern': re.compile(r'<cfxml[^>]*>\s*<!DOCTYPE[^>]*ENTITY', re.IGNORECASE | re.DOTALL),
                'exclude': None,
                'description': 'XML External Entity (XXE) vulnerability'
            },
            {
                'id': 'CF-TRAVERSAL-001',
                'name': 'Directory Traversal',
                'severity': 'HIGH',
                'pattern': re.compile(r'<cffile[^>]*destination\s*=\s*["\'][^"\']*(\.\.[\/\\]|#[^#]*\.\.)', re.IGNORECASE),
                'exclude': None,
                'description': 'Directory traversal in file operations'
            }
        ]
        self.findings = []
        self.scanned_count = 0
    
    def load_ignore_patterns(self):
        """Load patterns from .sastignore file"""
        ignore_patterns = []
        try:
            ignore_file = Path('.sastignore')
            if ignore_file.exists():
                with open(ignore_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Convert glob patterns to regex safely
                            pattern = re.escape(line).replace('\\*', '.*').replace('\\?', '.')
                            if len(pattern) > 500:  # Prevent ReDoS
                                continue
                            ignore_patterns.append(re.compile(pattern, re.IGNORECASE))
        except Exception as e:
            print(f"Warning: Error loading .sastignore: {e}", file=sys.stderr)
        return ignore_patterns
    
    def should_ignore_file(self, file_path):
        """Check if file should be ignored based on .sastignore patterns"""
        file_str = str(file_path).replace('\\', '/')
        for pattern in self.ignore_patterns:
            if pattern.search(file_str):
                return True
        return False
    
    def should_ignore_finding(self, finding):
        """Check if finding should be ignored based on patterns"""
        # Check file-level ignores
        if self.should_ignore_file(finding['file']):
            return True
        
        # Check rule-specific ignores (format: rule_id:file_pattern)
        finding_key = f"{finding['rule_id']}:{finding['file']}"
        for pattern in self.ignore_patterns:
            if pattern.search(finding_key):
                return True
        
        return False

    def scan_file(self, file_path):
        try:
            # Strict path validation to prevent traversal attacks
            if not isinstance(file_path, (str, Path)):
                return
            
            # Sanitize input path
            clean_path = str(file_path).replace('..', '').replace('~', '')
            resolved_path = Path(clean_path).resolve()
            
            # Security: Only allow files within current directory tree
            cwd = Path.cwd().resolve()
            try:
                resolved_path.relative_to(cwd)
            except ValueError:
                print(f"Security: Blocked path traversal attempt: {file_path}", file=sys.stderr)
                return
            
            # Check if file should be ignored
            if self.should_ignore_file(file_path):
                return
            
            # Skip very large files for performance
            file_size = resolved_path.stat().st_size
            if file_size > self.max_file_size:
                print(f"Warning: Skipping large file {file_path} ({file_size // 1024 // 1024}MB > {self.max_file_size // 1024 // 1024}MB)", file=sys.stderr)
                return
            
            # Check scan timeout
            if time.time() - self.scan_start_time > self.max_scan_time:
                print("Warning: Scan timeout reached", file=sys.stderr)
                return
            
            with open(resolved_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except (FileNotFoundError, PermissionError):
            print(f"Warning: Cannot access {file_path}", file=sys.stderr)
            return
        except UnicodeDecodeError:
            print(f"Warning: Cannot decode {file_path} (binary file?)", file=sys.stderr)
            return
        except Exception as e:
            print(f"Error scanning {file_path}: {e}", file=sys.stderr)
            return

        for rule in self.rules:
            try:
                # Use pre-compiled pattern for better performance
                matches = rule['pattern'].finditer(content)
                for match in matches:
                    try:
                        if rule['exclude'] and rule['exclude'].search(match.group()):
                            continue
                        
                        line_num = content[:match.start()].count('\n') + 1
                        # Sanitize finding data
                        safe_file = str(file_path)[:500]
                        safe_match = match.group()[:100].replace('\n', '\\n').replace('\r', '\\r')
                        
                        finding = {
                            'file': safe_file,
                            'line': max(1, min(line_num, 999999)),  # Validate line number
                            'rule_id': rule['id'],
                            'severity': rule['severity'],
                            'description': rule['description'],
                            'match': safe_match
                        }
                        
                        # Check if finding should be ignored
                        if not self.should_ignore_finding(finding):
                            # Prevent memory exhaustion
                            if len(self.findings) >= self.max_findings:
                                print(f"Warning: Maximum findings limit reached ({self.max_findings})", file=sys.stderr)
                                return
                            
                            # Check scan timeout
                            if time.time() - self.scan_start_time > self.max_scan_time:
                                print("Warning: Scan timeout reached", file=sys.stderr)
                                return
                            
                            self.findings.append(finding)
                    except Exception as e:
                        print(f"Warning: Error processing match in {file_path}: {e}", file=sys.stderr)
                        continue
            except Exception as e:
                print(f"Warning: Error applying rule {rule['id']} to {file_path}: {e}", file=sys.stderr)
                continue

    def scan_files(self, file_paths):
        cfml_extensions = {'.cfm', '.cfc', '.cfml', '.cfinclude'}
        self.scanned_count = 0
        max_files = 10000  # Prevent DoS attacks
        
        if len(file_paths) > max_files:
            print(f"Error: Too many files specified (max: {max_files})", file=sys.stderr)
            return
        
        for file_path in file_paths:
            try:
                # Input validation
                if not isinstance(file_path, (str, Path)) or len(str(file_path)) > 500:
                    continue
                
                # Sanitize path
                clean_path = str(file_path).replace('..', '').replace('~', '')
                path = Path(clean_path).resolve()
                
                # Security: Only scan files within current directory
                try:
                    path.relative_to(Path.cwd().resolve())
                    path_ok = True
                except ValueError:
                    print(f"Security: Blocked path traversal: {file_path}", file=sys.stderr)
                    path_ok = False
                
                if (path_ok and path.exists() and path.is_file() and path.suffix.lower() in cfml_extensions):
                    self.scan_file(path)
                    self.scanned_count += 1
                elif not path.exists():
                    safe_path = str(file_path)[:100]  # Truncate for safety
                    print(f"Warning: File not found: {safe_path}", file=sys.stderr)
                elif path.suffix.lower() not in cfml_extensions:
                    safe_path = str(file_path)[:100]
                    print(f"Warning: Skipping non-CFML file: {safe_path}", file=sys.stderr)
            except Exception as e:
                safe_path = str(file_path)[:100]
                print(f"Error processing {safe_path}: {str(e)[:200]}", file=sys.stderr)
                continue
        
        if self.scanned_count == 0:
            print("Warning: No valid CFML files were scanned", file=sys.stderr)

    def print_results(self, json_output=False, sarif_output=False):
        try:
            # Validate findings data
            if not isinstance(self.findings, list):
                print("Error: Invalid findings data", file=sys.stderr)
                return False
            
            if sarif_output:
                sarif_data = self.generate_sarif()
                if sarif_data:
                    print(json.dumps(sarif_data, indent=2, ensure_ascii=True))
                return False
            
            if json_output:
                print(json.dumps(self.findings, indent=2, ensure_ascii=True))
                return False

            # Count findings safely
            high = sum(1 for f in self.findings if isinstance(f, dict) and f.get('severity') == 'HIGH')
            medium = sum(1 for f in self.findings if isinstance(f, dict) and f.get('severity') == 'MEDIUM')
            low = sum(1 for f in self.findings if isinstance(f, dict) and f.get('severity') == 'LOW')

            print("=== CFML SAST (edited files) ===")
            print(f"Files scanned: {max(0, self.scanned_count)}")
            print(f"Findings: High={high}  Medium={medium}  Low={low}")

            # Sort and display findings safely
            valid_findings = [f for f in self.findings if isinstance(f, dict) and all(k in f for k in ['severity', 'file', 'line'])]
            for finding in sorted(valid_findings, key=lambda x: (x['severity'], x['file'], x['line'])):
                try:
                    # Sanitize output to prevent injection
                    safe_file = str(finding['file']).replace('\n', '').replace('\r', '')[:200]
                    safe_desc = str(finding['description']).replace('\n', '').replace('\r', '')[:500]
                    safe_line = max(1, min(int(finding['line']), 999999))
                    print(f"- [{finding['severity']}] {finding['rule_id']} :: {safe_file}:{safe_line} – {safe_desc}")
                except (KeyError, ValueError, TypeError) as e:
                    print(f"Warning: Skipped malformed finding: {str(e)[:100]}", file=sys.stderr)
                    continue

            print("Scan complete.")
            return high > 0
        except Exception as e:
            safe_error = str(e)[:200].replace('\n', ' ').replace('\r', ' ')
            print(f"Error generating results: {safe_error}", file=sys.stderr)
            return False
    
    def generate_sarif(self):
        """Generate SARIF 2.1.0 format output"""
        # Convert findings to SARIF results
        results = []
        for finding in self.findings:
            try:
                # Validate finding data
                if not isinstance(finding, dict):
                    continue
                
                # Map severity to SARIF levels
                level_map = {'HIGH': 'error', 'MEDIUM': 'warning', 'LOW': 'note'}
                
                # Sanitize data for SARIF output
                safe_file = str(finding.get('file', ''))[:500].replace('\\', '/')
                safe_desc = str(finding.get('description', ''))[:1000]
                safe_line = max(1, min(int(finding.get('line', 1)), 999999))
                
                result = {
                    "ruleId": finding.get('rule_id', 'UNKNOWN'),
                    "level": level_map.get(finding.get('severity'), 'warning'),
                    "message": {
                        "text": safe_desc
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": safe_file
                            },
                            "region": {
                                "startLine": safe_line
                            }
                        }
                    }]
                }
                results.append(result)
            except Exception as e:
                print(f"Warning: Error processing finding for SARIF: {e}", file=sys.stderr)
                continue
        
        # Generate SARIF document
        sarif = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "CFML SAST Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/madhabdhakal/CF-SAST",
                        "rules": self.generate_sarif_rules()
                    }
                },
                "results": results
            }]
        }
        return sarif
    
    def generate_sarif_rules(self):
        """Generate SARIF rule definitions"""
        rules = []
        for rule in self.rules:
            sarif_rule = {
                "id": rule['id'],
                "name": rule['name'],
                "shortDescription": {
                    "text": rule['description']
                },
                "fullDescription": {
                    "text": rule['description']
                },
                "defaultConfiguration": {
                    "level": "error" if rule['severity'] == 'HIGH' else "warning" if rule['severity'] == 'MEDIUM' else "note"
                },
                "properties": {
                    "security-severity": "9.0" if rule['severity'] == 'HIGH' else "5.0" if rule['severity'] == 'MEDIUM' else "2.0"
                }
            }
            rules.append(sarif_rule)
        return rules
    
    def get_finding_key(self, finding):
        """Generate unique key for finding (file:line:rule_id)"""
        return f"{finding['file']}:{finding['line']}:{finding['rule_id']}"
    
    def load_baseline(self, baseline_file):
        """Load baseline findings from file"""
        try:
            # Validate baseline file path
            baseline_path = Path(baseline_file).resolve()
            try:
                baseline_path.relative_to(Path.cwd().resolve())
            except ValueError:
                print(f"Security: Blocked baseline path traversal: {baseline_file}", file=sys.stderr)
                return set()
            
            # Limit file size to prevent DoS
            if baseline_path.stat().st_size > 10 * 1024 * 1024:  # 10MB limit
                print(f"Error: Baseline file too large: {baseline_file}", file=sys.stderr)
                return set()
            
            with open(baseline_path, 'r', encoding='utf-8') as f:
                baseline_data = json.load(f)
                if not isinstance(baseline_data, list):
                    print(f"Error: Invalid baseline format: {baseline_file}", file=sys.stderr)
                    return set()
                return {self.get_finding_key(finding) for finding in baseline_data if isinstance(finding, dict)}
        except FileNotFoundError:
            return set()
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in baseline file: {baseline_file}", file=sys.stderr)
            return set()
        except Exception as e:
            print(f"Warning: Error loading baseline {baseline_file}: {e}", file=sys.stderr)
            return set()
    
    def apply_baseline(self, baseline_file):
        """Filter out findings that exist in baseline"""
        baseline_keys = self.load_baseline(baseline_file)
        if not baseline_keys:
            return
        
        original_count = len(self.findings)
        self.findings = [f for f in self.findings if self.get_finding_key(f) not in baseline_keys]
        suppressed_count = original_count - len(self.findings)
        
        if suppressed_count > 0:
            print(f"Baseline: Suppressed {suppressed_count} existing findings", file=sys.stderr)
    
    def update_baseline(self, baseline_file):
        """Update baseline file with current findings"""
        try:
            # Validate baseline file path
            baseline_path = Path(baseline_file).resolve()
            try:
                baseline_path.relative_to(Path.cwd().resolve())
            except ValueError:
                print(f"Security: Blocked baseline path traversal: {baseline_file}", file=sys.stderr)
                return 1
            
            # Validate findings data before writing
            if not isinstance(self.findings, list):
                print("Error: Invalid findings data", file=sys.stderr)
                return 1
            
            # Create backup if baseline exists
            if baseline_path.exists():
                backup_path = baseline_path.with_suffix(baseline_path.suffix + '.bak')
                shutil.copy2(baseline_path, backup_path)
                print(f"Backup created: {backup_path}", file=sys.stderr)
            
            # Write current findings as new baseline with safe JSON
            with open(baseline_path, 'w', encoding='utf-8') as f:
                json.dump(self.findings, f, indent=2, ensure_ascii=True)
            
            print(f"Baseline updated: {len(self.findings)} findings saved to {baseline_file}")
            return 0
        except Exception as e:
            print(f"Error updating baseline: {e}", file=sys.stderr)
            return 1

def main():
    try:
        parser = argparse.ArgumentParser(description='CFML SAST Scanner')
        parser.add_argument('--files', nargs='+', help='Files to scan')
        parser.add_argument('--scan-all', action='store_true', help='Scan all CFML files in current directory recursively')
        parser.add_argument('--scan-changed', action='store_true', help='Scan only Git-modified CFML files')
        parser.add_argument('--fail-on-high', action='store_true', help='Exit 1 if high severity issues found')
        parser.add_argument('--json-out', action='store_true', help='Output JSON format')
        parser.add_argument('--sarif', action='store_true', help='Output SARIF 2.1.0 format')
        parser.add_argument('--init-ignore', action='store_true', help='Create default .sastignore file')
        parser.add_argument('--baseline', metavar='FILE', help='Create or use baseline file to suppress existing findings')
        parser.add_argument('--update-baseline', action='store_true', help='Update existing baseline with current findings')
        
        args = parser.parse_args()
        
        # Handle --init-ignore flag
        if args.init_ignore:
            return create_default_sastignore()
        
        # Handle baseline operations
        if args.update_baseline and not args.baseline:
            print("Error: --update-baseline requires --baseline FILE", file=sys.stderr)
            return 1
        
        # Handle --scan-all flag
        if args.scan_all:
            return scan_all_files(args)
        
        # Handle --scan-changed flag
        if args.scan_changed:
            return scan_changed_files(args)
        
        if not args.files:
            print("Error: No files specified. Use --files *.cfm *.cfc or --scan-all", file=sys.stderr)
            return 1
        
        # Validate and sanitize file arguments
        safe_files = []
        for file_arg in args.files:
            if isinstance(file_arg, str) and len(file_arg) < 1000:  # Prevent DoS
                safe_files.append(file_arg)
        
        if not safe_files:
            print("Error: No valid files specified", file=sys.stderr)
            return 1

        scanner = CFMLSASTScanner()
        scanner.scan_files(safe_files)
        
        # Handle baseline operations
        if args.baseline:
            if args.update_baseline:
                return scanner.update_baseline(args.baseline)
            else:
                scanner.apply_baseline(args.baseline)
        
        has_high = scanner.print_results(args.json_out, args.sarif)
        
        if args.fail_on_high and has_high:
            return 1
        return 0
    except KeyboardInterrupt:
        print("\nScan interrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        return 1

def create_default_sastignore():
    """Create a default .sastignore file"""
    ignore_content = '''# CFML SAST Ignore Patterns
# Lines starting with # are comments

# Ignore test files
*test*
*Test*
*/tests/*
*/spec/*

# Ignore third-party libraries
*/lib/*
*/vendor/*
*/node_modules/*
*/external/*

# Ignore generated files
*generated*
*auto*
*.min.cfm
*.min.cfc

# Ignore specific rules in certain files
# CF-XSS-001:*/admin/*
# CF-SQLI-001:*/legacy/*

# Ignore development/debug files
*debug*
*temp*
*tmp*
*.bak

# Ignore documentation
*/docs/*
*.md
*.txt
'''
    
    try:
        ignore_path = Path('.sastignore').resolve()
        
        # Security: Ensure we're creating file in current directory
        try:
            ignore_path.relative_to(Path.cwd().resolve())
        except ValueError:
            print("Security: Blocked attempt to create .sastignore outside current directory", file=sys.stderr)
            return 1
        
        if ignore_path.exists():
            print("Warning: .sastignore already exists", file=sys.stderr)
            return 1
        
        # Validate content length
        if len(ignore_content) > 10000:  # Reasonable limit
            print("Error: Ignore content too large", file=sys.stderr)
            return 1
        
        with open(ignore_path, 'w', encoding='utf-8') as f:
            f.write(ignore_content)
        
        print("Created .sastignore file with default patterns")
        print("Edit .sastignore to customize ignore patterns for your project")
        return 0
    except PermissionError:
        print("Error: Permission denied creating .sastignore", file=sys.stderr)
        return 1
    except Exception as e:
        # Sanitize error message
        safe_error = str(e)[:200].replace('\n', ' ').replace('\r', ' ')
        print(f"Error creating .sastignore: {safe_error}", file=sys.stderr)
        return 1

def scan_changed_files(args):
    """Scan only Git-modified CFML files with batch processing"""
    try:
        import subprocess
        
        # Get changed files from Git
        try:
            # Get modified, added, and staged files
            result = subprocess.run(['git', 'diff', '--name-only', 'HEAD'], 
                                  capture_output=True, text=True, check=True)
            changed_files = result.stdout.strip().split('\n') if result.stdout.strip() else []
            
            # Also get staged files
            result = subprocess.run(['git', 'diff', '--cached', '--name-only'], 
                                  capture_output=True, text=True, check=True)
            staged_files = result.stdout.strip().split('\n') if result.stdout.strip() else []
            
            # Combine and filter for CFML files
            all_changed = set(changed_files + staged_files)
            cfml_extensions = {'.cfm', '.cfc', '.cfml'}
            cfml_files = [f for f in all_changed if f and Path(f).suffix.lower() in cfml_extensions and Path(f).exists()]
            
        except subprocess.CalledProcessError:
            print("Error: Not a Git repository or Git not available", file=sys.stderr)
            return 1
        
        if not cfml_files:
            print("No changed CFML files found")
            return 0
        
        print(f"Found {len(cfml_files)} changed CFML files")
        
        # Process files (batch if needed)
        scanner = CFMLSASTScanner()
        if len(cfml_files) > 50:
            batch_size = 50
            for i in range(0, len(cfml_files), batch_size):
                batch = cfml_files[i:i + batch_size]
                scanner.scan_files(batch)
        else:
            scanner.scan_files(cfml_files)
        
        # Handle baseline operations
        if args.baseline:
            if args.update_baseline:
                return scanner.update_baseline(args.baseline)
            else:
                scanner.apply_baseline(args.baseline)
        
        has_high = scanner.print_results(args.json_out, args.sarif)
        
        if args.fail_on_high and has_high:
            return 1
        return 0
        
    except Exception as e:
        print(f"Error scanning changed files: {e}", file=sys.stderr)
        return 1

def scan_all_files(args):
    """Scan all CFML files in current directory with batch processing"""
    try:
        from pathlib import Path
        import glob
        
        # Find all CFML files recursively
        cfml_patterns = ['**/*.cfm', '**/*.cfc', '**/*.cfml']
        all_files = []
        
        for pattern in cfml_patterns:
            files = glob.glob(pattern, recursive=True)
            all_files.extend([str(Path(f).resolve()) for f in files])
        
        if not all_files:
            print("No CFML files found in current directory", file=sys.stderr)
            return 1
        
        print(f"Found {len(all_files)} CFML files. Processing in batches...")
        
        # Process in batches to avoid command line length issues
        batch_size = 50
        scanner = CFMLSASTScanner()
        
        for i in range(0, len(all_files), batch_size):
            batch = all_files[i:i + batch_size]
            print(f"Processing batch {i//batch_size + 1}/{(len(all_files) + batch_size - 1)//batch_size}...")
            scanner.scan_files(batch)
        
        # Handle baseline operations
        if args.baseline:
            if args.update_baseline:
                return scanner.update_baseline(args.baseline)
            else:
                scanner.apply_baseline(args.baseline)
        
        has_high = scanner.print_results(args.json_out, args.sarif)
        
        if args.fail_on_high and has_high:
            return 1
        return 0
        
    except Exception as e:
        print(f"Error scanning all files: {e}", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())