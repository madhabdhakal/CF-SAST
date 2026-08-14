#!/usr/bin/env python3
import bisect
import re
import sys
import argparse
import json
import shutil
import time
from pathlib import Path

# A <cfquery> block and its body. Non-greedy so adjacent queries stay distinct.
CFQUERY_BLOCK = re.compile(r'<cfquery\b[^>]*>(.*?)</cfquery\s*>', re.IGNORECASE | re.DOTALL)
# Regions inside a query body where interpolation is safe or inert.
CFQUERYPARAM_TAG = re.compile(r'<cfqueryparam\b[^>]*>', re.IGNORECASE)
CFML_COMMENT = re.compile(r'<!---.*?--->', re.DOTALL)
# A #...# interpolation. Bounded and newline-free: CFML expressions do not
# span lines, and bounding it keeps the scan linear.
CFML_INTERPOLATION = re.compile(r'#[^#\r\n]{1,200}#')


def find_unparameterized_sql(content):
    """Yield each #...# interpolation inside a <cfquery> that is not bound.

    Evaluating interpolations individually is the whole point. Asking merely
    whether the block contains a <cfqueryparam> anywhere misses the dominant
    real-world shape, where a developer parameterizes most of a query and
    leaves one clause concatenated:

        WHERE id = <cfqueryparam value="#url.id#" ...>
          AND name = '#url.name#'          <-- still injectable

    Interpolation inside a cfqueryparam value attribute is bound and safe;
    interpolation inside a CFML comment is inert. Everything else in the
    query body reaches the database as literal SQL text.
    """
    for block in CFQUERY_BLOCK.finditer(content):
        body = block.group(1)
        body_offset = block.start(1)

        safe_spans = [m.span() for m in CFQUERYPARAM_TAG.finditer(body)]
        safe_spans += [m.span() for m in CFML_COMMENT.finditer(body)]

        for interp in CFML_INTERPOLATION.finditer(body):
            if any(lo <= interp.start() < hi for lo, hi in safe_spans):
                continue
            yield body_offset + interp.start(), interp.group()


CFXML_BLOCK = re.compile(r'<cfxml\b[^>]*>(.*?)</cfxml\s*>', re.IGNORECASE | re.DOTALL)
ENTITY_DECL = re.compile(r'<!ENTITY\b', re.IGNORECASE)


def find_xxe(content):
    """Yield <cfxml> blocks that declare an internal entity.

    Checking the block for an <!ENTITY declaration is order-independent. The
    previous pattern demanded that <!DOCTYPE follow the opening tag with only
    whitespace between, so an XML declaration or a comment ahead of the
    doctype defeated it.
    """
    for block in CFXML_BLOCK.finditer(content):
        if ENTITY_DECL.search(block.group(1)):
            yield block.start(), block.group()[:100]


# Request-scoped, attacker-controlled variable scopes.
UNTRUSTED_SCOPE = re.compile(r'\b(?:form|url)\s*\.', re.IGNORECASE)
# Output encoders that neutralise an interpolated value.
OUTPUT_ENCODER = re.compile(
    r'\b(?:encodeFor\w+|htmlEditFormat|htmlCodeFormat|xmlFormat|jsStringFormat)\s*\(',
    re.IGNORECASE)


def find_unencoded_output(content):
    """Yield interpolations of form/url scope that are not passed through an encoder.

    The previous pattern `#(form|url)\\.[^#]+#` could only ever match a bare
    `#form.x#`, so its EncodeForHTML() exclusion was unreachable dead code:
    `#EncodeForHTML(form.x)#` did not match the pattern in the first place.

    Matching any interpolation that *references* an untrusted scope and then
    excluding the encoded ones makes the exclusion meaningful, and it catches
    partially-processed cases such as `#trim(form.x)#` that the old pattern
    silently let through.

    Interpolation inside a <cfquery> is SQL, not markup: it is reported by
    CF-SQLI-001 instead of being double-counted here.
    """
    inert_spans = [m.span() for m in CFQUERY_BLOCK.finditer(content)]
    inert_spans += [m.span() for m in CFML_COMMENT.finditer(content)]

    for interp in CFML_INTERPOLATION.finditer(content):
        text = interp.group()
        if not UNTRUSTED_SCOPE.search(text):
            continue
        if OUTPUT_ENCODER.search(text):
            continue
        if any(lo <= interp.start() < hi for lo, hi in inert_spans):
            continue
        yield interp.start(), text


class CFMLSASTScanner:
    # Display and gating order. Also drives SARIF level mapping.
    SEVERITY_RANK = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}

    def __init__(self, max_scan_time=300):
        # Security and performance limits
        self.max_file_size = 5 * 1024 * 1024  # 5MB
        self.max_findings = 10000  # Prevent memory exhaustion
        self.scan_start_time = time.time()
        self.max_scan_time = max_scan_time
        # Latched when a limit cuts the scan short. Callers must not report an
        # incomplete scan as a clean one.
        self.incomplete = False


        # Load ignore patterns
        self.ignore_patterns = self.load_ignore_patterns()
        
        # Pre-compile regex patterns for performance
        self.rules = [
            {
                'id': 'CF-SQLI-001',
                'name': 'SQL Injection',
                'severity': 'HIGH',
                # Needs per-interpolation analysis, not a whole-block regex.
                'finder': find_unparameterized_sql,
                'pattern': None,
                'exclude': None,
                'description': 'Possible SQL Injection (unparameterized value in <cfquery>)'
            },
            {
                'id': 'CF-XSS-001',
                'name': 'XSS',
                'severity': 'MEDIUM',
                # Encoder detection has to inspect the interpolation contents.
                'finder': find_unencoded_output,
                'pattern': None,
                'exclude': None,
                'description': 'Potential XSS (form/url variable unencoded)'
            },
            {
                'id': 'CF-UPLOAD-001',
                'name': 'Unsafe Upload',
                'severity': 'HIGH',
                # action= may appear at any position in the tag, not just first.
                'pattern': re.compile(r'<cffile\b[^>]*\baction\s*=\s*["\']upload["\'][^>]*>', re.IGNORECASE),
                # Only an accept= allow-list mitigates this. nameconflict=
                # controls overwrite behaviour and was previously suppressing
                # genuine findings.
                'exclude': re.compile(r'\baccept\s*=', re.IGNORECASE),
                'description': 'Unsafe file upload without validation'
            },
            {
                'id': 'CF-EXEC-001',
                'name': 'Command Execution',
                'severity': 'HIGH',
                # The literal "Runtime.exec" almost never appears in real CFML;
                # the idiomatic form is createObject(...).getRuntime().exec().
                'pattern': re.compile(
                    r'(?:<cfexecute\b'
                    r'|\bRuntime\s*\.\s*exec\s*\('
                    r'|\bgetRuntime\s*\(\s*\)\s*\.\s*exec\s*\()',
                    re.IGNORECASE),
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
                # Word-bounded so identifiers such as sha1Hash or md5sumColumn
                # are not reported, and hyphenated spellings ("SHA-1", the form
                # ColdFusion's hash() actually takes) are.
                'pattern': re.compile(r'\b(?:MessageDigest|MD-?5|SHA-?1)\b', re.IGNORECASE),
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
            # CF-EVAL-002 (retired): its pattern was a strict subset of
            # CF-EVAL-001, so every match it produced was a duplicate finding
            # on the same line. Unlike the EXEC and INCLUDE pairs, evaluate()
            # is spelled identically in tag and script context, so there was
            # no CFScript variant to detect. The ID stays retired rather than
            # being reused, so old baselines remain unambiguous.
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
                'finder': find_xxe,
                'pattern': None,
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
    
    def budget_exceeded(self):
        """Whether a resource limit has cut the scan short.

        Latches so the message is printed once and every later call is cheap.
        Callers treat this as fatal to the run rather than to a single file:
        continuing would produce a partial result set indistinguishable from
        a clean scan.
        """
        if self.incomplete:
            return True
        if time.time() - self.scan_start_time > self.max_scan_time:
            self.incomplete = True
            print(f"Warning: Scan timeout reached after {self.max_scan_time}s; "
                  f"results are INCOMPLETE", file=sys.stderr)
        elif len(self.findings) >= self.max_findings:
            self.incomplete = True
            print(f"Warning: Maximum findings limit reached ({self.max_findings}); "
                  f"results are INCOMPLETE", file=sys.stderr)
        return self.incomplete

    @staticmethod
    def build_line_index(content):
        """Offsets at which each line begins, for O(log n) line lookup."""
        starts = [0]
        for i, ch in enumerate(content):
            if ch == '\n':
                starts.append(i + 1)
        return starts

    @staticmethod
    def line_of_offset(line_starts, offset):
        """1-based line number containing the given character offset."""
        return bisect.bisect_right(line_starts, offset)

    def rule_matches(self, rule, content):
        """Yield (offset, matched_text) pairs for one rule against one file.

        A rule is expressed either as a regex with an optional exclusion, or
        as a `finder` callable for logic regexes cannot express (see
        find_unparameterized_sql). Exclusions are evaluated against the scope
        named by `exclude_scope`:

          'match' - the matched text itself
          'line'  - the whole source line the match starts on

        'line' exists because most mitigations sit adjacent to the sink
        rather than inside it: EncodeForHTML() wraps the variable, so it can
        never appear within a `#form.x#` match.
        """
        finder = rule.get('finder')
        if finder is not None:
            for start, text in finder(content):
                yield start, text
            return

        exclude = rule.get('exclude')
        scope = rule.get('exclude_scope', 'match')
        for match in rule['pattern'].finditer(content):
            if exclude is not None:
                if scope == 'line':
                    line_start = content.rfind('\n', 0, match.start()) + 1
                    line_end = content.find('\n', match.end())
                    haystack = content[line_start:line_end if line_end != -1 else len(content)]
                else:
                    haystack = match.group()
                if exclude.search(haystack):
                    continue
            yield match.start(), match.group()

    def relative_path(self, file_path):
        """Render a path relative to the scan root using forward slashes.

        Findings are reported and keyed in this form so that baselines stay
        valid across machines and CI checkouts, and so that SARIF
        artifactLocation URIs anchor correctly in GitHub code scanning
        (which resolves them against the repository root).
        """
        try:
            resolved = Path(file_path).resolve()
            return resolved.relative_to(Path.cwd().resolve()).as_posix()
        except (ValueError, OSError):
            # Outside the scan root, or unresolvable: fall back to the input
            # rather than inventing a path.
            return Path(file_path).as_posix()

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
            
            # resolve() normalises ".." segments and symlinks; the
            # relative_to() check below is what actually confines the scan.
            # Do not pre-strip ".." or "~" from the string: that corrupts
            # legitimate filenames (report..v2.cfm, draft~1.cfm) and makes
            # them silently unscannable.
            resolved_path = Path(file_path).resolve()

            # Security: Only allow files within current directory tree
            cwd = Path.cwd().resolve()
            try:
                resolved_path.relative_to(cwd)
            except ValueError:
                print(f"Security: Blocked path traversal attempt: {file_path}", file=sys.stderr)
                return
            
            # Every downstream consumer sees this project-relative form.
            rel_path = self.relative_path(resolved_path)

            # Check if file should be ignored
            if self.should_ignore_file(rel_path):
                return

            # Skip very large files for performance
            file_size = resolved_path.stat().st_size
            if file_size > self.max_file_size:
                print(f"Warning: Skipping large file {file_path} ({file_size // 1024 // 1024}MB > {self.max_file_size // 1024 // 1024}MB)", file=sys.stderr)
                return
            
            if self.budget_exceeded():
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

        # Precomputed once per file: turning an offset into a line number by
        # counting newlines in a prefix is O(file) per finding, which becomes
        # quadratic on large files with many findings.
        line_starts = self.build_line_index(content)

        for rule in self.rules:
            try:
                for start, matched_text in self.rule_matches(rule, content):
                    try:
                        line_num = self.line_of_offset(line_starts, start)
                        # Sanitize finding data
                        safe_file = rel_path[:500]
                        safe_match = matched_text[:100].replace('\n', '\\n').replace('\r', '\\r')


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
                            # Checked per match: this is the finest granularity
                            # available without interrupting a regex mid-run.
                            if self.budget_exceeded():
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
        # scanned_count accumulates across calls: --scan-all invokes this once
        # per 50-file batch, and resetting here would report only the last one.
        batch_scanned = 0
        max_files = 10000  # Prevent DoS attacks


        if len(file_paths) > max_files:
            print(f"Error: Too many files specified (max: {max_files})", file=sys.stderr)
            return
        
        for file_path in file_paths:
            # Stop outright rather than looping over the remainder producing
            # nothing: a partial result set must not masquerade as a clean run.
            if self.budget_exceeded():
                break

            try:
                # Input validation
                if not isinstance(file_path, (str, Path)):
                    continue

                # See scan_file(): resolve() plus the relative_to() check below
                # is the confinement mechanism. No string pre-stripping.
                path = Path(file_path).resolve()


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
                    batch_scanned += 1
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
        
        if batch_scanned == 0:
            print("Warning: No valid CFML files were scanned", file=sys.stderr)

    def has_high_severity(self):
        """Whether any HIGH finding survived ignore and baseline filtering.

        Kept separate from print_results so that the --fail-on-high exit code
        is decided by the findings alone and never by the output format.
        """
        if not isinstance(self.findings, list):
            return False
        return any(isinstance(f, dict) and f.get('severity') == 'HIGH' for f in self.findings)

    def print_results(self, json_output=False, sarif_output=False):
        try:
            # Validate findings data
            if not isinstance(self.findings, list):
                print("Error: Invalid findings data", file=sys.stderr)
                return

            if sarif_output:
                sarif_data = self.generate_sarif()
                if sarif_data:
                    print(json.dumps(sarif_data, indent=2, ensure_ascii=True))
                return

            if json_output:
                print(json.dumps(self.findings, indent=2, ensure_ascii=True))
                return

            # Count findings safely
            high = sum(1 for f in self.findings if isinstance(f, dict) and f.get('severity') == 'HIGH')
            medium = sum(1 for f in self.findings if isinstance(f, dict) and f.get('severity') == 'MEDIUM')
            low = sum(1 for f in self.findings if isinstance(f, dict) and f.get('severity') == 'LOW')

            print("=== CFML SAST (edited files) ===")
            print(f"Files scanned: {max(0, self.scanned_count)}")
            print(f"Findings: High={high}  Medium={medium}  Low={low}")

            # Sort and display findings safely
            valid_findings = [f for f in self.findings if isinstance(f, dict) and all(k in f for k in ['severity', 'file', 'line'])]
            # Sort by severity rank, not alphabetically: sorting the strings
            # directly yields HIGH, LOW, MEDIUM and buries the middle tier.
            def sort_key(f):
                return (self.SEVERITY_RANK.get(f['severity'], len(self.SEVERITY_RANK)),
                        f['file'], f['line'])

            for finding in sorted(valid_findings, key=sort_key):
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
        except Exception as e:
            safe_error = str(e)[:200].replace('\n', ' ').replace('\r', ' ')
            print(f"Error generating results: {safe_error}", file=sys.stderr)
    
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
            
            print(f"Baseline updated: {len(self.findings)} findings saved to {baseline_file}",
                  file=sys.stderr)
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
        parser.add_argument('--timeout', type=int, default=300, metavar='SECONDS',
                            help='Wall-clock budget for the scan (default: 300). '
                                 'Exceeding it exits 2 to mark results incomplete.')


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

        scanner = CFMLSASTScanner(max_scan_time=args.timeout)
        scanner.scan_files(safe_files)
        
        # Handle baseline operations
        if args.baseline:
            if args.update_baseline:
                return scanner.update_baseline(args.baseline)
            else:
                scanner.apply_baseline(args.baseline)
        
        scanner.print_results(args.json_out, args.sarif)

        if args.fail_on_high and scanner.has_high_severity():
            return 1
        # Exit 2 distinguishes "scan did not finish" from "scan found nothing",
        # so a pipeline cannot read a truncated run as a pass.
        if scanner.incomplete:
            return 2
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
        
        # Status text goes to stderr so that stdout stays a clean JSON/SARIF
        # payload for CI pipelines and the VS Code extension.
        if not cfml_files:
            print("No changed CFML files found", file=sys.stderr)
            return 0

        print(f"Found {len(cfml_files)} changed CFML files", file=sys.stderr)
        
        # Process files (batch if needed)
        scanner = CFMLSASTScanner(max_scan_time=args.timeout)
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
        
        scanner.print_results(args.json_out, args.sarif)

        if args.fail_on_high and scanner.has_high_severity():
            return 1
        # Exit 2 distinguishes "scan did not finish" from "scan found nothing",
        # so a pipeline cannot read a truncated run as a pass.
        if scanner.incomplete:
            return 2
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
        
        print(f"Found {len(all_files)} CFML files. Processing in batches...", file=sys.stderr)

        # Process in batches to avoid command line length issues
        batch_size = 50
        scanner = CFMLSASTScanner(max_scan_time=args.timeout)

        for i in range(0, len(all_files), batch_size):
            batch = all_files[i:i + batch_size]
            print(f"Processing batch {i//batch_size + 1}/{(len(all_files) + batch_size - 1)//batch_size}...",
                  file=sys.stderr)
            scanner.scan_files(batch)
        
        # Handle baseline operations
        if args.baseline:
            if args.update_baseline:
                return scanner.update_baseline(args.baseline)
            else:
                scanner.apply_baseline(args.baseline)
        
        scanner.print_results(args.json_out, args.sarif)

        if args.fail_on_high and scanner.has_high_severity():
            return 1
        # Exit 2 distinguishes "scan did not finish" from "scan found nothing",
        # so a pipeline cannot read a truncated run as a pass.
        if scanner.incomplete:
            return 2
        return 0
        
    except Exception as e:
        print(f"Error scanning all files: {e}", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())