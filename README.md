# CFML SAST Scanner

🔒 **Professional security scanner for ColdFusion applications with enterprise features**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![VS Code Extension](https://img.shields.io/badge/VS%20Code-Extension-blue.svg)](https://marketplace.visualstudio.com/items?itemName=MadhabDhakal.cfml-sast-scanner)

## 🚀 Features

- **🔍 Comprehensive Security Rules** - 16+ vulnerability detection patterns
- **⚡ Zero Dependencies** - Uses only Python standard library
- **🎯 Git-Aware Scanning** - Scans only changed/modified files
- **📝 CFScript Support** - Detects modern CFML syntax vulnerabilities
- **🏢 Enterprise Ready** - SARIF 2.1.0 output, baseline suppression, ignore patterns
- **🔧 VS Code Extension** - Professional IDE integration with visual results
- **📊 Multiple Output Formats** - Console, JSON, and SARIF output
- **🛡️ Security Hardened** - Path traversal protection, input validation, timeout controls
- **📈 Performance Optimized** - File size limits, scan timeouts, memory management

## 🔐 Security Rules

### Tag-Based CFML Detection
| Rule ID | Severity | Description |
|---------|----------|-------------|
| **CF-SQLI-001** | 🔴 HIGH | SQL Injection in `<cfquery>` without `<cfqueryparam>` |
| **CF-XSS-001** | 🟡 MEDIUM | Unencoded form/url variables (missing `EncodeForHTML()`) |
| **CF-UPLOAD-001** | 🔴 HIGH | Unsafe file uploads without validation |
| **CF-EXEC-001** | 🔴 HIGH | Command execution via `<cfexecute>` or `Runtime.exec` |
| **CF-INCLUDE-001** | 🟡 MEDIUM | Dynamic includes with user input |
| **CF-CRYPTO-001** | 🔵 LOW | Weak cryptographic algorithms (MD5, SHA1) |
| **CF-EVAL-001** | 🟡 MEDIUM | Dynamic code evaluation with `evaluate()` |
| **CF-LDAP-001** | 🔴 HIGH | LDAP injection vulnerabilities |
| **CF-XXE-001** | 🔴 HIGH | XML External Entity (XXE) attacks |
| **CF-TRAVERSAL-001** | 🔴 HIGH | Directory traversal in file operations |

### CFScript Detection
| Rule ID | Severity | Description |
|---------|----------|-------------|
| **CF-SQLI-002** | 🔴 HIGH | SQL Injection in `queryExecute()` without params |
| **CF-XSS-002** | 🟡 MEDIUM | Unencoded output in `writeOutput()` |
| **CF-EXEC-002** | 🔴 HIGH | Command execution via `cfexecute()` |
| **CF-INCLUDE-002** | 🟡 MEDIUM | Dynamic includes in CFScript |
| **CF-EVAL-002** | 🟡 MEDIUM | Dynamic evaluation in CFScript |

## 📦 Installation

### Option 1: One-Click Install (Recommended)
```bash
# Navigate to your ColdFusion project
cd C:\path\to\your-coldfusion-project

# Download and run secure installer
py -3 -c "import urllib.request; urllib.request.urlretrieve('https://raw.githubusercontent.com/madhabdhakal/CF-SAST/main/install.py', 'install.py')"
py -3 install.py
```

### Option 2: VS Code Extension (Professional)
1. Install **"CFML SAST Scanner"** from VS Code Marketplace
2. Open Command Palette (`Ctrl+Shift+P`)
3. Run: `CFML SAST: Install Git Hooks`
4. Start scanning files with right-click context menu!

### Option 3: Manual Installation
```bash
# Create CFSAST folder
mkdir CFSAST

# Download scanner with integrity verification
py -3 -c "import urllib.request; urllib.request.urlretrieve('https://raw.githubusercontent.com/madhabdhakal/CF-SAST/main/scripts/cfml_sast_simple.py', 'CFSAST/cfml_sast_simple.py')"

# Test installation
py -3 CFSAST/cfml_sast_simple.py --files *.cfm
```

## 🎯 Usage

### Command Line Scanning

**Basic Scanning:**
```bash
# Scan specific files
py -3 CFSAST/cfml_sast_simple.py --files login.cfm user.cfc

# Scan all CFML files in current directory
py -3 CFSAST/cfml_sast_simple.py --files *.cfm *.cfc *.cfml

# Scan with wildcard patterns
py -3 CFSAST/cfml_sast_simple.py --files src/**/*.cfm components/*.cfc
```

**Output Formats:**
```bash
# JSON output (for CI/CD integration)
py -3 CFSAST/cfml_sast_simple.py --files *.cfm --json-out

# SARIF 2.1.0 output (enterprise security tools)
py -3 CFSAST/cfml_sast_simple.py --files *.cfm --sarif

# SARIF with GitHub Advanced Security
py -3 CFSAST/cfml_sast_simple.py --files *.cfm --sarif > results.sarif
```

**Advanced Options:**
```bash
# Fail CI/CD pipeline on high-severity issues
py -3 CFSAST/cfml_sast_simple.py --files *.cfm --fail-on-high

# Create baseline to suppress existing findings
py -3 CFSAST/cfml_sast_simple.py --files *.cfm --baseline .sast-baseline.json --update-baseline

# Scan with baseline (only show NEW findings)
py -3 CFSAST/cfml_sast_simple.py --files *.cfm --baseline .sast-baseline.json

# Initialize .sastignore file for noise management
py -3 CFSAST/cfml_sast_simple.py --init-ignore
```

### VS Code Extension Usage

**File-Level Scanning:**
- **Right-click scanning**: Right-click any `.cfm`, `.cfc`, or `.cfml` file → **"CFML SAST: Scan Current File"**
- **Active file scanning**: Open a CFML file and use Command Palette

**Workspace-Level Scanning:**
- **Changed files**: Command Palette (`Ctrl+Shift+P`) → **"CFML SAST: Scan Changed Files"**
- **Git integration**: Automatically detects changed files since last commit

**Management Commands:**
- **Baseline creation**: **"CFML SAST: Create Baseline"** to suppress existing findings
- **Ignore file**: **"CFML SAST: Create .sastignore File"** for noise management
- **Installation**: **"CFML SAST: Install Git Hooks"** for automated scanning

**Visual Results:**
- Professional webview panel with color-coded severity levels
- Clickable file locations with line numbers
- Summary statistics (High/Medium/Low counts)
- Responsive design matching VS Code theme

### Git Integration (Automated Security)

The scanner automatically runs on `git push` and scans only changed files:

```bash
git add .
git commit -m "Updated user authentication"
git push  # ← SAST scanner runs here automatically
```

**Cross-Platform Git Hooks:**
- **Windows**: `prepush.bat` with proper error handling
- **Unix/Linux/Mac**: `prepush.sh` with strict bash settings
- **Security**: Path validation and input sanitization
- **Performance**: Only scans changed CFML files

## 🎛️ Configuration & Noise Management

### .sastignore File

Create a `.sastignore` file to exclude files, directories, or specific rules:

```bash
# Initialize with default patterns
py -3 CFSAST/cfml_sast_simple.py --init-ignore
```

**Example .sastignore:**
```
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
CF-XSS-001:*/admin/*
CF-SQLI-001:*/legacy/*

# Ignore development/debug files
*debug*
*temp*
*tmp*
*.bak

# Ignore documentation
*/docs/*
*.md
*.txt
```

### Baseline Suppression

Suppress existing findings to focus only on new security issues:

```bash
# Create baseline from current state (one-time setup)
py -3 CFSAST/cfml_sast_simple.py --files *.cfm *.cfc --baseline .sast-baseline.json --update-baseline

# Future scans only show NEW findings
py -3 CFSAST/cfml_sast_simple.py --files *.cfm *.cfc --baseline .sast-baseline.json

# Update baseline when fixing issues
py -3 CFSAST/cfml_sast_simple.py --files *.cfm *.cfc --baseline .sast-baseline.json --update-baseline
```

### VS Code Configuration

**Settings (File → Preferences → Settings → Extensions → CFML SAST):**

```json
{
    "cfmlSast.outputFormat": "json",        // "json" or "sarif"
    "cfmlSast.useBaseline": true,           // Use .sast-baseline.json
    "cfmlSast.showIgnoredFiles": true       // Show ignored file counts
}
```

## 🏢 Enterprise Features

### SARIF 2.1.0 Output

Generate industry-standard SARIF reports for enterprise security tools:

```bash
# GitHub Advanced Security
py -3 CFSAST/cfml_sast_simple.py --files *.cfm --sarif > results.sarif

# Azure DevOps Security
py -3 CFSAST/cfml_sast_simple.py --files src/**/*.cfm --sarif --baseline .sast-baseline.json

# SonarQube Integration
py -3 CFSAST/cfml_sast_simple.py --files *.cfm *.cfc --sarif --fail-on-high
```

### CI/CD Integration

**GitHub Actions:**
```yaml
- name: CFML Security Scan
  run: |
    python -m pip install --upgrade pip
    py -3 CFSAST/cfml_sast_simple.py --files *.cfm *.cfc --sarif --fail-on-high > results.sarif
    
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

**Jenkins Pipeline:**
```groovy
stage('CFML Security Scan') {
    steps {
        sh 'python3 CFSAST/cfml_sast_simple.py --files *.cfm *.cfc --json-out --fail-on-high'
    }
}
```

### Security Features

- **Path Traversal Protection**: Prevents scanning outside project directory
- **Input Validation**: Sanitizes all file paths and arguments
- **Resource Limits**: File size limits (5MB), scan timeouts (5min), memory controls
- **Secure Downloads**: SSL verification and integrity checking
- **Safe Regex**: ReDoS protection in ignore patterns
- **Output Sanitization**: Prevents injection in scan results

## 📊 Performance & Limits

- **Maximum File Size**: 5MB per file
- **Maximum Files**: 10,000 files per scan
- **Scan Timeout**: 5 minutes
- **Maximum Findings**: 10,000 per scan
- **Memory Management**: Automatic cleanup and limits
- **Concurrent Safety**: Thread-safe operations

## 🔧 Requirements

- **Python**: 3.6+ (3.8+ recommended)
- **Git**: For changed file detection and hooks
- **VS Code**: 1.74.0+ (for extension)
- **File Types**: `.cfm`, `.cfc`, `.cfml`, `.cfinclude`
- **Operating Systems**: Windows, macOS, Linux

## 🚀 Getting Started (Quick Start)

1. **Install in your ColdFusion project:**
   ```bash
   cd your-coldfusion-project
   py -3 -c "import urllib.request; urllib.request.urlretrieve('https://raw.githubusercontent.com/madhabdhakal/CF-SAST/main/install.py', 'install.py')"
   py -3 install.py
   ```

2. **Run your first scan:**
   ```bash
   py -3 CFSAST/cfml_sast_simple.py --files *.cfm *.cfc
   ```

3. **Set up noise management:**
   ```bash
   py -3 CFSAST/cfml_sast_simple.py --init-ignore
   py -3 CFSAST/cfml_sast_simple.py --files *.cfm --baseline .sast-baseline.json --update-baseline
   ```

4. **Install VS Code extension** for enhanced experience

## 📝 License

MIT License - See [LICENSE](LICENSE) file.

## 🤝 Contributing

Contributions welcome! Please read our contributing guidelines and submit pull requests to our [GitHub repository](https://github.com/madhabdhakal/CF-SAST).

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/madhabdhakal/CF-SAST/issues)
- **Documentation**: [GitHub Wiki](https://github.com/madhabdhakal/CF-SAST/wiki)
- **VS Code Extension**: [Marketplace](https://marketplace.visualstudio.com/items?itemName=MadhabDhakal.cfml-sast-scanner)