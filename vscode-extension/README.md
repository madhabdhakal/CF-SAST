# CFML SAST Scanner - VS Code Extension

🔒 **Professional security scanner for ColdFusion files integrated into VS Code**

## Quick Start

1. Install from VS Code Marketplace
2. Right-click any `.cfm`, `.cfc`, or `.cfml` file → "CFML SAST: Scan Current File"
3. Run `CFML SAST: Install Git Hooks` for automatic scanning

## Commands

- `CFML SAST: Scan Current File` - Scan the active file
- `CFML SAST: Scan Changed Files` - Scan Git changed files
- `CFML SAST: Install Git Hooks` - Set up automatic pre-push scanning
- `CFML SAST: Create Baseline` - Suppress existing findings
- `CFML SAST: Create .sastignore File` - Create ignore patterns

## Features

- **13 Security Rules** - SQL injection, XSS, command execution, unsafe uploads
- **CFScript Support** - Modern CFML syntax detection  
- **Visual Results** - Beautiful webview with severity indicators
- **Git Integration** - Scan only changed files automatically
- **Enterprise Ready** - SARIF output, baseline suppression, ignore patterns
- **Zero Dependencies** - Uses Python standard library only

## Security Rules Detected

- SQL Injection (CF-SQLI-001, CF-SQLI-002)
- Cross-Site Scripting (CF-XSS-001, CF-XSS-002)
- Command Execution (CF-EXEC-001, CF-EXEC-002)
- Unsafe File Uploads (CF-UPLOAD-001)
- Dynamic Includes (CF-INCLUDE-001, CF-INCLUDE-002)
- Weak Cryptography (CF-CRYPTO-001)
- Code Evaluation (CF-EVAL-001, CF-EVAL-002)

## Requirements

- VS Code 1.74.0+
- Python 3.6+
- ColdFusion files (`.cfm`, `.cfc`, `.cfml`)

## License

MIT License