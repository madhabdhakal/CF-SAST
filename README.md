# CFML SAST Scanner

🔒 **Static analysis for ColdFusion (CFML) applications**

[![CI](https://github.com/madhabdhakal/CF-SAST/actions/workflows/ci.yml/badge.svg)](https://github.com/madhabdhakal/CF-SAST/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![VS Code Extension](https://img.shields.io/badge/VS%20Code-Extension-blue.svg)](https://marketplace.visualstudio.com/items?itemName=MadhabDhakal.cfml-sast-scanner)

## 🚀 Features

- **🔍 14 security rules** covering tag-based and CFScript CFML
- **⚡ Zero dependencies** — Python standard library only
- **🎯 Git-aware scanning** — scan only changed files
- **📊 Console, JSON and SARIF 2.1.0 output**
- **🏢 Baseline suppression and `.sastignore` patterns** for adopting the tool on an existing codebase
- **🔧 VS Code extension** with a results panel
- **🪝 Pre-push git hook** for Windows, macOS and Linux

## 🔐 Security Rules

### Tag-based CFML

| Rule ID | Severity | Description |
|---------|----------|-------------|
| **CF-SQLI-001** | 🔴 HIGH | Unparameterized value interpolated into a `<cfquery>` |
| **CF-XSS-001** | 🟡 MEDIUM | `form`/`url` value output without an encoder |
| **CF-UPLOAD-001** | 🔴 HIGH | `<cffile action="upload">` without an `accept` allow-list |
| **CF-EXEC-001** | 🔴 HIGH | Command execution via `<cfexecute>` or `Runtime.exec()` |
| **CF-INCLUDE-001** | 🟡 MEDIUM | `<cfinclude>` with an interpolated template path |
| **CF-CRYPTO-001** | 🔵 LOW | Weak hash algorithm (MD5, SHA-1, `MessageDigest`) |
| **CF-EVAL-001** | 🟡 MEDIUM | Dynamic code evaluation via `evaluate()` |
| **CF-LDAP-001** | 🔴 HIGH | `<cfldap>` filter built from interpolation or concatenation |
| **CF-XXE-001** | 🔴 HIGH | `<cfxml>` block declaring an internal entity |
| **CF-TRAVERSAL-001** | 🔴 HIGH | `<cffile>` destination containing a traversal sequence |

### CFScript

| Rule ID | Severity | Description |
|---------|----------|-------------|
| **CF-SQLI-002** | 🔴 HIGH | `queryExecute()` built by concatenation instead of bound params |
| **CF-XSS-002** | 🟡 MEDIUM | `writeOutput()` of a `form`/`url`/`arguments` value |
| **CF-EXEC-002** | 🔴 HIGH | Command execution via `cfexecute()` |
| **CF-INCLUDE-002** | 🟡 MEDIUM | `include()` with a concatenated path |

> **CF-EVAL-002 is retired.** Its pattern was a strict subset of CF-EVAL-001, so
> it only ever produced duplicate findings on the same line. `evaluate()` is
> spelled identically in tag and script context, so there was no CFScript
> variant to detect. The ID is not reused.

### What CF-SQLI-001 does and does not catch

The rule inspects each `#...#` interpolation in a query body individually. A
value bound through `<cfqueryparam>` is safe; anything else reaches the
database as literal SQL. This is what lets it catch the most common real-world
shape, where most of a query is parameterized and one clause is not:

```cfml
<cfquery name="findUser" datasource="ds">
    SELECT * FROM users
    WHERE id = <cfqueryparam value="#url.id#" cfsqltype="cf_sql_integer">
      AND name = '#url.name#'      <!--- reported: still injectable --->
</cfquery>
```

Like any regex-based scanner this is a lint, not a proof. It does no data-flow
analysis, so it cannot tell a sanitized variable from a tainted one once the
value has been assigned to a local.

## 📦 Installation

### Option 1: Installer (recommended)

Run this from the root of your ColdFusion project. It downloads the scanner
into `CFSAST/` and installs a pre-push hook if the directory is a git
repository.

```bash
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/madhabdhakal/CF-SAST/main/install.py -o install.py
python3 install.py
```

```powershell
# Windows (PowerShell)
curl.exe -fsSL https://raw.githubusercontent.com/madhabdhakal/CF-SAST/main/install.py -o install.py
py -3 install.py
```

### Option 2: VS Code extension

1. Install **"CFML SAST Scanner"** from the VS Code Marketplace
2. Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
3. Run **CFML SAST: Install Git Hooks**
4. Right-click any `.cfm`/`.cfc`/`.cfml` file to scan it

### Option 3: Clone the repository

```bash
git clone https://github.com/madhabdhakal/CF-SAST.git
python3 CF-SAST/scripts/cfml_sast_simple.py --scan-all
```

## 🎯 Usage

Examples use `python3`. On Windows, substitute `py -3`.

### Scanning

```bash
# Scan every CFML file beneath the current directory
python3 CFSAST/cfml_sast_simple.py --scan-all

# Scan only files git reports as changed
python3 CFSAST/cfml_sast_simple.py --scan-changed

# Scan specific files
python3 CFSAST/cfml_sast_simple.py --files login.cfm components/user.cfc
```

> **On `--files` with wildcards:** the scanner does not expand globs itself, it
> relies on the shell. `--files *.cfm` works in bash and zsh but **not** in
> `cmd.exe`, and PowerShell does not expand globs for external commands either.
> On Windows, prefer `--scan-all` or `--scan-changed`.

### Output formats

```bash
# JSON, for scripting
python3 CFSAST/cfml_sast_simple.py --scan-all --json-out

# SARIF 2.1.0, for GitHub code scanning and other security tooling
python3 CFSAST/cfml_sast_simple.py --scan-all --sarif > results.sarif
```

Only the report goes to stdout; progress and warnings go to stderr, so
`--json-out` and `--sarif` can be piped directly into another tool.

Paths in every format are relative to the directory you scan from. That is what
makes a baseline file portable between a developer machine and CI, and what
lets GitHub anchor SARIF annotations to the right lines.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed; no HIGH findings (or `--fail-on-high` not passed) |
| `1` | Scan completed and `--fail-on-high` found at least one HIGH finding |
| `2` | Scan did **not** complete — it hit the time budget or the findings cap, so results are partial |
| `130` | Interrupted (Ctrl-C) |

Exit code `2` exists so a truncated scan cannot be mistaken for a clean one.
Treat it as a failure in CI.

### Noise management

```bash
# Create a starter .sastignore
python3 CFSAST/cfml_sast_simple.py --init-ignore

# Record current findings as the baseline (one-time)
python3 CFSAST/cfml_sast_simple.py --scan-all --baseline .sast-baseline.json --update-baseline

# Later scans report only findings not in the baseline
python3 CFSAST/cfml_sast_simple.py --scan-all --baseline .sast-baseline.json
```

**`.sastignore` matching:** each line is a glob (`*` and `?`) matched as an
**unanchored substring** against the whole relative path. `*test*` therefore
excludes anything with "test" anywhere in its path, including
`src/latest/order.cfm`. Prefer specific patterns such as `tests/*` or
`vendor/*`.

### Other options

| Flag | Purpose |
|------|---------|
| `--fail-on-high` | Exit 1 when a HIGH finding survives ignores and baseline |
| `--timeout SECONDS` | Wall-clock budget (default 300). Exceeding it exits 2 |
| `--baseline FILE` | Suppress findings recorded in FILE |
| `--update-baseline` | Rewrite FILE with the current findings (backs up the old one) |
| `--init-ignore` | Write a starter `.sastignore` |

## 🏢 CI/CD integration

### GitHub Actions

```yaml
- name: CFML security scan
  run: python3 CFSAST/cfml_sast_simple.py --scan-all --sarif > results.sarif
  continue-on-error: true      # let the upload run, then gate below

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif

- name: Gate on high-severity findings
  run: python3 CFSAST/cfml_sast_simple.py --scan-all --fail-on-high
```

The gate is a separate step because `--fail-on-high` exits non-zero, which
would otherwise skip the upload.

### Jenkins

```groovy
stage('CFML security scan') {
    steps {
        sh 'python3 CFSAST/cfml_sast_simple.py --scan-all --json-out --fail-on-high > findings.json'
    }
}
```

## 🔧 VS Code extension

**Commands** (Command Palette):

- **CFML SAST: Scan Current File**
- **CFML SAST: Scan Changed Files**
- **CFML SAST: Install Git Hooks** — installs the scanner and the pre-push hook
- **CFML SAST: Create Baseline**
- **CFML SAST: Create .sastignore File**

**Results panel:** findings are listed as cards showing the rule, severity,
description and the file path with its line number. **Select a finding to jump
straight to that line** — click it, or move to it with `Tab` and press `Enter`
or `Space`. The source opens in the main editor column with the cursor on the
reported line, while the results stay open beside it.

**Settings:**

```json
{
    "cfmlSast.outputFormat": "json",        // "json" or "sarif"
    "cfmlSast.useBaseline": true,           // apply .sast-baseline.json when present
    "cfmlSast.showIgnoredFiles": true       // log skipped-file counts
}
```

The extension does not evaluate `.sastignore` itself; it passes files to the
scanner, which applies the patterns. This keeps one implementation of the
matching rules.

## 🪝 Git hook

`install.py` writes `.git/hooks/pre-push`, which runs the scanner over the CFML
files changed since the upstream branch and blocks the push on a HIGH finding.

The hook is a POSIX shell script on every platform, because git only executes
`.git/hooks/pre-push` — a `pre-push.bat` is never invoked. On Windows this runs
under the bash that ships with Git for Windows. `scripts/sast/prepush.bat` is
provided for running a scan by hand from `cmd.exe`.

`prepush.sh` is written for bash 3.2, the version macOS still ships as
`/bin/bash`.

To bypass the hook for a single push:

```bash
git push --no-verify
```

## 📊 Limits

| Limit | Value | Behaviour when hit |
|-------|-------|--------------------|
| File size | 5 MB | File skipped, warning on stderr |
| Files per invocation | 10,000 | Run aborts with an error |
| Findings | 10,000 | Scan stops, exit code 2 |
| Wall clock | 300s (`--timeout`) | Scan stops, exit code 2 |

## 🛡️ Security properties

Accurately, and no more than this:

- **Scan confinement** — files resolving outside the working directory are
  refused, so a path in a file list cannot pull in `/etc/passwd`.
- **Resource limits** — the caps above bound memory and runtime, and a scan cut
  short reports exit code 2 rather than presenting partial results as complete.
- **Bounded patterns** — rule regexes avoid unbounded nested quantifiers, and
  `.sastignore` patterns are length-capped. Note that the time budget is checked
  between matches; it cannot interrupt a single regex already executing.
- **Output escaping** — the VS Code results panel HTML-escapes all finding text
  and runs with scripts disabled under a restrictive CSP.
- **Transport** — `install.py` downloads over HTTPS with certificate
  verification. There is **no** published hash pinning; if you need supply-chain
  guarantees, clone the repository at a reviewed commit instead of using the
  installer.

The scanner is single-threaded. It makes no thread-safety guarantees because it
needs none.

## 🔧 Requirements

- **Python** 3.8 or newer
- **Git** — for `--scan-changed` and the pre-push hook
- **VS Code** 1.74.0+ for the extension
- **File types** — `.cfm`, `.cfc`, `.cfml`, `.cfinclude`
- **Platforms** — Windows, macOS, Linux

## 🧪 Development

```bash
# Python test suite (rule fixtures, CLI behaviour, git hook integration)
python3 -m unittest discover -s tests -t tests -v

# VS Code extension unit tests
node --test vscode-extension/test/extension.test.js
```

### Adding a rule

1. Add the rule to `self.rules` in `scripts/cfml_sast_simple.py`. Use a
   `pattern` regex, or a `finder` callable when the decision needs more context
   than a regex can express — see `find_unparameterized_sql`.
2. Add a fixture under `tests/fixtures/`, annotating each expected finding with
   an inline `EXPECT: <RULE-ID>` comment on the line it should be reported on.
3. Run the suite. A test is generated per fixture automatically; no
   registration step. Any finding **without** a matching `EXPECT` marker fails
   the test, so fixtures guard against false positives as well as regressions.

```cfml
<cfquery name="q" datasource="ds">
    SELECT * FROM t WHERE id = #url.id#   <!--- EXPECT: CF-SQLI-001 --->
</cfquery>
```

CI runs the suite on Ubuntu, macOS and Windows, shellchecks the git hook, and
verifies that a real SARIF document parses and uses repo-relative URIs.

## 📝 License

MIT — see [LICENSE](LICENSE).

## 🤝 Contributing

Issues and pull requests welcome at the
[GitHub repository](https://github.com/madhabdhakal/CF-SAST). Please include a
fixture with any rule change.

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/madhabdhakal/CF-SAST/issues)
- **VS Code Extension**: [Marketplace](https://marketplace.visualstudio.com/items?itemName=MadhabDhakal.cfml-sast-scanner)
