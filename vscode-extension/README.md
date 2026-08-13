# CFML SAST Scanner

🔒 **Static analysis for ColdFusion (CFML) files, inside VS Code**

Finds SQL injection, XSS, command execution, unsafe uploads, LDAP injection,
XXE and path traversal in `.cfm`, `.cfc` and `.cfml` files — across both
tag-based and CFScript syntax.

## Quick start

1. Install this extension
2. Run **CFML SAST: Install Git Hooks** from the Command Palette
   (`Ctrl+Shift+P` / `Cmd+Shift+P`) — this downloads the scanner into
   `CFSAST/` and sets up a pre-push hook
3. Right-click any `.cfm`, `.cfc` or `.cfml` file → **CFML SAST: Scan Current File**

> **Requires Python 3.8+** on your `PATH`. The scanner itself is a single
> Python file with no third-party dependencies.

## Jump straight to a finding

Results appear as cards showing the rule, severity, description, file path and
line. **Select a finding to jump to that line** — click it, or `Tab` to it and
press `Enter`. The source opens in the main editor while the results stay open
beside it.

## Commands

| Command | Purpose |
|---------|---------|
| **CFML SAST: Scan Current File** | Scan the active or right-clicked file |
| **CFML SAST: Scan Changed Files** | Scan only what git reports as modified |
| **CFML SAST: Install Git Hooks** | Install the scanner and the pre-push hook |
| **CFML SAST: Create Baseline** | Record current findings so later scans show only new ones |
| **CFML SAST: Create .sastignore File** | Write a starter ignore file |

## Security rules

14 rules covering both CFML dialects.

**Tag-based:** SQL injection in `<cfquery>` (CF-SQLI-001), unencoded `form`/`url`
output (CF-XSS-001), unsafe `<cffile action="upload">` (CF-UPLOAD-001), command
execution (CF-EXEC-001), dynamic `<cfinclude>` (CF-INCLUDE-001), weak hashes
(CF-CRYPTO-001), `evaluate()` (CF-EVAL-001), LDAP filter injection
(CF-LDAP-001), XXE in `<cfxml>` (CF-XXE-001), path traversal (CF-TRAVERSAL-001).

**CFScript:** `queryExecute()` concatenation (CF-SQLI-002), unencoded
`writeOutput()` (CF-XSS-002), `cfexecute()` (CF-EXEC-002), concatenated
`include()` (CF-INCLUDE-002).

### SQL injection detection

Each `#...#` interpolation in a query is judged on its own. A value bound
through `<cfqueryparam>` is safe; anything else is reported. That means a query
which is *mostly* parameterized is still flagged for the clause that is not —
the most common way CFML injection reaches production:

```cfml
<cfquery name="findUser" datasource="ds">
    SELECT * FROM users
    WHERE id = <cfqueryparam value="#url.id#" cfsqltype="cf_sql_integer">
      AND name = '#url.name#'      <!--- reported: still injectable --->
</cfquery>
```

Like any pattern-based scanner this is a lint, not a proof. It performs no
data-flow analysis, so it cannot follow a value once it has been assigned to a
local variable.

## Managing noise

**Baseline** — run **CFML SAST: Create Baseline** to record everything you have
today. Later scans report only findings that are not in the baseline, so you
can adopt the tool on an existing codebase without a wall of results.

**.sastignore** — run **CFML SAST: Create .sastignore File** for a starter
template. Each line is a glob matched as an *unanchored substring* against the
whole relative path, so `*test*` also excludes `src/latest/order.cfm`. Prefer
specific patterns such as `tests/*` or `vendor/*`.

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `cfmlSast.outputFormat` | `json` | `json` or `sarif` |
| `cfmlSast.useBaseline` | `true` | Apply `.sast-baseline.json` when present |
| `cfmlSast.showIgnoredFiles` | `true` | Log counts of files skipped before scanning |

## Requirements

- **VS Code** 1.74.0 or newer
- **Python** 3.8 or newer on your `PATH`
- **Git** for changed-file scanning and the pre-push hook

## Command line

The same scanner runs standalone and in CI, with SARIF output for GitHub code
scanning. See the
[project README](https://github.com/madhabdhakal/CF-SAST#readme).

## License

MIT — see [LICENSE](LICENSE).

## Issues

Please report bugs at
[github.com/madhabdhakal/CF-SAST/issues](https://github.com/madhabdhakal/CF-SAST/issues).
