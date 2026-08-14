# Changelog

All notable changes to the CFML Security Scanner extension.

## [1.4.3]

### Added

- **Every finding now shows how to fix it.** Each card carries a short
  remediation note and the safe form of the construct — `<cfqueryparam>` for
  SQL injection, `encodeForHTML()` for XSS, an `accept` allow-list for uploads,
  and so on for all 14 rules. Advice supplied by the scanner itself takes
  precedence, so a rule added to a newer scanner explains itself without
  needing an extension update.

- **Scanning works immediately after install.** The scanner now ships inside
  the extension, so a fresh Marketplace install can scan without first running
  "Install Git Hooks" or cloning the repository. A copy in the workspace's
  `CFSAST/` folder still wins when present, so a project pinned to a specific
  scanner version keeps using it.

### Changed

- **Python is located more reliably.** Instead of assuming one command name,
  the extension tries the candidates for the platform in order — the `py`
  launcher first on Windows — and verifies each one actually runs before using
  it, with a 5-second cap per candidate so an unresponsive entry on `PATH`
  cannot hang the command. When nothing usable is found, the error says so and
  offers a link to the Python download page rather than failing silently.

### Fixed

- **"Install Git Hooks" no longer crashes on Windows.** The command runs the
  installer with its output piped, so Python picked the legacy ANSI codepage
  (`cp1252`) instead of UTF-8 and died with `UnicodeEncodeError` on the very
  first line it printed — before doing any work. The extension now runs Python
  with `PYTHONIOENCODING=utf-8`, and the installer falls back to plain ASCII
  labels (`[OK]`, `[ERROR]`) when the output stream cannot encode its symbols.

  This fix also shipped in 1.4.2.

## [1.4.2]

### Fixed

- **"Install Git Hooks" no longer crashes on Windows.** The command runs the
  installer with its output piped, so Python picked the legacy ANSI codepage
  (`cp1252`) instead of UTF-8 and died with `UnicodeEncodeError` on the very
  first line it printed — before doing any work. The extension now runs Python
  with `PYTHONIOENCODING=utf-8`, and the installer falls back to plain ASCII
  labels (`[OK]`, `[ERROR]`) when the output stream cannot encode its symbols.

## [1.4.1]

**This extension moved to a new Marketplace listing and was renamed** from
"CFML SAST Scanner" to "CFML Security Scanner". It is now published as
`MadhabDhakal.cfml-security-scanner`; the previous listing
(`MadhabDhakal.cfml-sast-scanner`) was removed, and neither its identifier nor
its display name can be reused. If you installed version 1.3.1 from the old
listing, uninstall it and install this one — the old entry cannot deliver
updates.

Code changes below are relative to 1.3.1. (1.4.0 was never released: an
interrupted upload reserved that version number without publishing it.)

### Added

- **Clickable results.** Select a finding to jump to that file and line —
  click it, or `Tab` to it and press `Enter`/`Space`. Results open beside the
  editor so the list stays visible.
- Results now show the full relative file path instead of just the file name,
  so repeated findings of the same rule can be told apart.
- A warning is shown when a scan does not finish (timeout or findings cap)
  rather than presenting partial results as a clean run.
- A notice when the result list is capped, stating how many findings were
  found in total.

### Fixed

- **SARIF output no longer fails.** Setting `cfmlSast.outputFormat` to `sarif`
  produced "Failed to parse scan results" every time: the parser required a
  JSON array, and SARIF is an object. Both formats are now handled.
- **"Install Git Hooks" now installs a git hook.** It previously downloaded
  only the scanner and never wrote a hook, so the command did not do what its
  name said. It now runs the project installer, which sets up the scanner, the
  pre-push scripts and `.git/hooks/pre-push` together.
- The scan timeout is now enforced. The constant existed but was never applied,
  so a wedged scanner left the command hanging indefinitely.
- Results exceeding the output cap now report that they were truncated instead
  of surfacing as a JSON parse error.
- Workspace containment checks no longer accept a sibling directory whose name
  merely shares a prefix (`/work` admitted `/work-evil`).

### Changed

- `.sastignore` is now applied only by the scanner. The extension had a second
  implementation in JavaScript that had drifted from the Python one — the two
  anchored patterns differently and disagreed about which files to skip.
- The `.sastignore` starter template is now produced by the scanner's
  `--init-ignore`, removing a second copy that could fall out of step.
- The results webview runs its click handler under a per-render CSP nonce. No
  remote or local resources are loadable, and all finding text remains
  HTML-escaped.

### Scanner changes in this release

The bundled scanner received fixes that change what you see:

- **SQL injection detection rewritten.** Each interpolation in a `<cfquery>` is
  now evaluated individually, so a partially parameterized query is correctly
  reported for the clause that is still injectable. Previously a single
  `<cfqueryparam>` anywhere in the query suppressed the whole block.
- **XSS encoder detection now works.** The exclusion was unreachable — a value
  wrapped in `EncodeForHTML()` never matched the pattern it was meant to be
  excluded from. Encoded output is now correctly not reported, and partially
  processed values such as `#trim(form.x)#` are now caught.
- Weak-crypto no longer fires on identifiers that merely contain `md5` or
  `sha1`, and now recognises the hyphenated `SHA-1` spelling.
- Unsafe uploads are detected regardless of attribute order, and
  `nameconflict=` no longer suppresses a finding (it controls overwrite
  behaviour, not upload safety).
- Command execution now detects the idiomatic
  `createObject(...).getRuntime().exec()` chain.
- XXE detection no longer requires the doctype to immediately follow `<cfxml>`.
- Findings are reported with paths relative to the project root, making
  baselines portable between machines and CI, and letting SARIF annotations
  anchor correctly in GitHub code scanning.
- Files whose names contain `..` or `~` are no longer silently skipped.
- `CF-EVAL-002` is retired. Its pattern was a strict subset of `CF-EVAL-001`,
  so it only ever produced duplicate findings on the same line. The rule count
  is now 14.

## [1.3.1]

- Initial published release.
