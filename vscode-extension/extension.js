const vscode = require('vscode');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Security constants
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
const MAX_OUTPUT_SIZE = 1024 * 1024; // 1MB
const MAX_FILES = 1000;
const SCAN_TIMEOUT = 120000; // 2 minutes
const CFML_EXTENSIONS = /\.(cfm|cfc|cfml|cfinclude)$/i;

// Exit codes from the scanner.
const EXIT_INCOMPLETE = 2;

const SEVERITY_BY_SARIF_LEVEL = { error: 'HIGH', warning: 'MEDIUM', note: 'LOW' };

/**
 * Whether `child` lies inside `parent`.
 *
 * A plain startsWith() comparison also accepts a sibling whose name merely
 * shares the prefix, so /work would admit /work-evil.
 */
function isInside(parent, child) {
    const rel = path.relative(path.resolve(parent), path.resolve(child));
    return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

/**
 * Resolve a finding's path to an absolute path inside the workspace.
 *
 * Findings carry paths relative to the scan root, so they need resolving
 * before the editor can open them. Returns null when the result would land
 * outside the workspace, so a crafted or corrupted scanner result cannot make
 * the extension open an arbitrary file on disk.
 */
function resolveFindingPath(workspacePath, file) {
    if (typeof file !== 'string' || file.length === 0) {
        return null;
    }
    const absolute = path.isAbsolute(file)
        ? path.resolve(file)
        : path.resolve(workspacePath, file);
    return isInside(workspacePath, absolute) ? absolute : null;
}

/**
 * Normalise scanner stdout into a findings array.
 *
 * The scanner writes only the payload to stdout (progress goes to stderr), so
 * this parses the whole stream rather than hunting for bracket boundaries.
 * Both output formats are accepted: `outputFormat: "sarif"` used to produce a
 * document this parser rejected outright, because SARIF is an object and the
 * old code asserted an array.
 */
function parseFindings(stdout) {
    const text = (stdout || '').trim();
    if (!text) {
        return [];
    }

    const parsed = JSON.parse(text);

    if (Array.isArray(parsed)) {
        return parsed;
    }

    if (parsed && Array.isArray(parsed.runs)) {
        const findings = [];
        for (const run of parsed.runs) {
            for (const result of run.results || []) {
                const loc = (result.locations || [])[0] || {};
                const physical = loc.physicalLocation || {};
                findings.push({
                    file: (physical.artifactLocation || {}).uri || '',
                    line: (physical.region || {}).startLine || 1,
                    rule_id: result.ruleId || '',
                    severity: SEVERITY_BY_SARIF_LEVEL[result.level] || 'MEDIUM',
                    description: (result.message || {}).text || ''
                });
            }
        }
        return findings;
    }

    throw new Error('Unrecognised scanner output');
}

/** Clamp and coerce findings coming back from an external process. */
function sanitizeFindings(findings) {
    const out = [];
    for (const f of findings.slice(0, 1000)) {
        if (!f || typeof f !== 'object') continue;
        out.push({
            file: typeof f.file === 'string' ? f.file.substring(0, 500) : '',
            line: typeof f.line === 'number' ? Math.max(1, Math.min(f.line, 999999)) : 1,
            rule_id: typeof f.rule_id === 'string' ? f.rule_id.substring(0, 50) : '',
            severity: ['HIGH', 'MEDIUM', 'LOW'].includes(f.severity) ? f.severity : 'UNKNOWN',
            description: typeof f.description === 'string' ? f.description.substring(0, 1000) : ''
        });
    }
    return out;
}

function generateResultsHtml(findings) {
    // Fresh per render, so the CSP admits only this page's own inline
    // script block.
    const nonce = crypto.randomBytes(16).toString('base64');

    // Escape HTML to prevent XSS
    const escapeHtml = (text) => {
        return String(text)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    };
    
    const getSeverityIcon = (severity) => {
        switch(severity) {
            case 'HIGH': return '🔴';
            case 'MEDIUM': return '🟡';
            case 'LOW': return '🔵';
            default: return '⚪';
        }
    };
    
    const shown = findings.slice(0, 500);
    const cards = shown.map((f, index) => {
        const severity = escapeHtml(f.severity || 'UNKNOWN');
        const ruleId = escapeHtml(f.rule_id || 'N/A');
        // The full relative path, not just the basename: with several
        // matches of the same rule, the basename alone cannot tell them
        // apart, and the path is what identifies the file to open.
        const filePath = escapeHtml(f.file || 'unknown');
        const line = parseInt(f.line) || 0;
        const description = escapeHtml(f.description || 'No description');
        const icon = getSeverityIcon(severity);

        return `
            <div class="finding-card ${severity.toLowerCase()}"
                 role="button"
                 tabindex="0"
                 data-index="${index}"
                 title="Open ${filePath} at line ${line}">
                <div class="card-header">
                    <span class="severity-badge">${icon} ${severity}</span>
                    <span class="rule-id">${ruleId}</span>
                </div>
                <div class="card-body">
                    <div class="description">${description}</div>
                    <div class="location">
                        <span class="file-name">${filePath}</span>
                        <span class="line-number">Line ${line}</span>
                    </div>
                </div>
            </div>`;
    }).join('');

    const truncationNote = findings.length > shown.length
        ? `<div class="tip">Showing the first ${shown.length} of ${findings.length} findings.
               Use the CLI for the full list.</div>`
        : '';

    const high = findings.filter(f => f.severity === 'HIGH').length;
    const medium = findings.filter(f => f.severity === 'MEDIUM').length;
    const low = findings.filter(f => f.severity === 'LOW').length;
    
    return `<!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
        <title>CFML SAST Results</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 0;
                padding: 20px;
                background: var(--vscode-editor-background);
                color: var(--vscode-editor-foreground);
                line-height: 1.5;
            }
            
            .header {
                margin-bottom: 24px;
                padding-bottom: 16px;
                border-bottom: 1px solid var(--vscode-panel-border);
            }
            
            .title {
                font-size: 24px;
                font-weight: 600;
                margin: 0 0 8px 0;
                color: var(--vscode-editor-foreground);
            }
            
            .summary {
                display: flex;
                gap: 16px;
                margin: 16px 0;
            }
            
            .stat {
                padding: 8px 12px;
                border-radius: 6px;
                font-weight: 500;
                font-size: 14px;
            }
            
            .stat.high { background: rgba(244, 67, 54, 0.1); color: #f44336; }
            .stat.medium { background: rgba(255, 152, 0, 0.1); color: #ff9800; }
            .stat.low { background: rgba(33, 150, 243, 0.1); color: #2196f3; }
            
            .findings {
                display: flex;
                flex-direction: column;
                gap: 12px;
            }
            
            .finding-card {
                background: var(--vscode-editor-widget-background);
                border: 1px solid var(--vscode-panel-border);
                border-radius: 8px;
                padding: 16px;
                transition: all 0.2s ease;
                cursor: pointer;
            }

            .finding-card:hover {
                border-color: var(--vscode-focusBorder);
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                background: var(--vscode-list-hoverBackground);
            }

            /* Keyboard users get the same affordance as mouse users. */
            .finding-card:focus-visible {
                outline: 1px solid var(--vscode-focusBorder);
                outline-offset: 2px;
            }

            .finding-card:active {
                background: var(--vscode-list-activeSelectionBackground);
            }
            
            .card-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 12px;
            }
            
            .severity-badge {
                font-weight: 600;
                font-size: 14px;
            }
            
            .rule-id {
                font-family: 'Courier New', monospace;
                font-size: 12px;
                background: var(--vscode-badge-background);
                color: var(--vscode-badge-foreground);
                padding: 4px 8px;
                border-radius: 4px;
            }
            
            .description {
                font-size: 14px;
                margin-bottom: 8px;
                color: var(--vscode-editor-foreground);
            }
            
            .location {
                display: flex;
                justify-content: space-between;
                align-items: center;
                font-size: 12px;
                color: var(--vscode-descriptionForeground);
            }
            
            .file-name {
                font-family: 'Courier New', monospace;
                font-weight: 500;
                color: var(--vscode-textLink-foreground);
                text-decoration: underline;
                word-break: break-all;
            }
            
            .line-number {
                background: var(--vscode-textBlockQuote-background);
                padding: 2px 6px;
                border-radius: 3px;
            }
            
            .tip {
                margin-top: 24px;
                padding: 12px;
                background: var(--vscode-textBlockQuote-background);
                border-left: 4px solid var(--vscode-textLink-foreground);
                border-radius: 0 4px 4px 0;
                font-size: 13px;
                color: var(--vscode-descriptionForeground);
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1 class="title">🔍 CFML Security Scan Results</h1>
            <div class="summary">
                <div class="stat high">🔴 ${high} High</div>
                <div class="stat medium">🟡 ${medium} Medium</div>
                <div class="stat low">🔵 ${low} Low</div>
            </div>
        </div>
        
        <div class="findings">
            ${cards}
        </div>

        ${truncationNote}

        <div class="tip">
            💡 <strong>Tip:</strong> Select a finding to jump to that line. Use a
            <code>.sastignore</code> file to exclude paths, or a baseline to suppress
            existing findings.
        </div>

        <script nonce="${nonce}">
            (function () {
                const vscodeApi = acquireVsCodeApi();

                // Only the card's index travels back to the extension; the
                // file path is resolved there, not supplied from here.
                function open(card) {
                    vscodeApi.postMessage({
                        command: 'open',
                        index: Number(card.getAttribute('data-index'))
                    });
                }

                for (const card of document.querySelectorAll('.finding-card')) {
                    card.addEventListener('click', () => open(card));
                    card.addEventListener('keydown', (event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                            event.preventDefault();
                            open(card);
                        }
                    });
                }
            })();
        </script>
    </body>
    </html>`;
}

function activate(context) {
    const scanFile = vscode.commands.registerCommand('cfmlSast.scanFile', (uri) => {
        const filePath = uri ? uri.fsPath : vscode.window.activeTextEditor?.document.fileName;
        if (!filePath) {
            vscode.window.showErrorMessage('No file selected');
            return;
        }
        
        runScan([filePath], false);
    });

    const scanWorkspace = vscode.commands.registerCommand('cfmlSast.scanWorkspace', () => {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            vscode.window.showErrorMessage('No workspace folder found');
            return;
        }
        
        runScanChanged(workspaceFolder.uri.fsPath);
    });

    const createIgnoreFile = vscode.commands.registerCommand('cfmlSast.createIgnoreFile', () => {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            vscode.window.showErrorMessage('No workspace folder found');
            return;
        }
        
        const ignorePath = path.join(workspaceFolder.uri.fsPath, '.sastignore');
        
        // Security: Validate path
        try {
            const resolvedPath = path.resolve(ignorePath);
            if (!isInside(workspaceFolder.uri.fsPath, resolvedPath)) {
                vscode.window.showErrorMessage('Invalid file path');
                return;
            }
        } catch (error) {
            vscode.window.showErrorMessage('Path validation failed');
            return;
        }
        
        if (fs.existsSync(ignorePath)) {
            vscode.window.showWarningMessage('.sastignore already exists');
            return;
        }

        // Delegate to the scanner's --init-ignore rather than keeping a second
        // copy of the template here; the two would drift apart otherwise.
        const workspacePath = workspaceFolder.uri.fsPath;
        const scannerPath = path.join(workspacePath, 'CFSAST', 'cfml_sast_simple.py');
        if (!fs.existsSync(scannerPath)) {
            vscode.window.showErrorMessage('CFML SAST scanner not found. Run "CFML SAST: Install Git Hooks" first.');
            return;
        }

        const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';
        const proc = spawn(pythonCmd, [scannerPath, '--init-ignore'], {
            cwd: workspacePath,
            stdio: ['ignore', 'pipe', 'pipe']
        });

        let procStderr = '';
        proc.stderr.on('data', (data) => { procStderr += data.toString(); });

        proc.on('close', (code) => {
            if (code !== 0) {
                vscode.window.showErrorMessage(`Failed to create .sastignore: ${procStderr.trim()}`);
                return;
            }
            vscode.window.showInformationMessage('✅ Created .sastignore file with default patterns');
            vscode.workspace.openTextDocument(ignorePath).then(doc => {
                vscode.window.showTextDocument(doc);
            });
        });
    });
    
    const createBaseline = vscode.commands.registerCommand('cfmlSast.createBaseline', () => {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            vscode.window.showErrorMessage('No workspace folder found');
            return;
        }
        
        vscode.window.showInformationMessage('Creating baseline from current findings...');
        
        const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';
        const scannerPath = path.join(workspaceFolder.uri.fsPath, 'CFSAST', 'cfml_sast_simple.py');
        
        // Security: Validate scanner path
        try {
            const resolvedPath = path.resolve(scannerPath);
            if (!isInside(workspaceFolder.uri.fsPath, resolvedPath) || !fs.existsSync(resolvedPath)) {
                vscode.window.showErrorMessage('CFML SAST scanner not found. Install first.');
                return;
            }
        } catch (error) {
            vscode.window.showErrorMessage('Scanner path validation failed');
            return;
        }
        
        // Get CFML files using git
        const gitProcess = spawn('git', ['ls-files', '*.cfm', '*.cfc', '*.cfml'], {
            cwd: workspaceFolder.uri.fsPath,
            stdio: ['ignore', 'pipe', 'pipe']
        });
        
        let stdout = '';
        let stderr = '';
        
        gitProcess.stdout.on('data', (data) => {
            stdout += data.toString();
            if (stdout.length > 500000) gitProcess.kill();
        });
        
        gitProcess.stderr.on('data', (data) => {
            stderr += data.toString();
        });
        
        gitProcess.on('close', (code) => {
            if (code !== 0) {
                vscode.window.showErrorMessage(`Git command failed: ${stderr}`);
                return;
            }
            
            const files = stdout.trim().split('\n').filter(f => f && f.length < 500);
            if (files.length === 0) {
                vscode.window.showInformationMessage('No CFML files found in repository');
                return;
            }
            
            if (files.length > MAX_FILES) {
                vscode.window.showErrorMessage(`Too many files (${files.length}). Maximum: ${MAX_FILES}`);
                return;
            }
            
            const baselinePath = path.join(workspaceFolder.uri.fsPath, '.sast-baseline.json');
            const args = [scannerPath, '--files', ...files, '--baseline', baselinePath, '--update-baseline'];
            
            const pythonProcess = spawn(pythonCmd, args, {
                cwd: workspaceFolder.uri.fsPath,
                stdio: ['ignore', 'pipe', 'pipe']
            });
            
            let pythonStdout = '';
            let pythonStderr = '';
            
            pythonProcess.stdout.on('data', (data) => {
                pythonStdout += data.toString();
                if (pythonStdout.length > MAX_OUTPUT_SIZE) pythonProcess.kill();
            });
            
            pythonProcess.stderr.on('data', (data) => {
                pythonStderr += data.toString();
            });
            
            pythonProcess.on('close', (code) => {
                if (code !== 0) {
                    vscode.window.showErrorMessage(`Baseline creation failed: ${pythonStderr}`);
                    return;
                }
                
                vscode.window.showInformationMessage('✅ Baseline created successfully! New scans will only show new findings.');
            });
        });
    });
    
    const install = vscode.commands.registerCommand('cfmlSast.install', () => {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            vscode.window.showErrorMessage('No workspace folder found');
            return;
        }
        
        vscode.window.showInformationMessage('Installing CFML SAST Scanner...');
        
        const workspacePath = workspaceFolder.uri.fsPath;
        const targetDir = path.join(workspacePath, 'CFSAST');
        const targetFile = path.join(targetDir, 'cfml_sast_simple.py');
        
        try {
            // Security: Validate paths
            const resolvedTargetDir = path.resolve(targetDir);
            const resolvedWorkspace = path.resolve(workspacePath);
            
            if (!isInside(resolvedWorkspace, resolvedTargetDir)) {
                vscode.window.showErrorMessage('Invalid installation path');
                return;
            }
            
            // Create CFSAST directory
            if (!fs.existsSync(resolvedTargetDir)) {
                fs.mkdirSync(resolvedTargetDir, { recursive: true });
            }
            
            // Try different Python commands
            const pythonCommands = process.platform === 'win32'
                ? ['py', 'python', 'python3']
                : ['python3', 'python'];

            // Fetch install.py and run it, rather than reimplementing the
            // install here. This command is titled "Install Git Hooks", and
            // the previous inline script downloaded only the scanner — it
            // never wrote a hook, so the command did not do what it said.
            // install.py sets up the scanner, the prepush scripts and
            // .git/hooks/pre-push together.
            const script = [
                'import ssl, urllib.request, runpy',
                "url = 'https://raw.githubusercontent.com/madhabdhakal/CF-SAST/main/install.py'",
                "req = urllib.request.Request(url, headers={'User-Agent': 'CFML-SAST-Extension'})",
                'ctx = ssl.create_default_context()',
                'with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:',
                '    data = resp.read()',
                'if len(data) > 1024 * 1024:',
                "    raise SystemExit('installer unexpectedly large')",
                "open('install.py', 'wb').write(data)",
                "runpy.run_path('install.py', run_name='__main__')"
            ].join('\n');

            let commandIndex = 0;
            
            function tryNextPython() {
                if (commandIndex >= pythonCommands.length) {
                    vscode.window.showErrorMessage(
                        'Python not found. Please install Python 3.6+ and ensure it\'s in your PATH.',
                        'Download Python'
                    ).then(selection => {
                        if (selection === 'Download Python') {
                            vscode.env.openExternal(vscode.Uri.parse('https://python.org/downloads'));
                        }
                    });
                    return;
                }
                
                const pythonCmd = pythonCommands[commandIndex];
                commandIndex++;
                
                // PYTHONIOENCODING is required: stdout is a pipe here, so
                // Python falls back to the ANSI codepage (cp1252 on most
                // Windows installs) and the installer's non-ASCII output
                // raises UnicodeEncodeError before it does any work.
                const pythonProcess = spawn(pythonCmd, ['-c', script], {
                    cwd: workspacePath,
                    stdio: ['ignore', 'pipe', 'pipe'],
                    env: { ...process.env, PYTHONIOENCODING: 'utf-8' }
                });
                
                let stdout = '';
                let stderr = '';
                
                pythonProcess.stdout.on('data', (data) => {
                    stdout += data.toString();
                    if (stdout.length > 1024 * 1024) pythonProcess.kill();
                });
                
                pythonProcess.stderr.on('data', (data) => {
                    stderr += data.toString();
                });
                
                pythonProcess.on('close', (code) => {
                    if (code !== 0) {
                        if (stderr.includes('not found') || stderr.includes('not recognized')) {
                            tryNextPython();
                            return;
                        } else {
                            vscode.window.showErrorMessage(`Installation failed with ${pythonCmd}: ${stderr}`);
                            return;
                        }
                    }
                    
                    if (fs.existsSync(targetFile)) {
                        const hookInstalled = fs.existsSync(path.join(workspacePath, '.git', 'hooks', 'pre-push'));
                        vscode.window.showInformationMessage(
                            `✅ CFML SAST installed using ${pythonCmd}` +
                            (hookInstalled ? ' (pre-push hook active)' : ' (no git repo - hook skipped)'));
                    } else {
                        vscode.window.showErrorMessage('Installation failed - scanner file not created');
                    }
                });
            }
            
            tryNextPython();
        } catch (error) {
            vscode.window.showErrorMessage(`Installation failed: ${error.message}`);
        }
    });

    function runScanChanged(workspacePath) {
        const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';
        const scannerPath = path.join(workspacePath, 'CFSAST', 'cfml_sast_simple.py');
        
        // Security: Validate scanner path
        try {
            const resolvedScannerPath = path.resolve(scannerPath);
            if (!isInside(workspacePath, resolvedScannerPath) || !fs.existsSync(resolvedScannerPath)) {
                vscode.window.showErrorMessage('CFML SAST scanner not found. Run "CFML SAST: Install Git Hooks" first.');
                return;
            }
        } catch (error) {
            vscode.window.showErrorMessage('Invalid scanner path');
            return;
        }
        
        // Build command arguments for changed files scan
        const args = [scannerPath, '--scan-changed', '--json-out'];
        
        // Add configuration options
        const config = vscode.workspace.getConfiguration('cfmlSast');
        if (config.get('outputFormat') === 'sarif') {
            args[args.indexOf('--json-out')] = '--sarif';
        }
        
        // Add baseline support if enabled
        const baselinePath = path.join(workspacePath, '.sast-baseline.json');
        if (config.get('useBaseline', true) && fs.existsSync(baselinePath)) {
            args.push('--baseline', baselinePath);
        }
        
        vscode.window.showInformationMessage('🔍 Scanning changed CFML files...');
        
        // Execute scan
        const pythonProcess = spawn(pythonCmd, args, {
            cwd: workspacePath,
            stdio: ['ignore', 'pipe', 'pipe'],
            // Without this the command hangs forever if the scanner wedges.
            timeout: SCAN_TIMEOUT,
            env: { ...process.env, PYTHONIOENCODING: 'utf-8' }
        });

        let stdout = '';
        let stderr = '';
        let truncated = false;

        pythonProcess.stdout.on('data', (data) => {
            stdout += data.toString();
            if (stdout.length > MAX_OUTPUT_SIZE) {
                // Killing mid-stream leaves stdout as invalid JSON, so record
                // why rather than reporting it as a parse failure.
                truncated = true;
                pythonProcess.kill();
            }
        });
        
        pythonProcess.stderr.on('data', (data) => {
            stderr += data.toString();
        });
        
        pythonProcess.on('close', (code) => {
            if (code === EXIT_INCOMPLETE) {
                vscode.window.showWarningMessage(
                    '⚠️ Scan did not finish (timeout or findings limit). Results are incomplete.');
            }

            if (!stdout.trim()) {
                if (stderr.includes('No changed CFML files found')) {
                    vscode.window.showInformationMessage('✅ No changed CFML files to scan');
                } else if (code !== 0 && code !== EXIT_INCOMPLETE) {
                    vscode.window.showErrorMessage(`Scan failed: ${stderr}`);
                } else {
                    vscode.window.showInformationMessage('✅ No security issues found in changed files');
                }
                return;
            }

            if (truncated) {
                vscode.window.showWarningMessage(
                    `⚠️ Results exceeded ${Math.round(MAX_OUTPUT_SIZE / 1024)}KB and were truncated. ` +
                    'Use the CLI for a full scan: python3 CFSAST/cfml_sast_simple.py --scan-all --json-out');
                return;
            }

            try {
                const findings = sanitizeFindings(parseFindings(stdout));
                if (findings.length === 0) {
                    vscode.window.showInformationMessage('✅ No security issues found in changed files');
                    return;
                }
                showResults(findings, true, workspacePath);
            } catch (parseError) {
                vscode.window.showErrorMessage(`Failed to parse scan results: ${parseError.message}`);
            }
        });
    }

    function runScan(files, isWorkspace) {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            vscode.window.showErrorMessage('No workspace folder found');
            return;
        }
        
        // Input validation
        if (!Array.isArray(files) || files.length === 0) {
            vscode.window.showErrorMessage('No files provided for scanning');
            return;
        }
        
        if (files.length > MAX_FILES) {
            vscode.window.showErrorMessage(`Too many files (${files.length}). Maximum allowed: ${MAX_FILES}`);
            return;
        }
        
        // Convert to absolute paths and validate
        const workspacePath = path.resolve(workspaceFolder.uri.fsPath);
        const absoluteFiles = [];
        
        for (const file of files) {
            try {
                if (typeof file !== 'string' || file.length > 500) continue;
                
                let resolvedPath;
                if (path.isAbsolute(file)) {
                    resolvedPath = path.resolve(file);
                } else {
                    resolvedPath = path.resolve(workspacePath, file);
                }
                
                // Security: Prevent path traversal
                if (!isInside(workspacePath, resolvedPath)) {
                    console.warn(`Blocked path traversal attempt: ${file}`);
                    continue;
                }
                
                // Check file exists and is CFML. .sastignore is deliberately
                // NOT evaluated here: the scanner applies it, and a second
                // implementation in JS drifted from the Python one (anchored
                // vs unanchored matching gave different results for the same
                // pattern).
                if (fs.existsSync(resolvedPath) &&
                    fs.statSync(resolvedPath).isFile() &&
                    CFML_EXTENSIONS.test(resolvedPath)) {


                    // Check file size
                    const stats = fs.statSync(resolvedPath);
                    if (stats.size > MAX_FILE_SIZE) {
                        console.warn(`Skipping large file: ${file} (${Math.round(stats.size/1024/1024)}MB)`);
                        continue;
                    }
                    
                    absoluteFiles.push(resolvedPath);
                }
            } catch (error) {
                console.warn(`Error processing file ${file}: ${error.message}`);
            }
        }
        
        const totalFiles = files.filter(f => typeof f === 'string' && CFML_EXTENSIONS.test(f)).length;
        const skippedCount = totalFiles - absoluteFiles.length;

        if (absoluteFiles.length === 0) {
            if (skippedCount > 0) {
                vscode.window.showInformationMessage(
                    `No CFML files to scan (${skippedCount} skipped: missing, too large, or outside the workspace)`);
            } else {
                vscode.window.showInformationMessage('No valid CFML files found to scan');
            }
            return;
        }

        const config = vscode.workspace.getConfiguration('cfmlSast');
        if (skippedCount > 0 && config.get('showIgnoredFiles', true)) {
            console.log(`CFML SAST: skipped ${skippedCount} files before scanning`);
        }


        const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';
        const scannerPath = path.join(workspacePath, 'CFSAST', 'cfml_sast_simple.py');
        
        // Security: Validate scanner path
        try {
            const resolvedScannerPath = path.resolve(scannerPath);
            if (!isInside(workspacePath, resolvedScannerPath) || !fs.existsSync(resolvedScannerPath)) {
                vscode.window.showErrorMessage('CFML SAST scanner not found. Run "CFML SAST: Install Git Hooks" first.');
                return;
            }
        } catch (error) {
            vscode.window.showErrorMessage('Invalid scanner path');
            return;
        }
        
        // Build command arguments safely
        const args = [scannerPath, '--files', ...absoluteFiles, '--json-out'];
        
        // Add SARIF output for enterprise users
        const outputFormat = config.get('outputFormat');
        if (outputFormat === 'sarif') {
            args[args.indexOf('--json-out')] = '--sarif';
        }
        
        // Add baseline support if enabled
        const baselinePath = path.join(workspacePath, '.sast-baseline.json');
        if (config.get('useBaseline', true) && fs.existsSync(baselinePath)) {
            args.push('--baseline', baselinePath);
        }
        
        // Execute scan with security measures
        const pythonProcess = spawn(pythonCmd, args, {
            cwd: workspacePath,
            stdio: ['ignore', 'pipe', 'pipe'],
            // Without this the command hangs forever if the scanner wedges.
            timeout: SCAN_TIMEOUT,
            env: { ...process.env, PYTHONIOENCODING: 'utf-8' }
        });

        let stdout = '';
        let stderr = '';
        let truncated = false;

        pythonProcess.stdout.on('data', (data) => {
            stdout += data.toString();
            if (stdout.length > MAX_OUTPUT_SIZE) {
                // Killing mid-stream leaves stdout as invalid JSON, so record
                // why rather than reporting it as a parse failure.
                truncated = true;
                pythonProcess.kill();
            }
        });
        
        pythonProcess.stderr.on('data', (data) => {
            stderr += data.toString();
        });
        
        pythonProcess.on('close', (code) => {
            if (code === EXIT_INCOMPLETE) {
                vscode.window.showWarningMessage(
                    '⚠️ Scan did not finish (timeout or findings limit). Results are incomplete.');
            }

            if (!stdout.trim()) {
                if (code !== 0 && code !== EXIT_INCOMPLETE) {
                    vscode.window.showErrorMessage(`Scan failed: ${stderr}`);
                } else {
                    vscode.window.showInformationMessage('✅ Scan completed with no security issues found');
                }
                return;
            }

            if (truncated) {
                vscode.window.showWarningMessage(
                    `⚠️ Results exceeded ${Math.round(MAX_OUTPUT_SIZE / 1024)}KB and were truncated. ` +
                    'Use the CLI for a full scan: python3 CFSAST/cfml_sast_simple.py --scan-all --json-out');
                return;
            }

            try {
                const findings = sanitizeFindings(parseFindings(stdout));
                if (findings.length === 0) {
                    vscode.window.showInformationMessage('✅ Scan completed with no security issues found');
                    return;
                }
                showResults(findings, isWorkspace, workspacePath);
            } catch (parseError) {
                console.error('Parse error:', parseError);
                vscode.window.showErrorMessage(`Failed to parse scan results: ${parseError.message}`);
            }
        });
    }

    function showResults(findings, isWorkspace, workspacePath) {
        if (findings.length === 0) {
            vscode.window.showInformationMessage('✅ No security issues found');
            return;
        }

        const high = findings.filter(f => f.severity === 'HIGH').length;
        const medium = findings.filter(f => f.severity === 'MEDIUM').length;
        const low = findings.filter(f => f.severity === 'LOW').length;

        const message = `🔍 CFML SAST Results: High=${high} Medium=${medium} Low=${low}`;

        vscode.window.showWarningMessage(message, 'View Details').then(selection => {
            if (selection !== 'View Details') {
                return;
            }

            const panel = vscode.window.createWebviewPanel(
                'cfmlSastResults',
                'CFML SAST Results',
                // Beside, so that opening a finding puts the source in the
                // main column instead of replacing this panel's tab.
                vscode.ViewColumn.Beside,
                {
                    // Scripts are needed to report clicks back to the
                    // extension. They are restricted to a single inline block
                    // by the nonce in the page's CSP; no remote or local
                    // resources are loadable.
                    enableScripts: true,
                    enableForms: false,
                    localResourceRoots: [],
                    retainContextWhenHidden: true
                }
            );

            panel.webview.html = generateResultsHtml(findings);

            panel.webview.onDidReceiveMessage(
                (msg) => {
                    if (!msg || msg.command !== 'open') {
                        return;
                    }
                    // The index is the only thing the webview controls; the
                    // path itself is looked up here rather than accepted from
                    // the message.
                    const finding = findings[msg.index];
                    if (!finding) {
                        return;
                    }
                    openFinding(finding, workspacePath);
                },
                undefined,
                context.subscriptions
            );
        });
    }

    /** Open a finding's file and put the cursor on the reported line. */
    function openFinding(finding, workspacePath) {
        const target = resolveFindingPath(workspacePath, finding.file);
        if (!target) {
            vscode.window.showErrorMessage(
                `Cannot open "${finding.file}": it resolves outside the workspace.`);
            return;
        }

        vscode.workspace.openTextDocument(target).then(
            (doc) => {
                // Findings are 1-based; the editor API is 0-based. Clamp in
                // case the file changed since the scan.
                const lineIndex = Math.max(0, Math.min((finding.line || 1) - 1, doc.lineCount - 1));
                const range = doc.lineAt(lineIndex).range;
                return vscode.window.showTextDocument(doc, {
                    viewColumn: vscode.ViewColumn.One,
                    selection: range,
                    preserveFocus: false
                });
            },
            (err) => {
                vscode.window.showErrorMessage(
                    `Could not open "${finding.file}": ${err && err.message ? err.message : err}`);
            }
        );
    }


    context.subscriptions.push(scanFile, scanWorkspace, createIgnoreFile, createBaseline, install);
}

function deactivate() {}

// The pure helpers are exported for the unit tests in test/. VS Code only
// ever calls activate/deactivate.
module.exports = {
    activate, deactivate,
    isInside, parseFindings, sanitizeFindings, resolveFindingPath, generateResultsHtml
};