const vscode = require('vscode');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

// Security constants
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
const MAX_OUTPUT_SIZE = 1024 * 1024; // 1MB
const MAX_FILES = 1000;
const SCAN_TIMEOUT = 120000; // 2 minutes
const CFML_EXTENSIONS = /\.(cfm|cfc|cfml|cfinclude)$/i;

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
            if (!resolvedPath.startsWith(path.resolve(workspaceFolder.uri.fsPath))) {
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
        
        const ignoreContent = `# CFML SAST Ignore Patterns
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
`;
        
        try {
            fs.writeFileSync(ignorePath, ignoreContent, 'utf8');
            vscode.window.showInformationMessage('✅ Created .sastignore file with default patterns');
            
            vscode.workspace.openTextDocument(ignorePath).then(doc => {
                vscode.window.showTextDocument(doc);
            });
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to create .sastignore: ${error.message}`);
        }
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
            if (!resolvedPath.startsWith(path.resolve(workspaceFolder.uri.fsPath)) || !fs.existsSync(resolvedPath)) {
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
            
            if (!resolvedTargetDir.startsWith(resolvedWorkspace)) {
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
            
            const script = `import urllib.request; urllib.request.urlretrieve('https://raw.githubusercontent.com/madhabdhakal/CF-SAST/main/scripts/cfml_sast_simple.py', 'CFSAST/cfml_sast_simple.py'); urllib.request.urlretrieve('https://raw.githubusercontent.com/madhabdhakal/CF-SAST/main/scan_project.ps1', 'CFSAST/scan_project.ps1'); print('Downloaded successfully')`;
            
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
                
                const pythonProcess = spawn(pythonCmd, ['-c', script], {
                    cwd: workspacePath,
                    stdio: ['ignore', 'pipe', 'pipe']
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
                    
                    const psFile = path.join(targetDir, 'scan_project.ps1');
                    if (fs.existsSync(targetFile)) {
                        const hasPs1 = fs.existsSync(psFile);
                        vscode.window.showInformationMessage(`✅ CFML SAST Scanner installed successfully using ${pythonCmd}!${hasPs1 ? ' (includes PowerShell script)' : ''}`);
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
            if (!resolvedScannerPath.startsWith(path.resolve(workspacePath)) || !fs.existsSync(resolvedScannerPath)) {
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
            env: { ...process.env, PYTHONIOENCODING: 'utf-8' }
        });
        
        let stdout = '';
        let stderr = '';
        
        pythonProcess.stdout.on('data', (data) => {
            stdout += data.toString();
            if (stdout.length > MAX_OUTPUT_SIZE) pythonProcess.kill();
        });
        
        pythonProcess.stderr.on('data', (data) => {
            stderr += data.toString();
        });
        
        pythonProcess.on('close', (code) => {
            if (code !== 0 && !stdout) {
                if (stderr.includes('No changed CFML files found')) {
                    vscode.window.showInformationMessage('✅ No changed CFML files to scan');
                } else {
                    vscode.window.showErrorMessage(`Scan failed: ${stderr}`);
                }
                return;
            }
            
            try {
                if (!stdout || stdout.trim().length === 0) {
                    vscode.window.showInformationMessage('✅ No security issues found in changed files');
                    return;
                }
                
                // Extract JSON from output (filter out status messages)
                const lines = stdout.split('\n');
                let jsonStart = -1;
                let jsonEnd = -1;
                
                // Find JSON array boundaries
                for (let i = 0; i < lines.length; i++) {
                    const line = lines[i].trim();
                    if (line.startsWith('[') && jsonStart === -1) {
                        jsonStart = i;
                    }
                    if (line.endsWith(']') && jsonStart !== -1) {
                        jsonEnd = i;
                        break;
                    }
                }
                
                if (jsonStart === -1 || jsonEnd === -1) {
                    // No JSON found, check for completion message
                    if (stdout.includes('Scan complete') || stdout.includes('No changed CFML files')) {
                        vscode.window.showInformationMessage('✅ No security issues found in changed files');
                    } else {
                        throw new Error('No valid JSON output found');
                    }
                    return;
                }
                
                // Extract and parse JSON
                const jsonLines = lines.slice(jsonStart, jsonEnd + 1);
                const jsonStr = jsonLines.join('\n');
                
                if (jsonStr.trim() === '[]') {
                    vscode.window.showInformationMessage('✅ No security issues found in changed files');
                    return;
                }
                
                const results = JSON.parse(jsonStr);
                if (!Array.isArray(results)) {
                    throw new Error('Invalid results format');
                }
                
                showResults(results, true);
                
            } catch (parseError) {
                if (stdout && (stdout.includes('Scan complete') || stdout.includes('No changed CFML files'))) {
                    vscode.window.showInformationMessage('✅ No security issues found in changed files');
                } else {
                    vscode.window.showErrorMessage(`Failed to parse scan results: ${parseError.message}`);
                }
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
                if (!resolvedPath.startsWith(workspacePath)) {
                    console.warn(`Blocked path traversal attempt: ${file}`);
                    continue;
                }
                
                // Check file exists and is CFML
                if (fs.existsSync(resolvedPath) && 
                    fs.statSync(resolvedPath).isFile() && 
                    CFML_EXTENSIONS.test(resolvedPath) &&
                    !shouldIgnoreFile(resolvedPath, workspacePath)) {
                    
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
        const ignoredCount = totalFiles - absoluteFiles.length;
        
        if (absoluteFiles.length === 0) {
            if (ignoredCount > 0) {
                vscode.window.showInformationMessage(`No CFML files to scan (${ignoredCount} files ignored)`);
            } else {
                vscode.window.showInformationMessage('No valid CFML files found to scan');
            }
            return;
        }
        
        // Show ignore feedback if enabled
        const config = vscode.workspace.getConfiguration('cfmlSast');
        if (ignoredCount > 0 && config.get('showIgnoredFiles', true)) {
            console.log(`CFML SAST: Ignored ${ignoredCount} files`);
        }
        
        const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';
        const scannerPath = path.join(workspacePath, 'CFSAST', 'cfml_sast_simple.py');
        
        // Security: Validate scanner path
        try {
            const resolvedScannerPath = path.resolve(scannerPath);
            if (!resolvedScannerPath.startsWith(workspacePath) || !fs.existsSync(resolvedScannerPath)) {
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
            env: { ...process.env, PYTHONIOENCODING: 'utf-8' }
        });
        
        let stdout = '';
        let stderr = '';
        
        pythonProcess.stdout.on('data', (data) => {
            stdout += data.toString();
            if (stdout.length > MAX_OUTPUT_SIZE) pythonProcess.kill();
        });
        
        pythonProcess.stderr.on('data', (data) => {
            stderr += data.toString();
        });
        
        pythonProcess.on('close', (code) => {
            if (code !== 0 && !stdout) {
                vscode.window.showErrorMessage(`Scan failed: ${stderr}`);
                return;
            }
            
            try {
                if (!stdout || stdout.trim().length === 0 || stdout.trim() === '[]') {
                    vscode.window.showInformationMessage('✅ Scan completed with no security issues found');
                    return;
                }
                
                // Security: Validate output size
                const output = stdout.trim();
                if (output.length > MAX_OUTPUT_SIZE) {
                    vscode.window.showWarningMessage(
                        `⚠️ Large scan results (${Math.round(output.length/1024)}KB). Use CLI for full results.`,
                        'Show Summary'
                    ).then(selection => {
                        if (selection === 'Show Summary') {
                            try {
                                const truncated = output.substring(0, 50000);
                                const partial = JSON.parse(truncated + ']');
                                showResults(partial.slice(0, 50), isWorkspace);
                            } catch {
                                vscode.window.showInformationMessage('Use CLI: py -3 CFSAST/cfml_sast_simple.py --files *.cfm --json-out');
                            }
                        }
                    });
                    return;
                }
                
                // Extract JSON from mixed output
                const lines = output.split('\n');
                let jsonStart = -1;
                let jsonEnd = -1;
                
                // Find JSON array boundaries
                for (let i = 0; i < lines.length; i++) {
                    const line = lines[i].trim();
                    if (line.startsWith('[') && jsonStart === -1) {
                        jsonStart = i;
                    }
                    if (line.endsWith(']') && jsonStart !== -1) {
                        jsonEnd = i;
                        break;
                    }
                }
                
                if (jsonStart === -1 || jsonEnd === -1) {
                    // No JSON found, assume no findings
                    vscode.window.showInformationMessage('✅ Scan completed with no security issues found');
                    return;
                }
                
                // Extract and parse JSON
                const jsonLines = lines.slice(jsonStart, jsonEnd + 1);
                const jsonStr = jsonLines.join('\n');
                
                let results;
                try {
                    results = JSON.parse(jsonStr);
                } catch (parseError) {
                    throw new Error(`Invalid JSON output: ${parseError.message}`);
                }
                
                // Validate results structure
                if (!Array.isArray(results)) {
                    throw new Error('Results must be an array');
                }
                
                if (results.length > 10000) {
                    throw new Error('Too many results - use CLI for large scans');
                }
                
                // Validate and sanitize each result object
                const sanitizedResults = [];
                for (let i = 0; i < Math.min(results.length, 1000); i++) {
                    const result = results[i];
                    if (!result || typeof result !== 'object') {
                        continue;
                    }
                    
                    // Create sanitized copy
                    const sanitized = {
                        file: typeof result.file === 'string' ? result.file.substring(0, 500) : '',
                        line: typeof result.line === 'number' ? Math.max(1, Math.min(result.line, 999999)) : 1,
                        rule_id: typeof result.rule_id === 'string' ? result.rule_id.substring(0, 50) : '',
                        severity: ['HIGH', 'MEDIUM', 'LOW'].includes(result.severity) ? result.severity : 'UNKNOWN',
                        description: typeof result.description === 'string' ? result.description.substring(0, 1000) : ''
                    };
                    
                    sanitizedResults.push(sanitized);
                }
                
                showResults(sanitizedResults, isWorkspace);
                
            } catch (parseError) {
                console.error('Parse error:', parseError);
                if (stdout && (stdout.includes('Scan complete') || stdout.includes('No valid CFML files'))) {
                    vscode.window.showInformationMessage('✅ Scan completed with no security issues found');
                } else {
                    vscode.window.showErrorMessage(`Failed to parse scan results: ${parseError.message}`);
                }
            }
        });
    }

    function showResults(findings, isWorkspace) {
        if (findings.length === 0) {
            vscode.window.showInformationMessage('✅ No security issues found');
            return;
        }
        
        const high = findings.filter(f => f.severity === 'HIGH').length;
        const medium = findings.filter(f => f.severity === 'MEDIUM').length;
        const low = findings.filter(f => f.severity === 'LOW').length;
        
        const message = `🔍 CFML SAST Results: High=${high} Medium=${medium} Low=${low}`;
        
        vscode.window.showWarningMessage(message, 'View Details').then(selection => {
            if (selection === 'View Details') {
                const panel = vscode.window.createWebviewPanel(
                    'cfmlSastResults',
                    'CFML SAST Results',
                    vscode.ViewColumn.One,
                    {
                        enableScripts: false,
                        enableForms: false,
                        localResourceRoots: [],
                        retainContextWhenHidden: false
                    }
                );
                
                panel.webview.html = generateResultsHtml(findings);
            }
        });
    }

    function generateResultsHtml(findings) {
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
        
        const cards = findings.slice(0, 500).map(f => {
            const severity = escapeHtml(f.severity || 'UNKNOWN');
            const ruleId = escapeHtml(f.rule_id || 'N/A');
            const fileName = escapeHtml(f.file ? f.file.split(/[\\\/]/).pop() : 'unknown');
            const line = parseInt(f.line) || 0;
            const description = escapeHtml(f.description || 'No description');
            const icon = getSeverityIcon(severity);
            
            return `
                <div class="finding-card ${severity.toLowerCase()}">
                    <div class="card-header">
                        <span class="severity-badge">${icon} ${severity}</span>
                        <span class="rule-id">${ruleId}</span>
                    </div>
                    <div class="card-body">
                        <div class="description">${description}</div>
                        <div class="location">
                            <span class="file-name">${fileName}</span>
                            <span class="line-number">Line ${line}</span>
                        </div>
                    </div>
                </div>`;
        }).join('');
        
        const high = findings.filter(f => f.severity === 'HIGH').length;
        const medium = findings.filter(f => f.severity === 'MEDIUM').length;
        const low = findings.filter(f => f.severity === 'LOW').length;
        
        return `<!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
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
                }
                
                .finding-card:hover {
                    border-color: var(--vscode-focusBorder);
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
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
            
            <div class="tip">
                💡 <strong>Tip:</strong> Use .sastignore file to exclude files or create baseline to suppress existing findings
            </div>
        </body>
        </html>`;
    }

    // Helper function to check .sastignore patterns
    function shouldIgnoreFile(filePath, workspacePath) {
        try {
            const ignorePath = path.join(workspacePath, '.sastignore');
            
            // Security: Validate ignore file path
            const resolvedIgnorePath = path.resolve(ignorePath);
            if (!resolvedIgnorePath.startsWith(path.resolve(workspacePath))) {
                return false;
            }
            
            if (!fs.existsSync(resolvedIgnorePath)) {
                return false;
            }
            
            // Security: Limit file size
            const stats = fs.statSync(resolvedIgnorePath);
            if (stats.size > 100 * 1024) { // 100KB limit
                console.warn('.sastignore file too large, ignoring');
                return false;
            }
            
            const ignoreContent = fs.readFileSync(resolvedIgnorePath, 'utf8');
            const lines = ignoreContent.split('\n');
            
            if (lines.length > 1000) { // Limit number of patterns
                console.warn('Too many ignore patterns, using first 1000');
                lines.splice(1000);
            }
            
            const patterns = lines
                .map(line => line.trim())
                .filter(line => line && !line.startsWith('#') && line.length < 200);
            
            const relativePath = path.relative(workspacePath, filePath).replace(/\\/g, '/');
            const fileName = path.basename(filePath);
            
            for (const pattern of patterns) {
                try {
                    // Security: Escape special regex chars except * and ?
                    const escapedPattern = pattern
                        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
                        .replace(/\*/g, '.*')
                        .replace(/\?/g, '.');
                    
                    // Limit regex complexity
                    if (escapedPattern.length > 500) continue;
                    
                    const regex = new RegExp(`^${escapedPattern}$`, 'i');
                    
                    if (regex.test(relativePath) || regex.test(fileName)) {
                        return true;
                    }
                } catch (regexError) {
                    // Skip invalid patterns
                    console.warn(`Invalid ignore pattern: ${pattern}`);
                    continue;
                }
            }
        } catch (error) {
            console.warn(`Error reading .sastignore: ${error.message}`);
        }
        
        return false;
    }
    
    context.subscriptions.push(scanFile, scanWorkspace, createIgnoreFile, createBaseline, install);
}

function deactivate() {}

module.exports = { activate, deactivate };