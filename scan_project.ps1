# CFML SAST project scanner (PowerShell wrapper).
#
# Works with Windows PowerShell 5.1 and PowerShell 7+.

[CmdletBinding()]
param(
    [ValidateSet('console', 'json', 'sarif')]
    [string]$OutputFormat = 'console',
    [string]$OutputFile = '',
    [switch]$FailOnHigh,
    [switch]$CreateBaseline,
    [switch]$ChangedOnly,
    [string]$BaselineFile = '.sast-baseline.json',
    [int]$TimeoutSeconds = 300
)

Write-Host "🔍 CFML SAST Scanner - Scanning Project..." -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$originalLocation = Get-Location

try {
    # Locate the scanner and pick the directory to scan from.
    if ($scriptDir -like "*CFSAST*") {
        $scannerPath = Join-Path $scriptDir 'cfml_sast_simple.py'
        Set-Location (Split-Path -Parent $scriptDir)
    }
    else {
        $scannerPath = Join-Path 'CFSAST' 'cfml_sast_simple.py'
        if (-not (Test-Path $scannerPath)) {
            $scannerPath = Join-Path 'scripts' 'cfml_sast_simple.py'
        }
    }

    if (-not (Test-Path $scannerPath)) {
        Write-Host "❌ Scanner not found. Run 'python3 install.py' first." -ForegroundColor Red
        exit 1
    }

    # Find a Python interpreter. `py` is the Windows launcher and does not
    # exist on PowerShell 7 for macOS or Linux.
    $pythonCmd = $null
    $pythonArgs = @()
    foreach ($candidate in @('py', 'python3', 'python')) {
        if (Get-Command $candidate -ErrorAction SilentlyContinue) {
            $pythonCmd = $candidate
            if ($candidate -eq 'py') { $pythonArgs = @('-3') }
            break
        }
    }

    if (-not $pythonCmd) {
        Write-Host "❌ Python 3.8+ not found in PATH." -ForegroundColor Red
        exit 1
    }

    # Note: not $args. That is an automatic variable in PowerShell and
    # assigning to it is unreliable.
    $scannerArgs = @()
    if ($ChangedOnly) {
        $scannerArgs += '--scan-changed'
        Write-Host "📝 Scanning only Git-modified files..." -ForegroundColor Yellow
    }
    else {
        $scannerArgs += '--scan-all'
    }

    switch ($OutputFormat) {
        'json'  { $scannerArgs += '--json-out' }
        'sarif' { $scannerArgs += '--sarif' }
    }

    if ($FailOnHigh) { $scannerArgs += '--fail-on-high' }
    $scannerArgs += @('--timeout', $TimeoutSeconds)

    if ($CreateBaseline) {
        $scannerArgs += @('--baseline', $BaselineFile, '--update-baseline')
    }
    elseif (Test-Path $BaselineFile) {
        $scannerArgs += @('--baseline', $BaselineFile)
        Write-Host "📋 Using baseline file: $BaselineFile" -ForegroundColor Yellow
    }

    if ($OutputFile) {
        # Deliberately not `> $OutputFile`: the redirection operator writes
        # UTF-16LE with a BOM under Windows PowerShell 5.1, which corrupts
        # JSON and SARIF for anything that reads the file afterwards.
        $output = & $pythonCmd @pythonArgs $scannerPath @scannerArgs
        $exitCode = $LASTEXITCODE
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        $resolved = [System.IO.Path]::GetFullPath(
            [System.IO.Path]::Combine((Get-Location).Path, $OutputFile))
        [System.IO.File]::WriteAllText($resolved, ($output -join "`n") + "`n", $utf8NoBom)
        Write-Host "✅ Results saved to: $resolved" -ForegroundColor Green
    }
    else {
        & $pythonCmd @pythonArgs $scannerPath @scannerArgs
        $exitCode = $LASTEXITCODE
    }

    switch ($exitCode) {
        0 {
            Write-Host "✅ Scan completed." -ForegroundColor Green
        }
        1 {
            Write-Host "🚨 High severity issues found!" -ForegroundColor Red
        }
        2 {
            Write-Host "⚠️  Scan did not finish (timeout or findings cap). Results are INCOMPLETE." -ForegroundColor Yellow
        }
        default {
            Write-Host "❌ Scanner exited with code $exitCode." -ForegroundColor Red
        }
    }

    exit $exitCode
}
catch {
    Write-Host "❌ Error running scanner: $_" -ForegroundColor Red
    exit 1
}
finally {
    # Restored on every path, including the early exits above.
    Set-Location $originalLocation
}
