# CFML SAST Project Scanner
# Handles large projects with batch processing

param(
    [string]$OutputFormat = "console",  # console, json, sarif
    [string]$OutputFile = "",
    [switch]$FailOnHigh,
    [switch]$CreateBaseline,
    [switch]$ChangedOnly,
    [string]$BaselineFile = ".sast-baseline.json"
)

Write-Host "🔍 CFML SAST Scanner - Scanning Project..." -ForegroundColor Cyan

# Determine scanner path based on script location
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$currentDir = Get-Location

if ($scriptDir -like "*CFSAST*") {
    # Script is in CFSAST folder, scanner should be in same folder
    $scannerPath = Join-Path $scriptDir "cfml_sast_simple.py"
    # Change to parent directory for scanning
    Set-Location (Split-Path -Parent $scriptDir)
} else {
    # Script is in project root, look for scanner in CFSAST subfolder
    $scannerPath = "CFSAST\cfml_sast_simple.py"
    if (-not (Test-Path $scannerPath)) {
        $scannerPath = "cfml_sast_simple.py"
    }
}

if (-not (Test-Path $scannerPath)) {
    Write-Host "❌ Scanner not found. Please run 'CFML SAST: Install Git Hooks' from VS Code first." -ForegroundColor Red
    exit 1
}

# Build command arguments
if ($ChangedOnly) {
    $args = @("--scan-changed")
    Write-Host "📝 Scanning only Git-modified files..." -ForegroundColor Yellow
} else {
    $args = @("--scan-all")
}

if ($OutputFormat -eq "json") {
    $args += "--json-out"
} elseif ($OutputFormat -eq "sarif") {
    $args += "--sarif"
}

if ($FailOnHigh) {
    $args += "--fail-on-high"
}

if ($CreateBaseline) {
    $args += "--baseline", $BaselineFile, "--update-baseline"
} elseif (Test-Path $BaselineFile) {
    $args += "--baseline", $BaselineFile
    Write-Host "📋 Using baseline file: $BaselineFile" -ForegroundColor Yellow
}

# Execute scanner
try {
    if ($OutputFile) {
        py -3 $scannerPath @args > $OutputFile
        Write-Host "✅ Results saved to: $OutputFile" -ForegroundColor Green
    } else {
        py -3 $scannerPath @args
    }
    
    if ($LASTEXITCODE -eq 1 -and $FailOnHigh) {
        Write-Host "🚨 High severity issues found!" -ForegroundColor Red
        Set-Location $currentDir
        exit 1
    }
    
    Write-Host "✅ Scan completed successfully!" -ForegroundColor Green
    Set-Location $currentDir
} catch {
    Write-Host "❌ Error running scanner: $_" -ForegroundColor Red
    Set-Location $currentDir
    exit 1
}