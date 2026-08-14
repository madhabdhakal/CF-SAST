@echo off
setlocal enabledelayedexpansion

REM CFML SAST scan of changed files, for running by hand from cmd.exe or
REM PowerShell. Git itself always executes .git/hooks/pre-push (no extension)
REM through the bash that ships with Git for Windows, so the installed hook
REM uses prepush.sh even on Windows. This file exists for manual invocation.

git rev-parse --show-toplevel >nul 2>&1
if errorlevel 1 (
    echo CFML SAST: not inside a git repository >&2
    exit /b 1
)

for /f "tokens=*" %%i in ('git rev-parse --show-toplevel') do cd /d "%%i"

REM Locate the scanner: installed layout first, then a source checkout.
set "scanner="
if exist "CFSAST\cfml_sast_simple.py" set "scanner=CFSAST\cfml_sast_simple.py"
if "%scanner%"=="" if exist "scripts\cfml_sast_simple.py" set "scanner=scripts\cfml_sast_simple.py"

if "%scanner%"=="" (
    echo CFML SAST: scanner not found ^(looked in CFSAST\ and scripts\^) >&2
    exit /b 1
)

REM Locate Python.
set "python_cmd="
py -3 --version >nul 2>&1
if not errorlevel 1 set "python_cmd=py -3"
if "%python_cmd%"=="" (
    python --version >nul 2>&1
    if not errorlevel 1 set "python_cmd=python"
)
if "%python_cmd%"=="" (
    echo CFML SAST: Python 3.8+ not found in PATH >&2
    exit /b 1
)

REM --scan-changed asks the scanner itself which files git reports as modified,
REM which avoids rebuilding a quoted file list in batch.
set "baseline_args="
if exist ".sast-baseline.json" set "baseline_args=--baseline .sast-baseline.json"

%python_cmd% "%scanner%" --scan-changed %baseline_args% --fail-on-high
exit /b %errorlevel%
