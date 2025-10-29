@echo off
setlocal enabledelayedexpansion

REM CFML SAST Pre-push Hook for Windows
REM Scans changed CFML files before git push

REM Check if git is available
git --version >nul 2>&1
if errorlevel 1 (
    echo Error: Git not found in PATH >&2
    exit /b 1
)

REM Get upstream branch
for /f "tokens=*" %%i in ('git rev-parse --abbrev-ref --symbolic-full-name @{u} 2^>nul') do set "upstream=%%i"
if "%upstream%"=="" set "upstream=HEAD~1"

REM Get base commit
for /f "tokens=*" %%i in ('git merge-base HEAD %upstream% 2^>nul') do set "base=%%i"
if "%base%"=="" set "base=HEAD~1"

REM Get changed files
set "cfml_files="
set "file_count=0"

for /f "tokens=*" %%f in ('git diff --name-only "%base%" HEAD 2^>nul') do (
    set "file=%%f"
    REM Check if file is CFML and exists
    if exist "!file!" (
        echo !file! | findstr /i "\.cfm$ \.cfc$ \.cfml$ \.cfinclude$" >nul
        if not errorlevel 1 (
            set "cfml_files=!cfml_files! "!file!""
            set /a file_count+=1
        )
    )
)

REM Fallback to staged files if no diff found
if %file_count%==0 (
    for /f "tokens=*" %%f in ('git diff --cached --name-only 2^>nul') do (
        set "file=%%f"
        if exist "!file!" (
            echo !file! | findstr /i "\.cfm$ \.cfc$ \.cfml$ \.cfinclude$" >nul
            if not errorlevel 1 (
                set "cfml_files=!cfml_files! "!file!""
                set /a file_count+=1
            )
        )
    )
)

if %file_count%==0 (
    echo No CFML files changed
    exit /b 0
)

echo Scanning %file_count% changed CFML files...

REM Find Python executable
set "python_cmd="
python --version >nul 2>&1
if not errorlevel 1 set "python_cmd=python"

if "%python_cmd%"=="" (
    py -3 --version >nul 2>&1
    if not errorlevel 1 set "python_cmd=py -3"
)

if "%python_cmd%"=="" (
    python3 --version >nul 2>&1
    if not errorlevel 1 set "python_cmd=python3"
)

if "%python_cmd%"=="" (
    echo Error: Python not found. Please install Python 3.6+ >&2
    exit /b 1
)

REM Run SAST scanner
%python_cmd% "scripts\cfml_sast_simple.py" --files%cfml_files% --fail-on-high
exit /b %errorlevel%