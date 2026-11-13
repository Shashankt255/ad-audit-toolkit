@echo off
title AD Audit Toolkit v1.0.0
echo.
echo  =============================================
echo   AD Audit Toolkit v1.0.0
echo   Active Directory Security Assessment
echo  =============================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    python3 --version >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Python 3 is not installed or not in PATH.
        echo Please install Python 3.8+ from https://www.python.org/downloads/
        pause
        exit /b 1
    )
    set PYTHON=python3
) else (
    set PYTHON=python
)

REM Check/install dependencies
echo [*] Checking dependencies...
%PYTHON% -m pip install -r "%~dp0requirements.txt" --quiet 2>nul
if errorlevel 1 (
    echo [!] Failed to install dependencies automatically.
    echo     Try: pip install -r requirements.txt
    pause
    exit /b 1
)
echo [+] Dependencies OK.
echo.

REM Gather parameters
set /p DOMAIN="Domain (e.g., corp.local): "
set /p USERNAME="Username: "
set /p DC_IP="Domain Controller IP/Hostname: "

set LDAPS_FLAG=
set /p USE_LDAPS="Use LDAPS? (y/N): "
if /i "%USE_LDAPS%"=="y" set LDAPS_FLAG=--use-ldaps

set MOD_FLAG=
set /p MODULES="Modules (comma-separated, Enter for all): "
if not "%MODULES%"=="" set MOD_FLAG=-m %MODULES%

set OUT_FLAG=
set /p OUTPUT="Output file (Enter for ad_audit_report.html): "
if not "%OUTPUT%"=="" set OUT_FLAG=-o %OUTPUT%

echo.
echo [*] Starting audit of %DOMAIN%...
echo.
%PYTHON% "%~dp0ad_audit.py" -d %DOMAIN% -u %USERNAME% -dc %DC_IP% %LDAPS_FLAG% %MOD_FLAG% %OUT_FLAG%

echo.
echo [*] Audit complete. Check the HTML report.
pause
