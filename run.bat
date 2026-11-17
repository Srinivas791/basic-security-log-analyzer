@echo off
title Basic Security Log Analyzer - BUILDERS Phase 2
echo ===============================================================================
echo            BASIC SECURITY LOG ANALYZER - BUILDERS PHASE 2
echo               Defensive Cybersecurity Log Intelligence System
echo ===============================================================================
echo.

:: Check standard python
python --version >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [*] Starting Security Log Analyzer via standard Python...
    python main.py
    pause
    exit /b
)

:: Check Thonny Python path
if exist "%LOCALAPPDATA%\Programs\Thonny\python.exe" (
    echo [*] Starting Security Log Analyzer via Python in %LOCALAPPDATA%\Programs\Thonny\python.exe...
    "%LOCALAPPDATA%\Programs\Thonny\python.exe" main.py
    pause
    exit /b
)

:: Check py launcher
py --version >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [*] Starting Security Log Analyzer via py launcher...
    py main.py
    pause
    exit /b
)

echo [!] Error: Python executable not found on system PATH.
echo [!] Please install Python 3.10+ or add it to PATH.
pause
