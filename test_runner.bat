@echo off
title Run Security Log Analyzer Test Suite (5 Test Cases)
echo ===============================================================================
echo            EXECUTING 5 AUTOMATED SECURITY VERIFICATION TESTS
echo ===============================================================================
echo.

:: Check standard python
python --version >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    python report_and_tests.py
    pause
    exit /b
)

:: Check Thonny Python path
if exist "%LOCALAPPDATA%\Programs\Thonny\python.exe" (
    "%LOCALAPPDATA%\Programs\Thonny\python.exe" report_and_tests.py
    pause
    exit /b
)

:: Check py launcher
py --version >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    py report_and_tests.py
    pause
    exit /b
)

echo [!] Error: Python executable not found on system PATH.
pause
