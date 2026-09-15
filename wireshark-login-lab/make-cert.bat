@echo off
REM Lab setup for Windows: checks prerequisites, offers to install anything
REM missing, generates the certificate, then verifies it. Safe to re-run.
cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
  echo Python 3 was not found on PATH.
  echo Install it from https://www.python.org/downloads/
  echo and tick "Add python.exe to PATH" during setup.
  pause
  exit /b 1
)

python make_cert.py %*
pause
