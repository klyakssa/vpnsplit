@echo off
rem Makes a release by double click: Windows does not run .ps1 files directly
rem ("running scripts is disabled on this system"), so this starts the script
rem with that check lifted for this one run only.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0make-release.ps1"
echo.
pause
