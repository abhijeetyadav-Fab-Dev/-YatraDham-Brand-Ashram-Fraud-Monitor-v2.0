@echo off
title YatraDham Brand & Ashram Fraud Monitor
echo ==================================================================
echo   YATRADHAM BRAND & ASHRAM FRAUD MONITOR - LIVE SERVER
echo   Initiative from YatraDham.Org
echo ==================================================================
echo.
echo Starting backend server on port 8090...
echo Dashboard will open at: http://127.0.0.1:8090/
cd /d "%~dp0"
python start_server.py
pause
