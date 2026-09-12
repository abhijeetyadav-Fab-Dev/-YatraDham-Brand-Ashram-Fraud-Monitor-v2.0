@echo off
REM ========================================================
REM YatraDham Digital Trust & Safety Fraud Sweep Runner
REM Runs automated sweep at 8:00 AM & 8:00 PM IST
REM ========================================================
cd /d "C:\Users\ydtva\yatradham-brand-fraud-monitor"
echo [%date% %time%] Starting automated YatraDham brand & ashram fraud sweep... >> logs\sweeps.log
python run_sweep.py --full >> logs\sweeps.log 2>&1
echo [%date% %time%] Sweep finished with exit code %errorlevel% >> logs\sweeps.log
