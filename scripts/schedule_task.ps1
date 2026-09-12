# PowerShell script to register YatraDham Fraud Monitor Scheduled Tasks
# Configures automated runs twice daily at 08:00 AM and 08:00 PM IST

$TaskNameMorning = "YatraDham_Fraud_Monitor_0800AM"
$TaskNameEvening = "YatraDham_Fraud_Monitor_0800PM"
$BatPath = "C:\Users\ydtva\yatradham-brand-fraud-monitor\scripts\run_scheduled.bat"

# Create logs directory
New-Item -ItemType Directory -Path "C:\Users\ydtva\yatradham-brand-fraud-monitor\logs" -Force | Out-Null

$Action = New-ScheduledTaskAction -Execute $BatPath

# 8:00 AM Trigger
$TriggerMorning = New-ScheduledTaskTrigger -Daily -At 8:00AM
Register-ScheduledTask -TaskName $TaskNameMorning -Action $Action -Trigger $TriggerMorning -Description "YatraDham Brand & Ashram Fraud Monitor (Morning Sweep)" -Force

# 8:00 PM Trigger
$TriggerEvening = New-ScheduledTaskTrigger -Daily -At 8:00PM
Register-ScheduledTask -TaskName $TaskNameEvening -Action $Action -Trigger $TriggerEvening -Description "YatraDham Brand & Ashram Fraud Monitor (Evening Sweep)" -Force

Write-Host "[✓] Scheduled tasks registered successfully: 8:00 AM & 8:00 PM IST daily." -ForegroundColor Green
