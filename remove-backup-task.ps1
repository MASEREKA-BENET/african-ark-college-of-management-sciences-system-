param([string]$TaskName = "NUU SQLite Daily Backup")

$ErrorActionPreference = "Stop"
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
Write-Output "Removed scheduled task '$TaskName'. Backup files were left untouched."
