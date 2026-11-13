param(
  [string]$TaskName = "NUU SQLite Daily Backup",
  [string]$At = "02:00",
  [string]$DatabasePath,
  [string]$BackupDirectory,
  [switch]$RequireBitLocker
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$backupScript = Join-Path $projectRoot "backup.py"
if (-not (Test-Path -LiteralPath $backupScript -PathType Leaf)) {
  throw "backup.py was not found beside this script."
}
$python = (Get-Command python -ErrorAction Stop).Source
$databasePath = if ($DatabasePath) { $DatabasePath } elseif ($env:NUU_DB_PATH) { $env:NUU_DB_PATH } else { Join-Path $projectRoot "data\nuu.sqlite3" }
$backupDirectory = if ($BackupDirectory) { $BackupDirectory } elseif ($env:NUU_BACKUP_DIR) { $env:NUU_BACKUP_DIR } else { Join-Path (Split-Path -Parent $databasePath) "backups" }
if ($RequireBitLocker) {
  $root = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($backupDirectory))
  if ($root.StartsWith('\\')) { throw "BitLocker verification does not apply to a network path; verify encryption and access on that target separately." }
  $volume = Get-BitLockerVolume -MountPoint $root -ErrorAction Stop
  if ($volume.VolumeStatus -ne 'FullyEncrypted' -or $volume.ProtectionStatus -ne 'On') {
    throw "Backup target $root is not fully BitLocker-encrypted and protected. No task was registered."
  }
}
$arguments = "`"$backupScript`" backup --retention-days 30 --database `"$databasePath`" --backup-dir `"$backupDirectory`""
$action = New-ScheduledTaskAction -Execute $python -Argument $arguments -WorkingDirectory $projectRoot
$trigger = New-ScheduledTaskTrigger -Daily -At $At
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType S4U -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Verified daily SQLite backup for NUU" -Force | Out-Null
Write-Output "Registered '$TaskName' to run daily at $At for $env:USERDOMAIN\$env:USERNAME."
Write-Output "Database: $databasePath"
Write-Output "Backups: $backupDirectory"
