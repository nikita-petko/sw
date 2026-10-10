#Requires -Version 5.1
# Creates a desktop shortcut to the CMD launcher.

param(
    [string]$Target = 'bootstrap.cmd',
    [string]$Name = 'lagsw'
)

$ErrorActionPreference = 'Stop'

$targetPath = Join-Path $PSScriptRoot $Target
if (-not (Test-Path $targetPath)) {
    throw "Target not found: $targetPath"
}

$desktop = [Environment]::GetFolderPath('Desktop')
$linkPath = Join-Path $desktop "$Name.lnk"

$shell = New-Object -ComObject WScript.Shell
$link = $shell.CreateShortcut($linkPath)
$link.TargetPath = $targetPath
$link.WorkingDirectory = $PSScriptRoot
$link.WindowStyle = 7  # minimized; the launcher opens its own maximized window
$link.Description = 'Launch lagsw as administrator'
$link.Save()

Write-Host "Created $linkPath"
