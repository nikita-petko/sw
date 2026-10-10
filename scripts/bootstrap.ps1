#Requires -Version 5.1
# Relaunches itself in an elevated, maximized PowerShell window and runs lagsw.exe with preset args.

param([switch]$Elevated)

# ---- Preconfigured settings: edit these ----
$ExeName  = 'lagsw.exe'
$AppArgs  = @(
    '--config', 'profiles/div1.yml',
    '--log-level', 'info',
    '--resolve-region'
    # '--server', 'name-or-address'
)
# --------------------------------------------

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
# In the repo the script lives in scripts/; in a package it sits next to the exe.
$root = if ((Split-Path $here -Leaf) -eq 'scripts') { Split-Path $here -Parent } else { $here }

if (-not $Elevated) {
    # -Verb RunAs triggers UAC; WindowStyle Maximized fills the screen.
    $argList = @('-NoExit', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                 '-File', "`"$PSCommandPath`"", '-Elevated')
    Start-Process -FilePath (Get-Process -Id $PID).Path -Verb RunAs `
        -WindowStyle Maximized -ArgumentList $argList
    return
}

$Host.UI.RawUI.WindowTitle = 'lagsw (Administrator)'
# Relative config paths resolve against the first of these that contains the config.
$config = $AppArgs[$AppArgs.IndexOf('--config') + 1]
$workDir = @($here, (Join-Path $root 'profiles'), $root) |
    Where-Object { Test-Path (Join-Path $_ $config) } | Select-Object -First 1
if (-not $workDir) { $workDir = $root }
Set-Location $workDir

$candidates = @(
    (Join-Path $here $ExeName),
    (Join-Path $root "build\windows\x64\release\$ExeName"),
    (Join-Path $root "build\windows\x64\debug\$ExeName")
)
$exe = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $exe) {
    Write-Error "Could not find $ExeName. Looked in:`n$($candidates -join "`n")"
    return
}

Write-Host "> $exe $($AppArgs -join ' ')" -ForegroundColor Cyan
& $exe @AppArgs
Write-Host "`nlagsw exited with code $LASTEXITCODE" -ForegroundColor Yellow
