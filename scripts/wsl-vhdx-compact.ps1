# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

<#
.SYNOPSIS
  Compact the WSL2 .vhdx after Docker prunes inside the distro.

.DESCRIPTION
  WSL2 distros are stored as a sparse .vhdx on Windows. ext4 inside
  the distro never returns freed blocks to Windows, so the .vhdx
  grows monotonically — even after `docker system prune` reclaims
  space inside the distro. Optimize-VHD compacts the file once the
  distro is shut down.

  This script:
    1. Discovers the active WSL2 distro's .vhdx path via the WSL registry —
       works for `wsl --import`ed distros on ANY drive (e.g. D:\wsl\Ubuntu),
       not just Store installs under LOCALAPPDATA. Override with -DistroName
       or -VhdxPath.
    2. Shuts down WSL (closes all distros).
    3. Runs Optimize-VHD on the .vhdx.
    4. Reports before/after sizes.

  Run from an *elevated* PowerShell prompt (Hyper-V module needs admin).

.PARAMETER DistroName
  Specific distro to compact. Default: the first non-docker WSL2 distro found
  in the WSL registry (e.g. "Ubuntu").

.PARAMETER VhdxPath
  Direct path override if discovery fails.

.EXAMPLE
  # Compact Docker Desktop's data disk
  .\wsl-vhdx-compact.ps1

.EXAMPLE
  # Compact a named distro
  .\wsl-vhdx-compact.ps1 -DistroName Ubuntu-22.04

.NOTES
  The canonical copy of this script lives INSIDE the WSL distro
  (~/pai-assistant/scripts/). Because it SHUTS DOWN WSL, the scheduled task must
  run it from a Windows-native copy — a \\wsl$ path would become unreachable
  mid-run. Deploy a copy, then schedule that copy:

    # Copy the script out to Windows (re-run after edits). Adjust the distro
    # name in the UNC path if yours isn't "Ubuntu".
    $dst = "$env:LOCALAPPDATA\pai\wsl-vhdx-compact.ps1"
    New-Item -ItemType Directory -Force (Split-Path $dst) | Out-Null
    Copy-Item "\\wsl.localhost\Ubuntu\home\<your-wsl-user>\pai-assistant\scripts\wsl-vhdx-compact.ps1" $dst -Force

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File $dst"
    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3am
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -RunLevel Highest
    Register-ScheduledTask -TaskName 'PAI WSL VHDX Compact' `
        -Action $action -Trigger $trigger -Principal $principal
#>

[CmdletBinding()]
param(
    [string]$DistroName = "",
    [string]$VhdxPath = ""
)

function Resolve-VhdxPath {
    param([string]$DistroName)

    # Strategy 1: explicit path override
    if ($VhdxPath) {
        if (Test-Path $VhdxPath) { return $VhdxPath }
        throw "VhdxPath not found: $VhdxPath"
    }

    # Strategy 2 (primary): resolve via the WSL registry. This is the ONLY
    # reliable way to locate a `wsl --import`ed distro, whose ext4.vhdx lives at
    # its BasePath (e.g. D:\wsl\Ubuntu\ext4.vhdx) — NOT under LOCALAPPDATA.
    # Each distro is a subkey of Lxss with DistributionName + BasePath.
    $lxssRoot = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss"
    if (Test-Path $lxssRoot) {
        $distros = Get-ChildItem $lxssRoot | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath
            [PSCustomObject]@{
                Name     = $p.DistributionName
                # BasePath is stored as \\?\D:\wsl\Ubuntu — strip the \\?\ prefix.
                BasePath = ($p.BasePath -replace '^\\\\\?\\', '')
            }
        } | Where-Object { $_.BasePath }

        # Prefer the requested name; else the first non-docker-desktop distro.
        $match = $null
        if ($DistroName) {
            $match = $distros | Where-Object { $_.Name -eq $DistroName } | Select-Object -First 1
            if (-not $match) { throw "No WSL distro named '$DistroName' in the registry." }
        }
        if (-not $match) {
            $match = $distros | Where-Object { $_.Name -notmatch 'docker' } | Select-Object -First 1
        }
        if (-not $match) { $match = $distros | Select-Object -First 1 }

        if ($match) {
            $vhdx = Join-Path $match.BasePath "ext4.vhdx"
            if (Test-Path $vhdx) { return $vhdx }
        }
    }

    # Strategy 3 (fallback): Store-installed distro under LOCALAPPDATA (C:).
    if ($DistroName) {
        $found = Get-ChildItem -Path "$env:LOCALAPPDATA\Packages\*${DistroName}*\LocalState\ext4.vhdx" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    $anyDistro = Get-ChildItem -Path "$env:LOCALAPPDATA\Packages\*\LocalState\ext4.vhdx" -ErrorAction SilentlyContinue |
        Sort-Object Length -Descending |
        Select-Object -First 1
    if ($anyDistro) { return $anyDistro.FullName }

    throw "No .vhdx found. Pass -VhdxPath explicitly (e.g. -VhdxPath 'D:\wsl\Ubuntu\ext4.vhdx')."
}

function Get-VhdxSizeMB {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return 0 }
    [Math]::Round((Get-Item $Path).Length / 1MB, 1)
}

# Require admin (Optimize-VHD needs Hyper-V module access)
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Must run as Administrator (Optimize-VHD requires Hyper-V cmdlets)." -ForegroundColor Red
    exit 1
}

# Locate Optimize-VHD (ships with Hyper-V module on Windows 10/11 Pro/Ent;
# also available on Home via the Hyper-V Management Tools optional feature).
if (-not (Get-Command Optimize-VHD -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Optimize-VHD not found. Install via:" -ForegroundColor Red
    Write-Host "  Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell" -ForegroundColor Yellow
    exit 1
}

$resolvedPath = Resolve-VhdxPath -DistroName $DistroName
Write-Host "Target: $resolvedPath" -ForegroundColor Cyan

$beforeMB = Get-VhdxSizeMB -Path $resolvedPath
Write-Host "Before: $beforeMB MB" -ForegroundColor Yellow

Write-Host "Shutting down WSL (closes all distros + Docker Desktop data VM)..." -ForegroundColor Cyan
wsl --shutdown
# Brief pause for the Hyper-V worker process to release the file
Start-Sleep -Seconds 5

Write-Host "Compacting (this can take a few minutes)..." -ForegroundColor Cyan
try {
    Optimize-VHD -Path $resolvedPath -Mode Full
} catch {
    Write-Host "Optimize-VHD failed: $_" -ForegroundColor Red
    Write-Host "If the file is still in use, wait 30s and retry." -ForegroundColor Yellow
    exit 1
}

$afterMB = Get-VhdxSizeMB -Path $resolvedPath
$reclaimedMB = $beforeMB - $afterMB
Write-Host "After:  $afterMB MB  (reclaimed $reclaimedMB MB)" -ForegroundColor Green

# Optional: write a structured log line for the audit trail
$logEntry = @{
    ts          = (Get-Date).ToString("o")
    vhdx        = $resolvedPath
    before_mb   = $beforeMB
    after_mb    = $afterMB
    reclaimed_mb = $reclaimedMB
} | ConvertTo-Json -Compress

# Write the audit line. If this script lives INSIDE the distro we just shut
# down (i.e. it was launched from \\wsl$ / \\wsl.localhost), $PSScriptRoot\..\logs
# is now unreachable — so fall back to a Windows-local path.
$logWritten = $false
foreach ($logDir in @((Join-Path $PSScriptRoot "..\logs"), (Join-Path $env:LOCALAPPDATA "pai"))) {
    try {
        if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -ErrorAction Stop | Out-Null }
        Add-Content -Path (Join-Path $logDir "vhdx-compact.jsonl") -Value $logEntry -ErrorAction Stop
        $logWritten = $true
        break
    } catch { }
}
if (-not $logWritten) { Write-Host "WARN: could not write vhdx-compact.jsonl audit line" -ForegroundColor Yellow }
