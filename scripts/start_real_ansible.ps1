# 以 WSL Ansible 真实修复模式启动 RayScan
. "$PSScriptRoot\Get-RayScanHostIp.ps1"

$env:RAYSCAN_ANSIBLE_MODE = "wsl"
$env:RAYSCAN_SIMULATE_ON_WINDOWS = "0"
$env:RAYSCAN_TARGET_OS = "windows"
if (-not $env:RAYSCAN_TARGET_IP) {
    $env:RAYSCAN_TARGET_IP = Get-RayScanHostIp
}
$env:RAYSCAN_ANSIBLE_USER = $env:USERNAME
Set-Location (Split-Path $PSScriptRoot -Parent)
Write-Host "RayScan 真实修复 | 用户: $env:RAYSCAN_ANSIBLE_USER | 目标IP: $env:RAYSCAN_TARGET_IP | 模式: wsl"
python app.py
