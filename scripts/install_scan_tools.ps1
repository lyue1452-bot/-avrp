# 安装流水线扫描工具 (Windows)
# 以管理员 PowerShell 运行:  Set-ExecutionPolicy Bypass -Scope Process; .\scripts\install_scan_tools.ps1

$ErrorActionPreference = "Continue"
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " RayScan 流水线扫描工具安装" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

function Test-Cmd($name) {
    if (Get-Command $name -ErrorAction SilentlyContinue) {
        Write-Host "[OK] $name 已安装" -ForegroundColor Green
        return $true
    }
    Write-Host "[--] $name 未安装" -ForegroundColor Yellow
    return $false
}

Test-Cmd "nmap" | Out-Null
Test-Cmd "gitleaks" | Out-Null
Test-Cmd "trivy" | Out-Null
Test-Cmd "docker" | Out-Null

if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Host "未找到 winget，请手动安装工具。" -ForegroundColor Red
    exit 1
}

if (-not (Test-Cmd "gitleaks")) {
    Write-Host "安装 Gitleaks..." -ForegroundColor Cyan
    winget install --id Gitleaks.Gitleaks -e --accept-source-agreements --accept-package-agreements
}

if (-not (Test-Cmd "trivy")) {
    Write-Host "安装 Trivy..." -ForegroundColor Cyan
    winget install --id AquaSecurity.Trivy -e --accept-source-agreements --accept-package-agreements
}

if (-not (Test-Cmd "docker")) {
    Write-Host "安装 Docker Desktop (用于 ZAP 全量扫描，可选)..." -ForegroundColor Cyan
    Write-Host "  winget install Docker.DockerDesktop" -ForegroundColor Gray
    Write-Host "  未安装 Docker 时将自动使用内置 Web 安全探测替代 ZAP" -ForegroundColor Gray
}

Write-Host ""
Write-Host "说明:" -ForegroundColor Cyan
Write-Host "  - Nmap: 需已安装 (https://nmap.org)" -ForegroundColor Gray
Write-Host "  - ZAP:  无 Docker/ZAP 时自动使用内置 Web 探测" -ForegroundColor Gray
Write-Host "  - 安装后请重新打开终端使 PATH 生效" -ForegroundColor Yellow
Write-Host ""
Test-Cmd "gitleaks"
Test-Cmd "trivy"
