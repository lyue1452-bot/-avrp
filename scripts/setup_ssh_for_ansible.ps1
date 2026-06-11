# 以管理员身份运行：配置 Windows OpenSSH，供 WSL Ansible 免密连接
# 用法：右键 PowerShell -> 以管理员身份运行 -> .\scripts\setup_ssh_for_ansible.ps1
# 可选：$env:RAYSCAN_TARGET_IP='192.168.101.36'  指定本机 IP

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\Get-RayScanHostIp.ps1"

Write-Host "=== RayScan SSH/Ansible 初始化 ===" -ForegroundColor Cyan

# 1. 确保 OpenSSH Server 已安装并运行
$sshd = Get-Service sshd -ErrorAction SilentlyContinue
if (-not $sshd) {
    Write-Host "安装 OpenSSH Server..."
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
}
Set-Service sshd -StartupType Automatic
Start-Service sshd
Write-Host "[OK] sshd 服务已运行" -ForegroundColor Green

# 2. 防火墙放行 22
if (-not (Get-NetFirewallRule -Name "RayScan-OpenSSH-In" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name "RayScan-OpenSSH-In" -DisplayName "RayScan OpenSSH" -Enabled True `
        -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
}
Write-Host "[OK] 防火墙已放行 TCP 22" -ForegroundColor Green

# 3. 从 WSL 读取公钥
$pub = wsl bash -lc "cat ~/.ssh/id_ed25519.pub 2>/dev/null || cat ~/.ssh/id_rsa.pub 2>/dev/null"
if (-not $pub) {
    Write-Host "WSL 未找到 SSH 公钥，正在生成..."
    wsl bash -lc "ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519 -q"
    $pub = wsl bash -lc "cat ~/.ssh/id_ed25519.pub"
}
Write-Host "公钥: $pub"

# 4. 管理员账户公钥
$adminAuth = "$env:ProgramData\ssh\administrators_authorized_keys"
if (-not (Test-Path $adminAuth)) {
    New-Item -ItemType File -Path $adminAuth -Force | Out-Null
}
$lines = @(Get-Content $adminAuth -ErrorAction SilentlyContinue)
if ($lines -notcontains $pub.Trim()) {
    Add-Content -Path $adminAuth -Value $pub.Trim()
}
icacls $adminAuth /inheritance:r | Out-Null
icacls $adminAuth /grant "Administrators:F" | Out-Null
icacls $adminAuth /grant "SYSTEM:F" | Out-Null
Write-Host "[OK] 已写入 $adminAuth" -ForegroundColor Green

# 5. 普通用户 authorized_keys
$userAuth = "$env:USERPROFILE\.ssh\authorized_keys"
$sshDir = "$env:USERPROFILE\.ssh"
if (-not (Test-Path $sshDir)) { New-Item -ItemType Directory -Path $sshDir -Force | Out-Null }
if (-not (Test-Path $userAuth)) { New-Item -ItemType File -Path $userAuth -Force | Out-Null }
$userLines = @(Get-Content $userAuth -ErrorAction SilentlyContinue)
if ($userLines -notcontains $pub.Trim()) {
    Add-Content -Path $userAuth -Value $pub.Trim()
}
icacls $userAuth /inheritance:r | Out-Null
icacls $userAuth /grant "$($env:USERNAME):(R,W)" | Out-Null
icacls $userAuth /grant "SYSTEM:(R)" | Out-Null
Write-Host "[OK] 已写入 $userAuth" -ForegroundColor Green

# 6. 解析本机 IP（排除 VMware 虚拟网卡 192.168.40.1 等）
$primaryIp = Get-RayScanHostIp
$wslGateway = ""
try {
    $gwRaw = & wsl.exe bash -lc 'grep -m1 nameserver /etc/resolv.conf 2>/dev/null | awk "{print `$2}"' 2>$null
    if ($gwRaw) {
        $wslGateway = ($gwRaw | Out-String).Trim()
    }
} catch {
    # WSL 未就绪时跳过
}
$testIps = @($primaryIp)
if ($wslGateway -and $testIps -notcontains $wslGateway) { $testIps += $wslGateway }
if ($testIps -notcontains '127.0.0.1') { $testIps += '127.0.0.1' }

Write-Host ""
Write-Host "本机 IP 说明:" -ForegroundColor Cyan
Write-Host "  主 IP（推荐）: $primaryIp"
if ($wslGateway) { Write-Host "  WSL 网关 IP : $wslGateway （WSL 访问 Windows 常用）" }
Write-Host "  192.168.40.1 / 192.168.42.1 多为 VMware 虚拟网卡，不是扫描目标，已自动排除" -ForegroundColor DarkGray
Write-Host ""

$sshOk = $false
$sshOkIp = ""
foreach ($ip in $testIps) {
    if (-not $ip) { continue }
    Write-Host "测试 SSH: $env:USERNAME@${ip}"
    try {
        $test = wsl bash -lc "ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=8 ${env:USERNAME}@${ip} 'echo SSH_OK && hostname'" 2>&1
    } catch {
        $test = $_.Exception.Message
    }
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[OK] SSH 连接成功 ($ip)" -ForegroundColor Green
        Write-Host $test
        $sshOk = $true
        $sshOkIp = $ip
        break
    } else {
        Write-Host "[FAIL] $ip : $test" -ForegroundColor Yellow
    }
}

if (-not $sshOk) {
    Write-Host "[WARN] 所有 IP SSH 均失败。请检查: Get-WinEvent -LogName OpenSSH/Operational -MaxEvents 20" -ForegroundColor Yellow
} else {
    Write-Host "测试 Ansible 连通 ($sshOkIp)..."
    try {
        $inv = "${sshOkIp},"
        $ansibleCmd = "cd /mnt/d/rayscan/playbooks && ANSIBLE_CONFIG=/mnt/d/rayscan/ansible.cfg ansible all -i '$inv' -m raw -a 'powershell.exe -NoProfile -Command \"Write-Output ANSIBLE_OK\"' -e ansible_user=${env:USERNAME} -e ansible_shell_type=cmd --ssh-common-args '-o StrictHostKeyChecking=no'"
        $ansibleTest = wsl bash -lc $ansibleCmd 2>&1
        if ($LASTEXITCODE -eq 0 -and "$ansibleTest" -match 'ANSIBLE_OK') {
            Write-Host "[OK] Ansible 连通成功" -ForegroundColor Green
            Write-Host $ansibleTest
        } else {
            Write-Host "[WARN] Ansible raw 测试未完全通过，但 SSH 已成功，playbook 修复仍可用" -ForegroundColor Yellow
            Write-Host $ansibleTest
        }
    } catch {
        Write-Host "[WARN] Ansible 测试跳过: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "SSH 已成功，可直接启动 RayScan 真实修复模式" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "=== 完成。启动 RayScan 真实修复模式 ===" -ForegroundColor Cyan
Write-Host @"

`$env:RAYSCAN_ANSIBLE_MODE='wsl'
`$env:RAYSCAN_SIMULATE_ON_WINDOWS='0'
`$env:RAYSCAN_TARGET_OS='windows'
`$env:RAYSCAN_TARGET_IP='$primaryIp'
`$env:RAYSCAN_ANSIBLE_USER='$env:USERNAME'
cd D:\rayscan
python app.py

"@
Write-Host "扫描/修复目标请使用: $primaryIp 或 http://${primaryIp}/..." -ForegroundColor Green
