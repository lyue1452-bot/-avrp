# 验证 HTTP 类漏洞是否真实修复（对比响应头）
param(
    [string]$Url = "http://192.168.101.36/DVWA-master/DVWA-master/"
)

Write-Host "=== RayScan HTTP 修复验证 ===" -ForegroundColor Cyan
Write-Host "目标: $Url"
Write-Host ""

try {
    $resp = Invoke-WebRequest -Uri $Url -Method Head -MaximumRedirection 0 -UseBasicParsing -ErrorAction SilentlyContinue
    $headers = $resp.Headers
} catch {
    if ($_.Exception.Response) {
        $headers = $_.Exception.Response.Headers
    } else {
        Write-Host "无法访问 URL: $_" -ForegroundColor Red
        exit 1
    }
}

$checks = @(
    @{ Name = "Server 版本隐藏"; Key = "Server"; Ok = { param($v) $v -and $v -notmatch '/\d+\.\d+' } },
    @{ Name = "X-Content-Type-Options"; Key = "X-Content-Type-Options"; Ok = { param($v) $v } },
    @{ Name = "X-Frame-Options"; Key = "X-Frame-Options"; Ok = { param($v) $v } },
    @{ Name = "Referrer-Policy"; Key = "Referrer-Policy"; Ok = { param($v) $v } },
    @{ Name = "Content-Security-Policy"; Key = "Content-Security-Policy"; Ok = { param($v) $v } }
)

$pass = 0
foreach ($c in $checks) {
    $val = $null
    if ($headers[$c.Key]) { $val = $headers[$c.Key] }
    $ok = & $c.Ok $val
    if ($ok) {
        Write-Host "[PASS] $($c.Name): $val" -ForegroundColor Green
        $pass++
    } else {
        Write-Host "[FAIL] $($c.Name): $(if ($val) { $val } else { '(未设置)' })" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "通过 $pass / $($checks.Count) 项"
if ($pass -eq $checks.Count) {
    Write-Host "结论: 修复已在 HTTP 响应中体现" -ForegroundColor Green
} elseif ($pass -gt 0) {
    Write-Host "结论: 部分修复已生效" -ForegroundColor Yellow
    Write-Host "提示: Server 版本隐藏需 ServerTokens 配置 + 在 phpstudy 面板重启 Apache（.htaccess 无法改 Server 头）" -ForegroundColor DarkGray
} else {
    Write-Host "结论: 修复未完全生效（或仍为演示模式修复）" -ForegroundColor Yellow
}
