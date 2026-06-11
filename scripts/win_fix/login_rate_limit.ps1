$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\ApacheCommon.ps1"

Enable-ApacheModule -ModuleToken 'LoadModule reqtimeout_module modules/mod_reqtimeout.so' | Out-Null
Enable-ApacheModule -ModuleToken 'LoadModule ratelimit_module modules/mod_ratelimit.so' | Out-Null

$snippet = @'
# RayScan: login path hardening (Apache layer)
<IfModule mod_reqtimeout.c>
  <LocationMatch "(?i)/(login|signin|auth|setup\.php|index\.php)">
    RequestReadTimeout header=20,MinRate=500 body=20,MinRate=500
  </LocationMatch>
</IfModule>

<IfModule mod_ratelimit.c>
  <LocationMatch "(?i)/(login|signin|auth|setup\.php)">
    SetOutputFilter RATE_LIMIT
    SetEnv rate-limit 400
    SetEnv rate-initial-burst 3
  </LocationMatch>
</IfModule>

<IfModule mod_headers.c>
  <LocationMatch "(?i)/(login|signin|auth|setup\.php)">
    Header always set X-RayScan-Login-Protection "rate-limit,reqtimeout"
  </LocationMatch>
</IfModule>
'@

Deploy-ApacheSnippet -FileName 'rayscan-login-hardening.conf' -MatchToken 'rayscan-login-hardening' -Snippet $snippet

$wwwRoots = @(
    'C:\phpstudy_pro\WWW',
    'D:\phpstudy_pro\WWW',
    'E:\phpstudy_pro\WWW',
    'C:\xampp\htdocs',
    'D:\xampp\htdocs'
)
$ht = @'
# RayScan login hardening (.htaccess layer)
<IfModule mod_reqtimeout.c>
  RequestReadTimeout header=20,MinRate=500 body=20,MinRate=500
</IfModule>
'@

foreach ($www in $wwwRoots) {
    if (-not (Test-Path $www)) { continue }
    Get-ChildItem -Path $www -Recurse -Filter 'login.php' -ErrorAction SilentlyContinue | ForEach-Object {
        $dir = $_.Directory.FullName
        $path = Join-Path $dir '.htaccess'
        if (Test-Path $path) {
            $existing = Get-Content $path -Raw
            if ($existing -match 'RayScan login hardening') { return }
            Add-Content -Path $path -Value "`n$ht"
        } else {
            Set-Content -Path $path -Value $ht -Encoding ASCII
        }
        Write-Output "Updated login .htaccess: $path"
    }
}

Restart-ApacheInstances
Write-Output 'NOTE: Apache 层已启用登录路径限速与读超时；验证码/账号锁定仍需应用层配置。'
