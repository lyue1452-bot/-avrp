$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\ApacheCommon.ps1"

$snippet = @'
<IfModule mod_headers.c>
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
  Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
</IfModule>
'@

Deploy-ApacheSnippet -FileName 'rayscan-security-headers.conf' -MatchToken 'rayscan-security-headers' -Snippet $snippet

$wwwRoots = @(
    'C:\phpstudy_pro\WWW',
    'D:\phpstudy_pro\WWW',
    'E:\phpstudy_pro\WWW',
    'C:\xampp\htdocs',
    'D:\xampp\htdocs'
)
$ht = @'
# RayScan HTTP security headers (no Apache restart required)
<IfModule mod_headers.c>
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
  Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
</IfModule>
'@

foreach ($www in $wwwRoots) {
    if (-not (Test-Path $www)) { continue }
    $path = Join-Path $www '.htaccess'
    if (Test-Path $path) {
        $existing = Get-Content $path -Raw
        if ($existing -match 'RayScan HTTP security headers') { continue }
        Add-Content -Path $path -Value "`n$ht"
    } else {
        Set-Content -Path $path -Value $ht -Encoding ASCII
    }
    Write-Output "Updated .htaccess: $path"
}

Restart-ApacheInstances
