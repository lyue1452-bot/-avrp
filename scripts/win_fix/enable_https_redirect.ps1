$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\ApacheCommon.ps1"

$wwwRoot = Get-PhpStudyWwwRoot
$roots = Get-ApacheConfRoots
if (-not $roots) {
    Write-Error 'No Apache httpd.conf found'
    exit 1
}

$sslDirs = @()
foreach ($root in $roots) {
    $sslDir = Join-Path $root 'ssl'
    if (-not (Test-Path $sslDir)) { New-Item -ItemType Directory -Path $sslDir -Force | Out-Null }
    $sslDirs += $sslDir
}

$primarySsl = $sslDirs[0]
$gen = Join-Path $PSScriptRoot 'generate_self_signed_cert.py'
if (-not (Test-Path $gen)) {
    Write-Error "Missing $gen"
    exit 1
}
$out = python $gen $primarySsl 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Certificate generation failed: $out"
    exit 1
}

$crtPath = Join-Path $primarySsl 'rayscan.crt'
$keyPath = Join-Path $primarySsl 'rayscan.key'
foreach ($sslDir in $sslDirs) {
    if ($sslDir -eq $primarySsl) { continue }
    Copy-Item $crtPath (Join-Path $sslDir 'rayscan.crt') -Force
    Copy-Item $keyPath (Join-Path $sslDir 'rayscan.key') -Force
}

Ensure-ApacheListen443 | Out-Null

$crtApache = $crtPath.Replace('\', '/')
$keyApache = $keyPath.Replace('\', '/')

$ip = ''
try {
    $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254*' } |
        Sort-Object { if ($_.IPAddress -like '192.168.101.*') { 0 } else { 1 } } |
        Select-Object -First 1).IPAddress
} catch { }

$serverNameLine = if ($ip) { "  ServerName ${ip}:443`n" } else { '' }

$snippet = @"
# RayScan: HTTPS + HSTS（HTTP 重定向见 vhosts/0localhost_80.conf）
<IfModule mod_ssl.c>
<VirtualHost *:443>
${serverNameLine}  SSLEngine on
  SSLCertificateFile "$crtApache"
  SSLCertificateKeyFile "$keyApache"
  DocumentRoot "$wwwRoot"
  <Directory "$wwwRoot">
    Options FollowSymLinks ExecCGI
    AllowOverride All
    Require all granted
  </Directory>
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</VirtualHost>
</IfModule>
"@

Deploy-ApacheSnippet -FileName 'rayscan-force-https.conf' -MatchToken 'rayscan-force-https' -Snippet $snippet

foreach ($root in $roots) {
    $vhost80 = Join-Path $root 'vhosts\0localhost_80.conf'
    if (-not (Test-Path $vhost80)) { continue }
    $raw = Get-Content $vhost80 -Raw
    if ($raw -match 'RayScan-HTTPS-Redirect') { continue }
    $inject = @"

  # RayScan-HTTPS-Redirect
  <IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301,NE]
  </IfModule>
"@
    $raw = $raw -replace '(</VirtualHost>)', "$inject`n`$1"
    Set-Content -Path $vhost80 -Value $raw -Encoding UTF8
    Write-Output "Patched vhost redirect: $vhost80"
}

Restart-ApacheInstances
Write-Output "HTTPS enabled with self-signed cert. Browser may warn until trusted."
Write-Output "Verify: curl -kI https://<host>/  and curl -I http://<host>/ (expect 301)"
