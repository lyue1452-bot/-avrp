$snippet = @'
ServerTokens Prod
ServerSignature Off
'@

$done = $false
foreach ($root in (Get-ApacheConfRoots)) {
    $extra = Join-Path $root 'extra'
    if (-not (Test-Path $extra)) { New-Item -ItemType Directory -Path $extra -Force | Out-Null }
    $conf = Join-Path $extra 'rayscan-server-tokens.conf'
    Set-Content -Path $conf -Value $snippet -Encoding UTF8
    $httpd = Join-Path $root 'httpd.conf'
    if (Test-Path $httpd) {
        $inc = 'Include conf/extra/rayscan-server-tokens.conf'
        if ((Get-Content $httpd -Raw) -notmatch 'rayscan-server-tokens') {
            Add-Content -Path $httpd -Value "`n$inc"
        }
        $done = $true
        Write-Output "ServerTokens config: $conf"
    }
}

if (-not $done) { Write-Error 'No Apache httpd.conf found'; exit 1 }
