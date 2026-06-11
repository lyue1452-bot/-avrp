function Get-ApacheConfRoots {
    $roots = [System.Collections.Generic.List[string]]::new()
    foreach ($p in @(
        'C:\xampp\apache\conf', 'D:\xampp\apache\conf',
        'C:\Apache24\conf', 'D:\Apache24\conf'
    )) {
        if (Test-Path (Join-Path $p 'httpd.conf')) { [void]$roots.Add($p) }
    }
    foreach ($base in @('C:\phpstudy_pro', 'D:\phpstudy_pro', 'E:\phpstudy_pro')) {
        if (-not (Test-Path $base)) { continue }
        $ext = Join-Path $base 'Extensions'
        if (-not (Test-Path $ext)) { continue }
        Get-ChildItem -Path $ext -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $conf = Join-Path $_.FullName 'conf\httpd.conf'
            if (Test-Path $conf) { [void]$roots.Add((Split-Path $conf -Parent)) }
        }
    }
    return $roots | Select-Object -Unique
}

function Restart-ApacheInstances {
    foreach ($n in @('Apache2.4', 'Apache', 'wampapache64', 'xamppapache')) {
        if (Get-Service -Name $n -ErrorAction SilentlyContinue) {
            Restart-Service $n -Force -ErrorAction SilentlyContinue
            Write-Output "Restarted service $n"
        }
    }

    foreach ($root in (Get-ApacheConfRoots)) {
        $bin = Join-Path (Split-Path $root -Parent) 'bin\httpd.exe'
        if (-not (Test-Path $bin)) { continue }
        $restarted = $false
        try {
            & $bin -k restart 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) {
                $restarted = $true
                Write-Output "Restarted httpd (service): $bin"
            }
        } catch { }

        if (-not $restarted) {
            $procs = Get-Process -Name httpd -ErrorAction SilentlyContinue
            if ($procs) {
                $procs | Stop-Process -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }
            Start-Process -FilePath $bin -ArgumentList '-k start' -WindowStyle Hidden
            Write-Output "Restarted httpd (process): $bin"
        }
    }
}

function Find-OpenSsl {
    foreach ($p in @(
        (Join-Path $env:ProgramFiles 'Git\usr\bin\openssl.exe'),
        'C:\Program Files\OpenSSL-Win64\bin\openssl.exe',
        'openssl'
    )) {
        if ($p -eq 'openssl') {
            $cmd = Get-Command openssl -ErrorAction SilentlyContinue
            if ($cmd) { return $cmd.Source }
            continue
        }
        if (Test-Path $p) { return $p }
    }
    return $null
}

function Enable-ApacheModule {
    param(
        [Parameter(Mandatory = $true)][string]$ModuleToken
    )
    foreach ($root in (Get-ApacheConfRoots)) {
        $httpd = Join-Path $root 'httpd.conf'
        if (-not (Test-Path $httpd)) { continue }
        $raw = Get-Content $httpd -Raw
        $escaped = [regex]::Escape($ModuleToken)
        if ($raw -match "(?m)^#\s*$escaped") {
            $raw = $raw -replace "(?m)^#\s*($escaped)", '$1'
            Set-Content -Path $httpd -Value $raw -Encoding UTF8
            Write-Output "Enabled module in $httpd : $ModuleToken"
        }
    }
}

function Ensure-ApacheListen443 {
    foreach ($root in (Get-ApacheConfRoots)) {
        $listenConf = Join-Path $root 'vhosts\Listen.conf'
        if (-not (Test-Path $listenConf)) { continue }
        $content = Get-Content $listenConf -Raw
        if ($content -notmatch '(?m)^Listen\s+443\b') {
            Add-Content -Path $listenConf -Value 'Listen 443'
            Write-Output "Added Listen 443: $listenConf"
        }
    }
}

function Get-PhpStudyWwwRoot {
    foreach ($base in @('C:\phpstudy_pro', 'D:\phpstudy_pro', 'E:\phpstudy_pro')) {
        $www = Join-Path $base 'WWW'
        if (Test-Path $www) { return $www.Replace('\', '/') }
    }
    foreach ($p in @('C:\xampp\htdocs', 'D:\xampp\htdocs')) {
        if (Test-Path $p) { return $p.Replace('\', '/') }
    }
    return 'D:/phpstudy_pro/WWW'
}

function Deploy-ApacheSnippet {
    param(
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][string]$Snippet,
        [Parameter(Mandatory = $true)][string]$MatchToken
    )
    $done = $false
    foreach ($root in (Get-ApacheConfRoots)) {
        $extra = Join-Path $root 'extra'
        if (-not (Test-Path $extra)) { New-Item -ItemType Directory -Path $extra -Force | Out-Null }
        $conf = Join-Path $extra $FileName
        Set-Content -Path $conf -Value $Snippet -Encoding UTF8
        $httpd = Join-Path $root 'httpd.conf'
        if (Test-Path $httpd) {
            $inc = "Include conf/extra/$FileName"
            if ((Get-Content $httpd -Raw) -notmatch [regex]::Escape($MatchToken)) {
                Add-Content -Path $httpd -Value "`n$inc"
            }
            $done = $true
            Write-Output "Updated Apache: $conf"
        }
    }
    if (-not $done) {
        Write-Error 'No Apache httpd.conf found'
        exit 1
    }
}