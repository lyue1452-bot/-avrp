function Get-ApacheConfRoots {
    $roots = [System.Collections.Generic.List[string]]::new()

    foreach ($p in @(
        'C:\xampp\apache\conf',
        'D:\xampp\apache\conf',
        'C:\Apache24\conf',
        'D:\Apache24\conf',
        'C:\wamp64\bin\apache\apache2.4.54\conf'
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

    Get-CimInstance Win32_Process -Filter "Name='httpd.exe'" -ErrorAction SilentlyContinue | ForEach-Object {
        $line = $_.CommandLine
        if (-not $line) { return }
        if ($line -match '(?i)([A-Z]:\\[^"\s]+\\conf)\\httpd\.conf') {
            [void]$roots.Add($Matches[1])
        } elseif ($line -match '(?i)([A-Z]:\\[^"\s]+)\\bin\\httpd\.exe') {
            $confDir = Join-Path (Split-Path $Matches[1] -Parent) 'conf'
            if (Test-Path (Join-Path $confDir 'httpd.conf')) { [void]$roots.Add($confDir) }
        }
    }

    return $roots | Select-Object -Unique
}

function Restart-ApacheInstances {
    foreach ($n in @('Apache2.4', 'Apache', 'wampapache64', 'xamppapache')) {
        $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
        if ($svc) {
            Restart-Service $n -Force -ErrorAction SilentlyContinue
            Write-Output "Restarted service $n"
        }
    }

    foreach ($root in (Get-ApacheConfRoots)) {
        $bin = Join-Path (Split-Path $root -Parent) 'bin\httpd.exe'
        if (Test-Path $bin) {
            & $bin -k restart 2>&1 | Out-Null
            Write-Output "Restarted httpd: $bin"
        }
    }
}
