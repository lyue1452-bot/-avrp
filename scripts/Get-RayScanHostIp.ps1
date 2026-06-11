# 解析本机用于 Ansible/SSH 的主机 IP（排除 VMware/虚拟网卡）
function Get-RayScanHostIp {
    param(
        [string]$Preferred = $env:RAYSCAN_TARGET_IP
    )
    if ($Preferred) {
        return $Preferred.Trim()
    }

    $skipAlias = 'VMware|VirtualBox|vEthernet|Hyper-V|Loopback|Teredo|Bluetooth|WSL|Npcap|TAP-Windows'

    $candidates = @()
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
        $ip = $_.IPAddress
        if ($ip -like '127.*' -or $ip -like '169.254*') { return }
        $adapter = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue
        $alias = if ($adapter) { $adapter.InterfaceAlias } else { '' }
        if ($alias -match $skipAlias) { return }

        $score = 0
        # 真实局域网网段优先（你环境 DVWA 使用 192.168.101.x）
        if ($ip -like '192.168.101.*') { $score += 100 }
        # 非 .1 结尾（虚拟网卡常为 x.x.x.1）
        if ($ip -notmatch '\.1$') { $score += 20 }
        # 有线/无线优先
        if ($alias -match 'Ethernet|Wi-?Fi|WLAN') { $score += 30 }

        $candidates += [PSCustomObject]@{ IP = $ip; Score = $score; Alias = $alias }
    }

    if ($candidates.Count -eq 0) {
        return '127.0.0.1'
    }
    return ($candidates | Sort-Object Score -Descending | Select-Object -First 1).IP
}

if ($MyInvocation.InvocationName -ne '.') {
    Get-RayScanHostIp
}
