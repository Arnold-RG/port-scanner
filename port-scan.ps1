<#
.SYNOPSIS
    TCP connect port scanner for a host, IP range or CIDR block.

.DESCRIPTION
    port-scan.ps1 performs full TCP connects against a list of ports on one
    or more hosts, in parallel through a runspace pool. It can grab a short
    banner from open ports and export the results to CSV or JSON.
    Works on Windows PowerShell 5.1 and PowerShell 7+ (Windows/Linux/macOS).

    Author : Arnold Rurangwa - MIT License
    Legal  : Only scan hosts you own or are explicitly authorised to test.

.PARAMETER Target
    Hostname, IPv4 address, last-octet range (10.0.0.10-20) or CIDR
    (10.0.0.0/28, prefix /22 to /32). At most 1024 hosts.

.PARAMETER Ports
    Ports as a list and/or ranges: 22,80,443 or 1-1024 or 20-25,80
    (quoted or unquoted).
    Default: 20 common service ports.

.PARAMETER TimeoutMs
    Connect timeout per port in milliseconds (100-10000). Default: 1000.

.PARAMETER Threads
    Parallel connections (1-500). Default: 100.

.PARAMETER Banner
    Read a banner from open ports (an HTTP HEAD request is sent on web ports).

.PARAMETER OutFile
    Write open ports to this file. Format comes from -Format or the extension.

.PARAMETER Format
    'csv' or 'json'.

.PARAMETER ShowClosed
    Also show ports that actively refused the connection.

.EXAMPLE
    .\port-scan.ps1 -Target 127.0.0.1 -Ports 1-1024

.EXAMPLE
    .\port-scan.ps1 -Target 192.168.1.10-20 -Ports 22,80,443 -Banner -OutFile scan.json

.NOTES
    Requirements: Windows PowerShell 5.1+ or PowerShell 7+. No admin rights needed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.\-/]{0,252}$')]
    [string]$Target,

    [ValidatePattern('^\d+(-\d+)?(,\d+(-\d+)?)*$')]
    [string[]]$Ports = '21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,8080',

    [ValidateRange(100, 10000)]
    [int]$TimeoutMs = 1000,

    [ValidateRange(1, 500)]
    [int]$Threads = 100,

    [switch]$Banner,

    [string]$OutFile,

    [ValidateSet('csv', 'json')]
    [string]$Format,

    [switch]$ShowClosed
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Well-known service names (kept small and offline on purpose).
$services = @{
    21 = 'ftp'; 22 = 'ssh'; 23 = 'telnet'; 25 = 'smtp'; 53 = 'domain'; 80 = 'http'
    110 = 'pop3'; 135 = 'msrpc'; 139 = 'netbios-ssn'; 143 = 'imap'; 443 = 'https'
    445 = 'microsoft-ds'; 993 = 'imaps'; 995 = 'pop3s'; 1433 = 'ms-sql-s'
    3306 = 'mysql'; 3389 = 'ms-wbt-server'; 5432 = 'postgresql'; 5900 = 'vnc'
    8000 = 'http-alt'; 8080 = 'http-alt'; 8443 = 'https-alt'
}

# ---- expand ports ----------------------------------------------------------------
$portSet = New-Object 'System.Collections.Generic.SortedSet[int]'
# -Ports 22,80 arrives as an array, -Ports '22,80' as one string: accept both.
foreach ($item in (($Ports -join ',').Split(','))) {
    $bounds = $item.Split('-')
    $lo = [int]$bounds[0]; $hi = [int]$bounds[-1]
    if ($lo -lt 1 -or $hi -gt 65535) { throw "Port out of range: $item" }
    if ($lo -gt $hi) { throw "Reversed range: $item" }
    for ($p = $lo; $p -le $hi; $p++) { [void]$portSet.Add($p) }
}
$portList = @($portSet)

# ---- expand targets --------------------------------------------------------------
function Test-IPv4([string]$Ip) {
    if ($Ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $false }
    foreach ($o in $Ip.Split('.')) { if ([int]$o -gt 255) { return $false } }
    return $true
}
function ConvertTo-UInt64([string]$Ip) {
    $b = ([System.Net.IPAddress]::Parse($Ip)).GetAddressBytes()
    return ([uint64]$b[0] * 16777216) + ([uint64]$b[1] * 65536) + ([uint64]$b[2] * 256) + [uint64]$b[3]
}
function ConvertTo-IpString([uint64]$n) {
    return '{0}.{1}.{2}.{3}' -f ([math]::Floor($n / 16777216) % 256), ([math]::Floor($n / 65536) % 256), ([math]::Floor($n / 256) % 256), ($n % 256)
}

$hosts = New-Object System.Collections.Generic.List[string]
if ($Target -match '^([\d.]+)/(\d+)$') {
    $ip = $Matches[1]; $prefix = [int]$Matches[2]
    if (-not (Test-IPv4 $ip)) { throw "Invalid IP in $Target" }
    if ($prefix -lt 22 -or $prefix -gt 32) { throw 'CIDR prefix must be /22 - /32 (max 1024 hosts).' }
    $size = [uint64][math]::Pow(2, 32 - $prefix)
    $net = (ConvertTo-UInt64 $ip) - ((ConvertTo-UInt64 $ip) % $size)
    if ($prefix -ge 31) { $first = $net; $last = $net + $size - 1 }
    else { $first = $net + 1; $last = $net + $size - 2 }
    for ($i = $first; $i -le $last; $i++) { $hosts.Add((ConvertTo-IpString $i)) }
}
elseif ($Target -match '^((\d{1,3}\.){3})(\d{1,3})-(\d{1,3})$') {
    $pre = $Matches[1]; $s = [int]$Matches[3]; $e = [int]$Matches[4]
    if (-not (Test-IPv4 "$pre$s") -or -not (Test-IPv4 "$pre$e") -or $s -gt $e) { throw "Bad range: $Target" }
    for ($i = $s; $i -le $e; $i++) { $hosts.Add("$pre$i") }
}
elseif ($Target -match '^\d{1,3}(\.\d{1,3}){3}$') {
    if (-not (Test-IPv4 $Target)) { throw "Invalid IPv4 address: $Target" }
    $hosts.Add($Target)
}
elseif ($Target -notmatch '/') {
    $hosts.Add($Target)                       # hostname
}
else { throw "Unrecognised target: $Target" }

$total = $hosts.Count * $portList.Count
if ($total -gt 200000) { throw "Too many probes ($total); narrow the hosts or ports." }

if ($OutFile -and -not $Format) {
    if ($OutFile -like '*.json') { $Format = 'json' } else { $Format = 'csv' }
}

# ---- probe (runs inside a runspace) ----------------------------------------------
$probe = {
    param([string]$HostName, [int]$Port, [int]$TimeoutMs, [bool]$GrabBanner)
    $state = 'filtered'; $text = ''
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        if ($async.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            try {
                $client.EndConnect($async); $state = 'open'
                if ($GrabBanner) {
                    $stream = $client.GetStream()
                    $stream.ReadTimeout = 2000
                    if (@(80, 8000, 8008, 8080, 8081, 8888) -contains $Port) {
                        $req = [Text.Encoding]::ASCII.GetBytes("HEAD / HTTP/1.0`r`n`r`n")
                        $stream.Write($req, 0, $req.Length)
                    }
                    $buf = New-Object byte[] 256
                    try {
                        $n = $stream.Read($buf, 0, $buf.Length)
                        if ($n -gt 0) {
                            $text = ([Text.Encoding]::ASCII.GetString($buf, 0, $n) -split "`r?`n")[0]
                            $text = ($text -replace '[^\x20-\x7E]', ' ').Trim()
                            if ($text.Length -gt 80) { $text = $text.Substring(0, 80) }
                        }
                    } catch { $text = '' }    # service sent nothing in time
                }
            }
            catch {
                $inner = $_.Exception.InnerException
                if ($inner -is [System.Net.Sockets.SocketException] -and
                    $inner.SocketErrorCode -eq 'ConnectionRefused') { $state = 'closed' }
            }
        }
    }
    finally { $client.Close() }
    [pscustomobject]@{ Host = $HostName; Port = $Port; State = $state; Banner = $text }
}

Write-Host ("Scanning {0} host(s) x {1} port(s) = {2} probes (timeout {3} ms, {4} threads)" -f `
    $hosts.Count, $portList.Count, $total, $TimeoutMs, $Threads)
$started = Get-Date
$pool = [RunspaceFactory]::CreateRunspacePool(1, $Threads)
$pool.Open()
$results = New-Object System.Collections.Generic.List[object]
try {
    $jobs = New-Object System.Collections.Generic.List[object]
    foreach ($h in $hosts) {
        foreach ($p in $portList) {
            $ps = [PowerShell]::Create(); $ps.RunspacePool = $pool
            [void]$ps.AddScript($probe).AddArgument($h).AddArgument($p).AddArgument($TimeoutMs).AddArgument([bool]$Banner)
            $jobs.Add([pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke() })
        }
    }
    $done = 0
    foreach ($j in $jobs) {
        foreach ($r in $j.PS.EndInvoke($j.Handle)) { if ($r.State -ne 'filtered') { $results.Add($r) } }
        $j.PS.Dispose(); $done++
        if ($done % 50 -eq 0) { Write-Progress -Activity 'Port scan' -Status "$done / $total" -PercentComplete ($done * 100 / $total) }
    }
    Write-Progress -Activity 'Port scan' -Completed
}
finally { $pool.Close(); $pool.Dispose() }

$rows = @($results | ForEach-Object {
        $svc = 'unknown'; if ($services.ContainsKey($_.Port)) { $svc = $services[$_.Port] }
        [pscustomobject]@{ Host = $_.Host; Port = $_.Port; State = $_.State; Service = $svc; Banner = $_.Banner }
    } | Sort-Object Host, Port)
$open = @($rows | Where-Object State -eq 'open')
$shown = $open
if ($ShowClosed) { $shown = $rows }

$shown | Format-Table -AutoSize | Out-String | Write-Host
Write-Host ("{0} open port(s) found in {1}s." -f $open.Count, [int]((Get-Date) - $started).TotalSeconds)

if ($OutFile) {
    if ($Format -eq 'json') { ConvertTo-Json -InputObject $open -Depth 3 | Set-Content -Path $OutFile -Encoding UTF8 }
    else { $open | Export-Csv -Path $OutFile -NoTypeInformation }
    Write-Host "Results ($Format) written to $OutFile"
}
$open
