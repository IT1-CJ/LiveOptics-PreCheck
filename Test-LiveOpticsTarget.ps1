<#
.SYNOPSIS
    Pre-check for Live Optics remote collection against Windows servers (WMI over RPC/DCOM).

.DESCRIPTION
    Run this from the SAME machine (and as the same account, or with the same credential)
    that will run LiveOptics.exe. For each target it checks, in order:

      1. Name resolution    - Is the target an IP, short name or FQDN? Forward/reverse DNS.
      2. Ping               - Informational only (ICMP is often blocked).
      3. TCP 135            - RPC Endpoint Mapper. If this fails you get the
                              "RPC network service ... was unreachable" error.
      4. TCP 445            - SMB. Informational, helps tell "host down" from "WMI blocked".
      5. WMI over DCOM      - Win32_OperatingSystem query. This uses the dynamic RPC
                              port range (49152-65535 by default), so it catches firewalls
                              that allow 135 but block the dynamic ports.
      6. Perf counters      - Win32_PerfRawData_PerfDisk_PhysicalDisk, which Live Optics needs.

    Works with an IP address, a short host name, or an FQDN. Using an IP address forces
    NTLM instead of Kerberos, which is a common cause of failures; the script flags this
    and suggests the FQDN when reverse DNS finds one.

.PARAMETER ComputerName
    One or more targets (IP, short name or FQDN).

.PARAMETER InputFile
    Text or CSV file of targets. Text: one per line. CSV: needs a ComputerName column.

.PARAMETER Credential
    Credential to test with. Use the same account the collector will use.
    If omitted, the current Windows logon is used.

.PARAMETER TimeoutMs
    TCP connect timeout in milliseconds. Default 2000.

.PARAMETER ExportCsv
    Optional path to save the results as CSV.

.EXAMPLE
    .\Test-LiveOpticsTarget.ps1 -ComputerName 10.0.10.8

.EXAMPLE
    .\Test-LiveOpticsTarget.ps1 -ComputerName sql01.contoso.local -Credential (Get-Credential)

.EXAMPLE
    .\Test-LiveOpticsTarget.ps1 -InputFile .\servers.txt -Credential (Get-Credential) -ExportCsv .\precheck.csv
#>
[CmdletBinding(DefaultParameterSetName = 'Names')]
param(
    [Parameter(ParameterSetName = 'Names', Mandatory, Position = 0, ValueFromPipeline)]
    [string[]]$ComputerName,

    [Parameter(ParameterSetName = 'File', Mandatory)]
    [string]$InputFile,

    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty,

    [int]$TimeoutMs = 2000,

    [string]$ExportCsv,

    # Also return the result objects to the pipeline (for scripting).
    [switch]$PassThru
)

begin {
    $ErrorActionPreference = 'Stop'
    $targets = [System.Collections.Generic.List[string]]::new()
    $results = [System.Collections.Generic.List[object]]::new()
    $useCred = $Credential -ne [System.Management.Automation.PSCredential]::Empty

    function Write-Check {
        param([string]$Name, [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO', 'SKIP')][string]$Status, [string]$Detail)
        $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan'; SKIP = 'DarkGray' }[$Status]
        Write-Host ('  [{0,-4}] ' -f $Status) -ForegroundColor $color -NoNewline
        Write-Host ('{0,-18} {1}' -f $Name, $Detail)
    }

    function Test-TcpPort {
        param([string]$Address, [int]$Port, [int]$Timeout)
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $task = $client.ConnectAsync($Address, $Port)
            if ($task.Wait($Timeout) -and $client.Connected) { return 'Open' }
            return 'Closed/Filtered'
        }
        catch { return 'Closed/Filtered' }
        finally { $client.Dispose() }
    }

    # Map common WMI/RPC error codes to plain-language causes and fixes.
    function Get-ErrorAdvice {
        param([System.Exception]$Exception)
        $msg = $Exception.Message
        $code = $null
        if ($Exception.PSObject.Properties['HResult']) { $code = '0x{0:X8}' -f $Exception.HResult }
        if ($msg -match '0x[0-9A-Fa-f]{8}') { $code = $Matches[0].ToUpper().Replace('0X', '0x') }

        switch -Regex ("$code $msg") {
            '800706BA|RPC server is unavailable' {
                return @{ Code = $code; Cause = 'RPC server unavailable'
                    Fix = 'Port 135 and/or the dynamic RPC ports (49152-65535) are blocked, or the WMI/RPC services are stopped. On the target run: Enable-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)"' }
            }
            '80070005|Access is denied|Access denied' {
                return @{ Code = $code; Cause = 'Access denied'
                    Fix = 'Account must be a local Administrator on the target. If using a LOCAL (non-domain) account, set LocalAccountTokenFilterPolicy=1 on the target. If using an IP address, try the FQDN (Kerberos).' }
            }
            '80041003' {
                return @{ Code = $code; Cause = 'WMI namespace access denied'
                    Fix = 'Grant the account Remote Enable on root\cimv2 (wmimgmt.msc > WMI Control > Security), or add it to local Administrators.' }
            }
            '800706BE|800706BF|remote procedure call failed' {
                return @{ Code = $code; Cause = 'RPC call failed mid-call'
                    Fix = 'Often a firewall/IPS dropping DCOM traffic or a WMI repository problem. On the target run: winmgmt /verifyrepository' }
            }
            '80070776|object exporter' {
                return @{ Code = $code; Cause = 'Object exporter not found'
                    Fix = 'Name/IP mismatch or NAT between collector and target. Check DNS and that the target is reachable by the address it reports.' }
            }
            '8007052E|user name or password' {
                return @{ Code = $code; Cause = 'Bad user name or password'
                    Fix = 'Re-enter the credential. Use DOMAIN\user or user@domain format.' }
            }
            '80041010|Invalid class' {
                return @{ Code = $code; Cause = 'Perf class missing'
                    Fix = 'Performance counters may be corrupt on the target. On the target run (admin): lodctr /R  then  winmgmt /resyncperf' }
            }
            default {
                return @{ Code = $code; Cause = 'Unexpected error'; Fix = $msg }
            }
        }
    }
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'Names') { $ComputerName -split '[,;\s]+' | Where-Object { $_ } | ForEach-Object { $targets.Add($_.Trim()) } }
}

end {
    if ($PSCmdlet.ParameterSetName -eq 'File') {
        if (-not (Test-Path $InputFile)) { throw "Input file not found: $InputFile" }
        if ($InputFile -like '*.csv') {
            Import-Csv $InputFile | ForEach-Object { $targets.Add($_.ComputerName.Trim()) }
        }
        else {
            Get-Content $InputFile | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object { $targets.Add($_.Trim()) }
        }
    }

    Write-Host ''
    Write-Host 'Live Optics Windows pre-check' -ForegroundColor White
    Write-Host ("Run from: {0}  as: {1}  credential: {2}" -f $env:COMPUTERNAME, "$env:USERDOMAIN\$env:USERNAME",
        $(if ($useCred) { $Credential.UserName } else { '(current logon)' }))

    foreach ($target in ($targets | Where-Object { $_ } | Select-Object -Unique)) {
        Write-Host ''
        Write-Host "=== $target ===" -ForegroundColor White

        $r = [ordered]@{
            Target = $target; InputType = ''; ResolvedIP = ''; ResolvedName = ''
            Ping = ''; Port135 = ''; Port445 = ''; WmiDcom = ''; PerfCounters = ''
            Result = ''; ErrorCode = ''; Cause = ''; Recommendation = ''
        }
        $warnings = [System.Collections.Generic.List[string]]::new()

        # ---- 1. Name resolution ----------------------------------------------
        $ipObj = $null
        $isIp = [System.Net.IPAddress]::TryParse($target, [ref]$ipObj)
        $connectTo = $target

        if ($isIp) {
            $r.InputType = 'IP address'
            $r.ResolvedIP = $target
            try {
                $rev = [System.Net.Dns]::GetHostEntry($target).HostName
                $r.ResolvedName = $rev
                Write-Check 'Input' 'WARN' "IP address used. Reverse DNS = $rev"
                $warnings.Add("Use the FQDN '$rev' instead of the IP so Kerberos auth can be used.")
            }
            catch {
                Write-Check 'Input' 'WARN' 'IP address used and no reverse DNS (PTR) record found.'
                $warnings.Add('IP forces NTLM auth. If NTLM is restricted, use the FQDN instead.')
            }
        }
        else {
            $r.InputType = if ($target -like '*.*') { 'FQDN' } else { 'Short name' }
            try {
                $entry = [System.Net.Dns]::GetHostEntry($target)
                $ipv4 = $entry.AddressList | Where-Object AddressFamily -eq 'InterNetwork' | Select-Object -First 1
                $ip = if ($ipv4) { $ipv4 } else { $entry.AddressList | Select-Object -First 1 }
                $r.ResolvedIP = "$ip"
                $r.ResolvedName = $entry.HostName
                Write-Check 'DNS' 'PASS' "$target -> $ip ($($entry.HostName))"
                if ($r.InputType -eq 'Short name') {
                    $warnings.Add("Short name used. Prefer the FQDN '$($entry.HostName)'.")
                }
                # Stale DNS check: does the IP reverse-resolve back to the same host?
                try {
                    $back = [System.Net.Dns]::GetHostEntry("$ip").HostName
                    $short = ($target -split '\.')[0]
                    if ($back -notlike "$short*") {
                        Write-Check 'Reverse DNS' 'WARN' "$ip reverse-resolves to $back (possible stale DNS record)"
                        $warnings.Add("Forward/reverse DNS mismatch: $ip -> $back.")
                    }
                    else { Write-Check 'Reverse DNS' 'PASS' "$ip -> $back" }
                }
                catch { Write-Check 'Reverse DNS' 'INFO' "No PTR record for $ip (not fatal)" }
            }
            catch {
                Write-Check 'DNS' 'FAIL' "Cannot resolve '$target'."
                $r.Result = 'FAIL'; $r.Cause = 'Name does not resolve'
                $r.Recommendation = 'Check spelling, DNS suffix, or that the collector uses the right DNS servers. Try the IP to confirm the host is up.'
                $results.Add([pscustomobject]$r)
                continue
            }
        }

        # ---- 2. Ping (informational) -----------------------------------------
        try {
            $ping = [System.Net.NetworkInformation.Ping]::new().Send($connectTo, 1500)
            $r.Ping = "$($ping.Status)"
            if ($ping.Status -eq 'Success') { Write-Check 'Ping' 'PASS' "$($ping.RoundtripTime) ms" }
            else { Write-Check 'Ping' 'INFO' "$($ping.Status) (ICMP is often blocked; not fatal)" }
        }
        catch { $r.Ping = 'Error'; Write-Check 'Ping' 'INFO' 'No reply (ICMP is often blocked; not fatal)' }

        # ---- 3/4. TCP ports --------------------------------------------------
        $r.Port135 = Test-TcpPort -Address $connectTo -Port 135 -Timeout $TimeoutMs
        $r.Port445 = Test-TcpPort -Address $connectTo -Port 445 -Timeout $TimeoutMs

        if ($r.Port135 -eq 'Open') { Write-Check 'TCP 135 (RPC)' 'PASS' 'Endpoint mapper reachable' }
        else { Write-Check 'TCP 135 (RPC)' 'FAIL' 'Not reachable - this is the error in the Live Optics screen' }

        if ($r.Port445 -eq 'Open') { Write-Check 'TCP 445 (SMB)' 'PASS' 'Reachable' }
        else { Write-Check 'TCP 445 (SMB)' 'INFO' 'Not reachable' }

        if ($r.Port135 -ne 'Open') {
            $r.Result = 'FAIL'
            $r.Cause = 'RPC port 135 blocked or host down'
            if ($r.Ping -eq 'Success' -or $r.Port445 -eq 'Open') {
                $r.Recommendation = 'Host is up but port 135 is blocked. Open the "Windows Management Instrumentation (WMI)" firewall rules on the target and any network firewall between (TCP 135 + 49152-65535), and confirm the RpcSs and Winmgmt services are running.'
            }
            else {
                $r.Recommendation = 'Host did not answer on any test. Check the address is correct, the server is powered on, and routing/firewalls between the collector and the target. Or run LiveOptics.exe locally on the server.'
            }
            Write-Check 'WMI (DCOM)' 'SKIP' 'Skipped because port 135 is closed'
            $results.Add([pscustomobject]$r)
            continue
        }

        # ---- 5/6. WMI over DCOM (same protocol Live Optics uses) --------------
        $session = $null
        try {
            $opt = New-CimSessionOption -Protocol Dcom
            $sessArgs = @{ ComputerName = $connectTo; SessionOption = $opt; OperationTimeoutSec = 30; ErrorAction = 'Stop' }
            if ($useCred) { $sessArgs.Credential = $Credential }
            $session = New-CimSession @sessArgs

            $os = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem -ErrorAction Stop
            $r.WmiDcom = 'OK'
            Write-Check 'WMI (DCOM)' 'PASS' "$($os.CSName) - $($os.Caption)"

            try {
                $disks = @(Get-CimInstance -CimSession $session -ClassName Win32_PerfRawData_PerfDisk_PhysicalDisk -ErrorAction Stop)
                $r.PerfCounters = 'OK'
                Write-Check 'Perf counters' 'PASS' "$($disks.Count) PhysicalDisk instances"
            }
            catch {
                $a = Get-ErrorAdvice $_.Exception
                $r.PerfCounters = 'FAIL'
                Write-Check 'Perf counters' 'FAIL' $a.Cause
                $r.Result = 'FAIL'; $r.ErrorCode = $a.Code; $r.Cause = $a.Cause; $r.Recommendation = $a.Fix
            }

            if (-not $r.Result) {
                $r.Result = if ($warnings.Count) { 'PASS (with warnings)' } else { 'PASS' }
                $r.Recommendation = ($warnings -join ' ')
            }
        }
        catch {
            $a = Get-ErrorAdvice $_.Exception
            $r.WmiDcom = 'FAIL'
            $r.Result = 'FAIL'; $r.ErrorCode = $a.Code; $r.Cause = $a.Cause
            $r.Recommendation = $a.Fix
            if ($a.Cause -eq 'RPC server unavailable') {
                # 135 open but DCOM failed => dynamic ports are the problem
                $r.Cause = 'Port 135 open but dynamic RPC ports blocked'
                $r.Recommendation = 'Port 135 answers, but the follow-up connection on the dynamic RPC range (TCP 49152-65535) is blocked. Open that range (or the WMI firewall rule group) on the target and any network firewall in between.'
            }
            if ($warnings.Count) { $r.Recommendation += ' Also: ' + ($warnings -join ' ') }
            Write-Check 'WMI (DCOM)' 'FAIL' "$($r.Cause) $($r.ErrorCode)"
        }
        finally {
            if ($session) { Remove-CimSession $session -ErrorAction SilentlyContinue }
        }

        $results.Add([pscustomobject]$r)
    }

    # ---- Summary ---------------------------------------------------------
    Write-Host ''
    Write-Host '=== Summary ===' -ForegroundColor White
    $results | Format-Table Target, InputType, ResolvedIP, Port135, WmiDcom, PerfCounters, Result -AutoSize | Out-Host

    $problems = $results | Where-Object { $_.Result -ne 'PASS' }
    foreach ($p in $problems) {
        $color = if ($p.Result -like 'PASS*') { 'Yellow' } else { 'Red' }
        Write-Host "$($p.Target): $($p.Result)" -ForegroundColor $color
        if ($p.Cause) { Write-Host "  Cause: $($p.Cause) $($p.ErrorCode)" }
        if ($p.Recommendation) { Write-Host "  Fix:   $($p.Recommendation)" }
    }

    if ($problems | Where-Object { $_.Result -eq 'FAIL' }) {
        Write-Host ''
        Write-Host 'If the network cannot be opened, copy LiveOptics.exe to the server and run it locally.' -ForegroundColor DarkGray
        Write-Host 'Quick checks to run ON THE TARGET (elevated PowerShell):' -ForegroundColor DarkGray
        Write-Host '  Get-Service RpcSs, Winmgmt' -ForegroundColor DarkGray
        Write-Host '  Get-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" | Select DisplayName, Enabled, Profile' -ForegroundColor DarkGray
        Write-Host '  Enable-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)"' -ForegroundColor DarkGray
    }

    if ($ExportCsv) {
        $results | Export-Csv -Path $ExportCsv -NoTypeInformation
        Write-Host "Results saved to $ExportCsv" -ForegroundColor Cyan
    }

    if ($PassThru) { $results }
}
