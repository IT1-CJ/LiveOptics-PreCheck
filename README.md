# Live Optics Pre-Check

A PowerShell pre-check for **Live Optics** remote collection against Windows servers.

Live Optics talks to remote Windows servers using WMI over RPC/DCOM. When that path is blocked, the collector shows:

> The Collector was unable to reach x.x.x.x. The error returned indicates that the RPC network service at that address was unreachable.

This script tests the same path step by step and explains which part failed and how to fix it.

## What it checks

| # | Check | Why |
|---|-------|-----|
| 1 | Name resolution | Accepts an IP, short name or FQDN. Warns when an IP is used (forces NTLM instead of Kerberos) and suggests the FQDN from reverse DNS. Flags stale forward/reverse DNS. |
| 2 | Ping | Informational only. ICMP is often blocked. |
| 3 | TCP 135 | RPC Endpoint Mapper. If this fails you get the "RPC network service unreachable" error. |
| 4 | TCP 445 | Informational. Helps tell "host down" apart from "WMI blocked". |
| 5 | WMI over DCOM | Real `Win32_OperatingSystem` query. Catches firewalls that allow 135 but block the dynamic RPC range (49152-65535). |
| 6 | Perf counters | `Win32_PerfRawData_PerfDisk_PhysicalDisk`, which Live Optics needs for disk data. |

Common error codes (`0x800706BA`, `0x80070005`, `0x80041003`, `0x800706BE`, `0x80070776`, `0x8007052E`, `0x80041010`) are translated into a likely cause and fix.

## Usage

Run it **from the same machine, and as the same account (or with the same credential), that will run LiveOptics.exe.**

```powershell
# Single target by IP or FQDN
.\Test-LiveOpticsTarget.ps1 -ComputerName 10.0.10.8
.\Test-LiveOpticsTarget.ps1 -ComputerName sql01.contoso.local -Credential (Get-Credential)

# Several targets
.\Test-LiveOpticsTarget.ps1 -ComputerName sql01.contoso.local, fs01.contoso.local

# From a file, saving results to CSV
.\Test-LiveOpticsTarget.ps1 -InputFile .\servers.txt -Credential (Get-Credential) -ExportCsv .\precheck.csv
```

`-InputFile` takes a text file with one target per line (see `servers.example.txt`) or a CSV with a `ComputerName` column.

If script execution is blocked, run it for this session only:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Test-LiveOpticsTarget.ps1 -ComputerName 10.0.10.8
```

### Parameters

| Parameter | Description |
|-----------|-------------|
| `-ComputerName` | One or more targets (IP, short name or FQDN). Comma-separated works too. |
| `-InputFile` | Text or CSV file of targets. |
| `-Credential` | Account to test with. Defaults to the current logon. |
| `-TimeoutMs` | TCP connect timeout. Default `2000`. |
| `-ExportCsv` | Save results to a CSV file. |
| `-PassThru` | Also return result objects to the pipeline. |

## Common fixes (run on the target server, elevated)

```powershell
# Services WMI depends on
Get-Service RpcSs, Winmgmt

# Allow WMI through Windows Firewall
Enable-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)"

# Rebuild perf counters if the perf check fails
lodctr /R
winmgmt /resyncperf
```

If the network path can't be opened, copy `LiveOptics.exe` to the server and run it locally. Start the collections within a few minutes of each other so the `.SIOKIT` files can be combined into one report.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+ on Windows (the WMI/DCOM check needs Windows).
- Account with local Administrator rights on the target.
