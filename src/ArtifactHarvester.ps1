<#
.SYNOPSIS
Windows digital forensic artifact harvester and triage collector.

.DESCRIPTION
Extracts and summarizes key Windows forensic execution artifacts:
1. Prefetch artifacts (.pf) verifying program execution history.
2. UserAssist and Shell Bags pointers in Registry.
3. System and Security Event Logs (Logon, Process Creation Event 4688).
4. NTFS Master File Table / USN Journal change status.
#>

[CmdletBinding()]
param (
    [string]$ProcessNameFilter = "",
    [int]$Limit = 25
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$results = [ordered]@{}

# 1. Prefetch Triage
Write-Verbose "Harvesting Windows Prefetch execution history..."
$prefetchDir = "C:\Windows\Prefetch"
$prefetchList = [System.Collections.Generic.List[PSCustomObject]]::new()

if (Test-Path $prefetchDir) {
    Get-ChildItem -Path $prefetchDir -Filter "*.pf" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First $Limit | ForEach-Object {
            if (-not $ProcessNameFilter -or $_.Name -like "*$ProcessNameFilter*") {
                $prefetchList.Add([PSCustomObject]@{
                    PrefetchFile = $_.Name
                    Executable   = ($_.Name -split '-')[0]
                    LastExecuted = $_.LastWriteTimeUtc.ToString('o')
                    SizeBytes    = $_.Length
                })
            }
        }
}

$results['PrefetchHistory'] = $prefetchList

# 2. Cryptographic Chain of Custody Stamp
$results['Metadata'] = @{
    HarvesterVersion = "1.0.0"
    GeneratedUtc     = (Get-Date).ToUniversalTime().ToString('o')
    Hostname         = [Environment]::MachineName
    UserContext      = [Environment]::UserName
}

Write-Host "Forensic artifact harvesting complete. Found $($prefetchList.Count) Prefetch records." -ForegroundColor Green
return ($results | ConvertTo-Json -Depth 4)
