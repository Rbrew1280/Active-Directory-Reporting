<#
.SYNOPSIS
    Active Directory reporting script. Generates CSV files plus a single HTML summary report.

.DESCRIPTION
    Reports available:
      InactiveUsers       - Enabled users with no logon in N days
      DisabledUsers       - All disabled user accounts
      PasswordNeverExpires- Enabled users whose password never expires
      PasswordExpiring    - Users whose password expires within N days
      LockedOut           - Currently locked-out accounts
      PrivilegedGroups    - Members of high-privilege groups (recursive)
      StaleComputers      - Enabled computers with no logon in N days
      EmptyGroups         - Groups with no members

    Read-only: this script makes no changes to Active Directory.

.PARAMETER OutputPath
    Base folder for reports. A timestamped subfolder is created per run.

.PARAMETER InactiveDays
    Days without logon before a user/computer is considered inactive. Default 90.

.PARAMETER PasswordExpiryWarnDays
    Window (days) for the PasswordExpiring report. Default 14.

.PARAMETER Reports
    One or more report names from the list above, or 'All' (default).

.PARAMETER SearchBase
    Optional OU distinguished name to limit the scope, e.g. "OU=Staff,DC=contoso,DC=com".

.PARAMETER Server
    Optional domain controller or domain FQDN to query.

.PARAMETER SkipHtml
    Skip the HTML summary and only write CSVs.

.EXAMPLE
    .\AD-Report.ps1

.EXAMPLE
    .\AD-Report.ps1 -Reports InactiveUsers,PasswordExpiring -InactiveDays 60 -OutputPath D:\Reports

.EXAMPLE
    .\AD-Report.ps1 -SearchBase "OU=Staff,DC=contoso,DC=com" -Server dc01.contoso.com

.NOTES
    Requires: PowerShell 5.1+ and the ActiveDirectory module (RSAT or run on a DC).
    Note: LastLogonDate is replicated and can lag by up to ~14 days. For strict accuracy
    use the non-replicated lastLogon attribute queried against every DC.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot 'ADReports'),

    [ValidateRange(1, 3650)]
    [int]$InactiveDays = 90,

    [ValidateRange(1, 365)]
    [int]$PasswordExpiryWarnDays = 14,

    [ValidateSet('All', 'InactiveUsers', 'DisabledUsers', 'PasswordNeverExpires',
                 'PasswordExpiring', 'LockedOut', 'PrivilegedGroups',
                 'StaleComputers', 'EmptyGroups')]
    [string[]]$Reports = 'All',

    [string]$SearchBase,
    [string]$Server,
    [switch]$SkipHtml
)

#region Setup
$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "The ActiveDirectory PowerShell module is not installed. Install RSAT: Active Directory Domain Services Tools."
}
Import-Module ActiveDirectory

# Common parameters splatted into every AD cmdlet
$adParams = @{}
if ($SearchBase) { $adParams['SearchBase'] = $SearchBase }
if ($Server)     { $adParams['Server']     = $Server }

# Server-only params for cmdlets that don't accept SearchBase
$serverParams = @{}
if ($Server) { $serverParams['Server'] = $Server }

$runStamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$runFolder = Join-Path $OutputPath $runStamp
New-Item -ItemType Directory -Path $runFolder -Force | Out-Null

$now         = Get-Date
$inactiveCut = $now.AddDays(-$InactiveDays)

$allReports = 'InactiveUsers', 'DisabledUsers', 'PasswordNeverExpires', 'PasswordExpiring',
              'LockedOut', 'PrivilegedGroups', 'StaleComputers', 'EmptyGroups'
if ($Reports -contains 'All') { $Reports = $allReports }

$results = [ordered]@{}   # ReportName -> array of rows
$errors  = [System.Collections.Generic.List[string]]::new()

function Write-Step([string]$Message) {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor Cyan
}
#endregion

#region Data collection (cached so users are only queried once)
$userProps = 'SamAccountName', 'DisplayName', 'EmailAddress', 'Department', 'Title', 'Manager',
             'Enabled', 'LastLogonDate', 'PasswordLastSet', 'PasswordNeverExpires',
             'PasswordExpired', 'LockedOut', 'WhenCreated', 'DistinguishedName',
             'msDS-UserPasswordExpiryTimeComputed'

$userReports = 'InactiveUsers', 'DisabledUsers', 'PasswordNeverExpires', 'PasswordExpiring'
$users = @()
if ($Reports | Where-Object { $_ -in $userReports }) {
    Write-Step 'Querying user accounts...'
    $users = @(Get-ADUser -Filter * -Properties $userProps @adParams)
    Write-Step "Retrieved $($users.Count) user accounts."
}

function Get-OU([string]$dn) {
    if ($dn -match '^CN=.+?(?<!\\),(?<ou>.+)$') { return $Matches['ou'] }
    return $dn
}
#endregion

#region Reports
foreach ($report in $Reports) {
    try {
        Write-Step "Running report: $report"

        switch ($report) {

            'InactiveUsers' {
                $results[$report] = @($users |
                    Where-Object {
                        $_.Enabled -and (
                            ($_.LastLogonDate -and $_.LastLogonDate -lt $inactiveCut) -or
                            (-not $_.LastLogonDate -and $_.WhenCreated -lt $inactiveCut)
                        )
                    } |
                    Sort-Object LastLogonDate |
                    Select-Object SamAccountName, DisplayName, Department, Title, EmailAddress,
                        LastLogonDate, PasswordLastSet, WhenCreated,
                        @{n='DaysInactive'; e={
                            if ($_.LastLogonDate) { [int]($now - $_.LastLogonDate).TotalDays }
                            else { 'Never logged on' }
                        }},
                        @{n='OU'; e={ Get-OU $_.DistinguishedName }})
            }

            'DisabledUsers' {
                $results[$report] = @($users |
                    Where-Object { -not $_.Enabled } |
                    Sort-Object SamAccountName |
                    Select-Object SamAccountName, DisplayName, Department, Title, EmailAddress,
                        LastLogonDate, WhenCreated, @{n='OU'; e={ Get-OU $_.DistinguishedName }})
            }

            'PasswordNeverExpires' {
                $results[$report] = @($users |
                    Where-Object { $_.Enabled -and $_.PasswordNeverExpires } |
                    Sort-Object PasswordLastSet |
                    Select-Object SamAccountName, DisplayName, Department, EmailAddress,
                        PasswordLastSet, LastLogonDate, @{n='OU'; e={ Get-OU $_.DistinguishedName }})
            }

            'PasswordExpiring' {
                $warnCut = $now.AddDays($PasswordExpiryWarnDays)
                $results[$report] = @($users |
                    Where-Object {
                        $_.Enabled -and -not $_.PasswordNeverExpires -and
                        $_.'msDS-UserPasswordExpiryTimeComputed' -and
                        $_.'msDS-UserPasswordExpiryTimeComputed' -ne 9223372036854775807
                    } |
                    Select-Object SamAccountName, DisplayName, Department, EmailAddress,
                        PasswordLastSet,
                        @{n='PasswordExpires'; e={ [datetime]::FromFileTime($_.'msDS-UserPasswordExpiryTimeComputed') }} |
                    Where-Object { $_.PasswordExpires -le $warnCut } |
                    Sort-Object PasswordExpires |
                    Select-Object *, @{n='DaysRemaining'; e={ [int][math]::Floor(($_.PasswordExpires - $now).TotalDays) }})
            }

            'LockedOut' {
                $results[$report] = @(Search-ADAccount -LockedOut -UsersOnly @adParams |
                    Get-ADUser -Properties DisplayName, Department, EmailAddress, LastLogonDate,
                        LockoutTime, BadLogonCount @serverParams |
                    Select-Object SamAccountName, DisplayName, Department, EmailAddress,
                        @{n='LockoutTime'; e={ if ($_.LockoutTime) { [datetime]::FromFileTime($_.LockoutTime) } }},
                        BadLogonCount, LastLogonDate, Enabled)
            }

            'PrivilegedGroups' {
                $privGroups = 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
                              'Account Operators', 'Backup Operators', 'Server Operators',
                              'Print Operators', 'DnsAdmins', 'Group Policy Creator Owners'
                $rows = foreach ($g in $privGroups) {
                    try {
                        Get-ADGroupMember -Identity $g -Recursive @serverParams |
                            Where-Object { $_.objectClass -eq 'user' } |
                            ForEach-Object {
                                $u = Get-ADUser -Identity $_.SamAccountName -Properties DisplayName,
                                    Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires @serverParams
                                [pscustomobject]@{
                                    Group                = $g
                                    SamAccountName       = $u.SamAccountName
                                    DisplayName          = $u.DisplayName
                                    Enabled              = $u.Enabled
                                    LastLogonDate        = $u.LastLogonDate
                                    PasswordLastSet      = $u.PasswordLastSet
                                    PasswordNeverExpires = $u.PasswordNeverExpires
                                }
                            }
                    }
                    catch {
                        # Group may not exist in this domain (e.g. Enterprise/Schema Admins in child domain)
                        Write-Verbose "Skipped group '$g': $($_.Exception.Message)"
                    }
                }
                $results[$report] = @($rows | Sort-Object Group, SamAccountName)
            }

            'StaleComputers' {
                Write-Step 'Querying computer accounts...'
                $results[$report] = @(Get-ADComputer -Filter { Enabled -eq $true } -Properties `
                        OperatingSystem, OperatingSystemVersion, LastLogonDate, PasswordLastSet,
                        WhenCreated, DistinguishedName @adParams |
                    Where-Object {
                        ($_.LastLogonDate -and $_.LastLogonDate -lt $inactiveCut) -or
                        (-not $_.LastLogonDate -and $_.WhenCreated -lt $inactiveCut)
                    } |
                    Sort-Object LastLogonDate |
                    Select-Object Name, OperatingSystem, OperatingSystemVersion, LastLogonDate,
                        PasswordLastSet, WhenCreated,
                        @{n='DaysInactive'; e={
                            if ($_.LastLogonDate) { [int]($now - $_.LastLogonDate).TotalDays }
                            else { 'Never logged on' }
                        }},
                        @{n='OU'; e={ Get-OU $_.DistinguishedName }})
            }

            'EmptyGroups' {
                $results[$report] = @(Get-ADGroup -Filter * -Properties Members, Description,
                        GroupCategory, GroupScope, WhenCreated, ManagedBy @adParams |
                    Where-Object { -not $_.Members -or $_.Members.Count -eq 0 } |
                    # Skip built-in/system containers
                    Where-Object { $_.DistinguishedName -notmatch 'CN=(Builtin|Users),' } |
                    Sort-Object Name |
                    Select-Object Name, GroupCategory, GroupScope, Description, ManagedBy, WhenCreated)
            }
        }

        Write-Host "    -> $($results[$report].Count) row(s)" -ForegroundColor Green
    }
    catch {
        $msg = "Report '$report' failed: $($_.Exception.Message)"
        Write-Warning $msg
        $errors.Add($msg)
        $results[$report] = @()
    }
}
#endregion

#region CSV export
foreach ($name in $results.Keys) {
    $csvPath = Join-Path $runFolder "$name.csv"
    if ($results[$name].Count -gt 0) {
        $results[$name] | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    }
    else {
        # Still create an empty marker so it's clear the report ran
        '' | Set-Content -Path $csvPath -Encoding UTF8
    }
}
Write-Step "CSV files written to: $runFolder"
#endregion

#region HTML summary
if (-not $SkipHtml) {
    $titles = @{
        InactiveUsers        = "Inactive Users (no logon in $InactiveDays+ days)"
        DisabledUsers        = 'Disabled Users'
        PasswordNeverExpires = 'Enabled Users - Password Never Expires'
        PasswordExpiring     = "Passwords Expiring Within $PasswordExpiryWarnDays Days"
        LockedOut            = 'Locked-Out Accounts'
        PrivilegedGroups     = 'Privileged Group Members'
        StaleComputers       = "Stale Computers (no logon in $InactiveDays+ days)"
        EmptyGroups          = 'Empty Groups'
    }

    $domainName = try { (Get-ADDomain @serverParams).DNSRoot } catch { 'Unknown' }

    $summaryRows = ($results.Keys | ForEach-Object {
        $count = $results[$_].Count
        $cls   = if ($count -gt 0) { 'warn' } else { 'ok' }
        "<tr><td><a href='#$_'>$($titles[$_])</a></td><td class='$cls'>$count</td></tr>"
    }) -join "`n"

    $sections = foreach ($name in $results.Keys) {
        $data = $results[$name]
        $body = if ($data.Count -gt 0) {
            ($data | ConvertTo-Html -Fragment) -join "`n"
        }
        else { '<p class="ok">No results.</p>' }
        "<h2 id='$name'>$($titles[$name]) <span class='count'>($($data.Count))</span></h2>`n<div class='scroll'>$body</div>"
    }

    $errorBlock = if ($errors.Count) {
        '<h2>Errors</h2><ul>' + (($errors | ForEach-Object { "<li>$([System.Net.WebUtility]::HtmlEncode($_))</li>" }) -join '') + '</ul>'
    } else { '' }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Active Directory Report - $domainName</title>
<style>
  body   { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #222; background: #fafafa; }
  h1     { margin-bottom: 4px; }
  h2     { margin-top: 36px; border-bottom: 2px solid #0b5cad; padding-bottom: 4px; color: #0b5cad; }
  .meta  { color: #666; margin-bottom: 20px; }
  .count { color: #888; font-weight: normal; font-size: 0.8em; }
  table  { border-collapse: collapse; font-size: 13px; background: #fff; }
  th     { background: #0b5cad; color: #fff; text-align: left; padding: 6px 10px; position: sticky; top: 0; }
  td     { border-bottom: 1px solid #ddd; padding: 5px 10px; white-space: nowrap; }
  tr:nth-child(even) td { background: #f3f7fb; }
  .scroll{ overflow-x: auto; max-height: 520px; overflow-y: auto; }
  .warn  { color: #b45309; font-weight: 600; }
  .ok    { color: #15803d; font-weight: 600; }
  .summary td, .summary th { padding: 6px 16px; }
</style>
</head>
<body>
<h1>Active Directory Report</h1>
<div class="meta">
  Domain: <b>$domainName</b> &nbsp;|&nbsp; Generated: <b>$($now.ToString('yyyy-MM-dd HH:mm'))</b>
  &nbsp;|&nbsp; Run by: <b>$env:USERDOMAIN\$env:USERNAME</b>
  $(if ($SearchBase) { "&nbsp;|&nbsp; Scope: <b>$SearchBase</b>" })
</div>
<h2>Summary</h2>
<table class="summary">
<tr><th>Report</th><th>Findings</th></tr>
$summaryRows
</table>
$($sections -join "`n")
$errorBlock
</body>
</html>
"@

    $htmlPath = Join-Path $runFolder 'ADReport.html'
    $html | Set-Content -Path $htmlPath -Encoding UTF8
    Write-Step "HTML report written to: $htmlPath"
}
#endregion

# Console summary
Write-Host "`n=== Summary ===" -ForegroundColor Yellow
$results.Keys | ForEach-Object {
    '{0,-22} {1,6}' -f $_, $results[$_].Count
} | Write-Host
Write-Host "`nOutput folder: $runFolder" -ForegroundColor Yellow

if (-not $SkipHtml -and (Test-Path (Join-Path $runFolder 'ADReport.html')) -and $Host.Name -eq 'ConsoleHost') {
    # Uncomment to auto-open the report:
    # Invoke-Item (Join-Path $runFolder 'ADReport.html')
}
