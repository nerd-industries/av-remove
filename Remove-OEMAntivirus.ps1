#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Nerdy Neighbor - Find and remove third-party / OEM antivirus, then confirm Defender.
.DESCRIPTION
    Step 1 always: scan and list EVERY installed component per vendor. Vendors
    like Norton ship many separate programs (360, Secure VPN, Password Manager,
    Utilities, AntiTrack, Safe Web, Genie); each is its own uninstall entry and
    this lists them all.

    Step 2 (unless NN_AV='scan'): uninstall each component using its own
    registered uninstaller (quiet where the vendor provides a quiet command,
    or a standard MSI silent uninstall). Components with no quiet option are
    reported so a tech can finish them with the vendor's removal tool.

    Step 3: report Microsoft Defender status and refresh its definitions.

    Malwarebytes is never touched (we install it: mbam.nerdyneighbor.net).

.NOTES
    Run:  irm avremove.nerdyneighbor.net | iex        (elevated Windows PowerShell)
    Log:  C:\ProgramData\NerdyNeighbor\avremove.log
    Options (set BEFORE the irm line, since iex can't take parameters):
      $env:NN_AV     = 'scan'   # only list what's installed, change nothing
      $env:NN_REBOOT = 'yes'    # restart at the end if needed ('no' = never;
                                #   default: ask when a tech runs it, never from RMM)
    Most AV needs a restart to finish removing. Run this again afterward: it
    re-scans, clears anything left, and confirms Defender is on.
#>

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host ""
    Write-Host "  This needs an ELEVATED PowerShell (Run as Administrator)." -ForegroundColor Red
    Write-Host "  Close this window, reopen PowerShell as Administrator, and run again." -ForegroundColor Yellow
    Write-Host ""
    return
}

# --- Vendors -------------------------------------------------------------------
# Match = regex tested against each Uninstall entry's DisplayName. Broad on
# purpose so every component of a suite is caught, not just the main app.
$Vendors = @(
    @{ Name = 'McAfee';      Match = 'McAfee' }
    @{ Name = 'Norton';      Match = 'Norton|NortonLifeLock|Norton 360|Norton Secure VPN|Norton Utilities|Norton AntiTrack|Norton Password Manager|Norton Family|Norton Genie' }
    @{ Name = 'Avast';       Match = 'Avast' }
    @{ Name = 'AVG';         Match = 'AVG ' }
    @{ Name = 'Avira';       Match = 'Avira' }
    @{ Name = 'Kaspersky';   Match = 'Kaspersky' }
    @{ Name = 'Bitdefender'; Match = 'Bitdefender' }
    @{ Name = 'ESET';        Match = 'ESET' }
    @{ Name = 'Trend Micro'; Match = 'Trend Micro' }
    @{ Name = 'Webroot';     Match = 'Webroot' }
    @{ Name = 'Sophos';      Match = 'Sophos' }
    @{ Name = 'TotalAV';     Match = 'TotalAV' }
    @{ Name = 'Panda';       Match = 'Panda (Dome|Security|Free|Antivirus)' }
    @{ Name = 'PC Matic';    Match = 'PC Matic|PCMatic' }
    @{ Name = 'Surfshark';   Match = 'Surfshark Antivirus' }
)
# Never remove these, even if a vendor regex would match.
$KeepRegex = 'Malwarebytes|Windows Defender|Microsoft Defender|Microsoft Security|Windows Security'

$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$script:Interactive = [Environment]::UserInteractive -and -not $me.IsSystem -and -not [Console]::IsInputRedirected
$ScanOnly   = "$env:NN_AV".Trim().ToLower() -eq 'scan'
$RebootMode = "$env:NN_REBOOT".Trim().ToLower()
$UninstallTimeoutMin = 20

# --- Logging -------------------------------------------------------------------
$LogDir  = Join-Path $env:ProgramData 'NerdyNeighbor'
$LogFile = Join-Path $LogDir 'avremove.log'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0}  [{1}]  {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
    switch ($Level) {
        'ERROR' { Write-Host "  $Message" -ForegroundColor Red }
        'WARN'  { Write-Host "  $Message" -ForegroundColor Yellow }
        'OK'    { Write-Host "  $Message" -ForegroundColor Green }
        'STEP'  { Write-Host "  $Message" -ForegroundColor White }
        'TECH'  { Write-Host "  >> $Message" -ForegroundColor Cyan }
        default { Write-Host "  $Message" -ForegroundColor Gray }
    }
}

# --- Detection -----------------------------------------------------------------
# Read every Uninstall entry from both registry views and every loaded user hive,
# so per-user installs and both 32/64-bit entries are covered.
function Get-UninstallEntries {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } |
        ForEach-Object { $roots += "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" }
    foreach ($r in $roots) {
        Get-ItemProperty $r -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and ($_.UninstallString -or $_.QuietUninstallString) }
    }
}

function Find-Products {
    $found = @()
    foreach ($e in Get-UninstallEntries) {
        $name = "$($e.DisplayName)".Trim()
        if ($name -match $KeepRegex) { continue }
        if ($e.SystemComponent -eq 1) { continue }
        foreach ($v in $Vendors) {
            if ($name -match $v.Match) {
                $found += [pscustomobject]@{
                    Vendor  = $v.Name
                    Name    = $name
                    Version = "$($e.DisplayVersion)".Trim()
                    Quiet   = "$($e.QuietUninstallString)".Trim()
                    Uninst  = "$($e.UninstallString)".Trim()
                    Key     = $e.PSPath
                }
                break
            }
        }
    }
    # De-dupe identical name+version (32/64-bit views register the same product twice).
    $found | Sort-Object Vendor, Name, Version -Unique
}

function Get-WscProducts {
    Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
        Where-Object { $_.displayName -and $_.displayName -notmatch $KeepRegex } |
        ForEach-Object { "$($_.displayName)".Trim() }
}

function Test-StillInstalled($p) { Test-Path -LiteralPath $p.Key }

# --- Removal -------------------------------------------------------------------
# Split 'C:\a b\uninst.exe /x' or '"C:\a b\uninst.exe" /x' into exe + arguments.
function Split-Command([string]$cmd) {
    $cmd = $cmd.Trim()
    if ($cmd.StartsWith('"')) {
        $end = $cmd.IndexOf('"', 1)
        if ($end -gt 0) { return @($cmd.Substring(1, $end - 1), $cmd.Substring($end + 1).Trim()) }
    }
    $i = $cmd.ToLower().IndexOf('.exe')
    if ($i -gt 0) { return @($cmd.Substring(0, $i + 4), $cmd.Substring($i + 4).Trim()) }
    return @($cmd, '')
}

# Known silent switches for uninstallers that don't register a quiet command.
# Only the vendor-documented unattended switch; nothing that alters protection.
$SilentSwitch = @{
    'Avira'   = '/remsilentnoreboot'
    'TotalAV' = '/S'
    'AVG'     = '/S'
    'Avast'   = '/S'
}

# Return @(exe, args) for a silent uninstall, or $null if there is no clean
# unattended path (the caller then flags it for the tech).
function Get-SilentCommand($p) {
    if ($p.Quiet) { return , (Split-Command $p.Quiet) }
    $u = $p.Uninst
    if (-not $u) { return $null }
    if ($u -match 'msiexec' -and $u -match '(\{[0-9A-Fa-f-]{36}\})') {
        return , @('msiexec.exe', "/x $($Matches[1]) /qn /norestart")
    }
    if ($SilentSwitch.ContainsKey($p.Vendor)) {
        $parts = Split-Command $u
        return , @($parts[0], ($parts[1] + ' ' + $SilentSwitch[$p.Vendor]).Trim())
    }
    return $null
}

function Invoke-Uninstall($p) {
    $cmd = Get-SilentCommand $p
    if (-not $cmd) {
        Write-Log ("no unattended uninstall for '{0}' - finish it with the vendor's removal tool." -f $p.Name) 'WARN'
        return 'manual'
    }
    Write-Log ("Removing: {0} {1}" -f $p.Name, $p.Version) 'STEP'
    Write-Log ("   {0} {1}" -f $cmd[0], $cmd[1])
    try {
        $proc = if ($cmd[1]) { Start-Process -FilePath $cmd[0] -ArgumentList $cmd[1] -PassThru -WindowStyle Hidden }
                else         { Start-Process -FilePath $cmd[0] -PassThru -WindowStyle Hidden }
        if (-not $proc.WaitForExit($UninstallTimeoutMin * 60 * 1000)) {
            Write-Log ("   still running after {0} min - moving on." -f $UninstallTimeoutMin) 'WARN'
            return 'timeout'
        }
        Start-Sleep -Seconds 2
        if (Test-StillInstalled $p) {
            Write-Log ("   exit {0}, but still registered - may need a restart or the vendor tool." -f $proc.ExitCode) 'WARN'
            return 'partial'
        }
        Write-Log ("   removed (exit {0})." -f $proc.ExitCode) 'OK'
        return 'ok'
    } catch {
        Write-Log ("   uninstall error: {0}" -f $_.Exception.Message) 'ERROR'
        return 'error'
    }
}

# --- Defender ------------------------------------------------------------------
function Show-DefenderStatus {
    try {
        $s = Get-MpComputerStatus -ErrorAction Stop
        $active = $s.AMRunningMode -eq 'Normal' -and $s.RealTimeProtectionEnabled -and $s.AntivirusEnabled
        Write-Log ("Defender: mode={0}, realtime={1}, antivirus={2}" -f $s.AMRunningMode, $s.RealTimeProtectionEnabled, $s.AntivirusEnabled) $(if ($active) { 'OK' } else { 'WARN' })
        if ($active) {
            try { Update-MpSignature -ErrorAction Stop; Write-Log "Defender definitions updated." 'OK' }
            catch { Write-Log "Couldn't update Defender definitions right now: $($_.Exception.Message)" 'WARN' }
        } else {
            Write-Log "Defender isn't the active antivirus yet. It usually turns itself back on after the other AV is fully gone and the PC restarts." 'WARN'
        }
    } catch {
        Write-Log "Couldn't read Defender status (Get-MpComputerStatus): $($_.Exception.Message)" 'WARN'
    }
}

# --- Main ----------------------------------------------------------------------
try {
    Write-Host ""
    Write-Host "  Nerdy Neighbor - Remove third-party antivirus" -ForegroundColor Cyan
    Write-Host ""
    Write-Log "=== Run started on $env:COMPUTERNAME (user: $env:USERNAME, interactive: $script:Interactive, scan-only: $ScanOnly) ==="

    # Step 1 - scan and list everything found.
    Write-Log "Scanning for installed antivirus..." 'STEP'
    $products = @(Find-Products)
    $wsc = @(Get-WscProducts)
    if ($wsc.Count) { Write-Log ("Security Center reports: {0}" -f ($wsc -join ', ')) }

    if ($products.Count -eq 0) {
        Write-Log "No third-party antivirus found in the installed-programs list." 'OK'
        Write-Host ""
        Show-DefenderStatus
        Write-Host ""
        return
    }

    Write-Log ("Found {0} component(s):" -f $products.Count)
    foreach ($g in ($products | Group-Object Vendor)) {
        Write-Host ("    {0}:" -f $g.Name) -ForegroundColor White
        foreach ($p in $g.Group) {
            $how = if (Get-SilentCommand $p) { 'silent' } else { 'manual' }
            Write-Host ("       - {0} {1}  [{2}]" -f $p.Name, $p.Version, $how) -ForegroundColor Gray
        }
    }

    if ($ScanOnly) {
        Write-Host ""
        Write-Log "Scan-only mode - nothing removed. Re-run without NN_AV='scan' to remove." 'WARN'
        Write-Host ""
        return
    }

    if ($script:Interactive) {
        Write-Host ""
        $a = Read-Host "  Remove all of the above? [Y/n]"
        if ($a.Trim().ToLower() -eq 'n') { Write-Log "Cancelled - nothing removed." 'WARN'; Write-Host ""; return }
    }

    # Step 2 - remove each component. Do suite sub-parts (VPN, password
    # manager, browser add-ons) before the main app so a suite uninstaller
    # doesn't renumber them mid-run; longest name first is a good proxy.
    Write-Host ""
    $results = @{ ok = 0; partial = 0; manual = 0; other = 0 }
    $manualList = @()
    foreach ($p in ($products | Sort-Object { $_.Name.Length } -Descending)) {
        if (-not (Test-StillInstalled $p)) { Write-Log ("Already gone: {0}" -f $p.Name); continue }
        switch (Invoke-Uninstall $p) {
            'ok'      { $results.ok++ }
            'partial' { $results.partial++; $manualList += $p.Name }
            'manual'  { $results.manual++;  $manualList += $p.Name }
            default   { $results.other++;   $manualList += $p.Name }
        }
    }

    # Step 3 - re-scan, report, Defender.
    Write-Host ""
    $left = @(Find-Products)
    Write-Log ("Done: {0} removed, {1} need attention." -f $results.ok, ($manualList.Count)) $(if ($manualList.Count) { 'WARN' } else { 'OK' })
    if ($manualList.Count) {
        Write-Log "Finish these with the vendor's own removal tool (see the README), then re-run this:" 'TECH'
        foreach ($m in ($manualList | Sort-Object -Unique)) { Write-Log "   - $m" 'TECH' }
    }
    Write-Host ""
    Show-DefenderStatus

    # Restart handling - many AV only finish removing after a reboot.
    if ($left.Count -gt 0) {
        Write-Host ""
        $doReboot = $false
        if ($RebootMode -eq 'yes') { $doReboot = $true }
        elseif ($RebootMode -ne 'no' -and $script:Interactive) {
            $a = Read-Host "  A restart helps finish removal. Restart now? [y/N]"
            $doReboot = $a.Trim().ToLower() -eq 'y'
        }
        if ($doReboot) {
            Write-Log "Restarting in 30 seconds. Run this again after the restart to clean up leftovers." 'WARN'
            shutdown.exe /r /t 30 /c "Nerdy Neighbor: restarting to finish antivirus removal" | Out-Null
        } else {
            Write-Log "Restart when you can, then run this again to clean up leftovers and confirm Defender." 'WARN'
        }
    }
    Write-Host ""
}
catch {
    Write-Log "FAILED: $($_.Exception.Message)" 'ERROR'
    Write-Host "  Log: $LogFile" -ForegroundColor Yellow
    Write-Host ""
}
