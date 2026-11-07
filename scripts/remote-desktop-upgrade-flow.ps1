<#
.SYNOPSIS
Stage and apply a reviewed Remote Desktop Service upgrade.
.DESCRIPTION
The existing service and upgrade helpers remain responsible for verifying
ownership, protected paths, file manifests, firewall state and recovery layouts.
This coordinator refuses active desktop sessions or client processes before
stopping the service and attempts a verified restore if replacement fails.
An installed and running service is not proof of a usable remote desktop.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$SourceDirectory,
    [Parameter(Mandatory=$true)][string]$OldManifest,
    [Parameter(Mandatory=$true)][string]$NewManifest
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$serviceName = 'RemoteDesktopService'
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
if (-not $programFiles) { throw 'Program Files is unavailable.' }
$target = [IO.Path]::GetFullPath((Join-Path $programFiles 'Remote Desktop Service'))
$binary = Join-Path $target 'rustdesk.exe'
$manifest = Join-Path $target '.install-manifest.json'
$installer = Join-Path $PSScriptRoot 'remote-desktop-service-installer.ps1'
$upgrade = Join-Path $PSScriptRoot 'remote-desktop-upgrade.ps1'

function Assert-Administrator {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'An elevated administrator is required.'
    }
}

function Assert-IdleHost {
    $services = @(Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop)
    if ($services.Count -ne 1) { throw 'Expected exactly one installed service.' }
    $service = $services[0]
    $expected = '"{0}" --service' -f $binary
    if ($service.State -ne 'Running' -or $service.StartMode -ne 'Auto' -or
        $service.StartName -ne 'LocalSystem' -or $service.PathName -cne $expected) {
        throw 'Installed service is not the expected running automatic service.'
    }
    $saved = Get-Content -LiteralPath $manifest -Raw -ErrorAction Stop | ConvertFrom-Json
    if ($null -eq $saved.PSObject.Properties['installation'] -or
        $saved.installation.schema -ne 1 -or
        $saved.installation.listenerPort -isnot [int] -and $saved.installation.listenerPort -isnot [long] -or
        $saved.installation.listenerPort -lt 1 -or $saved.installation.listenerPort -gt 65535) {
        throw 'Reviewed firewall installation metadata is missing or invalid.'
    }
    $port = [int]$saved.installation.listenerPort
    # Query all TCP rows so an empty established set cannot hide a query error.
    $connections = @(Get-NetTCPConnection -ErrorAction Stop)
    # An interactive client may have a pending session on another port. Do not
    # stop it or rely on a guessed title. Permit only the service process tree.
    $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop)
    $owned = [Collections.Generic.HashSet[uint32]]::new()
    $installed = [Collections.Generic.HashSet[uint32]]::new()
    [void]$owned.Add([uint32]$service.ProcessId)
    do {
        $changed = $false
        foreach ($process in $processes) {
            if ($owned.Contains([uint32]$process.ParentProcessId) -and
                $owned.Add([uint32]$process.ProcessId)) { $changed = $true }
        }
    } while ($changed)
    foreach ($process in @($processes | Where-Object { $_.Name -eq 'rustdesk.exe' })) {
        if ([string]::IsNullOrWhiteSpace($process.ExecutablePath)) {
            throw 'A RustDesk process path is unavailable; cannot safely upgrade.'
        }
        if ([string]::Equals([IO.Path]::GetFullPath($process.ExecutablePath), $binary,
                [StringComparison]::OrdinalIgnoreCase)) {
            [void]$installed.Add([uint32]$process.ProcessId)
            if (-not $owned.Contains([uint32]$process.ProcessId)) {
                throw 'Close the installed client and tray before upgrading.'
            }
        }
    }
    if (@($connections | Where-Object {
        $_.State -eq 'Established' -and $installed.Contains([uint32]$_.OwningProcess) -and
            ($_.LocalPort -eq $port -or $_.RemotePort -eq $port)
    }).Count -ne 0) { throw 'A remote desktop connection is active; close it before upgrading.' }
}

function Restore-AfterFailure {
    param([string]$Phase)
    if ($Phase -eq 'stopping') {
        $services = @(Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop)
        if ($services.Count -ne 1) { throw 'Service state is unavailable; inspect it before recovery.' }
        $service = $services[0]
        if ($service.State -eq 'Running' -and $service.StartMode -eq 'Auto') { return }
        if ($service.State -ne 'Stopped' -or $service.StartMode -ne 'Disabled' -or
            $service.ExitCode -ne 0 -or $service.ServiceSpecificExitCode -ne 0) {
            throw 'Service stop outcome is uncertain; inspect it before recovery.'
        }
        & $installer -Action Activate | Out-Host
        return
    }
    if ($Phase -eq 'stopped') {
        & $installer -Action Activate | Out-Host
        return
    }
    if ($Phase -in @('replacing','replaced')) {
        $layout = (& $upgrade -Action Validate | Out-String).Trim()
        if ($layout -eq 'Interrupted between moves; run Upgrade or Restore.' -or
            $layout -eq 'Upgraded; verified original payload is retained.') {
            & $upgrade -Action Restore | Out-Host
        } elseif ($layout -ne 'Staged; original payload is installed.') {
            throw 'Upgrade layout is not recognized; inspect recovery workspace.'
        }
        & $installer -Action Activate | Out-Host
    }
}

Assert-Administrator
Assert-IdleHost
& $installer -Action Plan -SourceDirectory $SourceDirectory -ExpectedManifest $NewManifest | Out-Null
# Stage verifies the protected installed package and both reviewed manifests;
# staging does not stop the service or alter protected enrollment/history.
& $upgrade -Action Stage -SourceDirectory $SourceDirectory -OldManifest $OldManifest -NewManifest $NewManifest | Out-Host
& $upgrade -Action Validate | Out-Host
$phase = 'staged'
try {
    # Recheck immediately before stopping. The installer and upgrade helper also
    # check service ownership and installed processes after the stop.
    Assert-IdleHost
    $phase = 'stopping'
    & $installer -Action Deactivate | Out-Host
    $phase = 'stopped'
    $phase = 'replacing'
    & $upgrade -Action Upgrade | Out-Host
    $phase = 'replaced'
    & $installer -Action Activate | Out-Host
    Write-Output 'Upgrade applied. Verify registration, listener and a remote connection.'
} catch {
    $failure = $_
    try { Restore-AfterFailure $phase }
    catch { throw "Upgrade failed at $phase and recovery requires inspection: $($_.Exception.Message). Original: $($failure.Exception.Message)" }
    throw "Upgrade failed at $phase. Verified recovery was attempted where applicable. $($failure.Exception.Message)"
}
