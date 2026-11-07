<# Installation and upgrade entry point for a reviewed release bundle. #>
[CmdletBinding()]
param(
    [ValidateSet('Plan','Install','Upgrade')][string]$Action = 'Plan',
    [string]$ClientConfigPath,
    [string]$ApprovedConfigPath,
    [string]$OldManifest
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$installer=Join-Path $PSScriptRoot 'remote-desktop-service-installer.ps1'
$payload=Join-Path $root 'payload'
$manifest=Join-Path $root 'payload-manifest.json'
if ($Action -eq 'Plan') {
    & $installer -Action Plan -SourceDirectory $payload -ExpectedManifest $manifest
    return
}
if ($Action -eq 'Upgrade') {
    if (-not $OldManifest) { throw 'Upgrade requires the separately reviewed manifest for the installed version.' }
    & (Join-Path $PSScriptRoot 'remote-desktop-upgrade-flow.ps1') -SourceDirectory $payload -OldManifest $OldManifest -NewManifest $manifest
    return
}
if (-not $ClientConfigPath -or -not $ApprovedConfigPath) {
    throw 'Install requires both the protected mailbox client configuration and approved host configuration paths.'
}
& $installer -Action Install -SourceDirectory $payload -ExpectedManifest $manifest -ClientConfigPath $ClientConfigPath -ApprovedConfigPath $ApprovedConfigPath
& $installer -Action Activate
Write-Output 'Service activated. Verify registration and a remote desktop connection.'
