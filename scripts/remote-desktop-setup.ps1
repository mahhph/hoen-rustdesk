<# Fresh-install entry point for a reviewed release bundle. #>
[CmdletBinding()]
param(
    [ValidateSet('Plan','Install')][string]$Action = 'Plan',
    [string]$ClientConfigPath,
    [string]$ApprovedConfigPath
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
if (-not $ClientConfigPath -or -not $ApprovedConfigPath) {
    throw 'Install requires both the protected mailbox client configuration and approved host configuration paths.'
}
& $installer -Action Install -SourceDirectory $payload -ExpectedManifest $manifest -ClientConfigPath $ClientConfigPath -ApprovedConfigPath $ApprovedConfigPath
& $installer -Action Activate
Write-Output 'Service activated. Verify registration and a remote desktop connection.'
