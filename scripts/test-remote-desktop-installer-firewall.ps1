# Synthetic tests for installer-owned firewall metadata; no service/firewall mutation.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'remote-desktop-service-installer.ps1'),[ref]$null,[ref]$parseErrors)
if($parseErrors.Count){throw 'Installer syntax is invalid.'}
foreach($name in @('Get-FirewallMetadata','Read-ApprovedListenerPort','Configure-InstallationFirewall','Remove-OwnedFirewall','Initialize-InstallNative','Assert-NoReparse','Read-InstalledManifest','Write-AdoptedManifest')) {
    $node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
    if($null -eq $node){throw "Missing function $name"}
    . ([scriptblock]::Create($node.Extent.Text))
}
function Expect-Refusal([scriptblock]$Action) {
    $failed=$false; try { & $Action | Out-Null } catch {$failed=$true}; if(-not $failed){throw 'Expected refusal was not raised.'}
}
$legacy=[pscustomobject]@{schema=1;product='Remote Desktop Service';serviceName='RemoteDesktopService';files=@([pscustomobject]@{path='rustdesk.exe';size=1;sha256=('a'*64)})}
if($null -ne (Get-FirewallMetadata $legacy)){throw 'Legacy metadata should be absent.'}
$bad=$legacy|ConvertTo-Json -Depth 6|ConvertFrom-Json
$bad|Add-Member -NotePropertyName installation -NotePropertyValue ([pscustomobject]@{schema=1;listenerPort=45123;firewallOwned='true'})
Expect-Refusal { Get-FirewallMetadata $bad }
$validLong=$legacy|ConvertTo-Json -Depth 6|ConvertFrom-Json
$validLong|Add-Member -NotePropertyName installation -NotePropertyValue ([pscustomobject]@{schema=[long]1;listenerPort=[long]45123;firewallOwned=$true})
if((Get-FirewallMetadata $validLong).listenerPort -ne 45123){throw '64-bit integral metadata rejected.'}
foreach($invalidPort in @('45123',[double]45123,[long]65536)) {
    $validLong.installation.listenerPort=$invalidPort
    Expect-Refusal { Get-FirewallMetadata $validLong }
}
$script:firewallResult='created'; $script:removeCalls=0; $script:failRemove=$false
$firewallScript={ param($Action,$ListenerPort)
    if($ListenerPort -ne 45123){throw 'Wrong selected port.'}
    if($Action -eq 'Configure'){return [pscustomobject]@{Result=$script:firewallResult}}
    if($Action -eq 'Remove') {if($script:failRemove){throw 'synthetic conflict'};$script:removeCalls++;return [pscustomobject]@{Result='removed'}}
    throw 'Unexpected firewall action.'
}
$created=Configure-InstallationFirewall 45123
if(-not $created){throw 'New rule not marked owned.'}
if((Remove-OwnedFirewall 45123 $created) -ne 'removed'){throw 'Owned-rule removal result not reported.'}
if($removeCalls -ne 1){throw 'Created rule not removed on cleanup.'}
$script:firewallResult='verified'
$created=Configure-InstallationFirewall 45123
if($created){throw 'Pre-existing rule was claimed.'}
if((Remove-OwnedFirewall 45123 $created) -ne 'not-owned'){throw 'Unowned-rule status not reported.'}
if($removeCalls -ne 1){throw 'Unowned rule was removed.'}
$script:failRemove=$true
Expect-Refusal { Remove-OwnedFirewall 45123 $true }
if($removeCalls -ne 1){throw 'Conflicting rule was removed.'}
$target=Join-Path $env:TEMP ('rds-metadata-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $target | Out-Null
$configPath=Join-Path $target 'approved.json';$manifestPath=Join-Path $target '.install-manifest.json'
try {
    [IO.File]::WriteAllText($configPath,'{"listen_port":45123}')
    $digest=(Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash
    if((Read-ApprovedListenerPort $configPath $digest) -ne 45123){throw 'Custom port not retained.'}
    [IO.File]::WriteAllText($configPath,'{"listen_port":45124}')
    Expect-Refusal { Read-ApprovedListenerPort $configPath $digest }
    foreach($invalidJson in @('{"listen_port":"45123"}','{"listen_port":45123.0}','{"listen_port":65536}')) {
        [IO.File]::WriteAllText($configPath,$invalidJson)
        $invalidDigest=(Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash
        Expect-Refusal { Read-ApprovedListenerPort $configPath $invalidDigest }
    }
    [IO.File]::WriteAllText($manifestPath,($legacy|ConvertTo-Json -Depth 6))
    $snapshot=Read-InstalledManifest $manifestPath
    Initialize-InstallNative
    Write-AdoptedManifest $snapshot.Manifest $manifestPath $snapshot.Sha256 45123 $false
    $roundtrip=Read-InstalledManifest $manifestPath
    $state=Get-FirewallMetadata $roundtrip.Manifest
    if($state.listenerPort -ne 45123 -or $state.firewallOwned -or $roundtrip.Manifest.files[0].path -ne 'rustdesk.exe'){throw 'Atomic adoption changed payload or ownership.'}
} finally {
    if(Test-Path -LiteralPath $configPath){Remove-Item -LiteralPath $configPath}
    if(Test-Path -LiteralPath $manifestPath){Remove-Item -LiteralPath $manifestPath}
    Remove-Item -LiteralPath $target
}
'Installer firewall metadata, ownership and rollback mocks passed.'
