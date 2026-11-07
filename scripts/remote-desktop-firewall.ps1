<#
.SYNOPSIS
Manage the explicit inbound firewall rule for the installed Remote Desktop Service.
.DESCRIPTION
This is a separate, partial installer prerequisite. The caller must supply the
listener port from protected, approved enrollment or installer metadata; this
script cannot read the LocalSystem-encrypted enrollment and does not infer it.
Validate is read-only and the default. Configure creates only a missing exact
rule; Remove deletes only the exact matching local rule. Both refuse conflicts.
A matching active rule does not prove reachability or host readiness.
#>
[CmdletBinding()]
param(
    [ValidateSet('Validate','Configure','Remove')][string]$Action='Validate',
    [Parameter(Mandatory=$true)][ValidateRange(1,65535)][int]$ListenerPort
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ruleName='RemoteDesktopService.Inbound.v1'
$ruleDescription='Remote Desktop Service owned inbound rule; version 1.'
$programFiles=[Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
if(-not $programFiles){throw 'Program Files location unavailable.'}
$expectedProgram=[IO.Path]::GetFullPath((Join-Path $programFiles 'Remote Desktop Service/rustdesk.exe'))

function Single-Is($Value,[string]$Expected) {
    $values=@($Value)
    return $values.Count -eq 1 -and [string]$values[0] -ieq $Expected
}
function Any-OrEmpty($Value) {
    return $null -eq $Value -or (Single-Is $Value '') -or (Single-Is $Value 'Any')
}
function Test-OwnedRule($Snapshot,[string]$Program,[int]$Port) {
    if($null -eq $Snapshot){return $false}
    $r=$Snapshot.Rule; $a=$Snapshot.Application; $p=$Snapshot.Port
    $address=$Snapshot.Address; $interface=$Snapshot.Interface; $interfaceType=$Snapshot.InterfaceType
    $service=$Snapshot.Service
    if($r.Name -cne $ruleName -or $r.Description -cne $ruleDescription -or
       [string]$r.Enabled -ne 'True' -or [string]$r.Direction -ne 'Inbound' -or
       [string]$r.Action -ne 'Allow' -or [string]$r.Profile -ne 'Any' -or
       [string]$r.EdgeTraversalPolicy -ne 'Block'){return $false}
    if(-not (Single-Is $a.Program $Program) -or -not (Any-OrEmpty $a.Package) -or
       -not ((Single-Is $p.Protocol 'TCP') -or (Single-Is $p.Protocol '6')) -or
       -not (Single-Is $p.LocalPort ([string]$Port)) -or -not (Single-Is $p.RemotePort 'Any') -or
       -not (Single-Is $address.LocalAddress 'Any') -or -not (Single-Is $address.RemoteAddress 'Any') -or
       -not (Single-Is $interface.InterfaceAlias 'Any') -or -not (Single-Is $interfaceType.InterfaceType 'Any') -or
       -not (Single-Is $service.Service 'Any')){return $false}
    return $true
}
function Get-RuleSnapshot([string]$PolicyStore) {
    # Do not suppress query errors: access denied cannot be treated as absent.
    $matches=@(Get-NetFirewallRule -PolicyStore $PolicyStore -ErrorAction Stop | Where-Object { $_.Name -ieq $ruleName })
    if($matches.Count -gt 1){throw 'Multiple rules use the reserved identity; refusing mutation.'}
    if($matches.Count -eq 0){return $null}
    $rule=$matches[0]
    $application=@(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -PolicyStore $PolicyStore -ErrorAction Stop)
    $ports=@(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -PolicyStore $PolicyStore -ErrorAction Stop)
    $address=@(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -PolicyStore $PolicyStore -ErrorAction Stop)
    $interfaces=@(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $rule -PolicyStore $PolicyStore -ErrorAction Stop)
    $types=@(Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $rule -PolicyStore $PolicyStore -ErrorAction Stop)
    $services=@(Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $rule -PolicyStore $PolicyStore -ErrorAction Stop)
    if($application.Count -ne 1 -or $ports.Count -ne 1 -or $address.Count -ne 1 -or $interfaces.Count -ne 1 -or $types.Count -ne 1 -or $services.Count -ne 1){throw 'Firewall rule filters are ambiguous.'}
    return [pscustomobject]@{Rule=$rule;Application=$application[0];Port=$ports[0];Address=$address[0];Interface=$interfaces[0];InterfaceType=$types[0];Service=$services[0]}
}
function Invoke-FirewallPolicy([string]$Operation,[string]$Program,[int]$Port) {
    $local=Get-RuleSnapshot 'PersistentStore'
    if($null -ne $local -and [string]$local.Rule.Enabled -eq 'False'){throw 'Reserved firewall rule is disabled; refusing mutation.'}
    if($null -ne $local -and -not (Test-OwnedRule $local $Program $Port)){throw 'Conflicting or modified local firewall rule; refusing mutation.'}
    if($Operation -eq 'Remove') {
        if($null -eq $local){return 'absent'}
        Remove-NetFirewallRule -InputObject $local.Rule -ErrorAction Stop
        if($null -ne (Get-RuleSnapshot 'PersistentStore')){throw 'Firewall rule removal could not be verified.'}
        return 'removed'
    }
    if($null -eq $local) {
        if($Operation -eq 'Validate'){throw 'Required local firewall rule is absent.'}
        if($null -ne (Get-RuleSnapshot 'ActiveStore')){throw 'A different active rule uses the reserved identity.'}
        New-NetFirewallRule -PolicyStore PersistentStore -Name $ruleName -DisplayName 'Remote Desktop Service - Inbound' -Description $ruleDescription -Enabled True -Direction Inbound -Action Allow -Profile Any -EdgeTraversalPolicy Block -Program $Program -Protocol TCP -LocalPort $Port -RemotePort Any -LocalAddress Any -RemoteAddress Any -InterfaceAlias Any -InterfaceType Any -Service Any -ErrorAction Stop | Out-Null
        $created=$true
    } else { $created=$false }
    try {
        if($created){
            $local=Get-RuleSnapshot 'PersistentStore'
            if(-not (Test-OwnedRule $local $Program $Port)){throw 'Created rule could not be verified.'}
        }
        $active=Get-RuleSnapshot 'ActiveStore'
        if(-not (Test-OwnedRule $active $Program $Port)){throw 'Local rule is not active as expected; check applied firewall policy.'}
    } catch {
        $original=$_
        if($created){
            try {
                $current=Get-RuleSnapshot 'PersistentStore'
                if(-not (Test-OwnedRule $current $Program $Port)){throw 'Created rule no longer matches; refusing cleanup.'}
                Remove-NetFirewallRule -InputObject $current.Rule -ErrorAction Stop
                if($null -ne (Get-RuleSnapshot 'PersistentStore')){throw 'Rule cleanup could not be verified.'}
            } catch { throw "Firewall setup failed and cleanup requires review: $($_.Exception.Message). Original: $($original.Exception.Message)" }
        }
        throw $original
    }
    if($created){return 'created'}
    return 'verified'
}
if($Action -ne 'Remove') {
    $part=$expectedProgram
    while($part) {
        $item=Get-Item -LiteralPath $part -Force -ErrorAction Stop
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Installed executable path contains a reparse point.'}
        $part=[IO.Path]::GetDirectoryName($part)
    }
}
if($Action -ne 'Validate') {
    $principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Configure and Remove require an elevated administrator.'}
}
$result=Invoke-FirewallPolicy $Action $expectedProgram $ListenerPort
[pscustomobject]@{Result=$result;RuleName=$ruleName;Program=$expectedProgram;ListenerPort=$ListenerPort;Profile='Any';RemoteAddress='Any';InterfaceType='Any'}
