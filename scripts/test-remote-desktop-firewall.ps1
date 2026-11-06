# Pure/mock firewall lifecycle tests. No NetSecurity mutation is invoked.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$scriptPath=Join-Path $PSScriptRoot 'remote-desktop-firewall.ps1'
$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($scriptPath,[ref]$null,[ref]$errors)
if($errors.Count){throw $errors[0]}
foreach($name in @('Single-Is','Any-OrEmpty','Test-OwnedRule','Invoke-FirewallPolicy')) {
    $node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
    if($null -eq $node){throw "Missing helper $name"}
    Invoke-Expression $node.Extent.Text
}
$ruleName='RemoteDesktopService.Inbound.v1'
$ruleDescription='Remote Desktop Service owned inbound rule; version 1.'
$program='C:\Program Files\Remote Desktop Service\rustdesk.exe'
$port=45123
function New-Fixture {
    [pscustomobject]@{
        Rule=[pscustomobject]@{Name=$ruleName;Description=$ruleDescription;Enabled='True';Direction='Inbound';Action='Allow';Profile='Any';EdgeTraversalPolicy='Block'}
        Application=[pscustomobject]@{Program=$program;Package=$null}
        Port=[pscustomobject]@{Protocol='TCP';LocalPort=[string]$port;RemotePort='Any'}
        Address=[pscustomobject]@{LocalAddress='Any';RemoteAddress='Any'}
        Interface=[pscustomobject]@{InterfaceAlias='Any'}
        InterfaceType=[pscustomobject]@{InterfaceType='Any'}
        Service=[pscustomobject]@{Service='Any'}
    }
}
$local=$null; $active=$null; $createCount=0; $removeCount=0; $queryFailure=$false; $makeActive=$true
$unrelated=[pscustomobject]@{Name='Unrelated.Rule';Present=$true}
function Get-RuleSnapshot([string]$PolicyStore) {
    if($script:queryFailure){throw 'synthetic query failure'}
    if($PolicyStore -eq 'PersistentStore'){return $script:local}
    return $script:active
}
function New-NetFirewallRule {
    $script:createCount++
    $script:local=New-Fixture
    if($script:makeActive){$script:active=$script:local}
}
function Remove-NetFirewallRule {
    param($InputObject)
    if($InputObject -ne $script:local.Rule){throw 'Unexpected removal target'}
    $script:removeCount++
    $script:local=$null; $script:active=$null
}
function Expect-Failure([scriptblock]$Action,[string]$Pattern) {
    $caught=$false
    try { & $Action | Out-Null } catch { if($_.Exception.Message -notlike $Pattern){throw}; $caught=$true }
    if(-not $caught){throw 'Expected refusal did not occur.'}
}
if(-not (Test-OwnedRule (New-Fixture) $program $port)){throw 'Native-shaped unrestricted package fixture rejected.'}
$fixture=New-Fixture; $fixture.Application.Package='Any'
if(-not (Test-OwnedRule $fixture $program $port)){throw 'Any package representation rejected.'}
$fixture.Application.Package='Some.Package'
if(Test-OwnedRule $fixture $program $port){throw 'Restricted package accepted.'}
Expect-Failure { Invoke-FirewallPolicy 'Validate' $program $port } '*rule is absent*'
if((Invoke-FirewallPolicy 'Configure' $program $port) -ne 'created' -or $createCount -ne 1){throw 'Create failed.'}
if((Invoke-FirewallPolicy 'Configure' $program $port) -ne 'verified' -or $createCount -ne 1){throw 'Idempotence failed.'}
if((Invoke-FirewallPolicy 'Validate' $program $port) -ne 'verified'){throw 'Validation failed.'}
$local.Rule.Enabled='False'
Expect-Failure { Invoke-FirewallPolicy 'Validate' $program $port } '*rule is disabled*'
Expect-Failure { Invoke-FirewallPolicy 'Configure' $program $port } '*rule is disabled*'
$local.Rule.Enabled='True'
$local.Port.LocalPort='45124'
Expect-Failure { Invoke-FirewallPolicy 'Configure' $program $port } '*Conflicting or modified*'
Expect-Failure { Invoke-FirewallPolicy 'Remove' $program $port } '*Conflicting or modified*'
if($createCount -ne 1 -or $removeCount -ne 0){throw 'Conflict mutated firewall.'}
$local=New-Fixture; $active=$local
if((Invoke-FirewallPolicy 'Remove' $program $port) -ne 'removed' -or $removeCount -ne 1 -or -not $unrelated.Present){throw 'Owned-only removal failed.'}
if((Invoke-FirewallPolicy 'Remove' $program $port) -ne 'absent' -or $removeCount -ne 1){throw 'Absent removal failed.'}
$queryFailure=$true
Expect-Failure { Invoke-FirewallPolicy 'Configure' $program $port } '*synthetic query failure*'
if($createCount -ne 1){throw 'Query failure treated as absence.'}
$queryFailure=$false; $makeActive=$false
Expect-Failure { Invoke-FirewallPolicy 'Configure' $program $port } '*not active as expected*'
if($null -eq $local -or $removeCount -ne 1){throw 'Inactive rule cleanup was unsafe.'}
'Firewall mock lifecycle and native-shaped filter tests passed.'
