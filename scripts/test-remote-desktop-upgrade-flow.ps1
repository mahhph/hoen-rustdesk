# Exercise only extracted guard/recovery functions with synthetic inputs.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot 'remote-desktop-upgrade-flow.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Upgrade coordinator syntax is invalid.' }
foreach ($name in @('Assert-IdleHost','Restore-AfterFailure')) {
    $function = $ast.Find({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if ($null -eq $function) { throw "Missing coordinator function: $name" }
    . ([scriptblock]::Create($function.Extent.Text))
}
$serviceName = 'RemoteDesktopService'
$binary = 'C:\Program Files\Remote Desktop Service\rustdesk.exe'
$manifest = 'C:\synthetic\manifest.json'
$script:service = [pscustomobject]@{
    State='Running'; StartMode='Auto'; StartName='LocalSystem'; ProcessId=100; ExitCode=0; ServiceSpecificExitCode=0
    PathName=('"{0}" --service' -f $binary)
}
$script:rows = @()
$script:processes = @(
    [pscustomobject]@{Name='rustdesk.exe';ProcessId=100;ParentProcessId=4;ExecutablePath=$binary},
    [pscustomobject]@{Name='rustdesk.exe';ProcessId=101;ParentProcessId=100;ExecutablePath=$binary}
)
$script:manifestJson = '{"installation":{"schema":1,"listenerPort":42830}}'
$script:tcpFails = $false
function Get-CimInstance {
    param($ClassName, $Filter, $ErrorAction)
    if ($ClassName -eq 'Win32_Service') { return $script:service }
    if ($ClassName -eq 'Win32_Process') { return $script:processes }
    throw 'Unexpected CIM query.'
}
function Get-Content { param($LiteralPath, [switch]$Raw, $ErrorAction) return $script:manifestJson }
function Get-NetTCPConnection {
    param($ErrorAction)
    if ($script:tcpFails) { throw 'Synthetic TCP query failure.' }
    return $script:rows
}
function Assert-Refused {
    $refused = $false
    try { Assert-IdleHost } catch { $refused = $true }
    if (-not $refused) { throw 'Expected unsafe upgrade to be refused.' }
}
Assert-IdleHost
$script:rows = @([pscustomobject]@{State='Established';LocalPort=42830;RemotePort=12345;OwningProcess=101})
Assert-Refused
$script:rows = @([pscustomobject]@{State='Established';LocalPort=12345;RemotePort=42830;OwningProcess=101})
Assert-Refused
$script:rows = @([pscustomobject]@{State='Established';LocalPort=12345;RemotePort=42830;OwningProcess=999})
Assert-IdleHost
$script:rows = @()
$script:processes += [pscustomobject]@{Name='rustdesk.exe';ProcessId=102;ParentProcessId=2;ExecutablePath=$binary}
Assert-Refused
$script:processes = $script:processes[0..1]
$script:tcpFails = $true; Assert-Refused; $script:tcpFails = $false
$script:manifestJson = '{"installation":{"schema":1,"listenerPort":"42830"}}'
Assert-Refused
$script:manifestJson = '{"installation":{"schema":1,"listenerPort":42830}}'

$script:calls = [Collections.Generic.List[string]]::new()
$script:layout = ''
$installer = { param($Action) $script:calls.Add("installer:$Action") }
$upgrade = { param($Action) $script:calls.Add("upgrade:$Action"); if ($Action -eq 'Validate') { return $script:layout } }
Restore-AfterFailure 'stopping'
if ($script:calls.Count -ne 0) { throw 'An already running service was modified during recovery.' }
$script:service.State = 'Stopped'; $script:service.StartMode = 'Disabled'
Restore-AfterFailure 'stopping'
if (($script:calls -join ',') -ne 'installer:Activate') { throw 'Cleanly stopped service was not restarted.' }
$script:calls.Clear(); $script:service.State = 'Stop Pending'
$refused = $false; try { Restore-AfterFailure 'stopping' } catch { $refused = $true }
if (-not $refused -or $script:calls.Count -ne 0) { throw 'Uncertain stop outcome was not refused.' }
$script:service.State = 'Running'; $script:service.StartMode = 'Auto'
Restore-AfterFailure 'stopped'
if (($script:calls -join ',') -ne 'installer:Activate') { throw 'Stopped service recovery was incorrect.' }
$script:calls.Clear(); $script:layout = 'Staged; original payload is installed.'
Restore-AfterFailure 'replacing'
if (($script:calls -join ',') -ne 'upgrade:Validate,installer:Activate') { throw 'Staged recovery was incorrect.' }
$script:calls.Clear(); $script:layout = 'Interrupted between moves; run Upgrade or Restore.'
Restore-AfterFailure 'replacing'
if (($script:calls -join ',') -ne 'upgrade:Validate,upgrade:Restore,installer:Activate') { throw 'Interrupted recovery was incorrect.' }
$script:calls.Clear(); $script:layout = 'unexpected'
$refused = $false; try { Restore-AfterFailure 'replacing' } catch { $refused = $true }
if (-not $refused -or ($script:calls -join ',') -ne 'upgrade:Validate') { throw 'Unknown recovery layout was not refused.' }
'Upgrade coordinator session guards and recovery scenarios passed.'
