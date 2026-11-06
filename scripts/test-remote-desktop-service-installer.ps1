# Read only the guard function from the installer; never execute its actions.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot 'remote-desktop-service-installer.ps1'),
    [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Installer syntax is invalid.' }
$guard = $ast.Find({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Assert-NoPayloadProcesses'
}, $true)
if ($null -eq $guard) { throw 'Rollback process guard is missing.' }
. ([scriptblock]::Create($guard.Extent.Text))
$binary = 'C:\Program Files\Remote Desktop Service\rustdesk.exe'
$script:processes = @()
$script:queryFails = $false
function Get-CimInstance {
    param($ClassName, $Filter, $ErrorAction)
    if ($ClassName -ne 'Win32_Process' -or $Filter -ne "Name='rustdesk.exe'") {
        throw 'Unexpected process query.'
    }
    if ($script:queryFails) { throw 'Synthetic process enumeration failure.' }
    $script:processes
}
function Assert-RefusesRollback {
    $refused = $false
    try { Assert-NoPayloadProcesses } catch { $refused = $true }
    if (-not $refused) { throw 'Rollback did not refuse unresolved running processes.' }
}
Assert-NoPayloadProcesses
$script:processes = @([pscustomobject]@{ExecutablePath='C:\Program Files\RustDesk\rustdesk.exe'})
Assert-NoPayloadProcesses
$script:processes += [pscustomobject]@{ExecutablePath=$binary.ToUpperInvariant()}
Assert-RefusesRollback
$script:processes = @([pscustomobject]@{ExecutablePath=$null})
Assert-RefusesRollback
$script:processes = @()
$script:queryFails = $true
Assert-RefusesRollback
Write-Output 'Rollback process guard: 5 scenarios passed; no service or process was changed.'
$stopGuard = $ast.Find({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Assert-CleanServiceStop'
}, $true)
if ($null -eq $stopGuard) { throw 'Service stop result guard is missing.' }
. ([scriptblock]::Create($stopGuard.Extent.Text))
Assert-CleanServiceStop ([pscustomobject]@{State='Stopped';ExitCode=0;ServiceSpecificExitCode=0})
foreach ($state in @(
    [pscustomobject]@{State='Stopped';ExitCode=1;ServiceSpecificExitCode=0},
    [pscustomobject]@{State='Stopped';ExitCode=0;ServiceSpecificExitCode=1},
    [pscustomobject]@{State='Stopped';ExitCode=$null;ServiceSpecificExitCode=0},
    [pscustomobject]@{State='Stop Pending';ExitCode=0;ServiceSpecificExitCode=0}
)) {
    $refused = $false
    try { Assert-CleanServiceStop $state } catch { $refused = $true }
    if (-not $refused) { throw 'An unsuccessful or incomplete stop was accepted.' }
}
Write-Output 'Service stop result guard: 5 scenarios passed.'
