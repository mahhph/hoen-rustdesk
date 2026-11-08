$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'remote-desktop-upgrade-flow.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Installer parse failed'}
$fn=$ast.Find({param($a) $a -is [Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq 'Stop-OwnedPayloadProcesses'},$true)
Invoke-Expression $fn.Extent.Text
$binary='C:\Program Files\Remote Desktop Service\rustdesk.exe'
$script:killed=0;$script:disposed=0
$fake=[pscustomobject]@{Handle=1;Path=$binary}
$fake|Add-Member ScriptMethod Kill {$script:killed++}
$fake|Add-Member ScriptMethod WaitForExit {param($timeout) return $true}
$fake|Add-Member ScriptMethod Dispose {$script:disposed++}
function Get-CimInstance { @([pscustomobject]@{ExecutablePath='C:\Other\rustdesk.exe';ProcessId=7},[pscustomobject]@{ExecutablePath=$binary;ProcessId=8}) }
function Get-Process {param($Id) if($Id -ne 8){throw 'Unrelated process targeted'}; return $fake}
Stop-OwnedPayloadProcesses
if($script:killed -ne 1 -or $script:disposed -ne 1){throw 'Owned process was not terminated and released'}
$fake.Path='C:\Other\rustdesk.exe'
$rejected=$false;try{Stop-OwnedPayloadProcesses}catch{$rejected=$true}
if(-not $rejected -or $script:killed -ne 1){throw 'Changed process identity was not rejected'}
function Get-CimInstance { @([pscustomobject]@{ExecutablePath=$null;ProcessId=8}) }
$rejected=$false;try{Stop-OwnedPayloadProcesses}catch{$rejected=$true}
if(-not $rejected -or $script:killed -ne 1){throw 'Unknown process ownership was not rejected'}
'PASS: only verified installed processes terminated; changed and unknown paths fail closed.'
