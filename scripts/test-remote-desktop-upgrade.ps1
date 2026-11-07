# Runs the upgrade state machine with temporary paths and synthetic service guards.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$leaf='remote-upgrade-test-'+[guid]::NewGuid().ToString('N')
$root=Join-Path ([IO.Path]::GetTempPath()) $leaf
[IO.Directory]::CreateDirectory($root) | Out-Null
try {
    $original=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'remote-desktop-upgrade.ps1') -Raw
    $quoted=$root.Replace("'","''")
    $sourcePathExpression="`$programFiles=[Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)"
    if (([regex]::Matches($original,[regex]::Escape($sourcePathExpression))).Count -ne 1) { throw 'Unsafe test path substitution.' }
    $original=$original.Replace($sourcePathExpression,"`$programFiles='$quoted'")
    $original=$original.Replace('Global\RemoteDesktopServiceUpgrade',('Local\RemoteDesktopUpgradeTest-'+[guid]::NewGuid().ToString('N')))
    $injection=@'
function Assert-Admin {}
function Assert-InstallSecurity([string]$Path) { Assert-NoReparse $Path }
function Get-InstallSecurity { Get-Acl -LiteralPath $programFiles }
function Get-OwnedService { return [pscustomobject]@{State='Running';StartMode='Auto'} }
function Assert-Quiescent { if (Test-Path -LiteralPath (Join-Path $programFiles 'busy')) { throw 'Synthetic active process.' } }
function Assert-ArchiveUnused([string]$Path) { if (Test-Path -LiteralPath (Join-Path $programFiles 'backup-busy')) { throw 'Synthetic recovery process.' } }
Assert-Admin
'@
    $original=$original.Replace("`r`n","`n")
    if (([regex]::Matches($original,"`nAssert-Admin`n")).Count -ne 1) { throw 'Unsafe test guard substitution.' }
    $original=$original.Replace("`nAssert-Admin`n", "`n$injection`n")
    $script=Join-Path $root 'test-upgrade.ps1'
    [IO.File]::WriteAllText($script,$original,[Text.UTF8Encoding]::new($false))
    $target=Join-Path $root 'Remote Desktop Service'; $source=Join-Path $root 'source'
    [IO.Directory]::CreateDirectory($target) | Out-Null
    [IO.Directory]::CreateDirectory($source) | Out-Null
    function New-Manifest([string]$Path,[string]$Version) {
        $files=@()
        foreach ($name in @('rustdesk.exe','librustdesk.dll','flutter_windows.dll')) {
            $file=Join-Path $Path $name; [IO.File]::WriteAllText($file,"$Version-$name")
            $item=Get-Item -LiteralPath $file
            $files += [ordered]@{path=$name;size=$item.Length;sha256=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()}
        }
        return [ordered]@{schema=1;product='Remote Desktop Service';serviceName='RemoteDesktopService';files=$files}
    }
    $old=New-Manifest $target 'old'; $new=New-Manifest $source 'new'
    $oldReviewed=Join-Path $root 'old.json'; $newReviewed=Join-Path $root 'new.json'
    $old | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $oldReviewed
    $new | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $newReviewed
    $installed=[ordered]@{schema=1;product=$old.product;serviceName=$old.serviceName;files=$old.files;installation=[ordered]@{schema=1;listenerPort=42830;firewallOwned=$true}}
    $installed | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $target '.install-manifest.json')
    & $script -Action Stage -SourceDirectory $source -OldManifest $oldReviewed -NewManifest $newReviewed | Out-Null
    & $script -Action Validate | Out-Null
    [IO.File]::WriteAllText((Join-Path $root 'busy'),'x')
    $rejected=$false; try { & $script -Action Upgrade | Out-Null } catch { $rejected=$true }
    if (-not $rejected -or (Get-Content -LiteralPath (Join-Path $target 'rustdesk.exe') -Raw) -cne 'old-rustdesk.exe') { throw 'Active process guard failed.' }
    Remove-Item -LiteralPath (Join-Path $root 'busy')
    & $script -Action Upgrade | Out-Null
    if ((Get-Content -LiteralPath (Join-Path $target 'rustdesk.exe') -Raw) -cne 'new-rustdesk.exe') { throw 'Upgrade failed.' }
    $meta=(Get-Content -LiteralPath (Join-Path $target '.install-manifest.json') -Raw | ConvertFrom-Json).installation
    if ($meta.listenerPort -ne 42830 -or -not $meta.firewallOwned) { throw 'Installation metadata changed.' }
    & $script -Action Restore | Out-Null
    if ((Get-Content -LiteralPath (Join-Path $target 'rustdesk.exe') -Raw) -cne 'old-rustdesk.exe') { throw 'Restore failed.' }
    $work=Join-Path $root 'Remote Desktop Service Upgrade'; $backup=Join-Path $work 'old'
    [IO.Directory]::Move($target,$backup)
    & $script -Action Validate | Out-Null
    & $script -Action Restore | Out-Null
    if ((Get-Content -LiteralPath (Join-Path $target 'rustdesk.exe') -Raw) -cne 'old-rustdesk.exe') { throw 'Interrupted recovery failed.' }
    [IO.File]::WriteAllText((Join-Path $target 'unexpected.txt'),'x')
    $rejected=$false; try { & $script -Action Upgrade | Out-Null } catch { $rejected=$true }
    if (-not $rejected) { throw 'Untracked payload was accepted.' }
    Remove-Item -LiteralPath (Join-Path $target 'unexpected.txt')
    & $script -Action Upgrade | Out-Null
    $rejected=$false; try { & $script -Action Archive | Out-Null } catch { $rejected=$true }
    if (-not $rejected) { throw 'Archive without a successful-connection confirmation was accepted.' }
    [IO.File]::WriteAllText((Join-Path $root 'backup-busy'),'x')
    $rejected=$false; try { & $script -Action Archive -ConfirmHealthy | Out-Null } catch { $rejected=$true }
    if (-not $rejected) { throw 'Archive accepted an active recovery package.' }
    Remove-Item -LiteralPath (Join-Path $root 'backup-busy')
    [IO.File]::WriteAllText((Join-Path $work 'unexpected.txt'),'x')
    $rejected=$false; try { & $script -Action Archive -ConfirmHealthy | Out-Null } catch { $rejected=$true }
    if (-not $rejected) { throw 'Archive accepted untracked workspace data.' }
    Remove-Item -LiteralPath (Join-Path $work 'unexpected.txt')
    $result=(& $script -Action Archive -ConfirmHealthy | Out-String).Trim()
    $archived=$result -replace '^Recovery workspace archived at ','' -replace '; previous package retained\.$',''
    if (-not (Test-Path -LiteralPath (Join-Path $archived 'old\rustdesk.exe')) -or
        (Test-Path -LiteralPath $work) -or
        (Get-Content -LiteralPath (Join-Path $target 'rustdesk.exe') -Raw) -cne 'new-rustdesk.exe') {
        throw 'Archive did not retain the old payload and leave the new payload installed.'
    }
    & $script -Action Stage -SourceDirectory $source -OldManifest $newReviewed -NewManifest $newReviewed | Out-Null
    if (-not (Test-Path -LiteralPath $work)) { throw 'A later upgrade could not be staged.' }
    'Upgrade: stage, guards, recovery, safe archive and subsequent staging passed.'
} finally {
    $resolved=[IO.Path]::GetFullPath($root)
    $prefix=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\remote-upgrade-test-'
    if (-not $resolved.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -cne $leaf) { throw 'Unsafe temporary cleanup path.' }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
