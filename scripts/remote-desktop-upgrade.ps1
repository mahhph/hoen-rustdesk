<#
.SYNOPSIS
Stage, replace, restore, or archive a reviewed Remote Desktop Service payload.
.DESCRIPTION
Upgrade and Restore require the owned service cleanly stopped and disabled and all
installed payload processes exited. No action changes service state, credentials,
history, or firewall configuration. Stage keeps an independently verified old
package recoverable across either directory rename. Never delete the protected
upgrade workspace while recovery may be needed.
Archive moves a verified recovery workspace aside after the operator confirms
the upgraded client works, retaining the previous package for manual recovery.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Stage','Upgrade','Restore','Validate','Archive')][string]$Action,
    [string]$SourceDirectory,
    [string]$OldManifest,
    [string]$NewManifest,
    [switch]$ConfirmHealthy
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$serviceName='RemoteDesktopService'
$manifestName='.install-manifest.json'
$programFiles=[Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
if (-not $programFiles) { throw 'Program Files is unavailable.' }
$target=[IO.Path]::GetFullPath((Join-Path $programFiles 'Remote Desktop Service'))
$work=[IO.Path]::GetFullPath((Join-Path $programFiles 'Remote Desktop Service Upgrade'))
$stage=Join-Path $work 'new'
$backup=Join-Path $work 'old'
$journal=Join-Path $work 'recovery.json'
$binary=Join-Path $target 'rustdesk.exe'
$serviceCommand='"{0}" --service' -f $binary

function Assert-Admin {
    $principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator required.' }
}
function Assert-NoReparse([string]$Path) {
    $path=[IO.Path]::GetFullPath($Path)
    while ($path) {
        $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse point in protected path.' }
        $path=[IO.Path]::GetDirectoryName($path)
    }
}
function Get-InstallSecurity {
    $security=[Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true,$false)
    $security.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]::FullControl,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    }
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),[Security.AccessControl.FileSystemRights]::ReadAndExecute,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    return $security
}
function Assert-InstallSecurity([string]$Path) {
    Assert-NoReparse $Path
    $actual=Get-Acl -LiteralPath $Path
    $sections=[Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
    if (-not $actual.AreAccessRulesProtected -or $actual.GetSecurityDescriptorSddlForm($sections) -cne (Get-InstallSecurity).GetSecurityDescriptorSddlForm($sections)) { throw 'Protected directory ACL mismatch.' }
}
function Read-Manifest([string]$Path) {
    Assert-NoReparse $Path
    $item=Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or $item.Length -gt 2097152) { throw 'Invalid manifest.' }
    $m=Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($m.schema -ne 1 -or $m.product -cne 'Remote Desktop Service' -or $m.serviceName -cne $serviceName -or @($m.files).Count -eq 0 -or @($m.files).Count -gt 10000) { throw 'Unexpected manifest.' }
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($f in $m.files) {
        $p=[string]$f.path
        if (-not $p -or [IO.Path]::IsPathRooted($p) -or $p -match '(^|[\\/])\.\.?($|[\\/])|:|/' -or $p -eq $manifestName -or -not $seen.Add($p) -or $f.size -lt 0 -or [string]$f.sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'Invalid manifest entry.' }
    }
    foreach ($required in @('rustdesk.exe','librustdesk.dll','flutter_windows.dll')) { if (-not $seen.Contains($required)) { throw 'Required payload file missing.' } }
    return $m
}
function Assert-Payload([string]$Root,$Manifest,[bool]$Installed) {
    Assert-NoReparse $Root
    $root=[IO.Path]::GetFullPath($Root).TrimEnd('\')+'\'
    $expected=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $dirs=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $Manifest.files) {
        $expected.Add([string]$entry.path,$entry)
        $dir=Split-Path -Parent $entry.path
        while ($dir) { [void]$dirs.Add($dir); $dir=Split-Path -Parent $dir }
    }
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $pending=[Collections.Generic.Stack[string]]::new(); $pending.Push($Root)
    while ($pending.Count) {
        foreach ($item in @(Get-ChildItem -LiteralPath $pending.Pop() -Force)) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse point in payload.' }
            $relative=$item.FullName.Substring($root.Length)
            if ($item.PSIsContainer) {
                if (-not $dirs.Contains($relative)) { throw 'Untracked payload directory.' }
                $pending.Push($item.FullName); continue
            }
            if ($Installed -and $relative -eq $manifestName) { continue }
            if (-not $expected.ContainsKey($relative) -or -not $seen.Add($relative)) { throw 'Untracked payload file.' }
            $entry=$expected[$relative]
            if ($item.Length -ne [long]$entry.size -or (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash -cne ([string]$entry.sha256).ToUpperInvariant()) { throw 'Payload differs from reviewed manifest.' }
        }
    }
    if ($seen.Count -ne $expected.Count) { throw 'Payload file is missing.' }
    if ($Installed) {
        $p=Join-Path $Root $manifestName; Assert-NoReparse $p
        if ((Get-Item -LiteralPath $p -Force).PSIsContainer) { throw 'Invalid install metadata.' }
    }
}
function Get-OwnedService {
    $services=@(Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop)
    if ($services.Count -ne 1) { throw 'Expected owned service.' }
    $s=$services[0]
    if ($s.Name -cne $serviceName -or $s.PathName -cne $serviceCommand -or $s.StartName -ne 'LocalSystem' -or $s.ServiceType -cne 'Own Process') { throw 'Service does not match the owned install.' }
    return $s
}
function Assert-Quiescent {
    $s=Get-OwnedService
    if ($s.State -ne 'Stopped' -or $s.StartMode -ne 'Disabled' -or $null -eq $s.ExitCode -or $s.ExitCode -ne 0 -or $null -eq $s.ServiceSpecificExitCode -or $s.ServiceSpecificExitCode -ne 0) { throw 'Owned service is not cleanly stopped and disabled.' }
    foreach ($p in @(Get-CimInstance Win32_Process -Filter "Name='rustdesk.exe'" -ErrorAction Stop)) {
        if ([string]::IsNullOrWhiteSpace($p.ExecutablePath)) { throw 'Cannot verify process path.' }
        if ([string]::Equals([IO.Path]::GetFullPath($p.ExecutablePath),$binary,[StringComparison]::OrdinalIgnoreCase)) { throw 'Installed client or host is still running.' }
    }
}
function Assert-Installation($Install) {
    if ($null -eq $Install -or $Install.schema -ne 1 -or ($Install.listenerPort -isnot [int] -and $Install.listenerPort -isnot [long]) -or $Install.listenerPort -lt 1 -or $Install.listenerPort -gt 65535 -or $Install.firewallOwned -isnot [bool]) { throw 'Missing or invalid firewall installation metadata.' }
}
function Initialize-UpgradeNative {
    if ('RemoteUpgradeNative' -as [type]) { return }
    Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class RemoteUpgradeNative {
  [StructLayout(LayoutKind.Sequential)] struct SA { public int size; public IntPtr sd; public int inherit; }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateDirectoryW(string path, ref SA sa);
  public static void CreateNew(string path, byte[] descriptor) {
    var pin=GCHandle.Alloc(descriptor,GCHandleType.Pinned);
    try { var sa=new SA {size=Marshal.SizeOf(typeof(SA)),sd=pin.AddrOfPinnedObject(),inherit=0};
      if(!CreateDirectoryW(path,ref sa)) throw new Win32Exception(Marshal.GetLastWin32Error());
    } finally { pin.Free(); }
  }
}
"@
}
function Assert-Package([string]$Path,$Manifest,$Installation) {
    Assert-InstallSecurity $Path
    Assert-Payload $Path $Manifest $true
    $installed=Read-Manifest (Join-Path $Path $manifestName)
    Assert-Payload $Path $installed $true
    Assert-Installation $installed.installation
    if ($installed.installation.schema -ne $Installation.schema -or $installed.installation.listenerPort -ne $Installation.listenerPort -or $installed.installation.firewallOwned -ne $Installation.firewallOwned) { throw 'Firewall installation metadata changed.' }
}
function Copy-Payload([string]$Source,[string]$Destination,$Manifest) {
    foreach ($entry in $Manifest.files) {
        $targetFile=Join-Path $Destination $entry.path
        $parent=[IO.Path]::GetDirectoryName($targetFile)
        [IO.Directory]::CreateDirectory($parent) | Out-Null
        $input=[IO.FileStream]::new((Join-Path $Source $entry.path),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            $output=[IO.FileStream]::new($targetFile,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try { $input.CopyTo($output); $output.Flush($true) } finally { $output.Dispose() }
        } finally { $input.Dispose() }
    }
}
function Move-Verified([string]$From,[string]$To) {
    if (Test-Path -LiteralPath $To) { throw 'Destination already exists; recovery requires inspection.' }
    [IO.Directory]::Move($From,$To)
}
function Assert-ArchiveUnused([string]$Path) {
    $prefix=[IO.Path]::GetFullPath($Path).TrimEnd('\')+'\'
    foreach ($process in @(Get-CimInstance Win32_Process -Filter "Name='rustdesk.exe'" -ErrorAction Stop)) {
        if ([string]::IsNullOrWhiteSpace($process.ExecutablePath)) { throw 'Cannot verify a RustDesk process path.' }
        if ([IO.Path]::GetFullPath($process.ExecutablePath).StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {
            throw 'A process is using the recovery package.'
        }
    }
}

Assert-Admin
Assert-NoReparse $programFiles
$mutex=[Threading.Mutex]::new($false,'Global\RemoteDesktopServiceUpgrade')
$locked=$false
try {
    try { $locked=$mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked=$true }
    if (-not $locked) { throw 'Another upgrade operation is running.' }
    $null=Get-OwnedService
    if ($Action -eq 'Stage') {
        if (-not $SourceDirectory -or -not $OldManifest -or -not $NewManifest) { throw 'SourceDirectory, OldManifest and NewManifest are required.' }
        if (Test-Path -LiteralPath $work) { throw 'Upgrade workspace exists; inspect or recover it first.' }
        Assert-InstallSecurity $target
        $old=Read-Manifest $OldManifest; $new=Read-Manifest $NewManifest
        $installed=Read-Manifest (Join-Path $target $manifestName)
        Assert-Installation $installed.installation
        $installation=$installed.installation
        Assert-Package $target $old $installation
        Assert-Payload $SourceDirectory $new $false
        $size=($new.files | Measure-Object -Property size -Sum).Sum
        $drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($programFiles))
        if ($drive.AvailableFreeSpace -lt ($size + 16777216)) { throw 'Insufficient free space for staging.' }
        Initialize-UpgradeNative
        [RemoteUpgradeNative]::CreateNew($work,(Get-InstallSecurity).GetSecurityDescriptorBinaryForm())
        Assert-InstallSecurity $work
        [RemoteUpgradeNative]::CreateNew($stage,(Get-InstallSecurity).GetSecurityDescriptorBinaryForm())
        Copy-Payload $SourceDirectory $stage $new
        $stageManifest=[ordered]@{schema=1;product='Remote Desktop Service';serviceName=$serviceName;files=$new.files;installation=$installation}
        $manifestBytes=[Text.Encoding]::UTF8.GetBytes(($stageManifest | ConvertTo-Json -Depth 12))
        $mf=[IO.FileStream]::new((Join-Path $stage $manifestName),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $mf.Write($manifestBytes,0,$manifestBytes.Length); $mf.Flush($true) } finally { $mf.Dispose() }
        Assert-Package $stage $new $installation
        $record=[ordered]@{schema=1;old=$old;new=$new;installation=$installation}
        $bytes=[Text.Encoding]::UTF8.GetBytes(($record | ConvertTo-Json -Depth 12))
        $file=[IO.FileStream]::new($journal,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $file.Write($bytes,0,$bytes.Length); $file.Flush($true) } finally { $file.Dispose() }
        Write-Output 'Replacement staged and verified. Service state was not changed.'
        return
    }
    Assert-InstallSecurity $work
    Assert-NoReparse $journal
    $record=Get-Content -LiteralPath $journal -Raw | ConvertFrom-Json
    if ($record.schema -ne 1) { throw 'Invalid recovery record.' }
    Assert-Installation $record.installation
    # Reuse the same full manifest validation for the protected journal copies.
    # Validate journal objects without writing files into the workspace.
    foreach ($m in @($record.old,$record.new)) {
        if ($m.schema -ne 1 -or $m.product -cne 'Remote Desktop Service' -or $m.serviceName -cne $serviceName -or @($m.files).Count -eq 0 -or @($m.files).Count -gt 10000) { throw 'Invalid recovery manifest.' }
    }
    if (Test-Path -LiteralPath $target) { $targetExists=$true } else { $targetExists=$false }
    $stageExists=Test-Path -LiteralPath $stage; $backupExists=Test-Path -LiteralPath $backup
    if ($Action -in @('Upgrade','Restore')) { Assert-Quiescent }
    if ($Action -eq 'Upgrade') {
        if ($targetExists -and $stageExists -and -not $backupExists) {
            Assert-Package $target $record.old $record.installation; Assert-Package $stage $record.new $record.installation
            Assert-Quiescent; Move-Verified $target $backup
            $targetExists=$false; $backupExists=$true
        }
        if (-not $targetExists -and $stageExists -and $backupExists) {
            Assert-Package $backup $record.old $record.installation; Assert-Package $stage $record.new $record.installation
            Assert-Quiescent; Move-Verified $stage $target
        } else { throw 'Upgrade layout is not recoverable automatically.' }
        Assert-Package $target $record.new $record.installation
        Assert-Package $backup $record.old $record.installation
        Write-Output 'Upgrade payload installed; verified old payload retained. Service remains stopped and disabled.'
        return
    }
    if ($Action -eq 'Restore') {
        if ($targetExists -and -not $stageExists -and $backupExists) {
            Assert-Package $target $record.new $record.installation; Assert-Package $backup $record.old $record.installation
            Assert-Quiescent; Move-Verified $target $stage
            $targetExists=$false; $stageExists=$true
        }
        if (-not $targetExists -and $stageExists -and $backupExists) {
            Assert-Package $backup $record.old $record.installation; Assert-Package $stage $record.new $record.installation
            Assert-Quiescent; Move-Verified $backup $target
        } else { throw 'Restore layout is not recoverable automatically.' }
        Assert-Package $target $record.old $record.installation
        Write-Output 'Original payload restored; verified replacement retained. Service remains stopped and disabled.'
        return
    }
    if ($Action -eq 'Archive') {
        if (-not $ConfirmHealthy) { throw 'Confirm a successful connection before archiving the recovery workspace.' }
        if (-not $targetExists -or $stageExists -or -not $backupExists) { throw 'Only a completed upgrade can be archived.' }
        $service=Get-OwnedService
        if ($service.State -ne 'Running' -or $service.StartMode -ne 'Auto') { throw 'The upgraded service is not running automatically.' }
        Assert-Package $target $record.new $record.installation
        Assert-Package $backup $record.old $record.installation
        $contents=@(Get-ChildItem -LiteralPath $work -Force)
        if ($contents.Count -ne 2 -or @($contents | Where-Object { $_.Name -notin @('old','recovery.json') -or ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }).Count -ne 0) {
            throw 'Unexpected recovery workspace contents; refusing to move it.'
        }
        Assert-ArchiveUnused $backup
        $archive=[IO.Path]::GetFullPath((Join-Path $programFiles ('Remote Desktop Service Upgrade Archive-' + [guid]::NewGuid().ToString('N'))))
        if ([IO.Path]::GetDirectoryName($archive) -ine [IO.Path]::GetFullPath($programFiles).TrimEnd('\')) { throw 'Invalid archive destination.' }
        Move-Verified $work $archive
        Write-Output "Recovery workspace archived at $archive; previous package retained."
        return
    }
    if ($targetExists -and $stageExists -and -not $backupExists) { Assert-Package $target $record.old $record.installation; Assert-Package $stage $record.new $record.installation; 'Staged; original payload is installed.'; return }
    if (-not $targetExists -and $stageExists -and $backupExists) { Assert-Package $stage $record.new $record.installation; Assert-Package $backup $record.old $record.installation; 'Interrupted between moves; run Upgrade or Restore.'; return }
    if ($targetExists -and -not $stageExists -and $backupExists) { Assert-Package $target $record.new $record.installation; Assert-Package $backup $record.old $record.installation; 'Upgraded; verified original payload is retained.'; return }
    throw 'Unexpected layout; no automatic recovery is safe.'
} finally {
    if ($locked) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
