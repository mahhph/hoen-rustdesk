<#
.SYNOPSIS
Plans, installs disabled, or rolls back the dedicated Remote Desktop Service.
.DESCRIPTION
Plan is read-only and emits a JSON payload hash manifest for independent review.
Install requires that reviewed manifest and creates only a new, disabled service.
The service cannot be used until its runtime name, protected enrollment, and
startup configuration are integrated. Rollback only removes an unchanged install.
Run in an elevated Windows PowerShell session only for Install or Rollback.
.EXAMPLE
.\scripts\remote-desktop-service-installer.ps1 -SourceDirectory C:\build\Release
#>
[CmdletBinding()]
param(
    [ValidateSet('Plan','Install','Rollback')][string]$Action = 'Plan',
    [string]$SourceDirectory,
    [string]$ExpectedManifest,
    [string]$ClientConfigPath,
    [string]$ApprovedConfigPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$serviceName = 'RemoteDesktopService'
$manifestName = '.install-manifest.json'
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
if (-not $programFiles) { throw 'The Windows Program Files location is unavailable.' }
$target = [IO.Path]::GetFullPath((Join-Path $programFiles 'Remote Desktop Service'))
$binary = Join-Path $target 'rustdesk.exe'
$serviceCommand = '"{0}" --service' -f $binary
$scExe = Join-Path ([Environment]::SystemDirectory) 'sc.exe'

function Assert-NoReparse([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    while ($full) {
        $item = Get-Item -LiteralPath $full -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Reparse point not allowed: $($item.FullName)" }
        $full = [IO.Path]::GetDirectoryName($full)
    }
}
function Require-Administrator {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Install and rollback require an elevated administrator.' }
}
function Get-SafeEntries([string]$Root) {
    $pending=[Collections.Generic.Stack[string]]::new(); $pending.Push($Root)
    $result=[Collections.Generic.List[object]]::new()
    while ($pending.Count) {
        $parent=$pending.Pop()
        foreach ($entry in @(Get-ChildItem -LiteralPath $parent -Force)) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Reparse point in payload: $($entry.FullName)" }
            $result.Add($entry)
            if ($result.Count -gt 10000) { throw 'Payload has too many entries.' }
            if ($entry.PSIsContainer) { $pending.Push($entry.FullName) }
        }
    }
    return $result.ToArray()
}
function Get-Payload([string]$Root) {
    $rootItem = Get-Item -LiteralPath $Root -Force
    if (-not $rootItem.PSIsContainer) { throw 'SourceDirectory must be a directory.' }
    Assert-NoReparse $rootItem.FullName
    $rootPath = $rootItem.FullName.TrimEnd('\') + '\'
    $entries = @(Get-SafeEntries $rootItem.FullName)
    $files = @(
        foreach ($entry in $entries) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Reparse point in payload: $($entry.FullName)" }
            if (-not $entry.PSIsContainer) {
                $relative = $entry.FullName.Substring($rootPath.Length)
                if ($relative -eq $manifestName -or $relative -match '(^|\\)\.\.?($|\\)|:' ) { throw 'Invalid payload path.' }
                [pscustomobject]@{ path=$relative; size=[long]$entry.Length; sha256=(Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
            }
        }
    )
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $files) { if (-not $seen.Add($entry.path)) { throw 'Duplicate payload path.' } }
    foreach ($required in @('rustdesk.exe','librustdesk.dll','flutter_windows.dll')) {
        if (-not $seen.Contains($required)) { throw "Missing required build file: $required" }
    }
    return @($files | Sort-Object path)
}
function Assert-ManifestMatches($Manifest, [object[]]$Actual) {
    if ($Manifest.schema -ne 1 -or $Manifest.product -ne 'Remote Desktop Service' -or $Manifest.serviceName -ne $serviceName) { throw 'Unexpected manifest identity or schema.' }
    $expected = @($Manifest.files | Sort-Object path)
    if ($expected.Count -ne $Actual.Count -or $expected.Count -eq 0) { throw 'Payload differs from reviewed manifest.' }
    for ($i=0; $i -lt $Actual.Count; $i++) {
        if ($expected[$i].path -cne $Actual[$i].path -or [long]$expected[$i].size -ne $Actual[$i].size -or $expected[$i].sha256 -cne $Actual[$i].sha256) { throw "Payload mismatch: $($Actual[$i].path)" }
    }
}
function Get-OwnService {
    @(Get-CimInstance Win32_Service -Filter "Name='$serviceName'")
}
function Assert-OwnService($Service) {
    if ($Service.Name -cne $serviceName -or $Service.PathName -cne $serviceCommand -or $Service.StartName -ne 'LocalSystem' -or $Service.State -ne 'Stopped' -or $Service.StartMode -ne 'Disabled') { throw 'Existing service does not match this disabled install; refusing mutation.' }
}
function New-InstallSecurity {
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagation = [Security.AccessControl.PropagationFlags]::None
    foreach ($identity in @('S-1-5-18','S-1-5-32-544')) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($identity),[Security.AccessControl.FileSystemRights]::FullControl,$inherit,$propagation,[Security.AccessControl.AccessControlType]::Allow))
    }
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),[Security.AccessControl.FileSystemRights]::ReadAndExecute,$inherit,$propagation,[Security.AccessControl.AccessControlType]::Allow))
    return $security
}
function Assert-InstallSecurity([string]$Path) {
    $expected=New-InstallSecurity; $actual=Get-Acl -LiteralPath $Path
    $sections=[Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
    if (-not $actual.AreAccessRulesProtected -or $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544' -or $actual.GetSecurityDescriptorSddlForm($sections) -cne $expected.GetSecurityDescriptorSddlForm($sections)) { throw 'Install directory ACL mismatch.' }
}
function Initialize-InstallNative {
    if ('RemoteInstallNative' -as [type]) { return }
    Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class RemoteInstallNative {
  [StructLayout(LayoutKind.Sequential)] struct SA { public int size; public IntPtr sd; public int inherit; }
  [StructLayout(LayoutKind.Sequential)] struct ATTR { public uint attributes; public uint tag; }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateDirectoryW(string path, ref SA sa);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle h, int infoClass, out ATTR info, uint size);
  public static void CreateNew(string path, byte[] descriptor) {
    var pin=GCHandle.Alloc(descriptor,GCHandleType.Pinned);
    try { var sa=new SA {size=Marshal.SizeOf(typeof(SA)),sd=pin.AddrOfPinnedObject(),inherit=0};
      if(!CreateDirectoryW(path,ref sa)) throw new Win32Exception(Marshal.GetLastWin32Error());
    } finally { pin.Free(); }
  }
  public static SafeFileHandle HoldDirectory(string path) {
    var h=CreateFileW(path,0x20080,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
    if(h.IsInvalid) { int e=Marshal.GetLastWin32Error(); h.Dispose(); throw new Win32Exception(e); }
    ATTR a; if(!GetFileInformationByHandleEx(h,9,out a,(uint)Marshal.SizeOf(typeof(ATTR)))) { int e=Marshal.GetLastWin32Error(); h.Dispose(); throw new Win32Exception(e); }
    if((a.attributes & 0x400)!=0 || (a.attributes & 0x10)==0) { h.Dispose(); throw new InvalidOperationException("Unsafe directory"); }
    return h;
  }
}
"@
}
function Hold-DirectoryChain([string]$Path) {
    $parts=[Collections.Generic.List[string]]::new(); $part=[IO.Path]::GetFullPath($Path)
    while ($part) { $parts.Add($part); $part=[IO.Path]::GetDirectoryName($part) }
    $parts.Reverse(); $handles=[Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]]::new()
    try { foreach ($part in $parts) { $handles.Add([RemoteInstallNative]::HoldDirectory($part)) } }
    catch { foreach ($handle in $handles) { $handle.Dispose() }; throw }
    return ,$handles
}
function Get-ManagedDirectories($Files) {
    $dirs=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $Files) {
        $parent=Split-Path -Parent $entry.path
        while ($parent) { [void]$dirs.Add($parent); $parent=Split-Path -Parent $parent }
    }
    return ,$dirs
}
function Assert-OnlyManagedDirectories($Files) {
    $dirs=Get-ManagedDirectories $Files
    $prefix=$target.TrimEnd('\')+'\'
    foreach ($dir in @(Get-SafeEntries $target | Where-Object PSIsContainer)) {
        Assert-NoReparse $dir.FullName
        if (-not $dirs.Contains($dir.FullName.Substring($prefix.Length))) { throw 'Untracked install directory; refusing removal.' }
    }
}
function Remove-InstallFiles($Files, $Directories, [bool]$RemoveManifest) {
    Assert-NoReparse $target
    foreach ($entry in $Files) {
        $path = Join-Path $target $entry.path
        if (Test-Path -LiteralPath $path) { Assert-NoReparse $path; Remove-Item -LiteralPath $path -Force }
    }
    $installedManifest = Join-Path $target $manifestName
    if ($RemoveManifest -and (Test-Path -LiteralPath $installedManifest)) { Assert-NoReparse $installedManifest; Remove-Item -LiteralPath $installedManifest -Force }
    foreach ($dir in @($Directories | Sort-Object { $_.Length } -Descending)) {
        $path=Join-Path $target $dir
        if (Test-Path -LiteralPath $path) { Assert-NoReparse $path; Remove-Item -LiteralPath $path -Force }
    }
    Remove-Item -LiteralPath $target -Force
}

if ($Action -eq 'Plan' -or $Action -eq 'Install') {
    if (-not $SourceDirectory) { throw 'SourceDirectory is required.' }
    if ([bool]$ClientConfigPath -ne [bool]$ApprovedConfigPath) { throw 'Both bootstrap input paths are required together.' }
    $bootstrapScript = Join-Path $PSScriptRoot 'remote-desktop-bootstrap.ps1'
    $validatedInputs=$null
    if ($ClientConfigPath) { $validatedInputs=& $bootstrapScript -Action Validate -ClientConfigPath $ClientConfigPath -ApprovedConfigPath $ApprovedConfigPath }
    $source = (Get-Item -LiteralPath $SourceDirectory -Force).FullName
    $files = @(Get-Payload $source)
    $manifest = [pscustomobject]@{ schema=1; product='Remote Desktop Service'; serviceName=$serviceName; files=$files }
    if ($ExpectedManifest) {
        $reviewed = Get-Content -LiteralPath $ExpectedManifest -Raw | ConvertFrom-Json
        Assert-ManifestMatches $reviewed $files
    }
    if ($Action -eq 'Plan') { $manifest | ConvertTo-Json -Depth 6; return }
    Require-Administrator
    if (-not $ExpectedManifest) { throw 'Install requires an independently reviewed ExpectedManifest.' }
    if (-not $ClientConfigPath) { throw 'Install requires existing mailbox and approved network configuration paths.' }
    Assert-NoReparse $programFiles
    if (Test-Path -LiteralPath $target) { throw 'Installation directory already exists; no upgrade or replacement is supported.' }
    if (@(Get-OwnService).Count -ne 0) { throw 'Service name already exists; refusing to modify it.' }
    Initialize-InstallNative
    $created = $false; $serviceCreated = $false; $manifestCreated = $false
    $copied = [Collections.Generic.List[object]]::new(); $createdDirs=[Collections.Generic.List[string]]::new()
    $held=Hold-DirectoryChain $programFiles
    try {
        $security=New-InstallSecurity
        [RemoteInstallNative]::CreateNew($target,$security.GetSecurityDescriptorBinaryForm()); $created = $true
        $held.Add([RemoteInstallNative]::HoldDirectory($target))
        Assert-InstallSecurity $target
        foreach ($dir in @((Get-ManagedDirectories $files) | Sort-Object { $_.Length })) {
            New-Item -ItemType Directory -Path (Join-Path $target $dir) | Out-Null
            $createdDirs.Add($dir)
        }
        foreach ($entry in $files) {
            $destination = Join-Path $target $entry.path
            $output=[IO.FileStream]::new($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            $copied.Add($entry)
            try {
                $input=[IO.FileStream]::new((Join-Path $source $entry.path),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
                try { $input.CopyTo($output); $output.Flush($true) } finally { $input.Dispose() }
            } finally { $output.Dispose() }
        }
        Assert-ManifestMatches $manifest @(Get-Payload $target)
        $manifestBytes=[Text.Encoding]::UTF8.GetBytes(($manifest | ConvertTo-Json -Depth 6))
        $manifestStream=[IO.FileStream]::new((Join-Path $target $manifestName),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $manifestCreated=$true
        try { $manifestStream.Write($manifestBytes,0,$manifestBytes.Length); $manifestStream.Flush($true) } finally { $manifestStream.Dispose() }
        New-Service -Name $serviceName -DisplayName 'Remote Desktop Service' -BinaryPathName $serviceCommand -StartupType Disabled | Out-Null
        $serviceCreated = $true
        Assert-OwnService (Get-OwnService | Select-Object -First 1)
        & $bootstrapScript -Action Provision -ClientConfigPath $ClientConfigPath -ApprovedConfigPath $ApprovedConfigPath -ExpectedClientSha256 $validatedInputs.ClientSha256 -ExpectedApprovedSha256 $validatedInputs.ApprovedSha256 | Out-Null
        Write-Output 'Installed disabled and encrypted bootstrap prepared. Service runtime integration is still required; the service was not started.'
    } catch {
        $original = $_
        foreach ($handle in $held) { $handle.Dispose() }
        if (-not $serviceCreated -and @(Get-OwnService).Count -ne 0) { throw "Install failed and a service now exists; refusing automatic cleanup. Original: $($original.Exception.Message)" }
        if ($serviceCreated) {
            try { Assert-OwnService (Get-OwnService | Select-Object -First 1); & $scExe delete $serviceName | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'Service deletion failed.' } } catch { throw "Install failed; service cleanup also failed: $($_.Exception.Message). Original: $($original.Exception.Message)" }
        }
        if ($created) { try { Remove-InstallFiles $copied $createdDirs $manifestCreated } catch { throw "Install failed; file cleanup also failed: $($_.Exception.Message). Original: $($original.Exception.Message)" } }
        throw $original
    } finally { foreach ($handle in $held) { $handle.Dispose() } }
    return
}
Require-Administrator
if (-not (Test-Path -LiteralPath $target)) { throw 'Install directory is absent.' }
Initialize-InstallNative
$held=Hold-DirectoryChain $target
try {
Assert-InstallSecurity $target
$own = @(Get-OwnService)
if ($own.Count -ne 1) { throw 'Expected exactly one matching service.' }
Assert-OwnService $own[0]
$installedManifest = Join-Path $target $manifestName
Assert-NoReparse $installedManifest
$manifest = Get-Content -LiteralPath $installedManifest -Raw | ConvertFrom-Json
# The install manifest itself is omitted from the payload hashes.
$actual = @(Get-SafeEntries $target | Where-Object { -not $_.PSIsContainer -and $_.FullName -ne $installedManifest })
$rootPrefix = $target.TrimEnd('\') + '\'
$files = @($actual | ForEach-Object { [pscustomobject]@{ path=$_.FullName.Substring($rootPrefix.Length); size=[long]$_.Length; sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() } } | Sort-Object path)
Assert-ManifestMatches $manifest $files
Assert-OnlyManagedDirectories $files
& $scExe delete $serviceName | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Service deletion failed; files were retained.' }
$held[$held.Count-1].Dispose()
Remove-InstallFiles $files (Get-ManagedDirectories $files) $true
Write-Output 'Removed the disabled Remote Desktop Service install.'
} finally { foreach ($handle in $held) { $handle.Dispose() } }
