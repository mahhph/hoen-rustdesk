<#
.SYNOPSIS
Plans, installs, activates, deactivates, or rolls back Remote Desktop Service.
.DESCRIPTION
Plan is read-only and emits a JSON payload hash manifest for independent review.
Install requires that reviewed manifest and creates only a new, disabled service.
Activate starts the service; SCM Running does not indicate host readiness.
Deactivate stops and disables it. Rollback removes only an unchanged disabled install.
Legacy installs require AdoptFirewall with the SHA-256 of a reviewed approved
configuration and an explicit confirmation that its port matches the existing
enrollment. This installer cannot inspect the encrypted enrollment to verify it.
Previously existing matching firewall rules are verified but never claimed or removed.
Run in an elevated Windows PowerShell session for actions other than Plan.
.EXAMPLE
.\scripts\remote-desktop-service-installer.ps1 -SourceDirectory C:\build\Release
.EXAMPLE
.\scripts\remote-desktop-service-installer.ps1 -Action Install -SourceDirectory C:\build\Release -ExpectedManifest C:\review\manifest.json -ClientConfigPath C:\private\client.json -ApprovedConfigPath C:\review\approved-network.json
.EXAMPLE
.\scripts\remote-desktop-service-installer.ps1 -Action Activate
.EXAMPLE
.\scripts\remote-desktop-service-installer.ps1 -Action Deactivate
.EXAMPLE
.\scripts\remote-desktop-service-installer.ps1 -Action AdoptFirewall -ApprovedConfigPath C:\review\approved.json -ExpectedApprovedSha256 <reviewed-sha256> -ConfirmedExistingListenerPort
.EXAMPLE
.\scripts\remote-desktop-service-installer.ps1 -Action Rollback
#>
[CmdletBinding()]
param(
    [ValidateSet('Plan','Install','Activate','Deactivate','Rollback','AdoptFirewall')][string]$Action = 'Plan',
    [string]$SourceDirectory,
    [string]$ExpectedManifest,
    [string]$ClientConfigPath,
    [string]$ApprovedConfigPath,
    [string]$ExpectedApprovedSha256,
    [switch]$ConfirmedExistingListenerPort
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.ServiceProcess
$serviceName = 'RemoteDesktopService'
$manifestName = '.install-manifest.json'
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
if (-not $programFiles) { throw 'The Windows Program Files location is unavailable.' }
$target = [IO.Path]::GetFullPath((Join-Path $programFiles 'Remote Desktop Service'))
$binary = Join-Path $target 'rustdesk.exe'
$serviceCommand = '"{0}" --service' -f $binary
$scExe = Join-Path ([Environment]::SystemDirectory) 'sc.exe'
$firewallScript = Join-Path $PSScriptRoot 'remote-desktop-firewall.ps1'

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
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'This action requires an elevated administrator.' }
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
function Get-FirewallMetadata($Manifest) {
    $property=$Manifest.PSObject.Properties['installation']
    if($null -eq $property){return $null}
    $state=$property.Value
    if($null -eq $state -or @($state.PSObject.Properties).Count -ne 3 -or
       $null -eq $state.PSObject.Properties['schema'] -or
       $null -eq $state.PSObject.Properties['listenerPort'] -or
       $null -eq $state.PSObject.Properties['firewallOwned'] -or
       ($state.schema -isnot [int] -and $state.schema -isnot [long]) -or $state.schema -ne 1 -or
       ($state.listenerPort -isnot [int] -and $state.listenerPort -isnot [long]) -or $state.listenerPort -lt 1 -or $state.listenerPort -gt 65535 -or
       $state.firewallOwned -isnot [bool]) { throw 'Invalid protected firewall installation metadata.' }
    return $state
}
function Read-ApprovedListenerPort([string]$Path,[string]$ExpectedSha256) {
    if($ExpectedSha256 -notmatch '^[a-fA-F0-9]{64}$'){throw 'A reviewed approved-config SHA-256 is required.'}
    $ExpectedSha256=$ExpectedSha256.ToLowerInvariant()
    $stream=[IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($stream.Length -le 0 -or $stream.Length -gt 131072){throw 'Invalid approved configuration size.'}
        $bytes=[byte[]]::new([int]$stream.Length); $offset=0
        while($offset -lt $bytes.Length){$n=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($n -eq 0){throw 'Approved configuration changed while reading.'};$offset+=$n}
        if($stream.ReadByte() -ne -1){throw 'Approved configuration changed while reading.'}
        $sha=[Security.Cryptography.SHA256]::Create()
        try {$digest=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
        if($digest -cne $ExpectedSha256){throw 'Approved configuration differs from the reviewed bytes.'}
        try {$text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xfeff);$config=$text|ConvertFrom-Json}catch{throw 'Invalid approved configuration.'}
        if($null -eq $config.PSObject.Properties['listen_port']){throw 'Approved listener port is missing.'}
        $port=$config.listen_port
        if(($port -isnot [int] -and $port -isnot [long]) -or $port -lt 1 -or $port -gt 65535){throw 'Approved listener port is invalid.'}
        return [int]$port
    } finally { $stream.Dispose() }
}
function Configure-InstallationFirewall([int]$Port) {
    $result=& $firewallScript -Action Configure -ListenerPort $Port
    if($result.Result -notin @('created','verified')){throw 'Unexpected firewall configuration result.'}
    return $result.Result -eq 'created'
}
function Remove-OwnedFirewall([int]$Port,[bool]$Owned) {
    if(-not $Owned){return 'not-owned'}
    $result=& $firewallScript -Action Remove -ListenerPort $Port
    if($result.Result -notin @('removed','absent')){throw 'Unexpected firewall removal result.'}
    return $result.Result
}
function Get-OwnService {
    @(Get-CimInstance Win32_Service -Filter "Name='$serviceName'")
}
function Assert-OwnServiceIdentity($Service) {
    if ($Service.Name -cne $serviceName -or $Service.PathName -cne $serviceCommand -or $Service.StartName -ne 'LocalSystem' -or $Service.ServiceType -cne 'Own Process') { throw 'Service identity does not match this install; refusing mutation.' }
}
function Assert-OwnService($Service) {
    Assert-OwnServiceIdentity $Service
    if ($Service.State -ne 'Stopped' -or $Service.StartMode -ne 'Disabled') { throw 'Existing service is not stopped and disabled; refusing mutation.' }
}
function Assert-NoServiceDependencies {
    $controller=[ServiceProcess.ServiceController]::new($serviceName)
    try {
        $dependencies=@($controller.ServicesDependedOn)
        try { if ($dependencies.Count -ne 0) { throw 'Unexpected service dependencies; refusing mutation.' } }
        finally { foreach ($dependency in $dependencies) { $dependency.Dispose() } }
    } finally { $controller.Dispose() }
}
function Assert-NoPayloadProcesses {
    # SCM Stopped does not prove that an orphaned host or the GUI has exited.
    # Do not kill processes here, including unrelated stock RustDesk instances.
    foreach ($process in @(Get-CimInstance Win32_Process -Filter "Name='rustdesk.exe'" -ErrorAction Stop)) {
        if ([string]::IsNullOrWhiteSpace($process.ExecutablePath)) {
            throw 'Cannot verify a running desktop executable path; files were retained.'
        }
        if ([string]::Equals([IO.Path]::GetFullPath($process.ExecutablePath), $binary, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'The installed client or host is still running; close it before rollback. Files were retained.'
        }
    }
}
function Assert-CleanServiceStop($Service) {
    if ($Service.State -ne 'Stopped' -or $null -eq $Service.ExitCode -or $Service.ExitCode -ne 0 -or $null -eq $Service.ServiceSpecificExitCode -or $Service.ServiceSpecificExitCode -ne 0) {
        throw 'Service shutdown was not confirmed successful; installed files were retained.'
    }
}
function Get-VerifiedService {
    $matches=@(Get-OwnService)
    if ($matches.Count -ne 1) { throw 'Expected exactly one matching service.' }
    Assert-OwnServiceIdentity $matches[0]
    Assert-NoServiceDependencies
    return $matches[0]
}
function Wait-OwnServiceState([string[]]$Allowed, [int]$TimeoutSeconds = 30) {
    $timer=[Diagnostics.Stopwatch]::StartNew()
    do {
        $current=Get-VerifiedService
        if ($current.State -in $Allowed) { return $current }
        if ($timer.Elapsed.TotalSeconds -ge $TimeoutSeconds) { throw 'Timed out waiting for service state.' }
        Start-Sleep -Milliseconds 250
    } while ($true)
}
function Set-OwnServiceMode([string]$Mode) {
    Set-Service -Name $serviceName -StartupType $Mode -ErrorAction Stop
}
function Start-OwnServiceProcess {
    $controller=[ServiceProcess.ServiceController]::new($serviceName)
    try { $controller.Start() } finally { $controller.Dispose() }
}
function Stop-OwnServiceProcess {
    # ServiceController.Stop() also stops dependents. The SCM stop request fails
    # instead if another running service depends on this one.
    & $scExe stop $serviceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Service stop request failed.' }
}
function Disable-AndStopOwnService {
    $current=Get-VerifiedService
    if ($current.StartMode -notin @('Auto','Disabled')) { throw 'Unexpected service startup mode; refusing mutation.' }
    if ($current.StartMode -ne 'Disabled') {
        Set-OwnServiceMode 'Disabled'
        $current=Get-VerifiedService
        if ($current.StartMode -ne 'Disabled') { throw 'Service could not be disabled.' }
    }
    if ($current.State -eq 'Start Pending') { $current=Wait-OwnServiceState @('Running','Stopped') }
    if ($current.State -eq 'Running') {
        Stop-OwnServiceProcess
        $current=Wait-OwnServiceState @('Stopped')
    } elseif ($current.State -eq 'Stop Pending') { $current=Wait-OwnServiceState @('Stopped') }
    if ($current.State -ne 'Stopped' -or $current.StartMode -ne 'Disabled') { throw 'Service did not reach stopped and disabled state.' }
    Assert-CleanServiceStop $current
}
function Activate-OwnService {
    Assert-OwnService (Get-VerifiedService)
    try {
        Set-OwnServiceMode 'Automatic'
        $current=Get-VerifiedService
        if ($current.StartMode -ne 'Auto' -or $current.State -ne 'Stopped') { throw 'Service did not reach the expected pre-start state.' }
        Start-OwnServiceProcess
        $current=Wait-OwnServiceState @('Running')
        if ($current.StartMode -ne 'Auto') { throw 'Service startup mode changed during activation.' }
    } catch {
        $original=$_
        try { Disable-AndStopOwnService } catch { throw "Activation failed; stopping and disabling also failed: $($_.Exception.Message). Original: $($original.Exception.Message)" }
        throw "Activation failed; the service was stopped and disabled. $($original.Exception.Message)"
    }
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
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool MoveFileExW(string from, string to, uint flags);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle h, int infoClass, out ATTR info, uint size);
  public static void CreateNew(string path, byte[] descriptor) {
    var pin=GCHandle.Alloc(descriptor,GCHandleType.Pinned);
    try { var sa=new SA {size=Marshal.SizeOf(typeof(SA)),sd=pin.AddrOfPinnedObject(),inherit=0};
      if(!CreateDirectoryW(path,ref sa)) throw new Win32Exception(Marshal.GetLastWin32Error());
    } finally { pin.Free(); }
  }
  public static void ReplaceFile(string from, string to) {
    if(!MoveFileExW(from,to,0x9)) throw new Win32Exception(Marshal.GetLastWin32Error());
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
function Read-InstalledManifest([string]$Path) {
    $stream=[IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($stream.Length -le 0 -or $stream.Length -gt 4MB){throw 'Invalid installed manifest size.'}
        $bytes=[byte[]]::new([int]$stream.Length);$offset=0
        while($offset -lt $bytes.Length){$n=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($n -eq 0){throw 'Installed manifest changed while reading.'};$offset+=$n}
        if($stream.ReadByte() -ne -1){throw 'Installed manifest changed while reading.'}
        $sha=[Security.Cryptography.SHA256]::Create()
        try {$hash=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','')}finally{$sha.Dispose()}
        $text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xfeff)
        return [pscustomobject]@{Manifest=($text|ConvertFrom-Json);Sha256=$hash}
    } finally {$stream.Dispose()}
}
function Write-AdoptedManifest($Manifest,[string]$Path,[string]$OriginalHash,[int]$Port,[bool]$Owned) {
    $Manifest | Add-Member -NotePropertyName installation -NotePropertyValue ([pscustomobject]@{schema=1;listenerPort=$Port;firewallOwned=$Owned})
    $temp=Join-Path $target ('.install-manifest-'+[Guid]::NewGuid().ToString('N')+'.tmp')
    $created=$false
    try {
        $bytes=[Text.Encoding]::UTF8.GetBytes(($Manifest | ConvertTo-Json -Depth 6))
        $stream=[IO.FileStream]::new($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $created=$true
        try {$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)} finally {$stream.Dispose()}
        Assert-NoReparse $Path
        if((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -cne $OriginalHash){throw 'Installed manifest changed during adoption.'}
        [RemoteInstallNative]::ReplaceFile($temp,$Path)
        $created=$false
    } finally {
        if($created -and (Test-Path -LiteralPath $temp)){Remove-Item -LiteralPath $temp -Force}
    }
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
    $approvedPort=Read-ApprovedListenerPort $ApprovedConfigPath $validatedInputs.ApprovedSha256
    Assert-NoReparse $programFiles
    if (Test-Path -LiteralPath $target) { throw 'Installation directory already exists; no upgrade or replacement is supported.' }
    if (@(Get-OwnService).Count -ne 0) { throw 'Service name already exists; refusing to modify it.' }
    Initialize-InstallNative
    $created = $false; $serviceCreated = $false; $manifestCreated = $false; $firewallCreated = $false
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
        $firewallCreated=Configure-InstallationFirewall $approvedPort
        $manifest | Add-Member -NotePropertyName installation -NotePropertyValue ([pscustomobject]@{schema=1;listenerPort=$approvedPort;firewallOwned=$firewallCreated})
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
        if($firewallCreated){
            try { Remove-OwnedFirewall $approvedPort $true | Out-Null }
            catch { throw "Install failed and owned firewall cleanup requires review: $($_.Exception.Message). Original: $($original.Exception.Message)" }
        }
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
$own = Get-VerifiedService
$installedManifest = Join-Path $target $manifestName
Assert-NoReparse $installedManifest
$manifestSnapshot=Read-InstalledManifest $installedManifest
$manifest=$manifestSnapshot.Manifest
# The install manifest itself is omitted from the payload hashes.
$actual = @(Get-SafeEntries $target | Where-Object { -not $_.PSIsContainer -and $_.FullName -ne $installedManifest })
$rootPrefix = $target.TrimEnd('\') + '\'
$files = @($actual | ForEach-Object { [pscustomobject]@{ path=$_.FullName.Substring($rootPrefix.Length); size=[long]$_.Length; sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() } } | Sort-Object path)
Assert-ManifestMatches $manifest $files
Assert-OnlyManagedDirectories $files
if ($Action -eq 'AdoptFirewall') {
    if($null -ne (Get-FirewallMetadata $manifest)){throw 'Firewall installation metadata already exists.'}
    if(-not $ApprovedConfigPath){throw 'Adoption requires a reviewed approved-config path and SHA-256.'}
    if(-not $ConfirmedExistingListenerPort){throw 'Confirm the reviewed port matches existing encrypted enrollment; the installer cannot verify it.'}
    Assert-OwnService (Get-VerifiedService)
    Assert-CleanServiceStop (Get-VerifiedService)
    Assert-NoPayloadProcesses
    $port=Read-ApprovedListenerPort $ApprovedConfigPath $ExpectedApprovedSha256
    $createdRule=$false
    try {
        $createdRule=Configure-InstallationFirewall $port
        Write-AdoptedManifest $manifest $installedManifest $manifestSnapshot.Sha256 $port $createdRule
    } catch {
        $original=$_
        if($createdRule){
            try { Remove-OwnedFirewall $port $true | Out-Null }
            catch { throw "Adoption failed and owned firewall cleanup requires review: $($_.Exception.Message). Original: $($original.Exception.Message)" }
        }
        throw $original
    }
    Write-Output 'Reviewed firewall configuration adopted; service remains stopped and disabled.'
    return
}
if ($Action -eq 'Activate') {
    $firewallState=Get-FirewallMetadata $manifest
    if($null -eq $firewallState){throw 'Firewall metadata is missing; adopt a reviewed approved configuration first.'}
    & $firewallScript -Action Validate -ListenerPort $firewallState.listenerPort | Out-Null
    Activate-OwnService
    Write-Output 'Service started with automatic startup. SCM running does not establish remote host readiness.'
    return
}
if ($Action -eq 'Deactivate') {
    Disable-AndStopOwnService
    Write-Output 'Service stopped and disabled. Installed files and enrollment data were retained.'
    return
}
$stoppedService = Get-VerifiedService
Assert-OwnService $stoppedService
Assert-CleanServiceStop $stoppedService
Assert-NoPayloadProcesses
$firewallState=Get-FirewallMetadata $manifest
if($null -eq $firewallState){throw 'Firewall metadata is missing; adopt a reviewed approved configuration first.'}
$firewallRemoval=Remove-OwnedFirewall $firewallState.listenerPort $firewallState.firewallOwned
& $scExe delete $serviceName | Out-Null
if ($LASTEXITCODE -ne 0) {
    if($firewallRemoval -eq 'removed'){throw 'Service deletion failed; files were retained, but the owned firewall rule was removed.'}
    throw 'Service deletion failed; files and any unowned firewall rule were retained.'
}
$held[$held.Count-1].Dispose()
Remove-InstallFiles $files (Get-ManagedDirectories $files) $true
Write-Output 'Removed the disabled Remote Desktop Service install.'
} finally { foreach ($handle in $held) { $handle.Dispose() } }
