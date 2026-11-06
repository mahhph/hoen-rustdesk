<#
.SYNOPSIS
Validates mailbox bootstrap input, or prepares an encrypted machine bootstrap.
.DESCRIPTION
Default Validate is read-only. Provision requires elevation and writes one new
machine-DPAPI blob under a SYSTEM/Administrators-only ProgramData directory.
The service must independently validate, reseal under its LocalSystem user scope,
verify durable read-back and consume the file. This script does not start it.
Inputs are file paths only. Do not pass credentials as arguments or log output.
#>
[CmdletBinding()]
param(
    [ValidateSet('Validate','Provision','SelfTest')][string]$Action = 'Validate',
    [string]$ClientConfigPath,
    [string]$ApprovedConfigPath,
    [string]$ExpectedClientSha256,
    [string]$ExpectedApprovedSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
try { Add-Type -AssemblyName System.Security.Cryptography.ProtectedData }
catch { Add-Type -AssemblyName System.Security }
$entropy = [Text.Encoding]::UTF8.GetBytes('remote-desktop-bootstrap-v1')
function ProtectedFileSecurity {
    $security = [Security.AccessControl.FileSecurity]::new()
    $security.SetAccessRuleProtection($true,$false)
    $security.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]::None,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    return $security
}
function Assert-ProtectedFileSecurity([Security.AccessControl.FileSecurity]$Security) {
    if (-not $Security.AreAccessRulesProtected -or $Security.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544') { throw 'Bootstrap file owner or DACL is not protected.' }
    $rules=@($Security.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 2) { throw 'Bootstrap file ACL is not restricted.' }
    $ids=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($rule in $rules) {
        if ($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or -not $ids.Add($rule.IdentityReference.Value)) { throw 'Bootstrap file ACL is not restricted.' }
    }
}
if ($Action -eq 'SelfTest') {
    $sample = [Text.Encoding]::UTF8.GetBytes('synthetic-bootstrap-test')
    $opened = $null
    try {
        $sealed = [Security.Cryptography.ProtectedData]::Protect($sample,$entropy,[Security.Cryptography.DataProtectionScope]::LocalMachine)
        $opened = [Security.Cryptography.ProtectedData]::Unprotect($sealed,$entropy,[Security.Cryptography.DataProtectionScope]::LocalMachine)
        if (-not [Linq.Enumerable]::SequenceEqual([byte[]]$sample,[byte[]]$opened)) { throw 'DPAPI self-test failed.' }
        $sealed[$sealed.Length-1] = $sealed[$sealed.Length-1] -bxor 1
        $rejected = $false
        try { [Security.Cryptography.ProtectedData]::Unprotect($sealed,$entropy,[Security.Cryptography.DataProtectionScope]::LocalMachine) | Out-Null } catch { $rejected = $true }
        if (-not $rejected) { throw 'DPAPI tamper self-test failed.' }
        $fileSecurity=ProtectedFileSecurity
        $roundtrip=[Security.AccessControl.FileSecurity]::new()
        $roundtrip.SetSecurityDescriptorBinaryForm($fileSecurity.GetSecurityDescriptorBinaryForm())
        Assert-ProtectedFileSecurity $roundtrip
        $roundtrip.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),[Security.AccessControl.FileSystemRights]::Read,[Security.AccessControl.AccessControlType]::Allow))
        $rejected=$false
        try { Assert-ProtectedFileSecurity $roundtrip } catch { $rejected=$true }
        if (-not $rejected) { throw 'File ACL self-test failed.' }
        $wrongOwner=[Security.AccessControl.FileSecurity]::new()
        $wrongOwner.SetSecurityDescriptorBinaryForm($fileSecurity.GetSecurityDescriptorBinaryForm())
        $wrongOwner.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
        $rejected=$false
        try { Assert-ProtectedFileSecurity $wrongOwner } catch { $rejected=$true }
        if (-not $rejected) { throw 'File owner self-test failed.' }
        'Synthetic machine-DPAPI roundtrip, tamper and file ACL descriptor checks passed.'
    } finally { [Array]::Clear($sample,0,$sample.Length); if ($opened) { [Array]::Clear($opened,0,$opened.Length) } }
    return
}
if (-not $ClientConfigPath -or -not $ApprovedConfigPath) { throw 'ClientConfigPath and ApprovedConfigPath are required.' }
function Read-InputBytes([string]$Path) {
    $file = Get-Item -LiteralPath $Path -Force
    if ($file.PSIsContainer -or $file.Length -gt 131072 -or $file.Length -eq 0 -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Invalid input file.' }
    $stream=[IO.FileStream]::new($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $bytes=$null
    try {
        if ($stream.Length -eq 0 -or $stream.Length -gt 131072) { throw 'Invalid input file.' }
        $bytes=[byte[]]::new([int]$stream.Length); $offset=0
        while ($offset -lt $bytes.Length) {
            $n=$stream.Read($bytes,$offset,$bytes.Length-$offset)
            if ($n -eq 0) { throw 'Input file changed while reading.' }
            $offset+=$n
        }
        if ($stream.ReadByte() -ne -1) { throw 'Input file changed while reading.' }
        $sha=[Security.Cryptography.SHA256]::Create()
        try { $digest=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
        return [pscustomobject]@{ Bytes=$bytes; Sha256=$digest }
    } catch {
        if ($bytes) { [Array]::Clear($bytes,0,$bytes.Length) }
        throw
    } finally { $stream.Dispose() }
}
function Parse-InputJson([byte[]]$Bytes) {
    try {
        $text=[Text.UTF8Encoding]::new($false,$true).GetString($Bytes).TrimStart([char]0xfeff)
        return ($text | ConvertFrom-Json)
    } catch { throw 'Input is not valid UTF-8 JSON.' }
}
function Require-Fields($Value,[string[]]$Names) {
    foreach ($name in $Names) { if ($null -eq $Value.PSObject.Properties[$name]) { throw 'Required bootstrap input is missing.' } }
}
$clientInput=$null; $approvedInput=$null
try {
    $clientInput=Read-InputBytes $ClientConfigPath
    $approvedInput=Read-InputBytes $ApprovedConfigPath
    if ($Action -eq 'Provision') {
        if ($ExpectedClientSha256 -cnotmatch '^[a-f0-9]{64}$' -or $ExpectedApprovedSha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'Provision requires validated input digests.' }
        if ($clientInput.Sha256 -cne $ExpectedClientSha256 -or $approvedInput.Sha256 -cne $ExpectedApprovedSha256) { throw 'Bootstrap input changed after validation.' }
    }
    $client=Parse-InputJson $clientInput.Bytes
    $config=Parse-InputJson $approvedInput.Bytes
} finally {
    if ($clientInput) { [Array]::Clear($clientInput.Bytes,0,$clientInput.Bytes.Length) }
    if ($approvedInput) { [Array]::Clear($approvedInput.Bytes,0,$approvedInput.Bytes.Length) }
}
Require-Fields $client @('url','fingerprint','environment','token')
Require-Fields $config @('identity','display_name','mailbox_ca_pem','local_address','listen_port')
if ($client.environment -cne 'production') { throw 'Mailbox environment must be production.' }
$uri = $null
if (-not [Uri]::TryCreate([string]$client.url,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -cne 'https' -or -not $uri.Host -or $uri.UserInfo -or $uri.AbsolutePath -cne '/' -or $uri.Query -or $uri.Fragment) { throw 'Invalid HTTPS mailbox endpoint.' }
if ([string]$client.token -cnotmatch '^[A-Za-z0-9_-]{43}$') { throw 'Invalid mailbox credential encoding.' }
$tokenBytes=$null
try {
    $tokenBytes=[Convert]::FromBase64String(([string]$client.token).Replace('-','+').Replace('_','/')+'=')
    $canonical=[Convert]::ToBase64String($tokenBytes).TrimEnd('=').Replace('+','-').Replace('/','_')
    if ($tokenBytes.Length -ne 32 -or $canonical -cne $client.token) { throw 'Invalid mailbox credential encoding.' }
} catch { throw 'Invalid mailbox credential encoding.' } finally { if ($tokenBytes) { [Array]::Clear($tokenBytes,0,$tokenBytes.Length) } }
$fingerprint=([string]$client.fingerprint).Replace(':','').ToLowerInvariant()
if ($fingerprint -cnotmatch '^[a-f0-9]{64}$') { throw 'Invalid mailbox certificate fingerprint.' }
try {
    $pem=[string]$config.mailbox_ca_pem
    if ($pem -cnotmatch '(?s)^\s*-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----\s*$') { throw 'Invalid certificate.' }
    $der=[Convert]::FromBase64String(($Matches[1] -replace '\s',''))
    $cert=[Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
    $sha=[Security.Cryptography.SHA256]::Create()
    try { $actual=([BitConverter]::ToString($sha.ComputeHash($cert.RawData))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose(); $cert.Dispose() }
    if ($actual -cne $fingerprint) { throw 'Certificate mismatch.' }
} catch { throw 'The approved certificate does not match the existing mailbox fingerprint.' }
if ([string]$config.identity -cnotmatch '^[a-z][a-z0-9-]{0,63}$' -or $config.identity -ceq 'operator') { throw 'Invalid device identity.' }
$name=[string]$config.display_name
if (-not $name -or $name.Length -gt 128 -or $name.Trim() -cne $name -or $name -match '[\x00-\x1f\x7f]') { throw 'Invalid display name.' }
$address=$null
if (-not [Net.IPAddress]::TryParse([string]$config.local_address,[ref]$address) -or $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $address.Equals([Net.IPAddress]::Any)) { throw 'Invalid local bind address.' }
$port=0
if (-not [int]::TryParse([string]$config.listen_port,[ref]$port) -or $port -lt 1 -or $port -gt 65535) { throw 'Invalid listener port.' }
if ($Action -eq 'Validate') { [pscustomobject]@{ ClientSha256=$clientInput.Sha256; ApprovedSha256=$approvedInput.Sha256 }; return }
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Provision requires an elevated administrator.' }

# SECURITY_ATTRIBUTES allows the initial directory DACL to be protected at creation,
# avoiding a period with inherited user write access. Handles disallow rename/delete.
Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class RemoteBootstrapNative {
  [StructLayout(LayoutKind.Sequential)] struct SA { public int size; public IntPtr sd; public int inherit; }
  [StructLayout(LayoutKind.Sequential)] struct ATTR { public uint attributes; public uint tag; }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateDirectoryW(string path, ref SA sa);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
  [DllImport("kernel32.dll", EntryPoint="CreateFileW", CharSet=CharSet.Unicode, SetLastError=true)] static extern SafeFileHandle CreateFileSecure(string path, uint access, uint share, ref SA sa, uint disposition, uint flags, IntPtr template);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle h, int infoClass, out ATTR info, uint size);
  [DllImport("kernel32.dll", SetLastError=true)] static extern uint GetFileType(SafeFileHandle h);
  [DllImport("advapi32.dll", SetLastError=true)] static extern uint GetSecurityInfo(SafeFileHandle h, uint objectType, uint info, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
  [DllImport("advapi32.dll", SetLastError=true)] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
  public static void CreateProtected(string path, byte[] descriptor) {
    var pinned=GCHandle.Alloc(descriptor, GCHandleType.Pinned);
    try { var sa=new SA {size=Marshal.SizeOf(typeof(SA)),sd=pinned.AddrOfPinnedObject(),inherit=0};
      if (!CreateDirectoryW(path,ref sa)) { int error=Marshal.GetLastWin32Error(); if (error!=183) throw new Win32Exception(error); }
    } finally { pinned.Free(); }
  }
  public static SafeFileHandle HoldDirectory(string path) {
    var h=CreateFileW(path,0x80,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
    if(h.IsInvalid) { int e=Marshal.GetLastWin32Error(); h.Dispose(); throw new Win32Exception(e); }
    ATTR a; if (!GetFileInformationByHandleEx(h,9,out a,(uint)Marshal.SizeOf(typeof(ATTR)))) { int e=Marshal.GetLastWin32Error(); h.Dispose(); throw new Win32Exception(e); }
    if ((a.attributes & 0x400)!=0 || (a.attributes & 0x10)==0) { h.Dispose(); throw new InvalidOperationException("Unsafe directory"); }
    return h;
  }
  public static SafeFileHandle CreateProtectedFile(string path, byte[] descriptor) {
    var pinned=GCHandle.Alloc(descriptor,GCHandleType.Pinned);
    try {
      var sa=new SA {size=Marshal.SizeOf(typeof(SA)),sd=pinned.AddrOfPinnedObject(),inherit=0};
      var h=CreateFileSecure(path,0x40020080,0,ref sa,1,0x00200080,IntPtr.Zero);
      if(h.IsInvalid) { int e=Marshal.GetLastWin32Error(); h.Dispose(); throw new Win32Exception(e); }
      ATTR a;
      if(GetFileType(h)!=1 || !GetFileInformationByHandleEx(h,9,out a,(uint)Marshal.SizeOf(typeof(ATTR)))) { int e=Marshal.GetLastWin32Error(); h.Dispose(); throw new Win32Exception(e); }
      if((a.attributes & 0x410)!=0) { h.Dispose(); throw new InvalidOperationException("Unsafe file"); }
      return h;
    } finally { pinned.Free(); }
  }
  public static byte[] FileSecurityDescriptor(SafeFileHandle h) {
    IntPtr owner,group,dacl,sacl,descriptor;
    uint error=GetSecurityInfo(h,1,5,out owner,out group,out dacl,out sacl,out descriptor);
    if(error!=0) throw new Win32Exception((int)error);
    try {
      uint length=GetSecurityDescriptorLength(descriptor);
      if(length==0 || length>65536 || owner==IntPtr.Zero || dacl==IntPtr.Zero) throw new InvalidOperationException("Invalid file security descriptor");
      var bytes=new byte[length]; Marshal.Copy(descriptor,bytes,0,(int)length); return bytes;
    } finally { LocalFree(descriptor); }
  }
}
"@
function Assert-ProtectedFileHandle([Microsoft.Win32.SafeHandles.SafeFileHandle]$Handle) {
    $security=[Security.AccessControl.FileSecurity]::new()
    $security.SetSecurityDescriptorBinaryForm([RemoteBootstrapNative]::FileSecurityDescriptor($Handle))
    Assert-ProtectedFileSecurity $security
}
function ProtectedDirectorySecurity {
    $s=[Security.AccessControl.DirectorySecurity]::new()
    $s.SetAccessRuleProtection($true,$false)
    $admins=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $s.SetOwner($admins)
    $inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($id in @('S-1-5-18','S-1-5-32-544')) {
        $s.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($id),[Security.AccessControl.FileSystemRights]::FullControl,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    }
    return $s
}
function Assert-PrivateDirectory([string]$Path) {
    $acl=Get-Acl -LiteralPath $Path
    $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if (-not $acl.AreAccessRulesProtected -or $owner -notin @('S-1-5-18','S-1-5-32-544')) { throw 'Bootstrap directory is not protected.' }
    $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 2) { throw 'Bootstrap directory ACL is not restricted.' }
    $ids=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($rule in $rules) {
        if ($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or $rule.InheritanceFlags -ne ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit) -or -not $ids.Add($rule.IdentityReference.Value)) { throw 'Bootstrap directory ACL is not restricted.' }
    }
}
$programData=[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
if (-not $programData) { throw 'ProgramData unavailable.' }
$root=Join-Path $programData 'Remote Desktop Service'
$bootstrap=Join-Path $root 'bootstrap'
$final=Join-Path $bootstrap 'enrollment.dpapi'
$sd=ProtectedDirectorySecurity
$sdbytes=$sd.GetSecurityDescriptorBinaryForm()
$fileSecurity=ProtectedFileSecurity
Assert-ProtectedFileSecurity $fileSecurity
$fileSdBytes=$fileSecurity.GetSecurityDescriptorBinaryForm()
$handles=[Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]]::new()
$temp=$null; $tempCreated=$false; $plaintext=$null
try {
    $ancestors=[Collections.Generic.List[string]]::new()
    $part=[IO.Path]::GetFullPath($programData)
    while ($part) { $ancestors.Add($part); $part=[IO.Path]::GetDirectoryName($part) }
    $ancestors.Reverse()
    foreach ($part in $ancestors) { $handles.Add([RemoteBootstrapNative]::HoldDirectory($part)) }
    [RemoteBootstrapNative]::CreateProtected($root,$sdbytes)
    $handles.Add([RemoteBootstrapNative]::HoldDirectory($root)); Assert-PrivateDirectory $root
    [RemoteBootstrapNative]::CreateProtected($bootstrap,$sdbytes)
    $handles.Add([RemoteBootstrapNative]::HoldDirectory($bootstrap)); Assert-PrivateDirectory $bootstrap
    if (Test-Path -LiteralPath $final) { throw 'Bootstrap already exists; refusing to replace it.' }
    $document=[ordered]@{ schema_version=1; client=[ordered]@{ url=[string]$client.url; fingerprint=$fingerprint; environment='production'; token=[string]$client.token }; config=[ordered]@{ identity=[string]$config.identity; display_name=$name; mailbox_ca_pem=$pem; local_address=[string]$address; listen_port=$port } }
    $json=ConvertTo-Json -InputObject $document -Compress -Depth 5
    $plaintext=[Text.Encoding]::UTF8.GetBytes($json)
    $encrypted=[Security.Cryptography.ProtectedData]::Protect($plaintext,$entropy,[Security.Cryptography.DataProtectionScope]::LocalMachine)
    $temp=Join-Path $bootstrap ('.pending-' + [Guid]::NewGuid().ToString('N'))
    $fileHandle=[RemoteBootstrapNative]::CreateProtectedFile($temp,$fileSdBytes)
    $tempCreated=$true
    try {
        Assert-ProtectedFileHandle $fileHandle
        $stream=[IO.FileStream]::new($fileHandle,[IO.FileAccess]::Write,4096,$false)
        try {
            $stream.Write($encrypted,0,$encrypted.Length)
            Assert-ProtectedFileHandle $stream.SafeFileHandle
            $stream.Flush($true)
            Assert-ProtectedFileHandle $stream.SafeFileHandle
        } finally { $stream.Dispose() }
    } finally { $fileHandle.Dispose() }
    [IO.File]::Move($temp,$final); $tempCreated=$false; $temp=$null
    'Encrypted bootstrap prepared. The disabled service has not consumed it.'
} finally {
    if ($plaintext) { [Array]::Clear($plaintext,0,$plaintext.Length) }
    if ($tempCreated -and $temp -and (Test-Path -LiteralPath $temp)) { Remove-Item -LiteralPath $temp -Force }
    foreach ($h in $handles) { $h.Dispose() }
}
