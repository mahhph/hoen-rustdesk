# Read-only candidate discovery. Output is not approval and is not enrollment.
# No adapters, routes, network profiles, or connections are modified.
$ErrorActionPreference = 'Stop'
# Strongly typed COM interfaces are required: PowerShell's late-bound COM
# marshaller cannot reliably decode Network List Manager's GUID returns.
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
[ComImport, Guid("DCB00002-570F-4A9B-8D69-199FDBA5723B"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
interface IHoenNetwork {
    [return: MarshalAs(UnmanagedType.BStr)] string GetName();
    void SetName([MarshalAs(UnmanagedType.BStr)] string name);
    [return: MarshalAs(UnmanagedType.BStr)] string GetDescription();
    void SetDescription([MarshalAs(UnmanagedType.BStr)] string description);
    Guid GetNetworkId();
}
[ComImport, Guid("DCB00005-570F-4A9B-8D69-199FDBA5723B"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
interface IHoenConnection {
    IHoenNetwork GetNetwork();
    [return: MarshalAs(UnmanagedType.VariantBool)] bool IsConnectedToInternet();
    [return: MarshalAs(UnmanagedType.VariantBool)] bool IsConnected();
    int GetConnectivity();
    Guid GetConnectionId();
    Guid GetAdapterId();
}
public static class HoenNetworkCandidateReader {
    public static string[] Read(object raw) {
        var connection = (IHoenConnection)raw;
        if (!connection.IsConnected()) return null;
        return new[] { connection.GetAdapterId().ToString("N"), connection.GetNetwork().GetNetworkId().ToString("N") };
    }
}
"@
$managerType = [type]::GetTypeFromCLSID([guid]'DCB00C01-570F-4A9B-8D69-199FDBA5723B')
$manager = [Activator]::CreateInstance($managerType)
$connections = @($manager.GetNetworkConnections())
foreach ($adapter in Get-NetAdapter) {
    $profiles = @(Get-NetConnectionProfile -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue)
    foreach ($connection in $connections) {
        $ids = [HoenNetworkCandidateReader]::Read($connection)
        if ($null -eq $ids -or [guid]$ids[0] -ne [guid]$adapter.InterfaceGuid) { continue }
        foreach ($address in @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue)) {
            if ($address.AddressState -ne 'Preferred') { continue }
            $ip = [System.Net.IPAddress]::Parse($address.IPAddress)
            $octets = $ip.GetAddressBytes()
            if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                if (-not ($octets[0] -eq 10 -or ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or ($octets[0] -eq 192 -and $octets[1] -eq 168))) { continue }
            } elseif ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
                if (($octets[0] -band 0xfe) -ne 0xfc) { continue }
            } else { continue }
            [pscustomobject]@{
                Adapter = $adapter.Name
                AdapterGuid = $ids[0]
                NetworkGuid = $ids[1]
                Address = $address.IPAddress
                AddressFamily = $address.AddressFamily
                AdapterStatus = $adapter.Status
                NetworkCategory = ($profiles.NetworkCategory -join ', ')
                PrivateProfileRequired = ($profiles.Count -eq 1 -and $profiles[0].NetworkCategory -eq 'Private')
            }
        }
    }
}
