<#
.SYNOPSIS
Read-only inventory for an existing Windows machine migration.
.DESCRIPTION
Does not decrypt SYSTEM enrollment, stop processes, change trust, reset watcher
state or write files. Output is an explicit public projection. The caller must
also inspect the native/non-packaged user context before authorizing migration.
#>
[CmdletBinding()]
param(
    [string]$MailboxDirectory = (Join-Path $env:LOCALAPPDATA 'HoenAgentMailbox-hoenlenovo'),
    [string]$PackagedMailboxDirectory = (Join-Path $env:USERPROFILE 'AppData\Local\Packages\OpenAI.Codex_2p2nqsd0c76g0\LocalCache\Local\HoenAgentMailbox-hoenlenovo')
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Get-MigrationFileState([string]$Path) {
    try {
        $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return 'unsupported' }
        return 'present'
    } catch {
        if($_.CategoryInfo.Category -eq 'ObjectNotFound') { return 'missing' }
        return 'unreadable'
    }
}

function Read-MigrationProfile([string]$Path,[string]$Label) {
    $state=Get-MigrationFileState $Path
    if($state -ne 'present') { return [pscustomobject]@{label=$Label;state=$state;mailboxUrl=$null;fingerprint=$null;hasCredential=$false} }
    try {
        if((Get-Item -LiteralPath $Path).Length -gt 65536){throw 'size'}
        $profile=[IO.File]::ReadAllText($Path)|ConvertFrom-Json
        $uri=[Uri]$profile.url
        if(!$uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or $uri.AbsolutePath -ne '/'){throw 'url'}
        $pin=[string]$profile.fingerprint
        if($pin -cnotmatch '^[a-fA-F0-9]{64}$'){throw 'pin'}
        $validToken=$profile.token -is [string] -and $profile.token -cmatch '^[-_a-zA-Z0-9]{43}$'
        if(!$validToken){throw 'credential'}
        return [pscustomobject]@{label=$Label;state='valid';mailboxUrl=$uri.GetLeftPart([UriPartial]::Authority);fingerprint=$pin.ToUpperInvariant();hasCredential=$true}
    } catch {
        return [pscustomobject]@{label=$Label;state='invalid';mailboxUrl=$null;fingerprint=$null;hasCredential=$false}
    } finally { $profile=$null }
}

function Compare-MigrationCredentials([string[]]$Paths) {
    # Compare in memory; never return a credential or its hash.
    $first=$null;$count=0
    try {
        foreach($path in $Paths) {
            if((Read-MigrationProfile $path 'comparison').state -ne 'valid'){return 'unknown'}
            $value=[IO.File]::ReadAllText($path)|ConvertFrom-Json
            if($count -gt 0 -and $first -cne $value.token){return 'conflict'}
            $first=$value.token;$count++
        }
        if($count -eq 0){return 'unknown'}
        return 'consistent'
    } catch { return 'unknown' }
    finally { $first=$null;$value=$null }
}

function Get-MigrationInventory {
    $base=$MailboxDirectory
    $candidates=@(
        @{label='user-current';path=(Join-Path $base 'client-san-20261106.json')},
        @{label='user-legacy';path=(Join-Path $base 'client.json')}
    )
    $packaged=$PackagedMailboxDirectory
    foreach($name in @('client-san-20261106.json','client.json')) {
        $candidates+=@{label=('packaged-'+$name);path=(Join-Path $packaged $name)}
    }
    $profiles=@($candidates|ForEach-Object {Read-MigrationProfile $_.path $_.label})
    $existing=@($candidates|Where-Object {(Get-MigrationFileState $_.path) -ne 'missing'}|ForEach-Object {$_.path})
    $agreement=Compare-MigrationCredentials $existing
    $connections=@($profiles|Where-Object state -eq 'valid'|ForEach-Object {$_.mailboxUrl+'|'+$_.fingerprint}|Select-Object -Unique)
    $serviceState='unavailable';$serviceAccount='unknown'
    try {
        $services=@(Get-CimInstance Win32_Service -Filter "Name='RemoteDesktopService'" -ErrorAction Stop)
        if($services.Count -eq 1){$serviceState=[string]$services[0].State;$serviceAccount=if($services[0].StartName -eq 'LocalSystem'){'LocalSystem'}else{'unexpected'}}
        elseif($services.Count -eq 0){$serviceState='missing'}
    } catch {}
    $store=Join-Path $env:ProgramData 'Remote Desktop Service State\host\service.dpapi'
    $watcher=Join-Path $base 'watcher\state.json'
    $app=Join-Path $env:APPDATA 'HoenAgentMailboxDesktop\connection.encrypted'
    [pscustomobject]@{
        schemaVersion=1
        readOnly=$true
        decision=if($agreement -eq 'conflict' -or $connections.Count -gt 1){'conflict_requires_review'}else{'requires_broker_validation'}
        credentialAgreement=$agreement
        connectionAgreement=if($connections.Count -gt 1){'conflict'}elseif($connections.Count -eq 1){'consistent'}else{'unknown'}
        profiles=$profiles
        protectedEnrollment=Get-MigrationFileState $store
        mailboxAppCredential=Get-MigrationFileState $app
        watcherState=Get-MigrationFileState $watcher
        serviceState=$serviceState
        serviceAccount=$serviceAccount
        nativeProfileReviewRequired=$true
        limitations=@('Current-user and explicit packaged profile views only; no all-user inventory.',
            'SYSTEM enrollment and app credential are not decrypted or compared.',
            'No authentication, live readiness, backup or migration has been performed.')
    }
}

if($MyInvocation.InvocationName -ne '.') { Get-MigrationInventory | ConvertTo-Json -Depth 5 }
