Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'remote-desktop-migration-preflight.ps1')
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('hoen-migration-test-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture|Out-Null
try {
    $a=Join-Path $fixture 'a.json';$b=Join-Path $fixture 'b.json'
    $data=@{url='https://192.168.1.9:42819';fingerprint=('a'*64);token=(('B'*21)+('C'*22))}
    $data|ConvertTo-Json|Set-Content $a
    Copy-Item $a $b
    $before=(Get-FileHash $a).Hash
    $summary=Read-MigrationProfile $a 'fixture'
    if($summary.state -ne 'valid' -or (Compare-MigrationCredentials @($a,$b)) -ne 'consistent'){throw 'Valid inventory rejected'}
    $json=$summary|ConvertTo-Json
    if($json.Contains($data.token) -or $json -match '"token"'){throw 'Credential leaked'}
    if((Get-FileHash $a).Hash -ne $before){throw 'Read-only inventory mutated input'}
    $data.token='B'*43;$data|ConvertTo-Json|Set-Content $b
    if((Compare-MigrationCredentials @($a,$b)) -ne 'conflict'){throw 'Credential conflict missed'}
    $data.url='https://user:password@example.invalid/';$data|ConvertTo-Json|Set-Content $b
    if((Read-MigrationProfile $b 'fixture').state -ne 'invalid' -or (Compare-MigrationCredentials @($a,$b)) -ne 'unknown'){throw 'Unsafe URL accepted or unknown credential guessed'}
    if((Read-MigrationProfile (Join-Path $fixture 'missing') 'fixture').state -ne 'missing'){throw 'Missing profile misreported'}
    'Migration inventory checks passed: valid/redacted/read-only, conflicting credentials, invalid/missing profile.'
} finally {
    $resolved=[IO.Path]::GetFullPath($fixture)
    $root=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
    if(!$resolved.StartsWith($root,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $resolved -Leaf) -notlike 'hoen-migration-test-*'){throw 'Test cleanup containment failed'}
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
