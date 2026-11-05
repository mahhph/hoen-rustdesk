# Read-only preflight for the Windows x64 Flutter build described in docs/HOEN-WINDOWS.md.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$missing = [System.Collections.Generic.List[string]]::new()
function Report([bool]$Ok, [string]$Name, [string]$Hint) {
    if ($Ok) { Write-Host "[OK] $Name" }
    else { Write-Host "[MISSING] $Name -- $Hint"; $script:missing.Add($Name) }
}
function Executable([string]$Name) {
    $cmd = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $cmd -or $cmd.Source -match '[\\/]WindowsApps[\\/]') { return $null }
    return $cmd.Source
}
Write-Host 'Hoen Windows x64 Flutter build preflight (read-only; no build or installation)'
$git = Executable 'git.exe'
Report ($null -ne $git) 'Git' 'Install Git locally or add an existing installation to PATH.'
$submoduleOk = $false
if ($git) {
    $env:GIT_OPTIONAL_LOCKS = '0'
    $subStatus = & $git -C $repo submodule status --recursive 2>$null
    $subExit = $LASTEXITCODE
    $submoduleOk = $subExit -eq 0 -and @($subStatus).Count -gt 0 -and -not (@($subStatus) | Where-Object { $_ -match '^[-+U]' })
}
Report $submoduleOk 'Pinned recursive submodules' 'Initialize exact recorded commits with git submodule update --init --recursive.'
$rustup = Executable 'rustup.exe'
Report ($null -ne (Executable 'cargo.exe') -and $null -ne (Executable 'rustc.exe') -and $null -ne $rustup) 'Rust, Cargo and rustup' 'Install rustup in the user profile.'
$rustPinned = $false
if ($rustup) {
    $toolchains = & $rustup toolchain list 2>$null
    $rustPinned = $LASTEXITCODE -eq 0 -and @($toolchains | Where-Object { $_ -match '^1\.75\.0-x86_64-pc-windows-msvc(?:\s|$)' }).Count -gt 0
}
Report $rustPinned 'CI Rust 1.75.0 x64 MSVC toolchain' 'Run rustup toolchain install 1.75.0 --profile minimal --target x86_64-pc-windows-msvc.'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$vsOk = $false
if (Test-Path -LiteralPath $vswhere -PathType Leaf) {
    $vsVersion = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 Microsoft.VisualStudio.Component.Windows10SDK -property installationVersion 2>$null
    $vsOk = $LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace(($vsVersion -join ''))
    # Windows11SDK installations may not advertise the generic Windows10SDK component.
    if (-not $vsOk) {
        $vsVersion = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 Microsoft.VisualStudio.Component.Windows11SDK.22621 -property installationVersion 2>$null
        $vsOk = $LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace(($vsVersion -join ''))
    }
}
Report $vsOk 'Visual Studio x64 C++ tools and Windows SDK' 'Install or select a VS instance with Desktop C++ tools and a Windows SDK; verify with flutter doctor.'
$vsPath = $null
if ($vsOk) { $vsPath = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null | Select-Object -First 1 }
$cmakeOk = $null -ne (Executable 'cmake.exe')
$ninjaOk = $null -ne (Executable 'ninja.exe')
if ($vsPath) {
    $cmakeOk = $cmakeOk -or (Test-Path -LiteralPath (Join-Path $vsPath 'Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe') -PathType Leaf)
    $ninjaOk = $ninjaOk -or (Test-Path -LiteralPath (Join-Path $vsPath 'Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja/ninja.exe') -PathType Leaf)
}
Report $cmakeOk 'CMake' 'Use the Visual Studio CMake component or an existing CMake executable.'
Report $ninjaOk 'Ninja' 'Use the Visual Studio Ninja component or an existing Ninja executable.'
$python = Executable 'python.exe'
$pythonOk = $false
if ($python) { $v = & $python --version 2>$null; $pythonOk = $LASTEXITCODE -eq 0 -and "$v" -match '^Python 3\.' }
Report $pythonOk 'Working Python 3 on PATH' 'Use a per-user Python 3.12 installation; WindowsApps aliases are not interpreters.'
$clang = Executable 'clang.exe'
$clangOk = $false
if ($clang) { $v = & $clang --version 2>$null | Select-Object -First 1; $clangOk = $LASTEXITCODE -eq 0 -and "$v" -match 'clang version 15\.0\.6\b' }
Report $clangOk 'LLVM/Clang 15.0.6 on PATH' 'Use an isolated LLVM 15.0.6 distribution and add its bin directory to this process PATH.'
$flutter = Executable 'flutter.bat'
$flutterRoot = if ($flutter) { Split-Path -Parent (Split-Path -Parent $flutter) } else { $null }
$flutterOk = $false
if ($flutterRoot) {
    $versionFile = Join-Path $flutterRoot 'bin/cache/flutter.version.json'
    if (Test-Path -LiteralPath $versionFile -PathType Leaf) {
        try { $flutterVersion = (Get-Content -Raw -LiteralPath $versionFile | ConvertFrom-Json).frameworkVersion; $flutterOk = $flutterVersion -eq '3.24.5' } catch { $flutterOk = $false }
    }
}
Report $flutterOk 'Flutter 3.24.5 version cache on PATH' 'Use an isolated Flutter 3.24.5 SDK and initialize its Windows artifacts outside this read-only check.'
$root = $env:VCPKG_ROOT
$vcpkgOk = $false
if ($root -and (Test-Path -LiteralPath (Join-Path $root 'vcpkg.exe') -PathType Leaf) -and $git) {
    $head = & $git -C $root rev-parse HEAD 2>$null
    $vcpkgOk = $LASTEXITCODE -eq 0 -and $head -eq '9e593bb18ea69cc5095e012465dcd675a822ed0d'
}
Report $vcpkgOk 'Bootstrapped pinned vcpkg checkout' 'Set VCPKG_ROOT to a bootstrapped checkout at CI commit 9e593bb18ea69cc5095e012465dcd675a822ed0d.'
$depsOk = $false
if ($root) {
    $statusFile = Join-Path $root 'installed/vcpkg/status'
    if (Test-Path -LiteralPath $statusFile -PathType Leaf) {
        $paragraphs = (Get-Content -Raw -LiteralPath $statusFile) -split "(?:\r?\n){2,}"
        $depsOk = $true
        foreach ($pkg in @('aom', 'libjpeg-turbo', 'opus', 'libvpx', 'libyuv', 'mfx-dispatch', 'ffmpeg')) {
            $present = $paragraphs | Where-Object { $_ -match "(?m)^Package: $([regex]::Escape($pkg))\r?$" -and $_ -match '(?m)^Architecture: x64-windows-static\r?$' -and $_ -match '(?m)^Status: install ok installed\r?$' }
            if (-not $present) { $depsOk = $false }
        }
    }
}
Report $depsOk 'Selected vcpkg x64 static packages' 'Install the repository manifest using x64-windows-static; see the build notes.'
Write-Host ''
Write-Host 'Generated bridge artifacts:'
foreach ($file in @('src/bridge_generated.rs', 'src/bridge_generated.io.rs', 'flutter/lib/generated_bridge.dart', 'flutter/lib/generated_bridge.freezed.dart', 'flutter/macos/Runner/bridge_generated.h', 'flutter/ios/Runner/bridge_generated.h')) {
    Report (Test-Path -LiteralPath (Join-Path $repo $file) -PathType Leaf) $file 'Restore the matching CI bridge-artifact; do not run local codegen.'
}
Write-Host ''
Write-Host '[MANUAL] Verify bridge artifact provenance matches this source revision; file presence does not prove it.'
Write-Host '[MANUAL] Verify CI custom x64 Flutter engine, dropdown patch, SDK tools, full vcpkg manifest, and packaging artifacts; this preflight cannot attest these.'
if ($missing.Count -gt 0) { Write-Host "Preflight incomplete: $($missing.Count) checks need attention."; exit 1 }
Write-Host 'File and tool checks passed; manual provenance and build validation remain required.'
exit 0

