param(
    [string]$Cxx = "x86_64-w64-mingw32-g++",
    [string]$WindRes = "",
    [string]$MakeNsis = "makensis"
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildDirectory = Join-Path $ProjectRoot "build"

New-Item -ItemType Directory -Force -Path $BuildDirectory | Out-Null

function Find-Tool($Preferred, $Fallbacks) {
    if ($Preferred -and (Get-Command $Preferred -ErrorAction SilentlyContinue)) {
        return $Preferred
    }

    foreach ($tool in $Fallbacks) {
        if (Get-Command $tool -ErrorAction SilentlyContinue) {
            return $tool
        }
    }

    throw "Required build tool not found: $($Fallbacks -join ', ')"
}

# Support both local MinGW installations and GitHub Actions runners
$Cxx = Find-Tool $Cxx @(
    "x86_64-w64-mingw32-g++",
    "g++"
)

$WindRes = Find-Tool $WindRes @(
    "x86_64-w64-mingw32-windres",
    "windres"
)

$MakeNsis = Find-Tool $MakeNsis @(
    "makensis"
)

Write-Host "Compiler: $Cxx"
Write-Host "Resource compiler: $WindRes"
Write-Host "NSIS: $MakeNsis"

$Libraries = @(
    "-lws2_32",
    "-lcomctl32",
    "-lcomdlg32",
    "-lcrypt32",
    "-lbcrypt",
    "-lshell32",
    "-ladvapi32",
    "-lole32"
)

& $WindRes `
    (Join-Path $ProjectRoot "src\PowerShellGuardian.rc") `
    "-O" `
    "coff" `
    "-o" `
    (Join-Path $BuildDirectory "PowerShellGuardian.res")

if ($LASTEXITCODE -ne 0) {
    throw "windres failed"
}

$Common = @(
    "-std=c++17",
    "-O2",
    "-municode",
    "-static",
    "-static-libgcc",
    "-static-libstdc++"
)

& $Cxx `
    @Common `
    "-mwindows" `
    (Join-Path $ProjectRoot "src\PowerShellGuardian.cpp") `
    (Join-Path $BuildDirectory "PowerShellGuardian.res") `
    "-o" `
    (Join-Path $BuildDirectory "PowerShellGuardian.exe") `
    @Libraries

if ($LASTEXITCODE -ne 0) {
    throw "PowerShellGuardian.exe build failed"
}

& $Cxx `
    @Common `
    "-DMOMENTUM_BRIDGE_CONSOLE" `
    "-mconsole" `
    (Join-Path $ProjectRoot "src\PowerShellGuardian.cpp") `
    "-o" `
    (Join-Path $BuildDirectory "PowerShellGuardianBridge.exe") `
    @Libraries

if ($LASTEXITCODE -ne 0) {
    throw "PowerShellGuardianBridge.exe build failed"
}

Push-Location (Join-Path $ProjectRoot "installer")

try {
    & $MakeNsis "PowerShellGuardian.nsi"

    if ($LASTEXITCODE -ne 0) {
        throw "PowerShellGuardianSetup.exe build failed"
    }
}
finally {
    Pop-Location
}

Write-Host "Build completed successfully:" -ForegroundColor Green

Get-Item `
    (Join-Path $BuildDirectory "PowerShellGuardian.exe"), `
    (Join-Path $BuildDirectory "PowerShellGuardianBridge.exe")
