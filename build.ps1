param(
    [string]$Cxx = "",
    [string]$WindRes = "",
    [string]$MakeNsis = ""
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildDirectory = Join-Path $ProjectRoot "build"

New-Item -ItemType Directory -Force -Path $BuildDirectory | Out-Null


function Find-Executable {
    param(
        [string[]]$Names,
        [string[]]$Paths
    )

    foreach ($name in $Names) {
        if ($name) {
            $cmd = Get-Command $name -ErrorAction SilentlyContinue
            if ($cmd) {
                return $cmd.Source
            }
        }
    }

    foreach ($path in $Paths) {
        if (Test-Path $path) {
            return $path
        }
    }

    return $null
}


# Detect C++ compiler
$CxxTool = Find-Executable `
    -Names @(
        $Cxx,
        "x86_64-w64-mingw32-g++",
        "g++"
    ) `
    -Paths @()

if (-not $CxxTool) {
    throw "C++ compiler not found. Install MinGW."
}


# Detect resource compiler
$WindResTool = Find-Executable `
    -Names @(
        $WindRes,
        "x86_64-w64-mingw32-windres",
        "windres"
    ) `
    -Paths @()

if (-not $WindResTool) {
    throw "Resource compiler not found. Install MinGW binutils."
}


# Detect NSIS installer compiler
$NsisTool = Find-Executable `
    -Names @(
        $MakeNsis,
        "makensis"
    ) `
    -Paths @(
        "C:\Program Files (x86)\NSIS\makensis.exe",
        "C:\Program Files\NSIS\makensis.exe",
        "C:\ProgramData\chocolatey\bin\makensis.exe"
    )


if (-not $NsisTool) {

    Write-Host "Searching Chocolatey NSIS installation..."

    $NsisTool = Get-ChildItem `
        "C:\ProgramData\chocolatey\lib" `
        -Filter "makensis.exe" `
        -Recurse `
        -ErrorAction SilentlyContinue |
        Select-Object -First 1 |
        ForEach-Object { $_.FullName }
}


if (-not $NsisTool) {
    throw "NSIS compiler not found. Install NSIS."
}


Write-Host "Compiler: $CxxTool"
Write-Host "Resource compiler: $WindResTool"
Write-Host "NSIS compiler: $NsisTool"


# Compile Windows resource
& $WindResTool `
    (Join-Path $ProjectRoot "src\PowerShellGuardian.rc") `
    -O coff `
    -o (Join-Path $BuildDirectory "PowerShellGuardian.res")

if ($LASTEXITCODE -ne 0) {
    throw "Resource compilation failed"
}


$CommonFlags = @(
    "-std=c++17",
    "-O2",
    "-municode",
    "-static",
    "-static-libgcc",
    "-static-libstdc++"
)


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


# Build main application
& $CxxTool `
    @CommonFlags `
    "-mwindows" `
    (Join-Path $ProjectRoot "src\PowerShellGuardian.cpp") `
    (Join-Path $BuildDirectory "PowerShellGuardian.res") `
    "-o" `
    (Join-Path $BuildDirectory "PowerShellGuardian.exe") `
    @Libraries

if ($LASTEXITCODE -ne 0) {
    throw "PowerShellGuardian.exe build failed"
}


# Build console bridge
& $CxxTool `
    @CommonFlags `
    "-DMOMENTUM_BRIDGE_CONSOLE" `
    "-mconsole" `
    (Join-Path $ProjectRoot "src\PowerShellGuardian.cpp") `
    "-o" `
    (Join-Path $BuildDirectory "PowerShellGuardianBridge.exe") `
    @Libraries

if ($LASTEXITCODE -ne 0) {
    throw "PowerShellGuardianBridge.exe build failed"
}


# Build installer
Push-Location (Join-Path $ProjectRoot "installer")

try {

    & $NsisTool "PowerShellGuardian.nsi"

    if ($LASTEXITCODE -ne 0) {
        throw "Installer build failed"
    }

}
finally {
    Pop-Location
}


Write-Host ""
Write-Host "PowerShell Guardian build completed successfully" -ForegroundColor Green
