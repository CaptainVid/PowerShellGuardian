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
    param([string[]]$Names)

    foreach ($name in $Names) {
        if ($name) {
            $cmd = Get-Command $name -ErrorAction SilentlyContinue
            if ($cmd) {
                return $cmd.Source
            }
        }
    }

    return $null
}

$CxxTool = Find-Executable @($Cxx, "x86_64-w64-mingw32-g++", "g++")
$WindResTool = Find-Executable @($WindRes, "x86_64-w64-mingw32-windres", "windres")

if (-not $CxxTool) { throw "C++ compiler not found" }
if (-not $WindResTool) { throw "Resource compiler not found" }

if ($MakeNsis) {
    $NsisTool = $MakeNsis
}
else {
    $NsisTool = Find-Executable @("makensis")
}

if (-not $NsisTool) { throw "NSIS compiler path not provided" }

Write-Host "Compiler: $CxxTool"
Write-Host "Resource compiler: $WindResTool"
Write-Host "NSIS compiler: $NsisTool"

& $WindResTool (Join-Path $ProjectRoot "src\PowerShellGuardian.rc") -O coff -o (Join-Path $BuildDirectory "PowerShellGuardian.res")

if ($LASTEXITCODE -ne 0) { throw "Resource compilation failed" }

$Flags = @("-std=c++17","-O2","-municode","-static","-static-libgcc","-static-libstdc++")

$Libraries = @("-lws2_32","-lcomctl32","-lcomdlg32","-lcrypt32","-lbcrypt","-lshell32","-ladvapi32","-lole32")

& $CxxTool @Flags "-mwindows" (Join-Path $ProjectRoot "src\PowerShellGuardian.cpp") (Join-Path $BuildDirectory "PowerShellGuardian.res") "-o" (Join-Path $BuildDirectory "PowerShellGuardian.exe") @Libraries

if ($LASTEXITCODE -ne 0) { throw "PowerShellGuardian.exe build failed" }

& $CxxTool @Flags "-DMOMENTUM_BRIDGE_CONSOLE" "-mconsole" (Join-Path $ProjectRoot "src\PowerShellGuardian.cpp") "-o" (Join-Path $BuildDirectory "PowerShellGuardianBridge.exe") @Libraries

if ($LASTEXITCODE -ne 0) { throw "PowerShellGuardianBridge.exe build failed" }

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

Write-Host "PowerShell Guardian build completed successfully" -ForegroundColor Green
