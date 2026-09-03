# Build PowerShell Guardian 1.1.4

## Requirements

- Windows 10 or 11 x64
- MinGW-w64 with a C++17 compiler and `windres`
- NSIS 3 (`makensis` in `PATH`)
- Official Windows x64 `tunnel-client.exe` and `cloudflared.exe` in `tunnel\`

The two runtime dependencies are separate Apache-2.0 projects. See `THIRD_PARTY_NOTICES.md`.

## Build

Open PowerShell in the project root and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\build.ps1
```

If your executable names differ, pass them explicitly:

```powershell
.\build.ps1 -Cxx g++.exe -WindRes windres.exe -MakeNsis makensis.exe
```

Outputs are written to `build\`:

- `PowerShellGuardian.exe`
- `PowerShellGuardianBridge.exe`
- `PowerShellGuardianSetup.exe`

## Tests

Run the source/security contract with Python 3:

```powershell
python tests\security_contract_test.py
python tests\file_safety_logic_test.py
python tests\session_lifecycle_test.py
```

The platform-independent JSON parser regression test can be compiled with any C++17 compiler:

```powershell
g++ -std=c++17 tests\jsonlite_test.cpp -o build\jsonlite_test.exe
.\build\jsonlite_test.exe
```

`file_safety_logic_test.py` models adjacent full windows, partial-window and skipped-window resets, inactive locked-session limits, and read operations that must not consume the quota. `session_lifecycle_test.py` verifies that lock-mode changes preserve the session identity/token, refresh activity and retain all command states except `SUCCESS` and `REJECTED` during history cleanup.

Never build a release from a directory containing copied `ProgramData\PowerShellGuardian` content, API keys, Tunnel IDs, sessions or production logs.
