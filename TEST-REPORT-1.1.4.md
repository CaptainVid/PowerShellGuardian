# PowerShell Guardian 1.1.4 — build and test report

## Result

Release build completed successfully with MinGW-w64 and NSIS 3. The source passes warning-free C++17 analysis with `-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror`.

## Automated checks

- `tests/security_contract_test.py`: PASS
- `tests/file_safety_logic_test.py`: PASS
- `tests/session_lifecycle_test.py`: PASS
- `tests/jsonlite_test.cpp`: PASS
- Windows x64 GUI cross-build: PASS
- Windows x64 console MCP bridge cross-build: PASS
- NSIS installer build: PASS
- PE inspection and 1.1.4 version-resource inspection: PASS

## Acceptance matrix

| Requirement | Implemented behavior |
|---|---|
| Locked commands followed by unlock | Lock-mode switching preserves the same session ID and token and refreshes expiry. |
| No token rotation | Audit records the existing token reference; neither lock nor unlock creates a session or token. |
| Token in locked mode | Approved `session_status` explicitly returns the token with `access_mode: LOCKED` and `unlock_required: false`. |
| Intermittent device mismatch | Device binding is computed once, protected with DPAPI and reused instead of re-reading the registry for every command. |
| Activity during commands | Local approval, command completion, `session_status`, `command_status` and lock-mode switching refresh the active timeout. |
| Clear command history | The new button removes only `SUCCESS` and `REJECTED`; waiting, running, failed and blocked entries stay visible. |
| Upgrade consistency | The installer stops both PowerShell Guardian and pre-rename services/processes, then migrates legacy `ProgramData` only when the new data directory does not exist. |
| Unicode ListView build | List insertion and updates use explicit UTF-16 messages; the strict MinGW-w64 build no longer depends on an ANSI/Unicode macro. |
| GitHub publication scan | No live credentials, private keys, user paths, runtime logs, session data or local secret files were found in the release tree. |

## SHA-256

- `PowerShellGuardian.exe`: `74cbd35ffd4adafbe1b8e14ae03462f7b11019a34b11ce28c3933ec1738c142a`
- `PowerShellGuardianBridge.exe`: `c676012fc562d457cb9a9bf76e0335943da8467b8e44b155efe0b01d7035b091`
- `PowerShellGuardianSetup.exe`: `6cb9bf496ebaed8341a05ff96190e7daccf31dccd980d9562ab49f1132773e6c`

## Test boundary

The Windows programs and installer were cross-compiled and structurally verified. Interactive UAC, GUI, DPAPI, PowerShell and tunnel-client behavior requires the final smoke test on Windows 10/11.
