# PowerShell Guardian 1.1.3 — build and test report

## Result

Release build completed successfully with MinGW-w64 and NSIS 3. The source passes a warning-free C++17 syntax analysis with `-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror`.

## Automated checks

- `tests/security_contract_test.py`: PASS
- `tests/file_safety_logic_test.py`: PASS
- `tests/jsonlite_test.cpp`: PASS
- Windows x64 GUI cross-build: PASS
- Windows x64 console MCP bridge cross-build: PASS
- NSIS installer build: PASS
- PE inspection: `PowerShellGuardian.exe` is Windows GUI x64; `PowerShellGuardianBridge.exe` is Windows console x64.

The deterministic file-safety test covers three adjacent full windows, a partial intervening window, a skipped window, reads/zero creations, and locked-session bypass of the creation guard.

## Acceptance matrix

| Requirement | Implemented behavior |
|---|---|
| Approved session continues | `session_status` is idempotent and returns the same valid token on retries. |
| Unlocked mode | Non-deletion operations queue without a local prompt. |
| File deletion | Always enters local approval, including recognized deletion commands inside PowerShell. |
| Locked mode | Every non-whitelisted operation waits for local approval. |
| Creation limiter scope | Evaluated only for new-file creation authorized by an unlocked session. |
| Consecutive full windows | Only adjacent full windows increase the streak; partial or skipped windows reset it. |
| Path reading | `read_path` performs bounded direct reads/listings and never invokes the creation limiter. |
| Loop/deadlock defense | Stable IDs, explicit state transitions, asynchronous long operations, bounded socket waits, and interruptible shutdown. |
| PowerShell timeout | The artificial five-minute execution timeout was removed. |

## Archived artifact hashes

The old 1.1.3 hashes were removed from this rebranded source tree because they belonged to binaries built before the final PowerShell Guardian filename and version-resource rename. Keeping those values beside the new filenames would make the report misleading. Current release hashes are recorded in `TEST-REPORT-1.1.4.md`.

## Test boundary

The Windows executables and installer were cross-compiled and structurally verified in the build environment. Final interactive validation of UAC, GUI approval dialogs, Windows DPAPI, PowerShell, and tunnel-client startup must run on Windows 10/11 because those facilities are not available in this Linux build environment.
