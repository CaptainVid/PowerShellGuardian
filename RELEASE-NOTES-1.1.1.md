# PowerShell Guardian 1.1.1

## Fixed

- File deletion now enters a dedicated `WAITING_LOCAL_DELETE_APPROVAL` path before unattended execution and file-rate safety checks. Both the `delete` tool and detected deletion commands therefore always open a local approval prompt instead of being reported as automatically blocked.
- The deletion approval prompt is brought to the foreground and clearly identifies the target or command.
- Input and Security Settings windows are wider, centered inside the active monitor, use a multi-line instruction area, and apply the standard GUI font so long setting descriptions remain fully visible.

## Unchanged

- Per-session unlocking, file creation limits, suspicious-activity termination, audit logging, whitelist behavior, tunnel startup, and stored configuration remain unchanged from 1.1.0.
