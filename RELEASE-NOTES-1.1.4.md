# PowerShell Guardian 1.1.4

## Stable session token across lock changes

- `LOCKED -> UNLOCKED` and `UNLOCKED -> LOCKED` now explicitly preserve the same session ID and token.
- A local lock-mode change refreshes session activity and expiry, preventing a token from expiring while the confirmation dialog is open.
- Local command approval and command completion refresh session activity as well.
- Successful `session_status` and `command_status` calls refresh the active session timeout.
- Device binding is computed once, stored with Windows DPAPI and reused. Token validation no longer depends on a fresh MachineGuid registry read for every command.
- New session tokens use a copy-safe 64-character hexadecimal representation. Existing saved tokens remain compatible.

## Reliable token acquisition in a new chat

- `session_status` now reports `session_id`, `access_mode`, `unlock_required: false` and `token_rotated: false` with every approved response.
- MCP instructions state explicitly that approval returns the token in both locked and unlocked modes, and that unlock is never required merely to retrieve a token.
- The bridge instructs the client to retry `session_status` with the original session ID before requesting another session.
- Authentication failures distinguish `INVALID_SESSION_TOKEN`, `SESSION_EXPIRED` and `SESSION_REVOKED` instead of combining them into one ambiguous message.
- Incoming tokens tolerate accidental surrounding whitespace, quotes or backticks without weakening token comparison.
- The installer stops any previous GUI, service and bridge processes before replacing binaries, preventing a mixed-version gateway/bridge pair during an in-place upgrade.

## Pending Command Center

- Added **Clear Success/Rejected**.
- The button removes only `SUCCESS` and `REJECTED` entries.
- `WAITING APPROVAL`, `RUNNING`, `FAILED` and `BLOCKED` entries are retained.
- Each cleanup is written to the audit log with the number of removed entries.
