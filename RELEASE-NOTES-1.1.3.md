# PowerShell Guardian 1.1.3

## Session state and approval

- Approved `session_status` responses are idempotent and always return the same active device-bound token.
- Session transitions are audited explicitly: `NEW -> WAITING_APPROVAL`, `WAITING_APPROVAL -> LOCKED`, `LOCKED -> UNLOCKED`, `UNLOCKED -> LOCKED`, revocation, expiry and suspicious termination.
- Session and command decisions use stable IDs after modal dialogs instead of mutable vector/list row indexes.
- Locked sessions require local approval for every non-whitelisted operation. Unlocked sessions queue every non-deletion operation without a local prompt.
- File deletion always enters `WAITING_LOCAL_DELETE_APPROVAL`, including deletion detected inside PowerShell commands.

## File-creation safety

- The file guard is evaluated only when the command was authorized by an unlocked session.
- Reads, directory listings, navigation, other commands and writes to an existing path do not consume the new-file quota.
- Consecutive full windows now use deterministic adjacent fixed windows. A partial window or a skipped window resets the streak; the configured Xth consecutive full window terminates the session.
- Locking, unlocking or changing file-safety settings resets the per-session file window state.
- Added configurable new-session request admission limits as a separate guard; it never affects actions inside an approved session.

## Stability and inspection fixes

- Removed the artificial five-minute PowerShell timeout.
- Potentially long unlocked operations run asynchronously and expose progress through `command_status`, leaving the gateway responsive.
- PowerShell output remains non-blocking; non-zero exit codes now correctly produce `FAILED` instead of false success.
- Stop, restart and Emergency Lock terminate active command processes.
- Gateway and health-check sockets use bounded waits, while PowerShell execution itself has no artificial deadline.
- GUI startup no longer loops forever when local gateway port `17654` cannot bind.
- Expired or revoked sessions reject waiting commands; completed command history is pruned after 24 hours.
- Audit writes are serialized to prevent interleaved JSONL records.

## `read_path`

- `read_path` directly reads one bounded text file or lists one directory without invoking PowerShell.
- It is an operational read, not a file-creation detector. Locked mode requires local approval; unlocked mode queues it immediately without a prompt.
- File contents are capped, text encoding is normalized, and the file-creation rate limiter is never called for the operation.
