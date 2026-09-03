# PowerShell Guardian 1.1.2

## Fixed

- `session_status` is now idempotent and returns the active device-bound token on every approved-session check. A lost response can no longer leave ChatGPT in an endless `token_already_delivered` loop.
- PowerShell output uses non-blocking pipe polling with a real five-minute timeout. A process or descendant that keeps the inherited output pipe open can no longer freeze the bridge indefinitely.
- Gateway connections are handled independently and use bounded socket waits, so a slow command no longer blocks session checks and unrelated actions.
- Added `read_path` for direct file reads and directory listings without PowerShell. Reads are excluded from all file-creation quota and suspicious-window accounting.
- File quota preflight ignores targets that already exist, so updating an existing file does not consume the new-file allowance.

## Security behavior retained

- Locked sessions still require local approval for arbitrary file reads and high-risk commands.
- Unlocked sessions execute non-deletion commands automatically.
- File deletion always requires explicit local approval.
- New-file creation remains limited per session and repeated full-rate windows still terminate the session according to the user-configured threshold.
