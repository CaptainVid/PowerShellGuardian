# PowerShell Guardian 1.1.0

## New

- Per-session **Unlock / Lock Session** control. Only the selected active session can run non-deletion commands without repeated local approval.
- Open-padlock access indicator in the active-session table.
- File deletion always requires explicit local approval, including detected deletion inside PowerShell commands.
- Configurable per-session file creation limit (default: 5 files per 5 minutes).
- Automatic blocking until the active file window expires when the limit is reached.
- Configurable suspicious-activity guard. The default terminates an unlocked session after three consecutive full-rate creation windows restarted immediately after expiry.
- Audit entry listing the counted files when suspicious activity terminates a session.
- Safety blocking for bulk or unbounded file creation scripts that cannot be reliably counted.

## Compatibility

- Existing whitelist behavior and ordinary session approvals are unchanged.
- Existing five-field `sessions.dat` entries are loaded and migrated when next saved.
- Existing configuration remains valid; new safety settings use secure defaults when absent.
