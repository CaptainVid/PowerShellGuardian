# Security policy

PowerShell Guardian exposes local Windows administration through an MCP bridge. Treat every non-whitelisted request as untrusted until its full command text has been reviewed locally.

## Safe publication

Never commit or upload files copied from `C:\ProgramData\PowerShellGuardian`. They can contain DPAPI-protected API material, device-bound sessions, Tunnel IDs, profiles and audit logs. Do not publish diagnostic logs without reviewing them for session tokens and personal paths.

The repository `.gitignore` blocks the common secret and runtime filenames, but it does not replace manual review.

## Reporting

Do not post exploitable vulnerabilities or live credentials in a public issue. Revoke affected sessions and rotate the runtime API key before sharing a redacted report with the repository owner.
