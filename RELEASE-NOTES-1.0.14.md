# PowerShell Guardian 1.0.14

## Changes

- Whitelist entries mean automatic execution after session validation.
- Every valid non-whitelisted command is queued for explicit local approval instead of being rejected.
- Added the MCP tool `execute_command` for arbitrary PowerShell, including file creation and modification commands.
- PowerShell payloads use `-EncodedCommand`, so quotes, Unicode and multiline commands are transported without command-line corruption.
- Existing 1.0.13 whitelist files are migrated from `default: block` to `default: approval_required` while preserving the `allowed` list.
- HIGH commands immediately appear in Pending Command Center and open the local approval dialog.
- The tunnel process tree is assigned to a Windows Job Object and is terminated when PowerShell Guardian exits.
- Uninstall now removes the service, process tree, shortcuts, registry entries, local tunnel profiles, logs, sessions, Tunnel ID and DPAPI-protected keys.

## Connector refresh

Stop and restart PowerShell Guardian after upgrading. If ChatGPT still shows the old MCP tool list, delete and recreate the connector so that it performs a fresh `tools/list` discovery.

## Security note

`execute_command` is intentionally powerful. Leave it outside the `allowed` array unless you explicitly want unattended arbitrary PowerShell execution. The default configuration always requires local approval.
