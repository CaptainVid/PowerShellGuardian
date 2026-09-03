import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
whitelist = json.loads((ROOT / "config" / "whitelist.json").read_text(encoding="utf-8"))
security = json.loads((ROOT / "config" / "security.json").read_text(encoding="utf-8"))
source = (ROOT / "src" / "PowerShellGuardian.cpp").read_text(encoding="utf-8")
json_parser = (ROOT / "src" / "JsonLite.h").read_text(encoding="utf-8")

tool_list_match = re.search(r'static std::string ToolListJson\(\) \{\s*return R"JSON\((\{"tools":\[.*?\]\})\)JSON";', source, re.S)
assert tool_list_match, "MCP tool list JSON not found"
tool_names = {tool["name"] for tool in json.loads(tool_list_match.group(1))["tools"]}
assert {"new_session_request", "session_status", "read_path", "command_status"} <= tool_names

assert whitelist["default"] == "approval_required"
assert set(whitelist["allowed"]) == {"system_info", "get_status", "read_logs"}
assert {"read_path", "execute_command", "powershell", "file_write", "install", "delete", "registry", "network_change"} <= set(whitelist["approval_required"])
assert security["zero_trust"] is True
assert security["listen_address"] == "127.0.0.1"
assert security["cleanup_choices_minutes"] == [30, 60, 720, 1440]
assert security["session_request_limit"] == 10
assert security["session_request_window_minutes"] == 5
assert security["unattended_file_limit"] == 5
assert security["unattended_file_window_minutes"] == 5
assert security["suspicious_full_windows"] == 3
assert security["suspicious_guard_enabled"] is True
for required in ["CryptProtectData", "FindSessionToken", "RiskFor", "EMERGENCY LOCK", "POWERSHELL_GUARDIAN_BRIDGE_KEY", "INADDR_LOOPBACK"]:
    assert required in source, required
assert "execute_powershell(" not in source
assert "CRYPTPROTECT_LOCAL_MACHINE" not in source
assert "g_bridgeSecret.empty()" in source
assert "(HMENU)5001" in source
assert "NormalizeTunnelId" in source
assert "g_apiKey.size()<8" in source
for diagnostic in ['CheckTunnelEndpoint("/healthz",1)', 'CheckTunnelEndpoint("/readyz",1)', "tunnel-client.log", "STARTF_USESTDHANDLES", "g_tunnelReady"]:
    assert diagnostic in source, diagnostic
for client_discovery in ["FindTunnelClient", "ChooseTunnelClient", "tunnel_client_path", "GetOpenFileNameW", "SaveTunnelConfig"]:
    assert client_discovery in source, client_discovery
assert "solana-sdk" not in source
for exact_bridge in ["g_executablePath", "BridgeExecutablePath", "VerifyBridgeProtocol", "GetModuleFileNameW", "WM_MS_SETUP"]:
    assert exact_bridge in source, exact_bridge
assert 'PostMessageW(g_main,WM_MS_SETUP,0,0)' in source
for bridge_direct in ["MCP BRIDGE PREFLIGHT", "PowerShellGuardianPreflight", "MCP bridge initialize response PASS", "mcpCommand=TunnelStdioCommand(bridgeExecutable)", "PowerShellGuardianBridge.exe", "POWERSHELL_GUARDIAN_BRIDGE_CONSOLE", "Version 1.1.4"]:
    assert bridge_direct in source, bridge_direct
assert "PrepareBridgeLauncher" not in source
assert "StartPowerShellGuardianBridge.ps1" not in source
for tunnel_persistence in ['SaveSecret(L"tunnel.id"', 'LoadSecret(L"tunnel.id")', "saved and verified"]:
    assert tunnel_persistence in source, tunnel_persistence
for persistent_stdin in ["g_tunnelStdinWrite", "CreatePipe", "SetHandleInformation", "Persistent stdin: enabled", "tunnel-client exit code"]:
    assert persistent_stdin in source, persistent_stdin
for profile_startup in ["init --force", "sample_mcp_stdio_local", "PROFILE INIT", "PROFILE DOCTOR", "doctor --profile", "run --profile", "TUNNEL_CLIENT_PROFILE_DIR", "XDG_CONFIG_HOME", "tunnel-client-config", "Profile saved and doctor preflight passed"]:
    assert profile_startup in source, profile_startup
for safe_windows_path in ["TunnelStdioCommand", "std::replace(executablePath.begin(),executablePath.end(),L'\\\\',L'/')", 'return L"\\\""+executablePath+L"\\\""']:
    assert safe_windows_path in source, safe_windows_path
assert "--control-plane.tunnel-id=" not in source
assert "--mcp.command=" not in source
assert 'CreateFileW(L"NUL"' not in source
assert 'StopTunnel("START FAILED")' not in source
assert 'CheckTunnelEndpoint("/readyz",60)' not in source
for readiness in ["RUNNING - READINESS PENDING", "MCP Server: ", 'L"Connecting"', "non-destructive background polling"]:
    assert readiness in source, readiness
for scoped_json in ['RawField(line,"params",params)', 'StringField(params,"name",name)', 'RawField(params,"arguments",arguments)', 'ScalarField(j,key)']:
    assert scoped_json in source, scoped_json
for parser_contract in ["ParseString", "SkipValue", "RawField", "StringField", "ScalarField"]:
    assert parser_contract in json_parser, parser_contract
assert 'JsonGet(line,"name")' not in source
assert "case WM_MS_COMMAND:PromptNewestCommand()" in source
assert 'return "BLOCKED"' not in source
assert "command blocked by whitelist" not in source
assert 'return std::find(g_autoApprovedCommands.begin(),g_autoApprovedCommands.end(),name)!=g_autoApprovedCommands.end()?"LOW":"HIGH"' in source
for arbitrary_command in ['{"name":"execute_command"', 'name=="execute_command"', 'JsonGet(arguments,"command")']:
    assert arbitrary_command in source, arbitrary_command
assert "-EncodedCommand" in source
for session_unlock in ["ID_TOGGLE_UNATTENDED", "Unlock / Lock Session", "s.unattended", "SESSION AUTO", "\\U0001F513 Unlocked"]:
    assert session_unlock in source, session_unlock
for stable_token in ["RandomSessionToken", "FindSessionTokenAnyState", "NormalizeSessionToken", "TouchSession", "device.binding", '\\"access_mode\\":', '\\"unlock_required\\":false', '\\"token_rotated\\":false', "same token preserved"]:
    assert stable_token in source, stable_token
assert "INVALID_SESSION_TOKEN" in source
assert "SESSION_EXPIRED" in source
assert "SESSION_REVOKED" in source
assert "session->token=RandomSessionToken()" in source
assert "s.unattended=unlocking;TouchSession(s);ResetFileSafetyState(s)" in source
assert "JsonEscape(s.token)" in source
assert "tokenDelivered" not in source
assert "token_already_delivered" not in source
for read_path in ['{"name":"read_path"', 'if(c.name=="read_path")', 'else if(name=="read_path")', "This tool never consumes the file-creation quota"]:
    assert read_path in source, read_path
assert "NormalizeTextEncoding(output)" in source
for hang_guard in ["PeekNamedPipe", "RunAutomaticCommand", "next_action", "GATEWAY_SOCKET_TIMEOUT_MS", "HandleGatewayClient", "std::thread([c]", "StopActiveCommands", "g_shutdownCv"]:
    assert hang_guard in source, hang_guard
assert "POWERSHELL_TIMEOUT_MS" not in source
assert "PowerShell timed out after" not in source
assert "PotentialNewFiles(detectedFiles)" in source
assert "g_fileExecutionMutex" in source and "fileExecution.lock()" in source
assert "bool applyFileGuard=s->unattended" in source
for deletion_boundary in ["ContainsDeleteIntent", "if(deleteIntent){", "WAITING_LOCAL_DELETE_APPROVAL", "requires_local_approval", "File Deletion Approval", "Always requires explicit local approval"]:
    assert deletion_boundary in source, deletion_boundary
gateway_command = source.index('if(action=="command")')
delete_branch = source.index("if(deleteIntent){", gateway_command)
unattended_branch = source.index('if(risk=="LOW"||s->unattended)', gateway_command)
assert delete_branch < unattended_branch
for readable_dialog in ["const int width=700,height=190", "648,44", "MONITOR_DEFAULTTONEAREST", "SS_NOPREFIX"]:
    assert readable_dialog in source, readable_dialog
for file_safety in ["CanCreateFiles", "RecordCreatedFiles", "unattended_file_limit", "unattended_file_window_minutes", "suspicious_full_windows", "TERMINATED_SUSPICIOUS_ACTIVITY", "FILE RATE LIMIT", "UNLOCKED -> TERMINATED_SUSPICIOUS_ACTIVITY"]:
    assert file_safety in source, file_safety
for deterministic_window in ["long long elapsed=(now-s.fileWindowStart)/seconds", "!previousFull||elapsed>1", "s.fullWindowStreak++", "ResetFileSafetyState"]:
    assert deterministic_window in source, deterministic_window
assert "FILE_BURST_RESTART_GRACE_SECONDS" not in source
assert "windowContinuesBurst" not in source
for state_safety in ["FindSessionIdUnsafe", "FindCommandIdUnsafe", "NEW -> WAITING_APPROVAL", "WAITING_APPROVAL -> LOCKED", "LOCKED -> UNLOCKED", "UNLOCKED -> LOCKED"]:
    assert state_safety in source, state_safety
for admission_guard in ["session_request_limit", "session_request_window_minutes", "SESSION_RATE_LIMIT"]:
    assert admission_guard in source, admission_guard
assert "for(int attempt=0;attempt<250&&!g_serverRunning;attempt++)" in source
assert "ERROR: PowerShell exit code" in source
assert "g_auditMutex" in source
for command_cleanup in ["ID_CLEAR_FINISHED", "Clear Success/Rejected", "ClearFinishedCommands", 'command.status=="SUCCESS"||command.status=="REJECTED"']:
    assert command_cleanup in source, command_cleanup
clear_function = source[source.index("static void ClearFinishedCommands"):source.index("static void ToggleSelectedSessionAccess")]
assert 'command.status=="WAITING APPROVAL"' not in clear_function
assert 'command.status=="RUNNING"' not in clear_function
for job_control in ["CreateTunnelJob", "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE", "AssignProcessToJobObject", "TerminateJobObject"]:
    assert job_control in source, job_control
installer = (ROOT / "installer" / "PowerShellGuardian.nsi").read_text(encoding="utf-8")
for full_removal in ['taskkill.exe /F /T /IM PowerShellGuardian.exe', 'RMDir /r "$0\\PowerShellGuardian"', 'RMDir /r "$APPDATA\\PowerShellGuardian"', 'RMDir /r "$LOCALAPPDATA\\PowerShellGuardian"']:
    assert full_removal in installer, full_removal
for rename_upgrade in ['sc.exe delete MomentumSecureGateway', 'taskkill.exe /F /T /IM MomentumSecure.exe', 'Rename "$0\\MomentumSecure" "$0\\PowerShellGuardian"']:
    assert rename_upgrade in installer, rename_upgrade
print("PowerShell Guardian security contract: PASS")
