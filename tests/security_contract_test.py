import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
whitelist = json.loads((ROOT / "config" / "whitelist.json").read_text(encoding="utf-8"))
security = json.loads((ROOT / "config" / "security.json").read_text(encoding="utf-8"))
source = (ROOT / "src" / "PowerShellGuardian.cpp").read_text(encoding="utf-8")
json_parser = (ROOT / "src" / "JsonLite.h").read_text(encoding="utf-8")

assert whitelist["default"] == "approval_required"
assert set(whitelist["allowed"]) == {"system_info", "get_status", "read_logs"}
assert {"execute_command", "powershell", "file_write", "install", "delete", "registry", "network_change"} <= set(whitelist["approval_required"])
assert security["zero_trust"] is True
assert security["listen_address"] == "127.0.0.1"
assert security["cleanup_choices_minutes"] == [30, 60, 720, 1440]
assert security["unattended_file_limit"] == 5
assert security["unattended_file_window_minutes"] == 5
assert security["suspicious_full_windows"] == 3
assert security["suspicious_guard_enabled"] is True
for required in ["CryptProtectData", "FindSessionToken", "RiskFor", "EMERGENCY LOCK", "MOMENTUM_BRIDGE_KEY", "INADDR_LOOPBACK"]:
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
assert "powershellguardian-solana-sdk" not in source
for exact_bridge in ["g_executablePath", "BridgeExecutablePath", "VerifyBridgeProtocol", "GetModuleFileNameW", "WM_MS_SETUP"]:
    assert exact_bridge in source, exact_bridge
assert 'PostMessageW(g_main,WM_MS_SETUP,0,0)' in source
for bridge_direct in ["MCP BRIDGE PREFLIGHT", "PowerShellGuardianPreflight", "MCP bridge initialize response PASS", "mcpCommand=TunnelStdioCommand(bridgeExecutable)", "PowerShellGuardianBridge.exe", "MOMENTUM_BRIDGE_CONSOLE", "Version 1.1.1"]:
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
for deletion_boundary in ["ContainsDeleteIntent", "if(deleteIntent){", "WAITING_LOCAL_DELETE_APPROVAL", "requires_local_approval", "File Deletion Approval", "Always requires explicit local approval"]:
    assert deletion_boundary in source, deletion_boundary
gateway_command = source.index('if(action=="command")')
delete_branch = source.index("if(deleteIntent){", gateway_command)
unattended_branch = source.index('if(risk=="LOW"||s->unattended)', gateway_command)
assert delete_branch < unattended_branch
for readable_dialog in ["const int width=700,height=190", "648,44", "MONITOR_DEFAULTTONEAREST", "SS_NOPREFIX"]:
    assert readable_dialog in source, readable_dialog
for file_safety in ["CanCreateFiles", "RecordCreatedFiles", "unattended_file_limit", "unattended_file_window_minutes", "suspicious_full_windows", "TERMINATED_SUSPICIOUS_ACTIVITY", "FILE RATE LIMIT", "AUTOMATIC SAFETY"]:
    assert file_safety in source, file_safety
for job_control in ["CreateTunnelJob", "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE", "AssignProcessToJobObject", "TerminateJobObject"]:
    assert job_control in source, job_control
installer = (ROOT / "installer" / "PowerShellGuardian.nsi").read_text(encoding="utf-8")
for full_removal in ['taskkill.exe /F /T /IM PowerShellGuardian.exe', 'RMDir /r "$0\\PowerShellGuardian"', 'RMDir /r "$APPDATA\\PowerShellGuardian"', 'RMDir /r "$LOCALAPPDATA\\PowerShellGuardian"']:
    assert full_removal in installer, full_removal
print("PowerShell Guardian security contract: PASS")
