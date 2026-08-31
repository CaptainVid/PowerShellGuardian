Unicode true
ManifestSupportedOS Win10
RequestExecutionLevel admin

!include "MUI2.nsh"
!include "x64.nsh"

!define PRODUCT "PowerShell Guardian"
!define VERSION "1.1.1"
Name "${PRODUCT} ${VERSION}"
OutFile "..\build\PowerShellGuardianSetup.exe"
InstallDir "$PROGRAMFILES64\PowerShellGuardian"
InstallDirRegKey HKLM "Software\PowerShellGuardian" "InstallDir"

!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\PowerShellGuardian.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Launch PowerShell Guardian and configure the API key"
!define MUI_UNCONFIRMPAGE_TEXT_TOP "Uninstall removes the application, service, shortcuts, local tunnel profiles, configuration, sessions, audit logs, Tunnel ID and DPAPI-protected API keys. This data cannot be recovered."
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\tunnel\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "PowerShell Guardian" SEC_MAIN
  SetRegView 64
  SetShellVarContext all
  SetOutPath "$INSTDIR"
  File "..\build\PowerShellGuardian.exe"
  File "..\build\PowerShellGuardianBridge.exe"
  File "..\README-SL.md"
  File "..\LICENSE"
  File "..\THIRD_PARTY_NOTICES.md"

  SetOutPath "$INSTDIR\tunnel"
  File "..\tunnel\tunnel-client.exe"
  File "..\tunnel\cloudflared.exe"
  File "..\tunnel\cloudflared-manifest.json"
  File "..\tunnel\LICENSE"

  SetOutPath "$INSTDIR\mcp"
  File "..\mcp\powershell-guardian.mcp.json"

  ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" "ProgramData"
  ExpandEnvStrings $0 $0
  StrCmp $0 "" 0 +2
    StrCpy $0 "$PROGRAMFILES64\..\ProgramData"
  CreateDirectory "$0\PowerShellGuardian\config"
  CreateDirectory "$0\PowerShellGuardian\logs"
  CreateDirectory "$0\PowerShellGuardian\data"
  CreateDirectory "$0\PowerShellGuardian\bin"
  CreateDirectory "$0\PowerShellGuardian\tunnel-client-config"
  SetOutPath "$0\PowerShellGuardian\config"
  IfFileExists "$0\PowerShellGuardian\config\whitelist.json" +2 0
    File "..\config\whitelist.json"
  IfFileExists "$0\PowerShellGuardian\config\security.json" +2 0
    File "..\config\security.json"
  IfFileExists "$0\PowerShellGuardian\config\tunnel.json" +2 0
    File "..\config\tunnel.json"

  WriteRegStr HKLM "Software\PowerShellGuardian" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\PowerShellGuardian" "DisplayName" "PowerShell Guardian"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\PowerShellGuardian" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\PowerShellGuardian" "Publisher" "PowerShellGuardian"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\PowerShellGuardian" "UninstallString" '"$INSTDIR\Uninstall.exe"'

  CreateDirectory "$SMPROGRAMS\PowerShell Guardian"
  CreateShortcut "$SMPROGRAMS\PowerShell Guardian\PowerShell Guardian.lnk" "$INSTDIR\PowerShellGuardian.exe"
  CreateShortcut "$DESKTOP\PowerShell Guardian.lnk" "$INSTDIR\PowerShellGuardian.exe"

  nsExec::ExecToLog 'sc.exe stop PowerShellGuardianGateway'
  nsExec::ExecToLog 'sc.exe delete PowerShellGuardianGateway'
  nsExec::ExecToLog 'sc.exe create PowerShellGuardianGateway binPath= "$\"$INSTDIR\PowerShellGuardian.exe$\" --service" start= demand DisplayName= "PowerShell Guardian Gateway"'
  nsExec::ExecToLog 'sc.exe description PowerShellGuardianGateway "Zero Trust local gateway. Headless mode blocks commands requiring local approval."'

  WriteUninstaller "$INSTDIR\Uninstall.exe"
SectionEnd

Section "Uninstall"
  SetRegView 64
  SetShellVarContext all
  nsExec::ExecToLog 'sc.exe stop PowerShellGuardianGateway'
  nsExec::ExecToLog 'sc.exe delete PowerShellGuardianGateway'
  nsExec::ExecToLog 'taskkill.exe /F /T /IM PowerShellGuardian.exe'
  nsExec::ExecToLog 'taskkill.exe /F /T /IM PowerShellGuardianBridge.exe'
  Sleep 1000

  ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" "ProgramData"
  ExpandEnvStrings $0 $0
  StrCmp $0 "" 0 +2
    StrCpy $0 "$PROGRAMFILES64\..\ProgramData"

  Delete "$SMSTARTUP\PowerShell Guardian.lnk"
  Delete "$DESKTOP\PowerShell Guardian.lnk"
  RMDir /r "$SMPROGRAMS\PowerShell Guardian"
  RMDir /r "$0\PowerShellGuardian"
  RMDir /r "$APPDATA\PowerShellGuardian"
  RMDir /r "$LOCALAPPDATA\PowerShellGuardian"
  RMDir /r "$INSTDIR"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\PowerShellGuardian"
  DeleteRegKey HKLM "Software\PowerShellGuardian"
  DeleteRegKey HKCU "Software\PowerShellGuardian"
SectionEnd
