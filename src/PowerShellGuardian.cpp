#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <commctrl.h>
#include <commdlg.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <shellapi.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <climits>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <cwctype>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "JsonLite.h"

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#endif

static const wchar_t* APP_VERSION = L"1.1.4";
static const wchar_t* APP_NAME = L"PowerShell Guardian Control Center 1.1.4";
static const UINT WM_MS_SESSION = WM_APP + 1;
static const UINT WM_MS_COMMAND = WM_APP + 2;
static const UINT WM_MS_REFRESH = WM_APP + 3;
static const UINT WM_MS_SETUP = WM_APP + 4;
static const int GATEWAY_PORT = 17654;

enum ControlId {
  ID_START=1001, ID_STOP, ID_RESTART, ID_TUNNEL_ID, ID_API_KEY,
  ID_DELETE_SESSION, ID_DELETE_ALL, ID_APPROVE, ID_REJECT,
  ID_TOGGLE_UNATTENDED, ID_SECURITY, ID_LOGS, ID_EMERGENCY, ID_CLEAR_FINISHED,
  ID_SESSION_LIST=1101, ID_COMMAND_LIST, ID_STATUS_TUNNEL, ID_STATUS_MCP,
  ID_STATUS_GATEWAY, ID_STATUS_SESSIONS, ID_STATUS_PENDING
};

struct Session {
  std::string id, code, token, tokenHash, deviceHash;
  long long created=0, lastActive=0, expires=0;
  bool approved=false, denied=false;
  bool unattended=false, suspiciousTerminated=false;
  long long fileWindowStart=0;
  int fileWindowCount=0, fullWindowStreak=0;
  std::vector<std::string> burstFiles;
};

struct PendingCommand {
  std::string id, sessionId, name, payload, risk="HIGH", status="WAITING APPROVAL", result;
  long long created=0;
};

static HINSTANCE g_instance=nullptr;
static HWND g_main=nullptr, g_sessions=nullptr, g_commands=nullptr;
static HWND g_tunnelStatus=nullptr, g_mcpStatus=nullptr, g_gatewayStatus=nullptr;
static HWND g_sessionCount=nullptr, g_pendingCount=nullptr;
static std::mutex g_mutex;
static std::mutex g_fileExecutionMutex;
static std::mutex g_auditMutex;
static std::mutex g_commandProcessMutex;
static std::mutex g_shutdownMutex;
static std::condition_variable g_shutdownCv;
static std::vector<Session> g_sessionData;
static std::vector<PendingCommand> g_commandData;
static std::vector<long long> g_sessionRequestTimes;
static std::vector<HANDLE> g_commandProcesses;
static std::atomic<bool> g_serverRunning{false}, g_emergency{false}, g_tunnelReady{false};
static HANDLE g_tunnelProcess=nullptr;
static HANDLE g_tunnelStdinWrite=nullptr;
static HANDLE g_tunnelJob=nullptr;
static DWORD g_tunnelPid=0;
static std::wstring g_base, g_install, g_executablePath, g_bridgeSecret, g_apiKey, g_tunnelId, g_tunnelClientPath;
static std::string g_deviceHash;
static int g_timeoutMinutes=60;
static int g_fileLimit=5, g_fileWindowMinutes=5, g_suspiciousFullWindows=3;
static int g_sessionRequestLimit=10, g_sessionRequestWindowMinutes=5;
static bool g_suspiciousGuardEnabled=true;
static const DWORD GATEWAY_SOCKET_TIMEOUT_MS=30000;
static const size_t COMMAND_OUTPUT_LIMIT=200000;
static std::vector<std::string> g_autoApprovedCommands={"system_info","get_status","read_logs"};
static bool g_headless=false;
static SERVICE_STATUS_HANDLE g_serviceHandle=nullptr;
static SERVICE_STATUS g_serviceStatus{};

static long long Now() {
  return std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::wstring Utf8ToWide(const std::string& s) {
  if (s.empty()) return L"";
  int n=MultiByteToWideChar(CP_UTF8,0,s.data(),(int)s.size(),nullptr,0);
  std::wstring out(n,0); MultiByteToWideChar(CP_UTF8,0,s.data(),(int)s.size(),out.data(),n); return out;
}

static std::string WideToUtf8(const std::wstring& s) {
  if (s.empty()) return "";
  int n=WideCharToMultiByte(CP_UTF8,0,s.data(),(int)s.size(),nullptr,0,nullptr,nullptr);
  std::string out(n,0); WideCharToMultiByte(CP_UTF8,0,s.data(),(int)s.size(),out.data(),n,nullptr,nullptr); return out;
}

static bool IsValidUtf8(const std::string& value){
  for(size_t i=0;i<value.size();){unsigned char first=(unsigned char)value[i];size_t count=first<0x80?1:(first&0xe0)==0xc0?2:(first&0xf0)==0xe0?3:(first&0xf8)==0xf0?4:0;if(!count||i+count>value.size())return false;
    if(count==2&&first<0xc2)return false;
    if(count==4&&first>0xf4)return false;
    for(size_t j=1;j<count;j++)if(((unsigned char)value[i+j]&0xc0)!=0x80)return false;
    if(count==3){unsigned char second=(unsigned char)value[i+1];if((first==0xe0&&second<0xa0)||(first==0xed&&second>=0xa0))return false;}
    if(count==4){unsigned char second=(unsigned char)value[i+1];if((first==0xf0&&second<0x90)||(first==0xf4&&second>=0x90))return false;}i+=count;
  }return true;
}

static std::string NormalizeTextEncoding(const std::string& value){
  if(value.size()>=3&&(unsigned char)value[0]==0xef&&(unsigned char)value[1]==0xbb&&(unsigned char)value[2]==0xbf)return value.substr(3);
  if(value.size()>=2&&(((unsigned char)value[0]==0xff&&(unsigned char)value[1]==0xfe)||((unsigned char)value[0]==0xfe&&(unsigned char)value[1]==0xff))){
    bool little=(unsigned char)value[0]==0xff;std::wstring wide;wide.reserve((value.size()-2)/2);for(size_t i=2;i+1<value.size();i+=2){unsigned char a=(unsigned char)value[i],b=(unsigned char)value[i+1];wide.push_back((wchar_t)(little?(a|(b<<8)):(b|(a<<8))));}return WideToUtf8(wide);
  }
  if(IsValidUtf8(value))return value;
  if(value.empty())return value;
  int count=MultiByteToWideChar(CP_ACP,0,value.data(),(int)value.size(),nullptr,0);if(count<=0)return "[PowerShell Guardian: output encoding could not be decoded]";
  std::wstring wide(count,0);MultiByteToWideChar(CP_ACP,0,value.data(),(int)value.size(),wide.data(),count);return WideToUtf8(wide);
}

static std::string JsonEscape(const std::string& s) {
  std::ostringstream o;
  for (unsigned char c: s) {
    switch(c) { case '"':o<<"\\\"";break; case '\\':o<<"\\\\";break;
      case '\n':o<<"\\n";break; case '\r':o<<"\\r";break; case '\t':o<<"\\t";break;
      default: if(c<32) o<<"\\u"<<std::hex<<std::setw(4)<<std::setfill('0')<<(int)c<<std::dec; else o<<c; }
  } return o.str();
}

static std::string JsonGet(const std::string& j,const std::string& key) {
  return powershell_guardian_json::ScalarField(j,key);
}

static bool JsonBool(const std::string& j,const std::string& key,bool fallback=false) {
  std::string x=JsonGet(j,key); if(x=="true")return true; if(x=="false")return false; return fallback;
}

static std::string ReadFileUtf8(const std::wstring& path) {
  std::ifstream f(path.c_str(),std::ios::binary); if(!f)return "";
  return std::string((std::istreambuf_iterator<char>(f)),std::istreambuf_iterator<char>());
}

static bool WriteFileUtf8(const std::wstring& path,const std::string& data) {
  std::ofstream f(path.c_str(),std::ios::binary|std::ios::trunc); if(!f)return false; f.write(data.data(),data.size()); return !!f;
}

static bool AppendFileUtf8(const std::wstring& path,const std::string& data) {
  std::ofstream f(path.c_str(),std::ios::binary|std::ios::app);if(!f)return false;f.write(data.data(),data.size());return !!f;
}

static std::string Hex(const BYTE* p,DWORD n) {
  static const char* h="0123456789abcdef"; std::string s; s.reserve(n*2);
  for(DWORD i=0;i<n;i++){s+=h[p[i]>>4];s+=h[p[i]&15];}return s;
}

static std::vector<BYTE> Unhex(const std::string& s) {
  std::vector<BYTE> v; if(s.size()%2)return v; v.reserve(s.size()/2);
  auto val=[](char c)->int{return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:-1;};
  for(size_t i=0;i<s.size();i+=2){int a=val(s[i]),b=val(s[i+1]);if(a<0||b<0){v.clear();return v;}v.push_back((BYTE)((a<<4)|b));}return v;
}

static std::string Sha256(const std::string& value) {
  BCRYPT_ALG_HANDLE alg=nullptr; BCRYPT_HASH_HANDLE hash=nullptr; DWORD objLen=0,cb=0;
  std::vector<BYTE> obj, out(32); std::string result;
  if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0)return result;
  BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,(PUCHAR)&objLen,sizeof(objLen),&cb,0); obj.resize(objLen);
  if(BCryptCreateHash(alg,&hash,obj.data(),objLen,nullptr,0,0)>=0 &&
     BCryptHashData(hash,(PUCHAR)value.data(),(ULONG)value.size(),0)>=0 &&
     BCryptFinishHash(hash,out.data(),(ULONG)out.size(),0)>=0) result=Hex(out.data(),(DWORD)out.size());
  if(hash)BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(alg,0);
  return result;
}

static std::string RandomToken(size_t bytes=32) {
  std::vector<BYTE> b(bytes); if(BCryptGenRandom(nullptr,b.data(),(ULONG)b.size(),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)return "";
  DWORD n=0; CryptBinaryToStringA(b.data(),(DWORD)b.size(),CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,nullptr,&n);
  std::string s(n,0); CryptBinaryToStringA(b.data(),(DWORD)b.size(),CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,s.data(),&n);
  if(!s.empty()&&s.back()==0)s.pop_back();
  return s;
}

static std::string RandomSessionToken() {
  std::vector<BYTE> bytes(32);
  if(BCryptGenRandom(nullptr,bytes.data(),(ULONG)bytes.size(),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)return "";
  return Hex(bytes.data(),(DWORD)bytes.size());
}

static std::string Base64(const BYTE* data,DWORD size){
  DWORD chars=0;if(!CryptBinaryToStringA(data,size,CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,nullptr,&chars))return "";
  std::string encoded(chars,0);if(!CryptBinaryToStringA(data,size,CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,encoded.data(),&chars))return "";
  if(!encoded.empty()&&encoded.back()==0)encoded.pop_back();
  return encoded;
}

static std::string Protect(const std::string& plain) {
  DATA_BLOB in{(DWORD)plain.size(),(BYTE*)plain.data()},out{};
  if(!CryptProtectData(&in,L"PowerShellGuardian",nullptr,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&out))return "";
  std::string h=Hex(out.pbData,out.cbData); LocalFree(out.pbData); return h;
}

static std::string Unprotect(const std::string& cipherHex) {
  auto b=Unhex(cipherHex); if(b.empty())return ""; DATA_BLOB in{(DWORD)b.size(),b.data()},out{};
  if(!CryptUnprotectData(&in,nullptr,nullptr,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&out))return "";
  std::string s((char*)out.pbData,out.cbData); LocalFree(out.pbData); return s;
}

static std::string Timestamp() {
  SYSTEMTIME st; GetLocalTime(&st); char b[64];
  snprintf(b,sizeof(b),"%04d-%02d-%02d %02d:%02d:%02d",st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond); return b;
}

static void EnsureDirs() {
  SHCreateDirectoryExW(nullptr,g_base.c_str(),nullptr);
  for(auto d:{L"config",L"logs",L"data",L"bin",L"tunnel-client-config"}) SHCreateDirectoryExW(nullptr,(g_base+L"\\"+d).c_str(),nullptr);
}

static void Audit(const std::string& session,const std::string& command,const std::string& decision,const std::string& result) {
  std::lock_guard<std::mutex> lock(g_auditMutex);std::wstring path=g_base+L"\\logs\\audit.jsonl"; std::ofstream f(path.c_str(),std::ios::binary|std::ios::app);
  if(f) f<<"{\"timestamp\":\""<<Timestamp()<<"\",\"session_id\":\""<<JsonEscape(session)
    <<"\",\"command\":\""<<JsonEscape(command)<<"\",\"user_decision\":\""<<JsonEscape(decision)
    <<"\",\"result\":\""<<JsonEscape(result)<<"\"}\n";
}

static std::string ComputeDeviceHash() {
  HKEY key=nullptr;wchar_t value[256]={};DWORD size=sizeof(value),type=0;std::wstring id;
  if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Cryptography",0,KEY_READ|KEY_WOW64_64KEY,&key)==ERROR_SUCCESS){
    if(RegQueryValueExW(key,L"MachineGuid",nullptr,&type,(BYTE*)value,&size)==ERROR_SUCCESS)id=value;
    RegCloseKey(key);
  }
  wchar_t name[256]={};DWORD length=256;if(GetComputerNameW(name,&length)){id+=L"|";id+=name;}
  return Sha256(WideToUtf8(id));
}

static std::string DeviceHash(){return g_deviceHash.empty()?ComputeDeviceHash():g_deviceHash;}

static bool SaveSecret(const wchar_t* name,const std::wstring& value) {
  std::string protectedValue=Protect(WideToUtf8(value));return !protectedValue.empty()&&WriteFileUtf8(g_base+L"\\config\\"+name,protectedValue);
}

static std::wstring LoadSecret(const wchar_t* name) {
  return Utf8ToWide(Unprotect(ReadFileUtf8(g_base+L"\\config\\"+name)));
}

static void SaveSessions() {
  std::wstring path=g_base+L"\\data\\sessions.dat"; std::ofstream f(path.c_str(),std::ios::binary|std::ios::trunc); if(!f)return;
  for(auto& s:g_sessionData) if(s.approved&&s.expires>Now()){
    std::ostringstream files;for(size_t i=0;i<s.burstFiles.size();++i){if(i)files<<'\n';files<<s.burstFiles[i];}
    f<<s.id<<'|'<<s.created<<'|'<<s.lastActive<<'|'<<s.expires<<'|'<<Protect(s.token+"|"+s.deviceHash)
      <<'|'<<(s.unattended?1:0)<<'|'<<(s.denied?1:0)<<'|'<<(s.suspiciousTerminated?1:0)
      <<'|'<<s.fileWindowStart<<'|'<<s.fileWindowCount<<'|'<<s.fullWindowStreak
      <<'|'<<0<<'|'<<Protect(files.str())<<"\n";
  }
}

static void LoadSessions() {
  std::wstring path=g_base+L"\\data\\sessions.dat"; std::ifstream f(path.c_str(),std::ios::binary); std::string line;
  while(std::getline(f,line)){std::vector<std::string>x;size_t p=0,q;
    while((q=line.find('|',p))!=std::string::npos){x.push_back(line.substr(p,q-p));p=q+1;}x.push_back(line.substr(p));
    if(x.size()!=5&&x.size()!=13)continue;
    std::string secret=Unprotect(x[4]);size_t z=secret.rfind('|');if(z==std::string::npos)continue;
    Session s;s.id=x[0];s.created=_strtoi64(x[1].c_str(),nullptr,10);s.lastActive=_strtoi64(x[2].c_str(),nullptr,10);
    s.expires=_strtoi64(x[3].c_str(),nullptr,10);s.token=secret.substr(0,z);s.deviceHash=secret.substr(z+1);
    s.tokenHash=Sha256(s.token+"|"+s.deviceHash);s.approved=true;
    if(x.size()==13){
      s.unattended=x[5]=="1";s.denied=x[6]=="1";s.suspiciousTerminated=x[7]=="1";
      s.fileWindowStart=_strtoi64(x[8].c_str(),nullptr,10);s.fileWindowCount=atoi(x[9].c_str());s.fullWindowStreak=atoi(x[10].c_str());
      std::string files=Unprotect(x[12]);size_t start=0,end;while((end=files.find('\n',start))!=std::string::npos){s.burstFiles.push_back(files.substr(start,end-start));start=end+1;}if(start<files.size())s.burstFiles.push_back(files.substr(start));
    }
    if(s.expires>Now()&&s.deviceHash==DeviceHash())g_sessionData.push_back(s);
  }
}

static bool ConstantEqual(const std::string&a,const std::string&b){
  if(a.size()!=b.size())return false;
  unsigned char d=0;for(size_t i=0;i<a.size();++i)d|=(unsigned char)(a[i]^b[i]);return d==0;
}

static std::string NormalizeSessionToken(std::string token){
  while(!token.empty()&&std::isspace((unsigned char)token.front()))token.erase(token.begin());
  while(!token.empty()&&std::isspace((unsigned char)token.back()))token.pop_back();
  if(token.size()>1&&((token.front()=='"'&&token.back()=='"')||(token.front()=='`'&&token.back()=='`')))token=token.substr(1,token.size()-2);
  return token;
}

static Session* FindSessionTokenAnyState(const std::string& suppliedToken) {
  std::string token=NormalizeSessionToken(suppliedToken),dev=DeviceHash(),hash=Sha256(token+"|"+dev);
  for(auto& session:g_sessionData)if(session.approved&&session.deviceHash==dev&&ConstantEqual(session.tokenHash,hash))return &session;
  return nullptr;
}

static Session* FindSessionToken(const std::string& token) {
  Session* session=FindSessionTokenAnyState(token);
  if(session&&!session->denied&&session->expires>Now())return session;
  return nullptr;
}

static std::string SessionTokenFailure(const Session* session){
  if(!session)return "{\"ok\":false,\"status\":\"INVALID_SESSION_TOKEN\",\"error\":\"session token does not match an approved session; retry session_status with the original session_id\"}";
  if(session->denied)return "{\"ok\":false,\"status\":\"SESSION_REVOKED\",\"error\":\"session was revoked; unlocking cannot restore a revoked session\"}";
  return "{\"ok\":false,\"status\":\"SESSION_EXPIRED\",\"error\":\"session expired due to inactivity; request and approve a new session\"}";
}

static void TouchSession(Session& session){session.lastActive=Now();session.expires=session.lastActive+(long long)g_timeoutMinutes*60;}

static std::string NewId(const char* prefix) {
  std::string t=RandomToken(8); for(char&c:t)if(!isalnum((unsigned char)c))c='X'; return std::string(prefix)+t.substr(0,10);
}

static bool ValidCommandName(const std::string& name){
  return !name.empty()&&name.size()<=64&&std::all_of(name.begin(),name.end(),[](unsigned char c){return std::isalnum(c)||c=='_'||c=='-';});
}

static bool KnownCommandName(const std::string& name){
  static const std::vector<std::string> names={"system_info","get_status","read_logs","read_path","execute_command","powershell","file_write","delete","install","registry","network_change"};
  return std::find(names.begin(),names.end(),name)!=names.end();
}

static void LoadWhitelist(){
  std::vector<std::string> configured;
  std::string json=ReadFileUtf8(g_base+L"\\config\\whitelist.json");
    if(powershell_guardian_json::StringArrayField(json,"allowed",configured)){
    configured.erase(std::remove_if(configured.begin(),configured.end(),[](const std::string& name){return !ValidCommandName(name);}),configured.end());
    g_autoApprovedCommands=configured;
  }
  if(JsonGet(json,"default")!="approval_required"){
    std::ostringstream migrated;migrated<<"{\n  \"allowed\": [";
    for(size_t i=0;i<g_autoApprovedCommands.size();++i){if(i)migrated<<", ";migrated<<"\""<<JsonEscape(g_autoApprovedCommands[i])<<"\"";}
    migrated<<"],\n  \"approval_required\": [\"read_path\", \"execute_command\", \"powershell\", \"file_write\", \"install\", \"delete\", \"registry\", \"network_change\"],\n  \"default\": \"approval_required\"\n}\n";
    WriteFileUtf8(g_base+L"\\config\\whitelist.json",migrated.str());
  }
}

static std::string RiskFor(const std::string& name) {
  return std::find(g_autoApprovedCommands.begin(),g_autoApprovedCommands.end(),name)!=g_autoApprovedCommands.end()?"LOW":"HIGH";
}

static std::string LowerAscii(std::string value){
  std::transform(value.begin(),value.end(),value.begin(),[](unsigned char c){return (char)std::tolower(c);});return value;
}

static bool ContainsDeleteIntent(const std::string& name,const std::string& payload){
  if(name=="delete")return true;
  if(name!="execute_command"&&name!="powershell"&&name!="install"&&name!="registry"&&name!="network_change")return false;
  static const std::regex deletePattern(
    R"((^|[\s;&|])(remove-item|del|erase|rmdir|rd|rm|ri|unlink|shred)(?=$|[\s;&|])|\[?(system\.)?io\.(file|directory)\]?::delete\s*\(|cmd(\.exe)?\s+/c\s+(del|erase|rd|rmdir)(?=$|[\s;&|])|\.delete\s*\(|os\.(remove|unlink)\s*\(|shutil\.rmtree\s*\(|-encodedcommand(?=$|[\s;&|]))",
    std::regex_constants::icase);
  return std::regex_search(payload,deletePattern);
}

static std::string ExtractPathNear(const std::string& script,size_t position,const std::string& command,int ordinal){
  std::string segment=script.substr(position,std::min<size_t>(320,script.size()-position));
  static const std::regex flagged(R"REGEX(-(destination|filepath|literalpath|path)\s+(?:"([^"]+)"|'([^']+)'|([^\s;|]+)))REGEX",std::regex_constants::icase);
  static const std::regex quoted(R"REGEX((?:"([^"]+)"|'([^']+)'))REGEX");std::smatch match;
  if(std::regex_search(segment,match,flagged)){for(int i=2;i<=4;i++)if(match[i].matched)return match[i].str();}
  if(std::regex_search(segment,match,quoted)){for(int i=1;i<=2;i++)if(match[i].matched)return match[i].str();}
  return command+" #"+std::to_string(ordinal)+" (path not parsed)";
}

static std::vector<std::string> DetectCreatedFiles(const std::string& name,const std::string& payload,bool& ambiguousBulk){
  ambiguousBulk=false;std::vector<std::string> files;
  if(name=="file_write"){std::string path=JsonGet(payload,"path");if(!path.empty())files.push_back(path);return files;}
  if(name!="execute_command"&&name!="powershell"&&name!="install")return files;
  std::string lower=LowerAscii(payload);
  const std::vector<std::string> commands={"new-item","set-content","add-content","out-file","tee-object","export-csv","export-clixml","copy-item","move-item","writealltext","writeallbytes","create(","invoke-webrequest","start-bitstransfer","expand-archive"};
  int ordinal=0;for(const auto& command:commands){size_t position=0;while((position=lower.find(command,position))!=std::string::npos){files.push_back(ExtractPathNear(payload,position,command,++ordinal));position+=command.size();}}
  for(size_t position=0;(position=payload.find('>',position))!=std::string::npos;){size_t cursor=position+1;if(cursor<payload.size()&&payload[cursor]=='>')cursor++;while(cursor<payload.size()&&std::isspace((unsigned char)payload[cursor]))cursor++;if(cursor>=payload.size()||payload[cursor]=='&'){position=cursor;continue;}char quote=(payload[cursor]=='\''||payload[cursor]=='"')?payload[cursor++]:0;size_t start=cursor;while(cursor<payload.size()&&(quote?payload[cursor]!=quote:!std::isspace((unsigned char)payload[cursor])&&payload[cursor]!=';'&&payload[cursor]!='|'))cursor++;std::string path=payload.substr(start,cursor-start);files.push_back(path.empty()?"redirection #"+std::to_string(++ordinal)+" (path not parsed)":path);position=cursor;}
  if(!files.empty()){
    const std::vector<std::string> bulkMarkers={"foreach","for(","for (","while(","while (","1..","get-childitem"," -recurse","*.*","expand-archive","tar ","7z ","git clone","npm install"};
    ambiguousBulk=std::any_of(bulkMarkers.begin(),bulkMarkers.end(),[&](const std::string& marker){return lower.find(marker)!=std::string::npos;});
  }
  return files;
}

static std::vector<std::string> PotentialNewFiles(const std::vector<std::string>& detected){
  std::vector<std::string> files;for(const auto& path:detected){
    DWORD attributes=path.find("(path not parsed)")!=std::string::npos?INVALID_FILE_ATTRIBUTES:GetFileAttributesW(Utf8ToWide(path).c_str());
    if(attributes!=INVALID_FILE_ATTRIBUTES)continue;
    if(std::find(files.begin(),files.end(),path)==files.end())files.push_back(path);
  }return files;
}

static void RejectWaitingCommandsUnsafe(const std::string& sessionId,const std::string& reason);

static void RotateFileWindow(Session& s,long long now){
  long long seconds=(long long)g_fileWindowMinutes*60;
  if(s.fileWindowStart<=0){s.fileWindowStart=now;s.fileWindowCount=0;return;}
  if(now<s.fileWindowStart+seconds)return;
  long long elapsed=(now-s.fileWindowStart)/seconds;bool previousFull=s.fileWindowCount>=g_fileLimit;
  if(!previousFull||elapsed>1){s.fullWindowStreak=0;s.burstFiles.clear();}
  s.fileWindowStart+=elapsed*seconds;s.fileWindowCount=0;
}

static void ResetFileSafetyState(Session& s){s.fileWindowStart=0;s.fileWindowCount=0;s.fullWindowStreak=0;s.burstFiles.clear();}

static bool CanCreateFiles(Session& s,int requested,long long now,std::string& reason,int& retryAfter){
  retryAfter=0;if(requested<=0)return true;RotateFileWindow(s,now);
  if(requested>g_fileLimit){reason="BLOCKED: one command requests more files than the configured limit";return false;}
  if(s.fileWindowCount+requested<=g_fileLimit)return true;
  retryAfter=(int)std::max(1LL,s.fileWindowStart+(long long)g_fileWindowMinutes*60-now);
  reason="BLOCKED: file creation limit reached; retry after "+std::to_string(retryAfter)+" seconds";return false;
}

static std::string FileAuditSummary(const Session& s){
  std::ostringstream out;out<<"created "<<s.burstFiles.size()<<" files: ";
  for(size_t i=0;i<s.burstFiles.size();++i){if(i)out<<", ";out<<s.burstFiles[i];if(out.tellp()>3500){out<<" ...";break;}}
  return out.str();
}

static bool RecordCreatedFiles(Session& s,const std::vector<std::string>& files,long long now){
  if(files.empty())return false;
  RotateFileWindow(s,now);
  s.fileWindowCount+=(int)files.size();
  s.burstFiles.insert(s.burstFiles.end(),files.begin(),files.end());
  Audit(s.id,"FILE CREATION","SESSION AUTO",FileAuditSummary(s));
  if(s.fileWindowCount<g_fileLimit)return false;
  s.fullWindowStreak++;
  if(!g_suspiciousGuardEnabled||s.fullWindowStreak<g_suspiciousFullWindows)return false;
  s.unattended=false;
  s.denied=true;
  s.suspiciousTerminated=true;
  RejectWaitingCommandsUnsafe(s.id,"Session terminated due to repeated full file-creation windows");
  Audit(s.id,"SESSION TRANSITION","UNLOCKED -> TERMINATED_SUSPICIOUS_ACTIVITY",FileAuditSummary(s));
  return true;
}

static std::string RunPowerShell(const std::string& script) {
  if(script.empty())return "ERROR: missing command";
  SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE}; HANDLE rd=nullptr,wr=nullptr;
  if(!CreatePipe(&rd,&wr,&sa,0))return "ERROR: CreatePipe";
  SetHandleInformation(rd,HANDLE_FLAG_INHERIT,0);
  std::wstring ws=Utf8ToWide(script);std::string encoded=Base64(reinterpret_cast<const BYTE*>(ws.data()),(DWORD)(ws.size()*sizeof(wchar_t)));
  if(encoded.empty()){CloseHandle(rd);CloseHandle(wr);return "ERROR: command encoding failed";}
  std::wstring command=L"powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -EncodedCommand "+Utf8ToWide(encoded);
  std::vector<wchar_t> cmd(command.begin(),command.end());cmd.push_back(0);
  STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};si.dwFlags=STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;si.wShowWindow=SW_HIDE;
  si.hStdOutput=wr;si.hStdError=wr;si.hStdInput=GetStdHandle(STD_INPUT_HANDLE);
  BOOL ok=CreateProcessW(nullptr,cmd.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW,nullptr,nullptr,&si,&pi);CloseHandle(wr);
  if(!ok){CloseHandle(rd);return "ERROR: CreateProcess "+std::to_string(GetLastError());}
  {std::lock_guard<std::mutex> lock(g_commandProcessMutex);g_commandProcesses.push_back(pi.hProcess);}
  std::string output;char b[4096];bool truncated=false;
  for(;;){
    DWORD available=0;if(!PeekNamedPipe(rd,nullptr,0,nullptr,&available,nullptr))break;
    while(available){DWORD got=0,wanted=std::min<DWORD>((DWORD)sizeof(b),available);if(!ReadFile(rd,b,wanted,&got,nullptr)||!got)break;
      if(output.size()<COMMAND_OUTPUT_LIMIT){size_t keep=std::min<size_t>(got,COMMAND_OUTPUT_LIMIT-output.size());output.append(b,keep);if(keep<got)truncated=true;}else truncated=true;
      if(!PeekNamedPipe(rd,nullptr,0,nullptr,&available,nullptr)){available=0;break;}
    }
    if(WaitForSingleObject(pi.hProcess,0)==WAIT_OBJECT_0){
      Sleep(20);DWORD tail=0;if(!PeekNamedPipe(rd,nullptr,0,nullptr,&tail,nullptr)||tail==0)break;continue;
    }
    Sleep(10);
  }
  DWORD ec=0;GetExitCodeProcess(pi.hProcess,&ec);{std::lock_guard<std::mutex> lock(g_commandProcessMutex);g_commandProcesses.erase(std::remove(g_commandProcesses.begin(),g_commandProcesses.end(),pi.hProcess),g_commandProcesses.end());}CloseHandle(pi.hThread);CloseHandle(pi.hProcess);CloseHandle(rd);
  output=NormalizeTextEncoding(output);if(truncated)output+="\n[PowerShell Guardian: command output truncated]";
  if(ec!=0)return "ERROR: PowerShell exit code "+std::to_string(ec)+"\n"+output;
  return "EXIT=0\n"+output;
}

static void StopActiveCommands(const char* reason){
  std::lock_guard<std::mutex> lock(g_commandProcessMutex);
  for(HANDLE process:g_commandProcesses)if(process)TerminateProcess(process,ERROR_CANCELLED);
  if(!g_commandProcesses.empty())Audit("SYSTEM","STOP ACTIVE COMMANDS","LOCAL",reason);
}

static std::string SystemInfo() {
  OSVERSIONINFOW os{};os.dwOSVersionInfoSize=sizeof(os);
  GetVersionExW(&os);
  MEMORYSTATUSEX mem{};mem.dwLength=sizeof(mem);GlobalMemoryStatusEx(&mem);SYSTEM_INFO si{};GetNativeSystemInfo(&si);
  wchar_t name[256]={};DWORD n=256;GetComputerNameW(name,&n);
  std::ostringstream o;o<<"{\"computer\":\""<<JsonEscape(WideToUtf8(name))<<"\",\"windows_version\":\""
    <<os.dwMajorVersion<<'.'<<os.dwMinorVersion<<'.'<<os.dwBuildNumber<<"\",\"architecture\":\""
    <<(si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64?"x64":si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_ARM64?"arm64":"other")
    <<"\",\"memory_total_mb\":"<<(mem.ullTotalPhys/1024/1024)<<",\"memory_available_mb\":"<<(mem.ullAvailPhys/1024/1024)<<"}";return o.str();
}

static bool TunnelAlive() {
  if(!g_tunnelProcess){g_tunnelReady=false;return false;}DWORD code=0;if(!GetExitCodeProcess(g_tunnelProcess,&code)||code!=STILL_ACTIVE){AppendFileUtf8(g_base+L"\\logs\\tunnel-client.log","\r\n[PowerShell Guardian] tunnel-client exit code: "+std::to_string(code)+"\r\n");if(g_tunnelStdinWrite){CloseHandle(g_tunnelStdinWrite);g_tunnelStdinWrite=nullptr;}CloseHandle(g_tunnelProcess);g_tunnelProcess=nullptr;if(g_tunnelJob){CloseHandle(g_tunnelJob);g_tunnelJob=nullptr;}g_tunnelPid=0;g_tunnelReady=false;return false;}return true;
}

static std::string StatusJson() {
  std::lock_guard<std::mutex> lock(g_mutex);size_t active=0,pending=0;long long now=Now();for(auto&s:g_sessionData)if(s.approved&&!s.denied&&s.expires>now)active++;
  for(auto&c:g_commandData)if(c.status=="WAITING APPROVAL")pending++;
  bool alive=TunnelAlive();std::ostringstream o;o<<"{\"tunnel\":\""<<(alive?"Running":"Stopped")<<"\",\"mcp_server\":\""
    <<(!alive?"Stopped":g_tunnelReady?"Ready":"Connecting")<<"\",\"security_gateway\":\""<<(g_emergency?"Locked":"Active")
    <<"\",\"active_sessions\":"<<active<<",\"pending_commands\":"<<pending<<"}";return o.str();
}

static std::string TailAudit() {
  std::string x=ReadFileUtf8(g_base+L"\\logs\\audit.jsonl"); if(x.size()>50000)x=x.substr(x.size()-50000); return x;
}

static std::string ExecuteApproved(const PendingCommand& c) {
  if(c.name=="system_info")return SystemInfo();
  if(c.name=="get_status")return StatusJson();
  if(c.name=="read_logs")return TailAudit();
  if(c.name=="read_path"){
    std::string path=JsonGet(c.payload,"path");if(path.empty())return "ERROR: missing path";
    int requested=atoi(JsonGet(c.payload,"max_bytes").c_str());size_t limit=requested>0?(size_t)requested:65536;
    limit=std::max<size_t>(1024,std::min<size_t>(limit,COMMAND_OUTPUT_LIMIT));std::wstring wide=Utf8ToWide(path);
    DWORD attributes=GetFileAttributesW(wide.c_str());if(attributes==INVALID_FILE_ATTRIBUTES)return "ERROR: path not found or inaccessible";
    if(attributes&FILE_ATTRIBUTE_DIRECTORY){
      std::wstring pattern=wide;if(!pattern.empty()&&pattern.back()!=L'\\'&&pattern.back()!=L'/')pattern+=L'\\';pattern+=L'*';
      WIN32_FIND_DATAW item{};HANDLE find=FindFirstFileW(pattern.c_str(),&item);if(find==INVALID_HANDLE_VALUE)return "ERROR: directory could not be listed";
      std::ostringstream out;size_t count=0;do{std::wstring name=item.cFileName;if(name==L"."||name==L"..")continue;
        bool directory=(item.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=0;unsigned long long size=((unsigned long long)item.nFileSizeHigh<<32)|item.nFileSizeLow;
        out<<(directory?"[DIR]  ":"[FILE] ")<<WideToUtf8(name);if(!directory)out<<" ("<<size<<" bytes)";out<<'\n';count++;
        if(count>=500||out.tellp()>=(std::streampos)limit){out<<"... listing truncated\n";break;}
      }while(FindNextFileW(find,&item));FindClose(find);return out.str();
    }
    std::ifstream file(wide.c_str(),std::ios::binary);if(!file)return "ERROR: file could not be opened";
    std::string output;output.resize(limit);file.read(output.data(),(std::streamsize)limit);output.resize((size_t)file.gcount());
    char extra=0;if(file.read(&extra,1))output+="\n[PowerShell Guardian: output truncated at "+std::to_string(limit)+" bytes]";
    return NormalizeTextEncoding(output);
  }
  if(c.name=="file_write"){
    std::string path=JsonGet(c.payload,"path"),content=JsonGet(c.payload,"content");if(path.empty())return "ERROR: missing path";
    return WriteFileUtf8(Utf8ToWide(path),content)?"SUCCESS":"ERROR: file write failed";
  }
  if(c.name=="delete"){
    std::string path=JsonGet(c.payload,"path");if(path.empty())return "ERROR: missing path";
    DWORD attr=GetFileAttributesW(Utf8ToWide(path).c_str());if(attr==INVALID_FILE_ATTRIBUTES)return "ERROR: target not found";
    if(attr&FILE_ATTRIBUTE_DIRECTORY)return "BLOCKED: recursive/directory deletion is not supported";
    return DeleteFileW(Utf8ToWide(path).c_str())?"SUCCESS":"ERROR: delete failed";
  }
  return RunPowerShell(c.payload);
}

static Session* FindSessionIdUnsafe(const std::string& id){for(auto& session:g_sessionData)if(session.id==id)return &session;return nullptr;}
static PendingCommand* FindCommandIdUnsafe(const std::string& id){for(auto& command:g_commandData)if(command.id==id)return &command;return nullptr;}
static void RejectWaitingCommandsUnsafe(const std::string& sessionId,const std::string& reason){for(auto& command:g_commandData)if(command.sessionId==sessionId&&command.status=="WAITING APPROVAL"){command.status="REJECTED";command.result=reason;}}
static bool ImmediateBuiltIn(const std::string& name){return name=="system_info"||name=="get_status"||name=="read_logs";}

static void RunAutomaticCommand(PendingCommand command,std::vector<std::string> createdFiles,bool applyFileGuard){
  std::thread([command,createdFiles,applyFileGuard]{
    std::unique_lock<std::mutex> fileExecution(g_fileExecutionMutex,std::defer_lock);if(applyFileGuard&&!createdFiles.empty())fileExecution.lock();
    {
      std::lock_guard<std::mutex> lock(g_mutex);Session* session=FindSessionIdUnsafe(command.sessionId);PendingCommand* queued=FindCommandIdUnsafe(command.id);
      if(!queued)return;
      if(g_emergency||!session||!session->approved||session->denied||session->expires<=Now()){queued->status="FAILED";queued->result="Session ended before automatic execution";Audit(command.sessionId,command.name,"SESSION AUTO","CANCELLED BEFORE EXECUTION");if(g_main)PostMessageW(g_main,WM_MS_REFRESH,0,0);return;}
      if(applyFileGuard&&!createdFiles.empty()){std::string blocked;int retryAfter=0;if(!CanCreateFiles(*session,(int)createdFiles.size(),Now(),blocked,retryAfter)){queued->status="BLOCKED";queued->result=blocked;Audit(command.sessionId,command.name,"FILE RATE LIMIT",blocked);SaveSessions();if(g_main)PostMessageW(g_main,WM_MS_REFRESH,0,0);return;}}
    }
    std::string result=ExecuteApproved(command);bool failed=result.rfind("ERROR",0)==0||result.rfind("BLOCKED",0)==0;
    {
      std::lock_guard<std::mutex> lock(g_mutex);Session* session=FindSessionIdUnsafe(command.sessionId);PendingCommand* queued=FindCommandIdUnsafe(command.id);bool terminated=false;
      if(session&&session->approved&&!session->denied)TouchSession(*session);
      if(applyFileGuard&&!failed&&session)terminated=RecordCreatedFiles(*session,createdFiles,Now());
      if(queued){queued->result=result;queued->status=failed?"FAILED":"SUCCESS";}Audit(command.sessionId,command.name,"SESSION AUTO",terminated?"SUCCESS - SESSION TERMINATED BY FILE SAFETY":failed?"FAILED":"SUCCESS");SaveSessions();
    }
    if(g_main)PostMessageW(g_main,WM_MS_REFRESH,0,0);
  }).detach();
}

static std::string HandleGateway(const std::string& req) {
  std::string bridge=JsonGet(req,"bridge_key");
  if(g_bridgeSecret.empty()||bridge.empty()||!ConstantEqual(bridge,WideToUtf8(g_bridgeSecret)))return "{\"ok\":false,\"error\":\"unauthorized bridge\"}";
  std::string action=JsonGet(req,"action");
  std::unique_lock<std::mutex> lock(g_mutex);
  if(action=="new_session"){
    if(g_emergency)return "{\"ok\":false,\"error\":\"emergency lock active\"}";
    long long now=Now(),window=(long long)g_sessionRequestWindowMinutes*60;g_sessionRequestTimes.erase(std::remove_if(g_sessionRequestTimes.begin(),g_sessionRequestTimes.end(),[&](long long created){return created<=now-window;}),g_sessionRequestTimes.end());
    if((int)g_sessionRequestTimes.size()>=g_sessionRequestLimit){int retryAfter=(int)std::max(1LL,g_sessionRequestTimes.front()+window-now);Audit("SYSTEM","NEW SESSION REQUEST","SESSION RATE LIMIT","retry after "+std::to_string(retryAfter)+" seconds");return "{\"ok\":false,\"status\":\"SESSION_RATE_LIMIT\",\"retry_after_seconds\":"+std::to_string(retryAfter)+"}";}
    BYTE r[2];BCryptGenRandom(nullptr,r,2,BCRYPT_USE_SYSTEM_PREFERRED_RNG);int code=100+(((int)r[0]<<8|r[1])%900);
    Session s;s.code=std::to_string(code);s.id="PSG-"+s.code+"-"+NewId("").substr(0,6);s.created=s.lastActive=Now();s.expires=s.created+g_timeoutMinutes*60;
    g_sessionRequestTimes.push_back(now);g_sessionData.push_back(s);Audit(s.id,"SESSION TRANSITION","NEW -> WAITING_APPROVAL","CODE "+s.code);
    if(g_main)PostMessageW(g_main,WM_MS_SESSION,0,0);
    return "{\"ok\":true,\"status\":\"WAITING APPROVAL\",\"session_id\":\""+s.id+"\",\"verification_code\":\""+s.code+"\"}";
  }
  if(action=="session_status"){
    std::string id=JsonGet(req,"session_id");for(auto&s:g_sessionData)if(s.id==id){
      if(s.suspiciousTerminated)return "{\"ok\":true,\"status\":\"TERMINATED_SUSPICIOUS_ACTIVITY\",\"reason\":\"repeated maximum-rate file creation\"}";
      if(s.denied)return "{\"ok\":true,\"status\":\"DENIED\"}";
      if(!s.approved)return "{\"ok\":true,\"status\":\"WAITING APPROVAL\",\"unlock_required\":false,\"next_action\":\"wait for local approval and retry session_status\"}";
      if(s.expires<=Now())return "{\"ok\":true,\"status\":\"EXPIRED\",\"unlock_required\":false,\"next_action\":\"request and approve a new session\"}";
      TouchSession(s);SaveSessions();
      return "{\"ok\":true,\"status\":\"APPROVED\",\"session_id\":\""+JsonEscape(s.id)+"\",\"session_token\":\""+JsonEscape(s.token)+"\",\"token_valid\":true,\"token_access\":\"AVAILABLE\",\"access_mode\":\""+(s.unattended?"UNLOCKED":"LOCKED")+"\",\"unlock_required\":false,\"token_rotated\":false,\"expires_at\":"+std::to_string(s.expires)+"}";
    }return "{\"ok\":false,\"error\":\"session not found\"}";
  }
  if(action=="command"){
    if(g_emergency)return "{\"ok\":false,\"error\":\"emergency lock active\"}";
    std::string token=JsonGet(req,"session_token"),name=JsonGet(req,"command"),payload=JsonGet(req,"payload");Session*matched=FindSessionTokenAnyState(token);Session*s=FindSessionToken(token);
    if(!s)return SessionTokenFailure(matched);
    if(!ValidCommandName(name)||!KnownCommandName(name))return "{\"ok\":false,\"error\":\"unknown command name\"}";
    TouchSession(*s);SaveSessions();std::string risk=RiskFor(name);bool deleteIntent=ContainsDeleteIntent(name,payload);
    if(deleteIntent){
      PendingCommand deletion;deletion.id=NewId("CMD-");deletion.sessionId=s->id;deletion.name=name;deletion.payload=payload;deletion.risk="DELETE";deletion.created=Now();g_commandData.push_back(deletion);
      Audit(s->id,name,"WAITING_LOCAL_DELETE_APPROVAL","file deletion always requires local approval");if(g_main)PostMessageW(g_main,WM_MS_COMMAND,0,0);
      return "{\"ok\":true,\"status\":\"WAITING_LOCAL_DELETE_APPROVAL\",\"requires_local_approval\":true,\"risk\":\"DELETE\",\"command_id\":\""+deletion.id+"\"}";
    }
    if(risk=="LOW"&&ImmediateBuiltIn(name)){
      PendingCommand automatic;automatic.sessionId=s->id;automatic.name=name;automatic.payload=payload;automatic.risk=risk;lock.unlock();std::string result=ExecuteApproved(automatic);bool failed=result.rfind("ERROR",0)==0||result.rfind("BLOCKED",0)==0;
      Audit(automatic.sessionId,name,"WHITELIST",failed?"FAILED":"SUCCESS");return "{\"ok\":"+std::string(failed?"false":"true")+",\"status\":\""+(failed?"FAILED":"SUCCESS")+"\",\"risk\":\"LOW\",\"approval\":\"WHITELIST\",\"result\":\""+JsonEscape(result)+"\"}";
    }
    if(risk=="LOW"||s->unattended){
      bool applyFileGuard=s->unattended;bool ambiguousBulk=false;std::vector<std::string> detectedFiles=DetectCreatedFiles(name,payload,ambiguousBulk);std::vector<std::string> createdFiles=applyFileGuard?PotentialNewFiles(detectedFiles):std::vector<std::string>{};
      if(applyFileGuard&&ambiguousBulk){std::string blocked="BLOCKED: bulk or unbounded file creation is not allowed in an unlocked session";Audit(s->id,name,"FILE SAFETY",blocked);return "{\"ok\":false,\"status\":\"BLOCKED\",\"result\":\""+JsonEscape(blocked)+"\"}";}
      PendingCommand automatic;automatic.id=NewId("CMD-");automatic.sessionId=s->id;automatic.name=name;automatic.payload=payload;automatic.risk=risk;automatic.status="RUNNING";automatic.created=Now();g_commandData.push_back(automatic);
      Audit(s->id,name,s->unattended?"SESSION AUTO":"WHITELIST","QUEUED RUNNING");std::string commandId=automatic.id;lock.unlock();RunAutomaticCommand(automatic,createdFiles,applyFileGuard);if(g_main)PostMessageW(g_main,WM_MS_REFRESH,0,0);
      return "{\"ok\":true,\"status\":\"RUNNING\",\"requires_local_approval\":false,\"command_id\":\""+commandId+"\",\"next_action\":\"call command_status\"}";
    }
    PendingCommand c;c.id=NewId("CMD-");c.sessionId=s->id;c.name=name;c.payload=payload;c.risk=risk;c.created=Now();g_commandData.push_back(c);
    Audit(s->id,name,"WAITING","pending local approval");if(g_main)PostMessageW(g_main,WM_MS_COMMAND,0,0);
    return "{\"ok\":true,\"status\":\"WAITING APPROVAL\",\"risk\":\""+risk+"\",\"command_id\":\""+c.id+"\"}";
  }
  if(action=="command_status"){
    std::string token=JsonGet(req,"session_token"),id=JsonGet(req,"command_id");Session*matched=FindSessionTokenAnyState(token);Session*s=FindSessionToken(token);if(!s)return SessionTokenFailure(matched);TouchSession(*s);SaveSessions();
    for(auto&c:g_commandData)if(c.id==id&&c.sessionId==s->id)return "{\"ok\":true,\"status\":\""+JsonEscape(c.status)+"\",\"risk\":\""+c.risk+"\",\"result\":\""+JsonEscape(c.result)+"\"}";
    return "{\"ok\":false,\"error\":\"command not found\"}";
  }
  return "{\"ok\":false,\"error\":\"unknown action\"}";
}

static void SetSocketTimeouts(SOCKET socket,DWORD milliseconds){
  setsockopt(socket,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&milliseconds),sizeof(milliseconds));
  setsockopt(socket,SOL_SOCKET,SO_SNDTIMEO,reinterpret_cast<const char*>(&milliseconds),sizeof(milliseconds));
}

static bool SendAll(SOCKET socket,const std::string& data){
  size_t sent=0;while(sent<data.size()){int amount=send(socket,data.data()+sent,(int)std::min<size_t>(data.size()-sent,INT_MAX),0);if(amount<=0)return false;sent+=(size_t)amount;}return true;
}

static void HandleGatewayClient(SOCKET client){
  SetSocketTimeouts(client,GATEWAY_SOCKET_TIMEOUT_MS);std::string request;char buffer[4096];int received=0;
  while((received=recv(client,buffer,sizeof(buffer),0))>0){request.append(buffer,received);if(request.find('\n')!=std::string::npos||request.size()>1024*1024)break;}
  std::string response=request.size()>1024*1024?"{\"ok\":false,\"error\":\"request too large\"}\n":HandleGateway(request)+"\n";
  SendAll(client,response);shutdown(client,SD_BOTH);closesocket(client);
}

static void GatewayServer() {
  WSADATA wd;if(WSAStartup(MAKEWORD(2,2),&wd)!=0)return;SOCKET listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);if(listener==INVALID_SOCKET){WSACleanup();return;}
  sockaddr_in a{};a.sin_family=AF_INET;a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);a.sin_port=htons(GATEWAY_PORT);int one=1;setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,(char*)&one,sizeof(one));
  if(bind(listener,(sockaddr*)&a,sizeof(a))==SOCKET_ERROR||listen(listener,8)==SOCKET_ERROR){closesocket(listener);WSACleanup();return;}g_serverRunning=true;
  while(g_serverRunning){fd_set f;FD_ZERO(&f);FD_SET(listener,&f);timeval tv{1,0};if(select(0,&f,nullptr,nullptr,&tv)<=0)continue;SOCKET c=accept(listener,nullptr,nullptr);if(c==INVALID_SOCKET)continue;
    std::thread([c]{HandleGatewayClient(c);}).detach();
  }closesocket(listener);WSACleanup();
}

static std::string GatewayCall(const std::string& json) {
  WSADATA wd;if(WSAStartup(MAKEWORD(2,2),&wd)!=0)return "{\"ok\":false,\"error\":\"winsock\"}";SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
  if(s==INVALID_SOCKET){WSACleanup();return "{\"ok\":false,\"error\":\"socket unavailable\"}";}SetSocketTimeouts(s,GATEWAY_SOCKET_TIMEOUT_MS);
  sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(GATEWAY_PORT);inet_pton(AF_INET,"127.0.0.1",&a.sin_addr);
  if(connect(s,(sockaddr*)&a,sizeof(a))==SOCKET_ERROR){closesocket(s);WSACleanup();return "{\"ok\":false,\"error\":\"gateway unavailable\"}";}
  std::string q=json+"\n";if(!SendAll(s,q)){closesocket(s);WSACleanup();return "{\"ok\":false,\"error\":\"gateway send failed\"}";}shutdown(s,SD_SEND);
  std::string r;char b[4096];int n=0;while((n=recv(s,b,sizeof(b),0))>0){r.append(b,n);if(r.size()>1024*1024)break;}int socketError=n==SOCKET_ERROR?WSAGetLastError():0;
  closesocket(s);WSACleanup();if(socketError==WSAETIMEDOUT)return "{\"ok\":false,\"error\":\"gateway response timed out\"}";if(r.empty())return "{\"ok\":false,\"error\":\"empty gateway response\"}";return r;
}

static std::string ToolListJson() {
  return R"JSON({"tools":[
{"name":"new_session_request","description":"NEW SESSION REQUEST. Creates a local 3-digit verification request; no computer access is possible before local approval.","inputSchema":{"type":"object","properties":{}}},
{"name":"session_status","description":"Check approval and retrieve the session token. Approval always returns a token in both LOCKED and UNLOCKED modes; unlocking is never required to obtain it. Safe to repeat with the original session_id, and switching lock mode never rotates the token.","inputSchema":{"type":"object","properties":{"session_id":{"type":"string"}},"required":["session_id"]}},
{"name":"system_info","description":"LOW risk system information; requires an approved session.","inputSchema":{"type":"object","properties":{"session_token":{"type":"string"}},"required":["session_token"]}},
{"name":"get_status","description":"LOW risk PowerShell Guardian status; requires an approved session.","inputSchema":{"type":"object","properties":{"session_token":{"type":"string"}},"required":["session_token"]}},
{"name":"read_logs","description":"LOW risk audit log read; requires an approved session.","inputSchema":{"type":"object","properties":{"session_token":{"type":"string"}},"required":["session_token"]}},
{"name":"read_path","description":"Read one text file or list one directory without invoking PowerShell. A locked session requires local approval; an unlocked session runs automatically. This tool never consumes the file-creation quota.","inputSchema":{"type":"object","properties":{"session_token":{"type":"string"},"path":{"type":"string"},"max_bytes":{"type":"integer","minimum":1024,"maximum":200000,"default":65536}},"required":["session_token","path"]}},
{"name":"execute_command","description":"Execute a PowerShell command. Normal sessions require local approval; a locally unlocked session runs automatically except for deletion and file-safety blocks.","inputSchema":{"type":"object","properties":{"session_token":{"type":"string"},"command":{"type":"string","description":"Complete PowerShell command, for example New-Item or Set-Content."}},"required":["session_token","command"]}},
{"name":"powershell","description":"HIGH risk PowerShell. Normal sessions require approval; a locally unlocked session runs automatically except for deletion and file-safety blocks.","inputSchema":{"type":"object","properties":{"session_token":{"type":"string"},"script":{"type":"string"}},"required":["session_token","script"]}},
{"name":"file_write","description":"Write one file. Unlocked sessions run automatically subject to the configurable per-session file creation limit.","inputSchema":{"type":"object","properties":{"session_token":{"type":"string"},"path":{"type":"string"},"content":{"type":"string"}},"required":["session_token","path","content"]}},
{"name":"delete","description":"HIGH risk single-file deletion. Always requires explicit local approval; directory/recursive deletion is blocked.","inputSchema":{"type":"object","properties":{"session_token":{"type":"string"},"path":{"type":"string"}},"required":["session_token","path"]}},
{"name":"install","description":"HIGH risk installation command. Runs automatically only for a locally unlocked session and remains subject to file safety.","inputSchema":{"type":"object","properties":{"session_token":{"type":"string"},"script":{"type":"string"}},"required":["session_token","script"]}},
{"name":"registry","description":"HIGH risk registry PowerShell command. Runs automatically only for a locally unlocked session.","inputSchema":{"type":"object","properties":{"session_token":{"type":"string"},"script":{"type":"string"}},"required":["session_token","script"]}},
{"name":"network_change","description":"HIGH risk network PowerShell command. Runs automatically only for a locally unlocked session.","inputSchema":{"type":"object","properties":{"session_token":{"type":"string"},"script":{"type":"string"}},"required":["session_token","script"]}},
{"name":"command_status","description":"Check a queued, locally approved/rejected or automatic command and retrieve its result. Use the same session token regardless of LOCKED/UNLOCKED mode.","inputSchema":{"type":"object","properties":{"session_token":{"type":"string"},"command_id":{"type":"string"}},"required":["session_token","command_id"]}}
]})JSON";
}

static std::string McpResult(const std::string& id,const std::string& text,bool error=false) {
  return "{\"jsonrpc\":\"2.0\",\"id\":"+id+",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\""+JsonEscape(text)+"\"}],\"isError\":"+(error?"true":"false")+"}}";
}

static int McpBridgeMain() {
  wchar_t secret[2048]={};DWORD n=GetEnvironmentVariableW(L"POWERSHELL_GUARDIAN_BRIDGE_KEY",secret,2048);if(!n)return 3;std::string key=WideToUtf8(secret);
  std::ios::sync_with_stdio(false);std::string line;
  while(std::getline(std::cin,line)){
    std::string method=JsonGet(line,"method"),id;if(!powershell_guardian_json::RawField(line,"id",id))id="null";
    if(method=="initialize"){
      std::cout<<"{\"jsonrpc\":\"2.0\",\"id\":"<<id<<",\"result\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"PowerShell Guardian MCP Bridge\",\"version\":\"1.1.4\"},\"instructions\":\"Begin each new chat with one new_session_request and keep its original session_id. Poll session_status until APPROVED. Approval returns a valid token in both LOCKED and UNLOCKED modes; never ask the user to unlock merely to obtain a token. Switching LOCKED/UNLOCKED preserves the same session_id and token. If a token call fails, retry session_status with the original session_id before requesting another session. Use read_path for bounded reads; it never affects file-creation safety. Locked sessions require local approval for every non-whitelisted operation. Unlocked and whitelisted non-immediate operations return RUNNING without a local prompt; poll command_status with the same token until SUCCESS, FAILED, BLOCKED, or REJECTED. Deletion always requires local approval.\"}}\n"<<std::flush;
    } else if(method=="tools/list") {
      std::cout<<"{\"jsonrpc\":\"2.0\",\"id\":"<<id<<",\"result\":"<<ToolListJson()<<"}\n"<<std::flush;
    } else if(method=="tools/call") {
      std::string params,arguments,name,token,request;
      powershell_guardian_json::RawField(line,"params",params);
      powershell_guardian_json::StringField(params,"name",name);
      if(!powershell_guardian_json::RawField(params,"arguments",arguments))arguments="{}";
      powershell_guardian_json::StringField(arguments,"session_token",token);
      if(name=="new_session_request")request="{\"bridge_key\":\""+JsonEscape(key)+"\",\"action\":\"new_session\"}";
      else if(name=="session_status")request="{\"bridge_key\":\""+JsonEscape(key)+"\",\"action\":\"session_status\",\"session_id\":\""+JsonEscape(JsonGet(arguments,"session_id"))+"\"}";
      else if(name=="command_status")request="{\"bridge_key\":\""+JsonEscape(key)+"\",\"action\":\"command_status\",\"session_token\":\""+JsonEscape(token)+"\",\"command_id\":\""+JsonEscape(JsonGet(arguments,"command_id"))+"\"}";
      else {
        std::string payload;
        if(name=="file_write")payload="{\"path\":\""+JsonEscape(JsonGet(arguments,"path"))+"\",\"content\":\""+JsonEscape(JsonGet(arguments,"content"))+"\"}";
        else if(name=="read_path")payload="{\"path\":\""+JsonEscape(JsonGet(arguments,"path"))+"\",\"max_bytes\":\""+JsonEscape(JsonGet(arguments,"max_bytes"))+"\"}";
        else if(name=="delete")payload="{\"path\":\""+JsonEscape(JsonGet(arguments,"path"))+"\"}";
        else if(name=="execute_command")payload=JsonGet(arguments,"command");
        else payload=JsonGet(arguments,"script");
        request="{\"bridge_key\":\""+JsonEscape(key)+"\",\"action\":\"command\",\"session_token\":\""+JsonEscape(token)+"\",\"command\":\""+JsonEscape(name)+"\",\"payload\":\""+JsonEscape(payload)+"\"}";
      }
      std::string result=GatewayCall(request);bool error=result.find("\"ok\":false")!=std::string::npos;std::cout<<McpResult(id,result,error)<<"\n"<<std::flush;
    } else if(method.rfind("notifications/",0)!=0) {
      std::cout<<"{\"jsonrpc\":\"2.0\",\"id\":"<<id<<",\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}\n"<<std::flush;
    }
  }SecureZeroMemory(secret,sizeof(secret));return 0;
}

struct InputState { std::wstring title,label,value;bool password=false,done=false,ok=false;HWND edit=nullptr; };
static LRESULT CALLBACK InputProc(HWND h,UINT m,WPARAM w,LPARAM l){
  InputState*s=(InputState*)GetWindowLongPtrW(h,GWLP_USERDATA);
  if(m==WM_CREATE){s=(InputState*)((CREATESTRUCTW*)l)->lpCreateParams;SetWindowLongPtrW(h,GWLP_USERDATA,(LONG_PTR)s);
    HFONT font=(HFONT)GetStockObject(DEFAULT_GUI_FONT);
    HWND label=CreateWindowW(L"STATIC",s->label.c_str(),WS_CHILD|WS_VISIBLE|SS_LEFT|SS_NOPREFIX,18,16,648,44,h,nullptr,g_instance,nullptr);
    s->edit=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",s->value.c_str(),WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL|(s->password?ES_PASSWORD:0),18,66,648,28,h,(HMENU)5001,g_instance,nullptr);
    HWND ok=CreateWindowW(L"BUTTON",L"OK",WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON,478,112,88,30,h,(HMENU)IDOK,g_instance,nullptr);
    HWND cancel=CreateWindowW(L"BUTTON",L"Cancel",WS_CHILD|WS_VISIBLE|WS_TABSTOP,578,112,88,30,h,(HMENU)IDCANCEL,g_instance,nullptr);
    for(HWND control:{label,s->edit,ok,cancel})if(control)SendMessageW(control,WM_SETFONT,(WPARAM)font,TRUE);
    SetFocus(s->edit);return 0;}
  if(m==WM_COMMAND&&s&&(LOWORD(w)==IDOK||LOWORD(w)==IDCANCEL)){s->ok=LOWORD(w)==IDOK;if(s->ok){int n=GetWindowTextLengthW(s->edit);s->value.resize(n+1);GetWindowTextW(s->edit,s->value.data(),n+1);s->value.resize(n);}s->done=true;DestroyWindow(h);return 0;}
  if(m==WM_CLOSE&&s){s->done=true;DestroyWindow(h);return 0;}return DefWindowProcW(h,m,w,l);
}

static bool InputBox(HWND owner,const std::wstring& title,const std::wstring& label,std::wstring& value,bool password=false){
  static bool registered=false;if(!registered){WNDCLASSW wc{};wc.lpfnWndProc=InputProc;wc.hInstance=g_instance;wc.hCursor=LoadCursor(nullptr,IDC_ARROW);wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);wc.lpszClassName=L"PowerShellGuardianInput";RegisterClassW(&wc);registered=true;}
  InputState s{title,label,value,password};const int width=700,height=190;RECT r{};GetWindowRect(owner,&r);int x=r.left+((r.right-r.left)-width)/2,y=r.top+((r.bottom-r.top)-height)/2;
  MONITORINFO monitor{};monitor.cbSize=sizeof(monitor);if(GetMonitorInfoW(MonitorFromWindow(owner,MONITOR_DEFAULTTONEAREST),&monitor)){int left=(int)monitor.rcWork.left,top=(int)monitor.rcWork.top,right=(int)monitor.rcWork.right,bottom=(int)monitor.rcWork.bottom;x=std::max(left,std::min(x,right-width));y=std::max(top,std::min(y,bottom-height));}
  HWND h=CreateWindowExW(WS_EX_DLGMODALFRAME|WS_EX_CONTROLPARENT,L"PowerShellGuardianInput",title.c_str(),WS_CAPTION|WS_SYSMENU|WS_VISIBLE,x,y,width,height,owner,nullptr,g_instance,&s);if(!h)return false;
  EnableWindow(owner,FALSE);MSG msg;while(!s.done&&GetMessageW(&msg,nullptr,0,0)>0){if(!IsDialogMessageW(h,&msg)){TranslateMessage(&msg);DispatchMessageW(&msg);}}EnableWindow(owner,TRUE);SetForegroundWindow(owner);if(s.ok)value=s.value;return s.ok;
}

static std::wstring NormalizeTunnelId(std::wstring id){
  while(!id.empty()&&iswspace(id.front()))id.erase(id.begin());
  while(!id.empty()&&iswspace(id.back()))id.pop_back();
  if(id.size()>=2&&((id.front()==L'"'&&id.back()==L'"')||(id.front()==L'\''&&id.back()==L'\''))){id=id.substr(1,id.size()-2);while(!id.empty()&&iswspace(id.front()))id.erase(id.begin());while(!id.empty()&&iswspace(id.back()))id.pop_back();}
  std::transform(id.begin(),id.end(),id.begin(),[](wchar_t c){return (wchar_t)towlower(c);});
  std::wstring raw=id.rfind(L"tunnel_",0)==0?id.substr(7):id,compact;for(wchar_t c:raw)if(c!=L'-'&&!iswspace(c))compact+=c;
  bool hex32=compact.size()==32&&std::all_of(compact.begin(),compact.end(),[](wchar_t c){return (c>=L'0'&&c<=L'9')||(c>=L'a'&&c<=L'f');});
  if(hex32)return L"tunnel_"+compact;
  return id;
}
static bool ValidTunnelId(const std::wstring&id){if(id.rfind(L"tunnel_",0)!=0||id.size()!=39)return false;for(size_t i=7;i<id.size();i++)if(!((id[i]>=L'0'&&id[i]<=L'9')||(id[i]>=L'a'&&id[i]<=L'f')))return false;return true;}

static void StopTunnel(const char* reason="STOPPED") {
  StopActiveCommands(reason);
  g_tunnelReady=false;
  if(g_tunnelStdinWrite){CloseHandle(g_tunnelStdinWrite);g_tunnelStdinWrite=nullptr;}
  if(g_tunnelJob)TerminateJobObject(g_tunnelJob,0);
  if(g_tunnelProcess){if(!g_tunnelJob)TerminateProcess(g_tunnelProcess,0);WaitForSingleObject(g_tunnelProcess,3000);CloseHandle(g_tunnelProcess);g_tunnelProcess=nullptr;g_tunnelPid=0;Audit("SYSTEM","STOP TUNNEL","LOCAL",reason);}
  if(g_tunnelJob){CloseHandle(g_tunnelJob);g_tunnelJob=nullptr;}
}

static HANDLE CreateTunnelJob(){
  HANDLE job=CreateJobObjectW(nullptr,nullptr);if(!job)return nullptr;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if(!SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits))){CloseHandle(job);return nullptr;}
  return job;
}

static bool CheckTunnelEndpoint(const char* path,int attempts){
  WSADATA wd;if(WSAStartup(MAKEWORD(2,2),&wd)!=0)return false;bool ok=false;
  std::string request=std::string("GET ")+path+" HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
  for(int attempt=0;attempt<attempts&&!ok;attempt++){if(!TunnelAlive())break;SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);if(s==INVALID_SOCKET)continue;SetSocketTimeouts(s,1000);sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(17655);inet_pton(AF_INET,"127.0.0.1",&a.sin_addr);
    if(connect(s,(sockaddr*)&a,sizeof(a))!=SOCKET_ERROR){SendAll(s,request);char b[1024]={};int n=recv(s,b,sizeof(b)-1,0);if(n>0&&strstr(b," 200 "))ok=true;}closesocket(s);if(!ok)Sleep(500);
  }WSACleanup();return ok;
}

static std::wstring WindowsErrorText(DWORD error){
  wchar_t* raw=nullptr;FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,nullptr,error,0,(LPWSTR)&raw,0,nullptr);
  std::wstring text=raw?raw:L"Unknown Windows error";if(raw)LocalFree(raw);while(!text.empty()&&(text.back()==L'\r'||text.back()==L'\n'))text.pop_back();return text;
}

static std::wstring TunnelLogPath(){return g_base+L"\\logs\\tunnel-client.log";}

static bool ExistingFile(const std::wstring& path){DWORD a=GetFileAttributesW(path.c_str());return a!=INVALID_FILE_ATTRIBUTES&&!(a&FILE_ATTRIBUTE_DIRECTORY);}

static bool SaveTunnelConfig(){
  return WriteFileUtf8(g_base+L"\\config\\tunnel.json","{\n  \"tunnel_id_protected\": true,\n  \"tunnel_client_path\": \""+JsonEscape(WideToUtf8(g_tunnelClientPath))+"\",\n  \"profile_mode\": \"sample_mcp_stdio_local\",\n  \"health_address\": \"127.0.0.1:17655\"\n}\n");
}

static std::wstring FindTunnelClient(){
  if(ExistingFile(g_tunnelClientPath))return g_tunnelClientPath;
  std::wstring bundled=g_install+L"\\tunnel\\tunnel-client.exe";if(ExistingFile(bundled))return bundled;
  wchar_t profile[32768]={};DWORD n=GetEnvironmentVariableW(L"USERPROFILE",profile,32768);if(n&&n<32768){std::wstring legacy=std::wstring(profile)+L"\\Tools\\tunnel-client-v0.0.11-windows-amd64\\tunnel-client.exe";if(ExistingFile(legacy))return legacy;}
  return L"";
}

static bool ChooseTunnelClient(){
  wchar_t file[32768]={};std::wstring current=FindTunnelClient();if(!current.empty())wcsncpy_s(file,current.c_str(),_TRUNCATE);
  const wchar_t filter[]=L"Tunnel client (tunnel-client.exe)\0tunnel-client.exe\0Executable files (*.exe)\0*.exe\0All files\0*.*\0\0";
  OPENFILENAMEW ofn{};ofn.lStructSize=sizeof(ofn);ofn.hwndOwner=g_main;ofn.lpstrFilter=filter;ofn.lpstrFile=file;ofn.nMaxFile=32768;ofn.lpstrTitle=L"Select tunnel-client.exe";ofn.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST|OFN_NOCHANGEDIR;
  if(!GetOpenFileNameW(&ofn)||!ExistingFile(file))return false;
  g_tunnelClientPath=file;SaveTunnelConfig();Audit("SYSTEM","CHANGE TUNNEL CLIENT","LOCAL","SUCCESS");return true;
}

static std::wstring CommandLineQuote(const std::wstring& value){
  std::wstring quoted=L"\"";size_t slashes=0;
  for(wchar_t c:value){if(c==L'\\'){slashes++;continue;}if(c==L'\"'){quoted.append(slashes*2+1,L'\\');quoted+=L'\"';slashes=0;continue;}quoted.append(slashes,L'\\');slashes=0;quoted+=c;}
  quoted.append(slashes*2,L'\\');quoted+=L'\"';return quoted;
}

static std::wstring TunnelStdioCommand(std::wstring executablePath){
  std::replace(executablePath.begin(),executablePath.end(),L'\\',L'/');
  return L"\""+executablePath+L"\"";
}

struct EnvironmentBackup{std::wstring name,value;bool existed=false;};
static EnvironmentBackup SetTemporaryEnvironment(const wchar_t* name,const std::wstring& value){
  EnvironmentBackup backup;backup.name=name;SetLastError(ERROR_SUCCESS);DWORD needed=GetEnvironmentVariableW(name,nullptr,0);DWORD error=GetLastError();backup.existed=needed>0||error!=ERROR_ENVVAR_NOT_FOUND;
  if(needed>0){std::vector<wchar_t> oldValue(needed);GetEnvironmentVariableW(name,oldValue.data(),needed);backup.value=oldValue.data();}
  SetEnvironmentVariableW(name,value.c_str());return backup;
}
static void RestoreEnvironment(const std::vector<EnvironmentBackup>& backups){for(auto it=backups.rbegin();it!=backups.rend();++it)SetEnvironmentVariableW(it->name.c_str(),it->existed?it->value.c_str():nullptr);}

static std::vector<EnvironmentBackup> SetTunnelEnvironment(){
  std::vector<EnvironmentBackup> backups;
  backups.push_back(SetTemporaryEnvironment(L"CONTROL_PLANE_API_KEY",g_apiKey));
  backups.push_back(SetTemporaryEnvironment(L"POWERSHELL_GUARDIAN_BRIDGE_KEY",g_bridgeSecret));
  backups.push_back(SetTemporaryEnvironment(L"TUNNEL_CLIENT_PROFILE_DIR",g_base+L"\\tunnel-client-config"));
  backups.push_back(SetTemporaryEnvironment(L"XDG_CONFIG_HOME",g_base+L"\\tunnel-client-config"));
  backups.push_back(SetTemporaryEnvironment(L"HEALTH_LISTEN_ADDR",L"127.0.0.1:17655"));
  return backups;
}

struct ProcessResult{bool started=false,timedOut=false;DWORD exitCode=0,windowsError=0;};
static ProcessResult RunTunnelTool(const std::wstring& exe,const std::wstring& arguments,const char* stage,DWORD timeoutMs){
  ProcessResult result;AppendFileUtf8(TunnelLogPath(),"\r\n[PowerShell Guardian] "+std::string(stage)+"\r\n");
  SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};HANDLE log=CreateFileW(TunnelLogPath().c_str(),FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,&sa,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
  if(log==INVALID_HANDLE_VALUE){result.windowsError=GetLastError();return result;}
  HANDLE inputRead=nullptr,inputWrite=nullptr;
  if(!CreatePipe(&inputRead,&inputWrite,&sa,0)||!SetHandleInformation(inputWrite,HANDLE_FLAG_INHERIT,0)){result.windowsError=GetLastError();if(inputRead)CloseHandle(inputRead);if(inputWrite)CloseHandle(inputWrite);CloseHandle(log);return result;}
  std::wstring command=CommandLineQuote(exe)+L" "+arguments;std::vector<wchar_t> mutableCommand(command.begin(),command.end());mutableCommand.push_back(0);
  STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};si.dwFlags=STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;si.wShowWindow=SW_HIDE;si.hStdInput=inputRead;si.hStdOutput=log;si.hStdError=log;
  BOOL ok=CreateProcessW(exe.c_str(),mutableCommand.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW,nullptr,g_install.c_str(),&si,&pi);result.windowsError=ok?ERROR_SUCCESS:GetLastError();CloseHandle(inputRead);CloseHandle(inputWrite);CloseHandle(log);
  if(!ok){AppendFileUtf8(TunnelLogPath(),"[PowerShell Guardian] "+std::string(stage)+" CreateProcess error "+std::to_string(result.windowsError)+"\r\n");return result;}
  result.started=true;CloseHandle(pi.hThread);DWORD wait=WaitForSingleObject(pi.hProcess,timeoutMs);
  if(wait==WAIT_TIMEOUT){result.timedOut=true;TerminateProcess(pi.hProcess,ERROR_TIMEOUT);WaitForSingleObject(pi.hProcess,3000);}
  if(!GetExitCodeProcess(pi.hProcess,&result.exitCode))result.windowsError=GetLastError();
  CloseHandle(pi.hProcess);
  AppendFileUtf8(TunnelLogPath(),"\r\n[PowerShell Guardian] "+std::string(stage)+(result.timedOut?" timed out":" exit code: "+std::to_string(result.exitCode))+"\r\n");return result;
}

static std::wstring BridgeExecutablePath(){return g_install+L"\\PowerShellGuardianBridge.exe";}

static bool VerifyBridgeProtocol(const std::wstring& bridgeExecutable){
  AppendFileUtf8(TunnelLogPath(),"\r\n[PowerShell Guardian] MCP BRIDGE PREFLIGHT\r\n");
  if(g_bridgeSecret.empty()){AppendFileUtf8(TunnelLogPath(),"ERROR: protected MCP bridge key is empty.\r\n");Audit("SYSTEM","MCP BRIDGE PREFLIGHT","LOCAL","EMPTY KEY");return false;}
  SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};HANDLE stdinRead=nullptr,stdinWrite=nullptr,stdoutRead=nullptr,stdoutWrite=nullptr;
  if(!CreatePipe(&stdinRead,&stdinWrite,&sa,0)||!CreatePipe(&stdoutRead,&stdoutWrite,&sa,0)||!SetHandleInformation(stdinWrite,HANDLE_FLAG_INHERIT,0)||!SetHandleInformation(stdoutRead,HANDLE_FLAG_INHERIT,0)){
    DWORD error=GetLastError();if(stdinRead)CloseHandle(stdinRead);if(stdinWrite)CloseHandle(stdinWrite);if(stdoutRead)CloseHandle(stdoutRead);if(stdoutWrite)CloseHandle(stdoutWrite);AppendFileUtf8(TunnelLogPath(),"ERROR: bridge preflight pipe creation failed: "+std::to_string(error)+".\r\n");return false;
  }
  auto environment=SetTunnelEnvironment();std::wstring command=CommandLineQuote(bridgeExecutable);std::vector<wchar_t> mutableCommand(command.begin(),command.end());mutableCommand.push_back(0);
  STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};si.dwFlags=STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;si.wShowWindow=SW_HIDE;si.hStdInput=stdinRead;si.hStdOutput=stdoutWrite;si.hStdError=stdoutWrite;
  BOOL started=CreateProcessW(bridgeExecutable.c_str(),mutableCommand.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW,nullptr,g_install.c_str(),&si,&pi);DWORD createError=started?ERROR_SUCCESS:GetLastError();CloseHandle(stdinRead);CloseHandle(stdoutWrite);
  if(!started){CloseHandle(stdinWrite);CloseHandle(stdoutRead);RestoreEnvironment(environment);AppendFileUtf8(TunnelLogPath(),"ERROR: PowerShellGuardianBridge.exe CreateProcess failed: "+std::to_string(createError)+" ("+WideToUtf8(WindowsErrorText(createError))+").\r\n");Audit("SYSTEM","MCP BRIDGE PREFLIGHT","LOCAL","CREATE FAILED");return false;}
  CloseHandle(pi.hThread);const std::string request="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{},\"clientInfo\":{\"name\":\"PowerShellGuardianPreflight\",\"version\":\"1.1.4\"}}}\n";DWORD written=0;BOOL sent=WriteFile(stdinWrite,request.data(),(DWORD)request.size(),&written,nullptr);CloseHandle(stdinWrite);
  DWORD wait=WaitForSingleObject(pi.hProcess,5000);bool timedOut=wait==WAIT_TIMEOUT;if(timedOut){TerminateProcess(pi.hProcess,ERROR_TIMEOUT);WaitForSingleObject(pi.hProcess,3000);}
  DWORD exitCode=0;GetExitCodeProcess(pi.hProcess,&exitCode);CloseHandle(pi.hProcess);std::string output;char buffer[2048];DWORD received=0;while(ReadFile(stdoutRead,buffer,sizeof(buffer),&received,nullptr)&&received&&output.size()<16384)output.append(buffer,received);CloseHandle(stdoutRead);RestoreEnvironment(environment);
  bool valid=sent&&written==request.size()&&!timedOut&&exitCode==0&&output.find("PowerShell Guardian MCP Bridge")!=std::string::npos&&output.find("\"version\":\"1.1.4\"")!=std::string::npos;
  if(valid){AppendFileUtf8(TunnelLogPath(),"[PowerShell Guardian] MCP bridge initialize response PASS; direct stdio process remained valid until EOF.\r\n");Audit("SYSTEM","MCP BRIDGE PREFLIGHT","LOCAL","PASS");return true;}
  std::string safeOutput=output.size()>2000?output.substr(0,2000):output;AppendFileUtf8(TunnelLogPath(),"ERROR: MCP bridge preflight failed. started=1 sent="+std::to_string(sent?1:0)+" timeout="+std::to_string(timedOut?1:0)+" exit_code="+std::to_string(exitCode)+" output="+safeOutput+"\r\n");Audit("SYSTEM","MCP BRIDGE PREFLIGHT","LOCAL","FAILED "+std::to_string(exitCode));return false;
}

static std::wstring TunnelProfileName(const std::wstring& mcpCommand){
  std::string fingerprint=Sha256(WideToUtf8(g_tunnelId+L"|"+mcpCommand));if(fingerprint.size()<16)fingerprint="profile0000000000";
  return L"powershell-guardian-"+Utf8ToWide(fingerprint.substr(0,16));
}

static bool PrepareAndVerifyTunnelProfile(const std::wstring& exe,const std::wstring& mcpCommand,std::wstring& profile){
  profile=TunnelProfileName(mcpCommand);
  auto environment=SetTunnelEnvironment();
  std::wstring initArguments=L"init --force --sample sample_mcp_stdio_local --profile "+CommandLineQuote(profile)+L" --tunnel-id "+CommandLineQuote(g_tunnelId)+L" --mcp-command "+CommandLineQuote(mcpCommand);
  ProcessResult initialized=RunTunnelTool(exe,initArguments,"PROFILE INIT",60000);
  if(!initialized.started||initialized.timedOut){RestoreEnvironment(environment);Audit("SYSTEM","TUNNEL PROFILE INIT","LOCAL","FAILED");return false;}
  if(initialized.exitCode!=0){RestoreEnvironment(environment);AppendFileUtf8(TunnelLogPath(),"ERROR: PROFILE INIT could not replace the deterministic PowerShell Guardian profile.\r\n");Audit("SYSTEM","TUNNEL PROFILE INIT","LOCAL","FAILED "+std::to_string(initialized.exitCode));return false;}
  if(g_tunnelStatus){SetWindowTextW(g_tunnelStatus,L"Tunnel: Verifying profile");UpdateWindow(g_tunnelStatus);}if(g_mcpStatus){SetWindowTextW(g_mcpStatus,L"MCP Server: Checking bridge");UpdateWindow(g_mcpStatus);}
  ProcessResult doctor=RunTunnelTool(exe,L"doctor --profile "+CommandLineQuote(profile)+L" --explain","PROFILE DOCTOR",90000);RestoreEnvironment(environment);
  if(!doctor.started||doctor.timedOut||doctor.exitCode!=0){Audit("SYSTEM","TUNNEL PROFILE DOCTOR","LOCAL","FAILED");return false;}
  WriteFileUtf8(g_base+L"\\config\\tunnel-profile.txt",WideToUtf8(profile+L"\r\n"+g_tunnelId+L"\r\n"));
  AppendFileUtf8(TunnelLogPath(),"[PowerShell Guardian] Profile saved and doctor preflight passed.\r\n");Audit("SYSTEM","TUNNEL PROFILE DOCTOR","LOCAL","PASS");return true;
}

static std::wstring TunnelFailureDetails(){
  std::string log=ReadFileUtf8(TunnelLogPath());std::string key=WideToUtf8(g_apiKey);if(!key.empty()){size_t p=0;while((p=log.find(key,p))!=std::string::npos){log.replace(p,key.size(),"[REDACTED]");p+=10;}}
  std::istringstream lines(log);std::string line;std::vector<std::string> important;
  while(std::getline(lines,line)){std::string lower=line;std::transform(lower.begin(),lower.end(),lower.begin(),[](unsigned char c){return (char)tolower(c);});
    bool relevant=lower.find("\"level\":\"error\"")!=std::string::npos||lower.find("\"level\":\"warn\"")!=std::string::npos||lower.rfind("error:",0)==0||lower.find("[powershell guardian]")!=std::string::npos;
    if(relevant){if(line.size()>1400)line.resize(1400);important.push_back(line);if(important.size()>12)important.erase(important.begin());}}
  std::string summary;for(const auto& item:important)summary+=item+"\r\n";std::string tail=log.size()>2500?log.substr(log.size()-2500):log;
  std::wstring message=L"Tunela ni bilo mogoče pripraviti. PowerShell Guardian je preveril neposredni MCP bridge, profil in tunnel-client.\n\n";
  if(!summary.empty())message+=L"Ključne diagnostične vrstice:\n"+Utf8ToWide(summary)+L"\n";
  if(!tail.empty())message+=L"Zadnji del zapisa:\n"+Utf8ToWide(tail)+L"\n\n";
  message+=L"Celoten zapis:\n"+TunnelLogPath()+L"\n\nNapaka stdio MCP procesa, 401/403 ali težava z vrati je zdaj prikazana med ključnimi vrsticami.";return message;
}

static void ShowTunnelFailure(HWND owner){std::wstring message=TunnelFailureDetails();MessageBoxW(owner,message.c_str(),APP_NAME,MB_OK|MB_ICONERROR);}

static bool StartTunnel() {
  if(TunnelAlive())return true;
  g_tunnelReady=false;
  if(g_apiKey.empty()||!ValidTunnelId(g_tunnelId))return false;
  if(g_tunnelStatus){SetWindowTextW(g_tunnelStatus,L"Tunnel: Preparing profile");UpdateWindow(g_tunnelStatus);}if(g_mcpStatus){SetWindowTextW(g_mcpStatus,L"MCP Server: Preflight");UpdateWindow(g_mcpStatus);}
  std::wstring exe=FindTunnelClient(),bridgeExecutable=BridgeExecutablePath();
  if(!ExistingFile(bridgeExecutable)){WriteFileUtf8(TunnelLogPath(),"ERROR: PowerShellGuardianBridge.exe is missing. Run PowerShellGuardianSetup.exe 1.1.4 or newer.\r\n");return false;}
  if(exe.empty()&&!g_headless&&MessageBoxW(g_main,L"tunnel-client.exe was not found. Select your existing tunnel-client.exe now?",APP_NAME,MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON1)==IDYES&&ChooseTunnelClient())exe=FindTunnelClient();
  if(exe.empty()){WriteFileUtf8(TunnelLogPath(),"ERROR: tunnel-client.exe was not found. Install PowerShellGuardianSetup.exe or select the existing executable.\r\n");return false;}
  g_tunnelClientPath=exe;SaveTunnelConfig();
  WriteFileUtf8(TunnelLogPath(),"PowerShell Guardian 1.1.4\r\nTunnel client: "+WideToUtf8(exe)+"\r\nBridge target: "+WideToUtf8(bridgeExecutable)+"\r\nStartup mode: direct console bridge through official named stdio profile\r\n");
  if(!VerifyBridgeProtocol(bridgeExecutable))return false;
  std::wstring mcpCommand=TunnelStdioCommand(bridgeExecutable),profile;if(!PrepareAndVerifyTunnelProfile(exe,mcpCommand,profile))return false;
  std::wstring cmd=CommandLineQuote(exe)+L" run --profile "+CommandLineQuote(profile)+L" --health.listen-addr=127.0.0.1:17655";
  auto environment=SetTunnelEnvironment();
  SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};HANDLE log=CreateFileW(TunnelLogPath().c_str(),FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,&sa,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);HANDLE inputRead=nullptr,inputWrite=nullptr;
  if(!CreatePipe(&inputRead,&inputWrite,&sa,0)||!SetHandleInformation(inputWrite,HANDLE_FLAG_INHERIT,0)){DWORD pipeError=GetLastError();if(inputRead)CloseHandle(inputRead);if(inputWrite)CloseHandle(inputWrite);if(log!=INVALID_HANDLE_VALUE)CloseHandle(log);RestoreEnvironment(environment);AppendFileUtf8(TunnelLogPath(),"ERROR: could not create persistent tunnel stdin pipe. Windows error "+std::to_string(pipeError)+".\r\n");return false;}
  if(log!=INVALID_HANDLE_VALUE){std::string header="PowerShell Guardian 1.1.4\r\nTunnel client: "+WideToUtf8(exe)+"\r\nProfile: "+WideToUtf8(profile)+"\r\nMCP command: "+WideToUtf8(mcpCommand)+"\r\nBridge target: "+WideToUtf8(bridgeExecutable)+"\r\nPersistent stdin: enabled\r\nReadiness policy: non-destructive background polling\r\n";DWORD written=0;WriteFile(log,header.data(),(DWORD)header.size(),&written,nullptr);}
  std::vector<wchar_t> c(cmd.begin(),cmd.end());c.push_back(0);STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};si.dwFlags=STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;si.wShowWindow=SW_HIDE;si.hStdInput=inputRead;si.hStdOutput=log==INVALID_HANDLE_VALUE?nullptr:log;si.hStdError=log==INVALID_HANDLE_VALUE?nullptr:log;
  HANDLE tunnelJob=CreateTunnelJob();
  BOOL ok=CreateProcessW(exe.c_str(),c.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW|CREATE_SUSPENDED,nullptr,g_install.c_str(),&si,&pi);DWORD createError=ok?ERROR_SUCCESS:GetLastError();CloseHandle(inputRead);if(log!=INVALID_HANDLE_VALUE)CloseHandle(log);
  bool assigned=ok&&tunnelJob&&AssignProcessToJobObject(tunnelJob,pi.hProcess);if(ok){if(!assigned)AppendFileUtf8(TunnelLogPath(),"WARNING: tunnel process job isolation could not be enabled.\r\n");ResumeThread(pi.hThread);g_tunnelStdinWrite=inputWrite;}else CloseHandle(inputWrite);if(!assigned&&tunnelJob){CloseHandle(tunnelJob);tunnelJob=nullptr;}
  RestoreEnvironment(environment);
  if(!ok){std::wstring error=L"ERROR CreateProcess "+std::to_wstring(createError)+L": "+WindowsErrorText(createError)+L"\r\n";AppendFileUtf8(TunnelLogPath(),WideToUtf8(error));Audit("SYSTEM","START TUNNEL","LOCAL","ERROR "+std::to_string(createError));return false;}CloseHandle(pi.hThread);g_tunnelProcess=pi.hProcess;g_tunnelJob=tunnelJob;g_tunnelPid=pi.dwProcessId;
  for(int stable=0;stable<6;stable++){Sleep(500);if(!TunnelAlive()){Audit("SYSTEM","VERIFY TUNNEL","LOCAL","PROCESS EXITED DURING STARTUP");return false;}}
  bool ready=CheckTunnelEndpoint("/readyz",1);bool healthy=ready&&CheckTunnelEndpoint("/healthz",1);g_tunnelReady=ready&&healthy;
  Audit("SYSTEM","START TUNNEL","LOCAL",g_tunnelReady?"READY":"RUNNING - READINESS PENDING");return true;
}

static void SetText(HWND h,const std::wstring&s){SetWindowTextW(h,s.c_str());}
static void AddColumn(HWND h,int index,const wchar_t* name,int width){LVCOLUMNW c{};c.mask=LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM;c.pszText=(LPWSTR)name;c.cx=width;c.iSubItem=index;ListView_InsertColumn(h,index,&c);}
static void AddCell(HWND h,int row,int col,const std::wstring&text){LVITEMW item{};item.iSubItem=col;item.pszText=(LPWSTR)text.c_str();if(col==0){item.mask=LVIF_TEXT;item.iItem=row;SendMessageW(h,LVM_INSERTITEMW,0,(LPARAM)&item);}else{item.iItem=row;SendMessageW(h,LVM_SETITEMTEXTW,(WPARAM)row,(LPARAM)&item);}}

static void RefreshUi(){
  if(!g_main)return;
  bool alive=TunnelAlive();if(alive&&!g_tunnelReady){bool ready=CheckTunnelEndpoint("/readyz",1);bool healthy=ready&&CheckTunnelEndpoint("/healthz",1);if(ready&&healthy){g_tunnelReady=true;Audit("SYSTEM","VERIFY TUNNEL","LOCAL","READY");}}
  std::lock_guard<std::mutex> lock(g_mutex);ListView_DeleteAllItems(g_sessions);ListView_DeleteAllItems(g_commands);long long now=Now();int row=0,active=0,pending=0;
  for(auto&s:g_sessionData){std::wstring status=s.suspiciousTerminated?L"TERMINATED: SUSPICIOUS":s.denied?L"DENIED":!s.approved?L"WAITING":s.expires<=now?L"EXPIRED":L"ACTIVE";if(status==L"ACTIVE")active++;
    std::wstring access=s.unattended?L"\U0001F513 Unlocked":L"\U0001F512 Approval";
    AddCell(g_sessions,row,0,Utf8ToWide(s.id));AddCell(g_sessions,row,1,Utf8ToWide(s.code));AddCell(g_sessions,row,2,status);AddCell(g_sessions,row,3,access);AddCell(g_sessions,row,4,std::to_wstring(std::max(0LL,(s.expires-now)/60)));row++;}
  row=0;for(auto&c:g_commandData){if(c.status=="WAITING APPROVAL")pending++;AddCell(g_commands,row,0,Utf8ToWide(c.id));AddCell(g_commands,row,1,Utf8ToWide(c.name));AddCell(g_commands,row,2,Utf8ToWide(c.risk));AddCell(g_commands,row,3,Utf8ToWide(c.status));AddCell(g_commands,row,4,Utf8ToWide(c.sessionId));row++;}
  alive=TunnelAlive();SetText(g_tunnelStatus,std::wstring(L"Tunnel: ")+(alive?L"Running":L"Stopped"));SetText(g_mcpStatus,std::wstring(L"MCP Server: ")+(!alive?L"Stopped":g_tunnelReady?L"Ready":L"Connecting"));
  SetText(g_gatewayStatus,std::wstring(L"Security Gateway: ")+(g_emergency?L"LOCKED":g_serverRunning?L"Active":L"Disabled"));SetText(g_sessionCount,L"Active Sessions: "+std::to_wstring(active));SetText(g_pendingCount,L"Pending Commands: "+std::to_wstring(pending));
}

static int Selected(HWND h){return ListView_GetNextItem(h,-1,LVNI_SELECTED);}

static void ApproveNewestSession(){
  std::string code,id;{std::lock_guard<std::mutex> lock(g_mutex);for(int i=(int)g_sessionData.size()-1;i>=0;i--)if(!g_sessionData[i].approved&&!g_sessionData[i].denied){code=g_sessionData[i].code;id=g_sessionData[i].id;break;}}
  if(id.empty())return;
  std::wstring msg=L"Nova ChatGPT seja zahteva dovoljenje\n\nVerification Code: "+Utf8ToWide(code)+L"\n\nAPPROVE SESSION?";
  int answer=MessageBoxW(g_main,msg.c_str(),APP_NAME,MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2|MB_TOPMOST);
  {std::lock_guard<std::mutex> lock(g_mutex);Session* session=FindSessionIdUnsafe(id);if(!session||session->approved||session->denied)return;
    if(answer==IDYES){session->approved=true;session->token=RandomSessionToken();session->deviceHash=DeviceHash();session->tokenHash=Sha256(session->token+"|"+session->deviceHash);TouchSession(*session);Audit(session->id,"SESSION TRANSITION","WAITING_APPROVAL -> LOCKED","token_ref "+session->tokenHash.substr(0,16));SaveSessions();}
    else{session->denied=true;Audit(session->id,"SESSION TRANSITION","WAITING_APPROVAL -> DENIED","no access granted");}}
  RefreshUi();
}

static void DecideCommand(bool approve){
  int row=Selected(g_commands);if(row<0){MessageBoxW(g_main,L"Select a pending command first.",APP_NAME,MB_OK|MB_ICONINFORMATION);return;}
  std::string id;{std::lock_guard<std::mutex> lock(g_mutex);if(row>=(int)g_commandData.size())return;id=g_commandData[row].id;PendingCommand* command=FindCommandIdUnsafe(id);if(!command||command->status!="WAITING APPROVAL")return;
    if(!approve){command->status="REJECTED";command->result="Rejected locally";Audit(command->sessionId,command->name,"REJECTED",command->result);}}
  if(!approve){RefreshUi();return;}
  std::wstring details,caption=L"PowerShell Guardian - Local Approval";{std::lock_guard<std::mutex> lock(g_mutex);PendingCommand* command=FindCommandIdUnsafe(id);if(!command||command->status!="WAITING APPROVAL")return;Session* session=FindSessionIdUnsafe(command->sessionId);if(!session||!session->approved||session->denied||session->expires<=Now()){command->status="REJECTED";command->result="Session is no longer active";if(g_main)PostMessageW(g_main,WM_MS_REFRESH,0,0);return;}bool deletion=command->risk=="DELETE";if(deletion){caption=L"PowerShell Guardian - File Deletion Approval";details=L"FILE DELETION REQUIRES YOUR LOCAL APPROVAL\n\nCOMMAND: "+Utf8ToWide(command->name)+L"\nSOURCE: ChatGPT\n\nTARGET / COMMAND:\n"+Utf8ToWide(command->payload)+L"\n\nAllow this file deletion?";}else details=L"COMMAND: "+Utf8ToWide(command->name)+L"\n\nSOURCE: ChatGPT\nRISK: "+Utf8ToWide(command->risk)+L"\n\n"+Utf8ToWide(command->payload)+L"\n\nExecute this command?";}
  if(MessageBoxW(g_main,details.c_str(),caption.c_str(),MB_ICONWARNING|MB_YESNO|MB_DEFBUTTON2|MB_TOPMOST|MB_SETFOREGROUND)!=IDYES){{std::lock_guard<std::mutex> lock(g_mutex);for(auto&c:g_commandData)if(c.id==id){c.status="REJECTED";c.result="Rejected locally";Audit(c.sessionId,c.name,"REJECTED",c.result);}}RefreshUi();return;}
  {std::lock_guard<std::mutex> lock(g_mutex);PendingCommand* command=FindCommandIdUnsafe(id);if(!command||command->status!="WAITING APPROVAL")return;Session* session=FindSessionIdUnsafe(command->sessionId);if(!session||!session->approved||session->denied){command->status="REJECTED";command->result="Session is no longer active";if(g_main)PostMessageW(g_main,WM_MS_REFRESH,0,0);return;}TouchSession(*session);command->status="RUNNING";SaveSessions();}RefreshUi();
  std::thread([id]{PendingCommand copy;bool found=false;{std::lock_guard<std::mutex> lock(g_mutex);PendingCommand* command=FindCommandIdUnsafe(id);if(command){copy=*command;found=true;}}if(!found)return;
    std::string result=ExecuteApproved(copy);{std::lock_guard<std::mutex> lock(g_mutex);for(auto&c:g_commandData)if(c.id==id){c.result=result;c.status=result.rfind("ERROR",0)==0||result.rfind("BLOCKED",0)==0?"FAILED":"SUCCESS";Session* session=FindSessionIdUnsafe(c.sessionId);if(session&&session->approved&&!session->denied)TouchSession(*session);Audit(c.sessionId,c.name,"APPROVED",c.status);SaveSessions();}}
    if(g_main)PostMessageW(g_main,WM_MS_REFRESH,0,0);
  }).detach();
}

static void PromptNewestCommand(){
  RefreshUi();
  int row=-1;
  {std::lock_guard<std::mutex> lock(g_mutex);for(int i=(int)g_commandData.size()-1;i>=0;--i)if(g_commandData[i].status=="WAITING APPROVAL"){row=i;break;}}
  if(row<0)return;
  ListView_SetItemState(g_commands,row,LVIS_SELECTED|LVIS_FOCUSED,LVIS_SELECTED|LVIS_FOCUSED);
  ListView_EnsureVisible(g_commands,row,FALSE);
  if(IsIconic(g_main))ShowWindow(g_main,SW_RESTORE);
  BringWindowToTop(g_main);
  SetForegroundWindow(g_main);
  DecideCommand(true);
}

static void DeleteSelectedSession(){int row=Selected(g_sessions);if(row<0)return;std::lock_guard<std::mutex> lock(g_mutex);if(row<(int)g_sessionData.size()){std::string id=g_sessionData[row].id;RejectWaitingCommandsUnsafe(id,"Session revoked locally");Audit(id,"SESSION TRANSITION","ACTIVE -> REVOKED","deleted locally");g_sessionData.erase(g_sessionData.begin()+row);SaveSessions();}}
static void DeleteAllSessions(){std::lock_guard<std::mutex> lock(g_mutex);for(auto&s:g_sessionData){RejectWaitingCommandsUnsafe(s.id,"All sessions revoked locally");Audit(s.id,"SESSION TRANSITION","ACTIVE -> REVOKED","delete all");}g_sessionData.clear();SaveSessions();}

static void ClearFinishedCommands(){
  std::lock_guard<std::mutex> lock(g_mutex);size_t before=g_commandData.size();
  g_commandData.erase(std::remove_if(g_commandData.begin(),g_commandData.end(),[](const PendingCommand& command){return command.status=="SUCCESS"||command.status=="REJECTED";}),g_commandData.end());
  size_t removed=before-g_commandData.size();Audit("SYSTEM","CLEAR COMMAND HISTORY","LOCAL","removed "+std::to_string(removed)+" SUCCESS/REJECTED entries");
}

static void ToggleSelectedSessionAccess(){
  int row=Selected(g_sessions);if(row<0){MessageBoxW(g_main,L"Select an active session first.",APP_NAME,MB_OK|MB_ICONINFORMATION);return;}
  bool unlocking=false;std::string id;{
    std::lock_guard<std::mutex> lock(g_mutex);if(row>=(int)g_sessionData.size())return;Session& s=g_sessionData[row];
    if(!s.approved||s.denied||s.expires<=Now()){MessageBoxW(g_main,L"Only an active approved session can be unlocked.",APP_NAME,MB_OK|MB_ICONWARNING);return;}
    unlocking=!s.unattended;id=s.id;
  }
  if(unlocking){
    std::wstring warning=L"Unlock only this session?\n\nAll commands from this session will run without local approval, except file deletion commands. File creation remains limited to "+std::to_wstring(g_fileLimit)+L" files per "+std::to_wstring(g_fileWindowMinutes)+L" minutes. Repeated maximum-rate creation can terminate the session.";
    if(MessageBoxW(g_main,warning.c_str(),L"PowerShell Guardian - Unlock Session",MB_ICONWARNING|MB_YESNO|MB_DEFBUTTON2)!=IDYES)return;
  }
  {std::lock_guard<std::mutex> lock(g_mutex);for(auto& s:g_sessionData)if(s.id==id){bool wasUnlocked=s.unattended;s.unattended=unlocking;TouchSession(s);ResetFileSafetyState(s);Audit(s.id,"SESSION TRANSITION",wasUnlocked?"UNLOCKED -> LOCKED":"LOCKED -> UNLOCKED",(unlocking?"same token preserved; deletion still requires approval; file safety counters reset; token_ref ":"same token preserved; approval restored; file safety inactive and reset; token_ref ")+s.tokenHash.substr(0,16));SaveSessions();break;}}
  RefreshUi();
}

static bool ReadIntSetting(HWND owner,const wchar_t* label,int current,int minimum,int maximum,int& output){
  std::wstring value=std::to_wstring(current);if(!InputBox(owner,L"Security Settings",label,value))return false;
  wchar_t* end=nullptr;long parsed=wcstol(value.c_str(),&end,10);if(!end||*end||parsed<minimum||parsed>maximum){MessageBoxW(owner,L"The value is outside the allowed range.",APP_NAME,MB_OK|MB_ICONERROR);return false;}output=(int)parsed;return true;
}

static bool SaveSecuritySettings(){
  std::ostringstream json;json<<"{\n  \"session_timeout_minutes\": "<<g_timeoutMinutes<<",\n  \"session_request_limit\": "<<g_sessionRequestLimit<<",\n  \"session_request_window_minutes\": "<<g_sessionRequestWindowMinutes<<",\n  \"unattended_file_limit\": "<<g_fileLimit<<",\n  \"unattended_file_window_minutes\": "<<g_fileWindowMinutes<<",\n  \"suspicious_full_windows\": "<<g_suspiciousFullWindows<<",\n  \"suspicious_guard_enabled\": "<<(g_suspiciousGuardEnabled?"true":"false")<<"\n}\n";
  return WriteFileUtf8(g_base+L"\\config\\security.local.json",json.str());
}

static void ConfigureSecurity(HWND owner){
  int timeout=g_timeoutMinutes,requestLimit=g_sessionRequestLimit,requestWindow=g_sessionRequestWindowMinutes,limit=g_fileLimit,window=g_fileWindowMinutes,streak=g_suspiciousFullWindows;
  if(!ReadIntSetting(owner,L"Session inactivity cleanup in minutes (30-1440):",timeout,30,1440,timeout))return;
  if(!ReadIntSetting(owner,L"Maximum new session requests in one session-request window (1-100):",requestLimit,1,100,requestLimit))return;
  if(!ReadIntSetting(owner,L"Session-request window in minutes (1-1440):",requestWindow,1,1440,requestWindow))return;
  if(!ReadIntSetting(owner,L"Maximum files an unlocked session may create in one window (1-100):",limit,1,100,limit))return;
  if(!ReadIntSetting(owner,L"File creation window in minutes (1-1440):",window,1,1440,window))return;
  if(!ReadIntSetting(owner,L"Full consecutive windows before suspicious-session termination (2-20):",streak,2,20,streak))return;
  int guard=MessageBoxW(owner,L"Enable automatic termination for repeated maximum-rate file creation?",L"PowerShell Guardian - Main Safety Guard",MB_ICONQUESTION|MB_YESNOCANCEL|MB_DEFBUTTON1);if(guard==IDCANCEL)return;
  bool saved=false;{std::lock_guard<std::mutex> lock(g_mutex);bool filePolicyChanged=limit!=g_fileLimit||window!=g_fileWindowMinutes||streak!=g_suspiciousFullWindows;bool requestPolicyChanged=requestLimit!=g_sessionRequestLimit||requestWindow!=g_sessionRequestWindowMinutes;
    g_timeoutMinutes=timeout;g_sessionRequestLimit=requestLimit;g_sessionRequestWindowMinutes=requestWindow;g_fileLimit=limit;g_fileWindowMinutes=window;g_suspiciousFullWindows=streak;g_suspiciousGuardEnabled=guard==IDYES;
    if(filePolicyChanged)for(auto& session:g_sessionData)ResetFileSafetyState(session);
    if(requestPolicyChanged)g_sessionRequestTimes.clear();
    saved=SaveSecuritySettings();
    SaveSessions();}
  if(!saved){MessageBoxW(owner,L"Security settings could not be saved.",APP_NAME,MB_OK|MB_ICONERROR);return;}
  Audit("SYSTEM","SECURITY SETTINGS","LOCAL","timeout "+std::to_string(timeout)+", session requests "+std::to_string(requestLimit)+" per "+std::to_string(requestWindow)+" minutes, file limit "+std::to_string(limit)+" per "+std::to_string(window)+" minutes, suspicious windows "+std::to_string(streak)+", guard "+(guard==IDYES?"enabled":"disabled"));
}

static void ChangeApiKey(){std::wstring v; if(InputBox(g_main,L"Change API Key",L"Enter the complete tunnel/runtime API key (stored with Windows DPAPI):",v,true)){while(!v.empty()&&iswspace(v.front()))v.erase(v.begin());while(!v.empty()&&iswspace(v.back()))v.pop_back();if(v.size()<8){MessageBoxW(g_main,L"API key is too short. Paste the complete key.",APP_NAME,MB_OK|MB_ICONERROR);return;}if(!SaveSecret(L"api.key",v)){MessageBoxW(g_main,L"API key could not be saved to the protected configuration.",APP_NAME,MB_OK|MB_ICONERROR);return;}g_apiKey=v;Audit("SYSTEM","CHANGE API KEY","LOCAL","SUCCESS");MessageBoxW(g_main,L"API key saved securely. It will remain stored until you use Change API Key again.",APP_NAME,MB_OK|MB_ICONINFORMATION);}}
static void ChangeTunnel(){
  std::wstring v=g_tunnelId;if(!InputBox(g_main,L"Change Tunnel ID",L"Paste Tunnel ID (stored with Windows DPAPI until you change it):",v,false))return;v=NormalizeTunnelId(v);
  if(!ValidTunnelId(v)){MessageBoxW(g_main,L"Tunnel ID is not recognized. Paste the complete value. Supported forms:\n\ntunnel_<32 hexadecimal characters>\n<32 hexadecimal characters>\n<UUID with 32 hexadecimal characters>",APP_NAME,MB_OK|MB_ICONERROR);return;}
  if(!SaveSecret(L"tunnel.id",v)||NormalizeTunnelId(LoadSecret(L"tunnel.id"))!=v){MessageBoxW(g_main,L"Tunnel ID could not be saved or verified in the protected configuration.",APP_NAME,MB_OK|MB_ICONERROR);return;}
  bool was=TunnelAlive();std::wstring oldId=g_tunnelId,oldProfile;
  if(ValidTunnelId(oldId)){std::wstring directBridgeCommand=TunnelStdioCommand(BridgeExecutablePath());oldProfile=TunnelProfileName(directBridgeCommand);}
  StopTunnel("CHANGE ID");g_tunnelId=v;
  if(oldId!=v&&!oldProfile.empty()){DeleteFileW((g_base+L"\\tunnel-client-config\\"+oldProfile+L".yaml").c_str());DeleteFileW((g_base+L"\\config\\tunnel-profile.txt").c_str());}
  SaveTunnelConfig();Audit("SYSTEM","CHANGE TUNNEL ID","LOCAL","SUCCESS");
  if(was){if(!StartTunnel())ShowTunnelFailure(g_main);}else MessageBoxW(g_main,L"Tunnel ID saved and verified with Windows DPAPI. It will remain stored until you use Change Tunnel ID again.",APP_NAME,MB_OK|MB_ICONINFORMATION);RefreshUi();
}

static void EmergencyLock(){if(MessageBoxW(g_main,L"EMERGENCY LOCK will stop the tunnel, revoke every session and reject pending commands. Continue?",L"PowerShell Guardian - EMERGENCY LOCK",MB_ICONSTOP|MB_YESNO|MB_DEFBUTTON2)!=IDYES)return;{std::lock_guard<std::mutex> lock(g_mutex);g_emergency=true;for(auto& session:g_sessionData)RejectWaitingCommandsUnsafe(session.id,"Emergency lock");}StopTunnel("EMERGENCY LOCK");{std::lock_guard<std::mutex> lock(g_mutex);for(auto& session:g_sessionData)Audit(session.id,"SESSION TRANSITION","ACTIVE -> REVOKED","emergency lock");g_sessionData.clear();SaveSessions();Audit("SYSTEM","EMERGENCY LOCK","LOCAL","ALL ACCESS BLOCKED");}RefreshUi();}

static HWND Button(HWND p,const wchar_t*t,int id,int x,int y,int w=125,int h=30){return CreateWindowW(L"BUTTON",t,WS_CHILD|WS_VISIBLE|WS_TABSTOP,x,y,w,h,p,(HMENU)(INT_PTR)id,g_instance,nullptr);}
static HWND Label(HWND p,const wchar_t*t,int id,int x,int y,int w=190){return CreateWindowW(L"STATIC",t,WS_CHILD|WS_VISIBLE,x,y,w,22,p,(HMENU)(INT_PTR)id,g_instance,nullptr);}

static LRESULT CALLBACK MainProc(HWND h,UINT m,WPARAM w,LPARAM l){
  switch(m){
  case WM_CREATE:{HFONT font=(HFONT)GetStockObject(DEFAULT_GUI_FONT);CreateWindowW(L"STATIC",L"PowerShell Guardian Control Center — Version 1.1.4",WS_CHILD|WS_VISIBLE,20,16,450,28,h,nullptr,g_instance,nullptr);
    g_tunnelStatus=Label(h,L"Tunnel: Stopped",ID_STATUS_TUNNEL,20,55);g_mcpStatus=Label(h,L"MCP Server: Stopped",ID_STATUS_MCP,220,55);g_gatewayStatus=Label(h,L"Security Gateway: Active",ID_STATUS_GATEWAY,420,55,230);g_sessionCount=Label(h,L"Active Sessions: 0",ID_STATUS_SESSIONS,670,55);g_pendingCount=Label(h,L"Pending Commands: 0",ID_STATUS_PENDING,830,55);
    Button(h,L"Start System",ID_START,20,86);Button(h,L"Stop System",ID_STOP,155,86);Button(h,L"Restart System",ID_RESTART,290,86);Button(h,L"Change Tunnel ID",ID_TUNNEL_ID,425,86,140);Button(h,L"Change API Key",ID_API_KEY,575,86,140);Button(h,L"Security Settings",ID_SECURITY,725,86,145);Button(h,L"Audit Logs",ID_LOGS,880,86,115);Button(h,L"EMERGENCY LOCK",ID_EMERGENCY,1005,82,155,38);
    CreateWindowW(L"STATIC",L"Active Sessions",WS_CHILD|WS_VISIBLE,20,136,300,22,h,nullptr,g_instance,nullptr);g_sessions=CreateWindowExW(WS_EX_CLIENTEDGE,WC_LISTVIEWW,L"",WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SINGLESEL,20,160,555,270,h,(HMENU)ID_SESSION_LIST,g_instance,nullptr);ListView_SetExtendedListViewStyle(g_sessions,LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES);AddColumn(g_sessions,0,L"Session ID",165);AddColumn(g_sessions,1,L"Code",55);AddColumn(g_sessions,2,L"Status",155);AddColumn(g_sessions,3,L"Access",120);AddColumn(g_sessions,4,L"Min",55);
    Button(h,L"Unlock / Lock Session",ID_TOGGLE_UNATTENDED,20,440,190);Button(h,L"Delete Selected",ID_DELETE_SESSION,220,440,145);Button(h,L"Delete All",ID_DELETE_ALL,375,440,120);
    CreateWindowW(L"STATIC",L"Pending Command Center",WS_CHILD|WS_VISIBLE,595,136,300,22,h,nullptr,g_instance,nullptr);g_commands=CreateWindowExW(WS_EX_CLIENTEDGE,WC_LISTVIEWW,L"",WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SINGLESEL,595,160,565,270,h,(HMENU)ID_COMMAND_LIST,g_instance,nullptr);ListView_SetExtendedListViewStyle(g_commands,LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES);AddColumn(g_commands,0,L"Command ID",130);AddColumn(g_commands,1,L"Command",110);AddColumn(g_commands,2,L"Risk",70);AddColumn(g_commands,3,L"Status",145);AddColumn(g_commands,4,L"Session",150);
    Button(h,L"APPROVE",ID_APPROVE,595,440,130);Button(h,L"REJECT",ID_REJECT,735,440,130);Button(h,L"Clear Success/Rejected",ID_CLEAR_FINISHED,875,440,205);
    EnumChildWindows(h,[](HWND c,LPARAM f)->BOOL{SendMessageW(c,WM_SETFONT,(WPARAM)f,TRUE);return TRUE;},(LPARAM)font);SetTimer(h,1,5000,nullptr);return 0;}
  case WM_MS_SESSION:ApproveNewestSession();return 0;case WM_MS_COMMAND:PromptNewestCommand();return 0;case WM_MS_REFRESH:RefreshUi();return 0;case WM_MS_SETUP:if(g_apiKey.size()<8)ChangeApiKey();if(!ValidTunnelId(g_tunnelId))ChangeTunnel();return 0;case WM_TIMER:RefreshUi();return 0;
  case WM_COMMAND:switch(LOWORD(w)){
    case ID_START:if(g_apiKey.size()<8)ChangeApiKey();if(!ValidTunnelId(g_tunnelId))ChangeTunnel();if(g_apiKey.size()>=8&&ValidTunnelId(g_tunnelId)){g_emergency=false;if(!StartTunnel())ShowTunnelFailure(h);}RefreshUi();break;
    case ID_STOP:StopTunnel();RefreshUi();break;case ID_RESTART:StopTunnel("RESTART");if(!StartTunnel())ShowTunnelFailure(h);RefreshUi();break;
    case ID_TUNNEL_ID:ChangeTunnel();break;case ID_API_KEY:ChangeApiKey();break;case ID_TOGGLE_UNATTENDED:ToggleSelectedSessionAccess();break;case ID_DELETE_SESSION:DeleteSelectedSession();RefreshUi();break;case ID_DELETE_ALL:DeleteAllSessions();RefreshUi();break;
    case ID_APPROVE:DecideCommand(true);break;case ID_REJECT:DecideCommand(false);break;case ID_CLEAR_FINISHED:ClearFinishedCommands();RefreshUi();break;case ID_LOGS:{std::wstring logs=g_base+L"\\logs";ShellExecuteW(h,L"open",logs.c_str(),nullptr,nullptr,SW_SHOW);}break;
    case ID_SECURITY:ConfigureSecurity(h);break;
    case ID_EMERGENCY:EmergencyLock();break;}return 0;
  case WM_CLOSE:StopTunnel("APPLICATION CLOSE");DestroyWindow(h);return 0;case WM_DESTROY:g_serverRunning=false;g_shutdownCv.notify_all();PostQuitMessage(0);return 0;}return DefWindowProcW(h,m,w,l);
}

static void CleanupLoop(){while(g_serverRunning){std::unique_lock<std::mutex> waitLock(g_shutdownMutex);if(g_shutdownCv.wait_for(waitLock,std::chrono::seconds(30),[]{return !g_serverRunning.load();}))break;waitLock.unlock();std::lock_guard<std::mutex>lock(g_mutex);long long n=Now();
    for(const auto& session:g_sessionData)if(session.expires<=n)RejectWaitingCommandsUnsafe(session.id,"Session expired");
    auto old=g_sessionData.size();
    g_sessionData.erase(std::remove_if(g_sessionData.begin(),g_sessionData.end(),[n](const Session&s){return (s.denied&&!s.suspiciousTerminated)||s.expires<=n;}),g_sessionData.end());
    g_commandData.erase(std::remove_if(g_commandData.begin(),g_commandData.end(),[n](const PendingCommand& command){return command.status!="WAITING APPROVAL"&&command.status!="RUNNING"&&command.created<n-86400;}),g_commandData.end());
    if(old!=g_sessionData.size())SaveSessions();
    if(g_main)PostMessageW(g_main,WM_MS_REFRESH,0,0);}}

static void InitPaths(){wchar_t p[MAX_PATH]={};SHGetFolderPathW(nullptr,CSIDL_COMMON_APPDATA,nullptr,SHGFP_TYPE_CURRENT,p);g_base=std::wstring(p)+L"\\PowerShellGuardian";std::vector<wchar_t> executable(32768);DWORD executableLength=GetModuleFileNameW(nullptr,executable.data(),(DWORD)executable.size());if(executableLength&&executableLength<executable.size())g_executablePath.assign(executable.data(),executableLength);g_install=g_executablePath;size_t z=g_install.find_last_of(L"\\/");if(z!=std::wstring::npos)g_install.resize(z);EnsureDirs();g_deviceHash=WideToUtf8(LoadSecret(L"device.binding"));if(g_deviceHash.size()!=64||!std::all_of(g_deviceHash.begin(),g_deviceHash.end(),[](unsigned char c){return std::isxdigit(c)!=0;}))g_deviceHash.clear();if(g_deviceHash.empty()){g_deviceHash=ComputeDeviceHash();if(!g_deviceHash.empty()&&!SaveSecret(L"device.binding",Utf8ToWide(g_deviceHash)))AppendFileUtf8(g_base+L"\\logs\\tunnel-client.log","WARNING: stable device binding could not be persisted; it remains stable for this process.\r\n");}LoadWhitelist();g_bridgeSecret=LoadSecret(L"bridge.key");if(g_bridgeSecret.empty()){g_bridgeSecret=Utf8ToWide(RandomToken(48));if(!SaveSecret(L"bridge.key",g_bridgeSecret))AppendFileUtf8(g_base+L"\\logs\\tunnel-client.log","ERROR: protected MCP bridge key could not be persisted; it was regenerated for this process.\r\n");}g_apiKey=LoadSecret(L"api.key");std::string tj=ReadFileUtf8(g_base+L"\\config\\tunnel.json");g_tunnelId=NormalizeTunnelId(LoadSecret(L"tunnel.id"));if(!ValidTunnelId(g_tunnelId)){g_tunnelId=NormalizeTunnelId(Utf8ToWide(JsonGet(tj,"tunnel_id")));if(ValidTunnelId(g_tunnelId))SaveSecret(L"tunnel.id",g_tunnelId);}g_tunnelClientPath=Utf8ToWide(JsonGet(tj,"tunnel_client_path"));
  std::string sj=ReadFileUtf8(g_base+L"\\config\\security.local.json");if(sj.empty())sj=ReadFileUtf8(g_base+L"\\config\\security.json");
  auto readBounded=[&](const char* key,int minimum,int maximum,int& target){std::string value=JsonGet(sj,key);if(value.empty())return;int parsed=atoi(value.c_str());if(parsed>=minimum&&parsed<=maximum)target=parsed;};
  readBounded("session_timeout_minutes",30,1440,g_timeoutMinutes);readBounded("session_request_limit",1,100,g_sessionRequestLimit);readBounded("session_request_window_minutes",1,1440,g_sessionRequestWindowMinutes);readBounded("unattended_file_limit",1,100,g_fileLimit);readBounded("unattended_file_window_minutes",1,1440,g_fileWindowMinutes);readBounded("suspicious_full_windows",2,20,g_suspiciousFullWindows);g_suspiciousGuardEnabled=JsonBool(sj,"suspicious_guard_enabled",true);LoadSessions();}

static void SetServiceState(DWORD state,DWORD error=NO_ERROR){if(!g_serviceHandle)return;g_serviceStatus.dwServiceType=SERVICE_WIN32_OWN_PROCESS;g_serviceStatus.dwCurrentState=state;g_serviceStatus.dwWin32ExitCode=error;g_serviceStatus.dwControlsAccepted=state==SERVICE_RUNNING?SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN:0;SetServiceStatus(g_serviceHandle,&g_serviceStatus);}
static DWORD WINAPI ServiceHandler(DWORD control,DWORD,LPVOID,LPVOID){if(control==SERVICE_CONTROL_STOP||control==SERVICE_CONTROL_SHUTDOWN){SetServiceState(SERVICE_STOP_PENDING);g_serverRunning=false;g_shutdownCv.notify_all();StopActiveCommands("SERVICE STOP");Audit("SYSTEM","SERVICE STOP","LOCAL","SUCCESS");}return NO_ERROR;}
static void WINAPI RealServiceMain(DWORD,LPWSTR*){g_serviceHandle=RegisterServiceCtrlHandlerExW(L"PowerShellGuardianGateway",ServiceHandler,nullptr);if(!g_serviceHandle)return;SetServiceState(SERVICE_START_PENDING);g_headless=true;InitPaths();std::thread server(GatewayServer);for(int i=0;i<100&&!g_serverRunning;i++)Sleep(20);if(!g_serverRunning){SetServiceState(SERVICE_STOPPED,ERROR_SERVICE_NOT_ACTIVE);server.join();return;}Audit("SYSTEM","SERVICE START","LOCAL","HEADLESS - local approvals remain blocked");SetServiceState(SERVICE_RUNNING);CleanupLoop();server.join();SetServiceState(SERVICE_STOPPED);}
static int ServiceMainMode(){SERVICE_TABLE_ENTRYW table[]={{(LPWSTR)L"PowerShellGuardianGateway",RealServiceMain},{nullptr,nullptr}};return StartServiceCtrlDispatcherW(table)?0:(int)GetLastError();}

#ifdef POWERSHELL_GUARDIAN_BRIDGE_CONSOLE
int wmain(){return McpBridgeMain();}
#else
int WINAPI wWinMain(HINSTANCE inst,HINSTANCE,LPWSTR cmd,int){
  g_instance=inst;std::wstring args=cmd?cmd:L"";if(args.find(L"--mcp-bridge")!=std::wstring::npos)return McpBridgeMain();if(args.find(L"--service")!=std::wstring::npos)return ServiceMainMode();
  HANDLE mutex=CreateMutexW(nullptr,TRUE,L"Local\\PowerShellGuardianControlCenter");if(GetLastError()==ERROR_ALREADY_EXISTS){MessageBoxW(nullptr,L"PowerShell Guardian is already running.",APP_NAME,MB_OK|MB_ICONINFORMATION);return 0;}
  InitCommonControls();InitPaths();WNDCLASSW wc{};wc.lpfnWndProc=MainProc;wc.hInstance=inst;wc.hIcon=LoadIcon(nullptr,IDI_SHIELD);wc.hCursor=LoadCursor(nullptr,IDC_ARROW);wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);wc.lpszClassName=L"PowerShellGuardianMain";RegisterClassW(&wc);
  g_main=CreateWindowExW(0,wc.lpszClassName,APP_NAME,WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX|WS_VISIBLE,CW_USEDEFAULT,CW_USEDEFAULT,1200,525,nullptr,nullptr,inst,nullptr);
  if(!g_main){if(mutex){ReleaseMutex(mutex);CloseHandle(mutex);}return (int)GetLastError();}
  std::thread server(GatewayServer);for(int attempt=0;attempt<250&&!g_serverRunning;attempt++)Sleep(20);if(!g_serverRunning){server.join();MessageBoxW(g_main,L"Security Gateway could not start on 127.0.0.1:17654. The port may already be used by the Windows service or another process.",APP_NAME,MB_OK|MB_ICONERROR);DestroyWindow(g_main);if(mutex){ReleaseMutex(mutex);CloseHandle(mutex);}return ERROR_ADDRESS_ALREADY_ASSOCIATED;}
  std::thread cleaner(CleanupLoop);RefreshUi();if(g_apiKey.size()<8||!ValidTunnelId(g_tunnelId))PostMessageW(g_main,WM_MS_SETUP,0,0);
  MSG msg;while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}g_serverRunning=false;server.join();cleaner.join();if(mutex){ReleaseMutex(mutex);CloseHandle(mutex);}SecureZeroMemory(g_apiKey.data(),g_apiKey.size()*sizeof(wchar_t));return (int)msg.wParam;
}
#endif
