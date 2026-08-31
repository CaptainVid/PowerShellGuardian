#include "../src/JsonLite.h"

#include <cassert>
#include <iostream>
#include <string>

int main() {
  using powershellguardian_json::RawField;
  using powershellguardian_json::ScalarField;
  using powershellguardian_json::StringField;

  const std::string call = R"JSON({"jsonrpc":"2.0","id":"call-7","method":"tools/call","params":{"arguments":{"session_token":"TOKEN-ABC","script":"Write-Output \"ok\"\nGet-Date"},"name":"powershell"}})JSON";
  std::string params, arguments, name, token, id;
  assert(RawField(call, "params", params));
  assert(RawField(params, "arguments", arguments));
  assert(StringField(params, "name", name));
  assert(StringField(arguments, "session_token", token));
  assert(RawField(call, "id", id));
  assert(name == "powershell");
  assert(token == "TOKEN-ABC");
  assert(id == "\"call-7\"");
  assert(ScalarField(arguments, "script") == "Write-Output \"ok\"\nGet-Date");

  const std::string gateway = R"JSON({"bridge_key":"secret","action":"command","session_token":"TOKEN-ABC","command":"system_info","payload":""})JSON";
  assert(ScalarField(gateway, "action") == "command");
  assert(ScalarField(gateway, "session_token") == "TOKEN-ABC");
  assert(ScalarField(gateway, "command") == "system_info");

  const std::string lowRisk = R"JSON({"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":"read_logs","arguments":{"session_token":"TOKEN-XYZ"}}})JSON";
  assert(RawField(lowRisk, "params", params));
  assert(StringField(params, "name", name));
  assert(RawField(params, "arguments", arguments));
  assert(StringField(arguments, "session_token", token));
  assert(name == "read_logs");
  assert(token == "TOKEN-XYZ");

  const std::string whitelist = R"JSON({"allowed":["system_info","get_status","read_logs"],"default":"approval_required"})JSON";
  std::vector<std::string> allowed;
  assert(powershellguardian_json::StringArrayField(whitelist, "allowed", allowed));
  assert(allowed.size() == 3);
  assert(allowed[0] == "system_info");
  assert(allowed[2] == "read_logs");

  std::cout << "PowerShellGuardian JSON/MCP protocol regression tests: PASS\n";
}
