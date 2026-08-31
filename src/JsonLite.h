#pragma once

#include <cctype>
#include <string>
#include <vector>

namespace powershellguardian_json {

inline void SkipWhitespace(const std::string& json, size_t& pos) {
  while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) ++pos;
}

inline int HexDigit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

inline void AppendUtf8(std::string& out, unsigned int codepoint) {
  if (codepoint <= 0x7f) out.push_back(static_cast<char>(codepoint));
  else if (codepoint <= 0x7ff) {
    out.push_back(static_cast<char>(0xc0 | (codepoint >> 6)));
    out.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
  } else if (codepoint <= 0xffff) {
    out.push_back(static_cast<char>(0xe0 | (codepoint >> 12)));
    out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
    out.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
  } else {
    out.push_back(static_cast<char>(0xf0 | (codepoint >> 18)));
    out.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3f)));
    out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
    out.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
  }
}

inline bool ParseString(const std::string& json, size_t& pos, std::string& out) {
  SkipWhitespace(json, pos);
  if (pos >= json.size() || json[pos] != '"') return false;
  ++pos;
  out.clear();
  while (pos < json.size()) {
    unsigned char c = static_cast<unsigned char>(json[pos++]);
    if (c == '"') return true;
    if (c < 0x20) return false;
    if (c != '\\') {
      out.push_back(static_cast<char>(c));
      continue;
    }
    if (pos >= json.size()) return false;
    char escaped = json[pos++];
    switch (escaped) {
      case '"': out.push_back('"'); break;
      case '\\': out.push_back('\\'); break;
      case '/': out.push_back('/'); break;
      case 'b': out.push_back('\b'); break;
      case 'f': out.push_back('\f'); break;
      case 'n': out.push_back('\n'); break;
      case 'r': out.push_back('\r'); break;
      case 't': out.push_back('\t'); break;
      case 'u': {
        if (pos + 4 > json.size()) return false;
        unsigned int value = 0;
        for (int i = 0; i < 4; ++i) {
          int digit = HexDigit(json[pos++]);
          if (digit < 0) return false;
          value = (value << 4) | static_cast<unsigned int>(digit);
        }
        if (value >= 0xd800 && value <= 0xdbff) {
          if (pos + 6 > json.size() || json[pos] != '\\' || json[pos + 1] != 'u') return false;
          pos += 2;
          unsigned int low = 0;
          for (int i = 0; i < 4; ++i) {
            int digit = HexDigit(json[pos++]);
            if (digit < 0) return false;
            low = (low << 4) | static_cast<unsigned int>(digit);
          }
          if (low < 0xdc00 || low > 0xdfff) return false;
          value = 0x10000 + ((value - 0xd800) << 10) + (low - 0xdc00);
        } else if (value >= 0xdc00 && value <= 0xdfff) return false;
        AppendUtf8(out, value);
        break;
      }
      default: return false;
    }
  }
  return false;
}

inline bool SkipValue(const std::string& json, size_t& pos) {
  SkipWhitespace(json, pos);
  if (pos >= json.size()) return false;
  if (json[pos] == '"') {
    std::string ignored;
    return ParseString(json, pos, ignored);
  }
  if (json[pos] == '{') {
    ++pos;
    SkipWhitespace(json, pos);
    if (pos < json.size() && json[pos] == '}') { ++pos; return true; }
    while (pos < json.size()) {
      std::string key;
      if (!ParseString(json, pos, key)) return false;
      SkipWhitespace(json, pos);
      if (pos >= json.size() || json[pos++] != ':') return false;
      if (!SkipValue(json, pos)) return false;
      SkipWhitespace(json, pos);
      if (pos < json.size() && json[pos] == ',') { ++pos; continue; }
      if (pos < json.size() && json[pos] == '}') { ++pos; return true; }
      return false;
    }
    return false;
  }
  if (json[pos] == '[') {
    ++pos;
    SkipWhitespace(json, pos);
    if (pos < json.size() && json[pos] == ']') { ++pos; return true; }
    while (pos < json.size()) {
      if (!SkipValue(json, pos)) return false;
      SkipWhitespace(json, pos);
      if (pos < json.size() && json[pos] == ',') { ++pos; continue; }
      if (pos < json.size() && json[pos] == ']') { ++pos; return true; }
      return false;
    }
    return false;
  }
  size_t start = pos;
  while (pos < json.size() && !std::isspace(static_cast<unsigned char>(json[pos])) &&
         json[pos] != ',' && json[pos] != '}' && json[pos] != ']') ++pos;
  return pos > start;
}

inline bool RawField(const std::string& object, const std::string& wanted, std::string& raw) {
  size_t pos = 0;
  SkipWhitespace(object, pos);
  if (pos >= object.size() || object[pos++] != '{') return false;
  SkipWhitespace(object, pos);
  if (pos < object.size() && object[pos] == '}') return false;
  while (pos < object.size()) {
    std::string key;
    if (!ParseString(object, pos, key)) return false;
    SkipWhitespace(object, pos);
    if (pos >= object.size() || object[pos++] != ':') return false;
    SkipWhitespace(object, pos);
    size_t valueStart = pos;
    if (!SkipValue(object, pos)) return false;
    if (key == wanted) {
      raw = object.substr(valueStart, pos - valueStart);
      return true;
    }
    SkipWhitespace(object, pos);
    if (pos < object.size() && object[pos] == ',') { ++pos; continue; }
    if (pos < object.size() && object[pos] == '}') return false;
    return false;
  }
  return false;
}

inline bool StringField(const std::string& object, const std::string& key, std::string& value) {
  std::string raw;
  if (!RawField(object, key, raw)) return false;
  size_t pos = 0;
  if (!ParseString(raw, pos, value)) return false;
  SkipWhitespace(raw, pos);
  return pos == raw.size();
}

inline std::string ScalarField(const std::string& object, const std::string& key) {
  std::string raw, value;
  if (!RawField(object, key, raw)) return "";
  size_t pos = 0;
  if (ParseString(raw, pos, value)) return value;
  size_t begin = 0, end = raw.size();
  while (begin < end && std::isspace(static_cast<unsigned char>(raw[begin]))) ++begin;
  while (end > begin && std::isspace(static_cast<unsigned char>(raw[end - 1]))) --end;
  return raw.substr(begin, end - begin);
}

inline bool StringArrayField(const std::string& object, const std::string& key,
                             std::vector<std::string>& values) {
  std::string raw;
  if (!RawField(object, key, raw)) return false;
  size_t pos = 0;
  SkipWhitespace(raw, pos);
  if (pos >= raw.size() || raw[pos++] != '[') return false;
  values.clear();
  SkipWhitespace(raw, pos);
  if (pos < raw.size() && raw[pos] == ']') {
    ++pos;
    SkipWhitespace(raw, pos);
    return pos == raw.size();
  }
  while (pos < raw.size()) {
    std::string value;
    if (!ParseString(raw, pos, value)) return false;
    values.push_back(value);
    SkipWhitespace(raw, pos);
    if (pos < raw.size() && raw[pos] == ',') { ++pos; continue; }
    if (pos < raw.size() && raw[pos] == ']') {
      ++pos;
      SkipWhitespace(raw, pos);
      return pos == raw.size();
    }
    return false;
  }
  return false;
}

}  // namespace powershellguardian_json
