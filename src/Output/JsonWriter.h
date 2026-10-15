#pragma once
#include "../Models.h"
#include "../Utilities.h"
#include <cstdio>
#include <string>

namespace sa::json_writer {
inline std::string Esc(const std::string& s) {
    std::string o; o.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '"': o += "\\\""; break;
        case '\\': o += "\\\\"; break;
        case '\b': o += "\\b"; break;
        case '\f': o += "\\f"; break;
        case '\n': o += "\\n"; break;
        case '\r': o += "\\r"; break;
        case '\t': o += "\\t"; break;
        default:
            if ((unsigned char)c < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                o += buf;
            } else o += c;
        }
    }
    return o;
}
inline std::string Q(const std::string& s) { return "\"" + Esc(s) + "\""; }
inline std::string Q(const std::wstring& w) { return Q(WideToUtf8(w)); }
inline std::string B(bool b) { return b ? "true" : "false"; }
inline std::string TriS(Tri t) {
    switch (t) { case Tri::Yes: return "\"Yes\""; case Tri::No: return "\"No\"";
                 case Tri::NotApplicable: return "\"N/A\""; default: return "\"Unknown\""; }
}
inline std::string StatusS(Status s) { return "\"" + std::string(WideToUtf8(ToW(s))) + "\""; }
// The export is a presentation snapshot, not a second system inventory.
// Internal evidence stays in memory for scoring; only renderer inputs are saved.
struct JsonObject {
    std::string data = "{";
    bool first = true;
    void Set(const char* key, const std::string& value) {
        if (!first) data += ',';
        first = false;
        data += Q(std::string(key)) + ":" + value;
    }
    void Text(const char* key, const std::wstring& value) { if (!value.empty()) Set(key, Q(value)); }
    std::string Finish() const { return data + "}"; }
};
template<class Range, class Function>
inline std::string Array(const Range& values, Function render) {
    std::string data = "[";
    bool first = true;
    for (const auto& value : values) {
        if (!first) data += ',';
        first = false;
        data += render(value);
    }
    return data + "]";
}
inline std::string Strings(const std::vector<std::wstring>& values) {
    return Array(values, [](const auto& value) { return Q(value); });
}
inline std::string SettingJson(const SecuritySetting& setting) {
    JsonObject object;
    object.Set("enabled", TriS(setting.enabled)); object.Set("status", StatusS(setting.status));
    return object.Finish();
}
} // namespace sa::json_writer
