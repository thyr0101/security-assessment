#pragma once
#include <windows.data.json.h>
#include <expected>
#include <string>
#include <string_view>

namespace sa {
// Versioned JSON representation with short keys, numeric states and text references.
std::string CompactJson(std::string_view readable);
std::expected<std::wstring, std::wstring> ExpandCompactJson(ABI::Windows::Data::Json::IJsonObject* root);
}
