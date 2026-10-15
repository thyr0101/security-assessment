#pragma once
#include <windows.data.json.h>
#include <expected>
#include <string>
#include <string_view>

namespace sa {
// Versioned JSON representation with numbered fields, direct values and numeric states.
std::string CompactJson(std::string_view readable);
std::expected<std::wstring, std::wstring> ExpandCompactJson(ABI::Windows::Data::Json::IJsonObject* root);
}
