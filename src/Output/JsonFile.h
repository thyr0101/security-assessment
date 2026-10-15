#pragma once
#include "../Models.h"
#include <expected>
#include <filesystem>
#include <string>
#include <string_view>

namespace sa {
std::expected<std::filesystem::path, std::wstring> SaveJsonReport(
    std::string_view report, const std::filesystem::path& destination = {});
std::expected<AssessmentResult, std::wstring> ReadJsonReport(const std::filesystem::path& source);
}
