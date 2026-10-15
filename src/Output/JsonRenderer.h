#pragma once
#include "../Models.h"
#include <string>
namespace sa {
enum class JsonFormat { Compact = 0, Readable = 1 };
std::string RenderJson(const AssessmentResult& r, JsonFormat format = JsonFormat::Readable);
}