#include "JsonFile.h"
#include "../Utilities.h"
#include <windows.data.json.h>
#include <wrl/client.h>
#include <wrl/wrappers/corewrappers.h>
#include <algorithm>
#include <cmath>
#include <format>

#pragma comment(lib, "runtimeobject.lib")

namespace sa {
namespace {
using Microsoft::WRL::ComPtr;
using Microsoft::WRL::Wrappers::HString;
using Microsoft::WRL::Wrappers::HStringReference;
constexpr size_t kInputLimit = 64u << 20;
constexpr size_t kDisplayLimit = 128u << 20;

std::unexpected<std::wstring> Error(std::wstring text) { return std::unexpected(std::move(text)); }
std::filesystem::path DefaultName() {
    SYSTEMTIME now{};
    ::GetLocalTime(&now);
    return std::format(L"security-assessment-{:04}{:02}{:02}-{:02}{:02}{:02}-{:03}-{}.json",
        now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond, now.wMilliseconds, ::GetCurrentProcessId());
}
bool ReportShape(ABI::Windows::Data::Json::IJsonObject* root) {
    using namespace ABI::Windows::Data::Json;
    ComPtr<IJsonObject> system, score;
    ComPtr<IJsonArray> rules;
    if (FAILED(root->GetNamedObject(HStringReference(L"system").Get(), system.GetAddressOf())) || !system ||
        FAILED(root->GetNamedObject(HStringReference(L"score").Get(), score.GetAddressOf())) || !score ||
        FAILED(score->GetNamedArray(HStringReference(L"rules").Get(), rules.GetAddressOf())) || !rules) return false;
    double total = 0, maximum = 0;
    return SUCCEEDED(score->GetNamedNumber(HStringReference(L"total").Get(), &total)) &&
        SUCCEEDED(score->GetNamedNumber(HStringReference(L"maximum").Get(), &maximum)) &&
        std::isfinite(total) && std::isfinite(maximum) && total >= 0 && maximum > 0 && total <= maximum &&
        std::floor(total) == total && std::floor(maximum) == maximum;
}
std::expected<std::wstring, std::wstring> Pretty(std::wstring_view source) {
    std::wstring output;
    output.reserve(source.size());
    size_t depth = 0;
    bool quoted = false, escaped = false;
    wchar_t previous = 0;
    auto space = [](wchar_t c) { return c == L' ' || c == L'\t' || c == L'\r' || c == L'\n'; };
    auto newline = [&] { output += L'\n'; output.append(depth * 2, L' '); };
    for (size_t i = 0; i < source.size(); ++i) {
        const wchar_t c = source[i];
        if (quoted) {
            output += c;
            if (escaped) escaped = false;
            else if (c == L'\\') escaped = true;
            else if (c == L'"') { quoted = false; previous = c; }
        } else {
            if (space(c)) continue;
            switch (c) {
            case L'"': quoted = true; output += c; break;
            case L'{': case L'[': {
                if (++depth > 128) return Error(L"The report exceeds the viewer's nesting limit (128).");
                output += c;
                size_t next = i + 1;
                while (next < source.size() && space(source[next])) ++next;
                const wchar_t close = c == L'{' ? L'}' : L']';
                if (next == source.size() || source[next] != close) newline();
                break;
            }
            case L'}': case L']':
                if (!depth) return Error(L"Invalid JSON structure.");
                --depth;
                if (previous != (c == L'}' ? L'{' : L'[')) newline();
                output += c;
                break;
            case L',': output += c; newline(); break;
            case L':': output += L": "; break;
            default: output += c; break;
            }
            previous = c;
        }
        if (output.size() > kDisplayLimit / sizeof(wchar_t)) return Error(L"The formatted report is too large to display.");
    }
    output += L'\n';
    return output;
}
} // namespace

std::expected<std::filesystem::path, std::wstring> SaveJsonReport(
    std::string_view report, const std::filesystem::path& destination) {
    try {
        const auto path = std::filesystem::absolute(destination.empty() ? DefaultName() : destination);
        WinHandle file(::CreateFileW(path.c_str(), GENERIC_WRITE | DELETE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!file) {
            const DWORD error = ::GetLastError();
            return Error(error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS
                ? L"The output file already exists. Choose a different filename."
                : L"Cannot create the report: " + FormatWinError(error));
        }
        auto failure = [&](DWORD error) {
            FILE_DISPOSITION_INFO cleanup{TRUE};
            const bool removed = ::SetFileInformationByHandle(file.get(), FileDispositionInfo, &cleanup, sizeof(cleanup)) != FALSE;
            return Error(L"Cannot finish writing the report: " + FormatWinError(error) +
                (removed ? L"" : L" An incomplete output file may remain."));
        };
        auto write = [&](std::string_view bytes) -> DWORD {
            while (!bytes.empty()) {
                DWORD written = 0;
                const DWORD chunk = static_cast<DWORD>((std::min)(bytes.size(), size_t{1u << 20}));
                if (!::WriteFile(file.get(), bytes.data(), chunk, &written, nullptr)) return ::GetLastError();
                if (!written) return ERROR_WRITE_FAULT;
                bytes.remove_prefix(written);
            }
            return ERROR_SUCCESS;
        };
        if (const DWORD error = write(report)) return failure(error);
        if (const DWORD error = write("\n")) return failure(error);
        if (!::FlushFileBuffers(file.get())) return failure(::GetLastError());
        return path;
    } catch (const std::filesystem::filesystem_error&) { return Error(L"The output path is invalid or unavailable."); }
}

std::expected<std::wstring, std::wstring> ReadJsonReport(const std::filesystem::path& source) {
    WinHandle file(::CreateFileW(source.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file) return Error(L"Cannot open the report: " + FormatWinError(::GetLastError()));
    LARGE_INTEGER size{};
    if (!::GetFileSizeEx(file.get(), &size)) return Error(L"Cannot read the report size.");
    if (size.QuadPart <= 0 || size.QuadPart > static_cast<LONGLONG>(kInputLimit))
        return Error(L"The report must be a nonempty UTF-8 JSON file no larger than 64 MiB.");
    std::string bytes(static_cast<size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    if (!::ReadFile(file.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) || read != bytes.size())
        return Error(L"Cannot read the complete report.");
    std::string_view utf8 = bytes;
    if (utf8.starts_with("\xef\xbb\xbf")) utf8.remove_prefix(3);
    const int length = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    if (!length) return Error(L"The report is not valid UTF-8.");
    std::wstring text(static_cast<size_t>(length), L'\0');
    if (!::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()), text.data(), length))
        return Error(L"The report is not valid UTF-8.");
    if (text.find(L'\0') != std::wstring::npos) return Error(L"The report contains an invalid JSON control character.");

    Microsoft::WRL::Wrappers::RoInitializeWrapper runtime(RO_INIT_MULTITHREADED);
    const HRESULT initialized = runtime;
    if (FAILED(initialized) && initialized != RPC_E_CHANGED_MODE) return Error(L"Windows JSON support could not be initialized.");
    using namespace ABI::Windows::Data::Json;
    ComPtr<IJsonObjectStatics> parser;
    if (FAILED(::RoGetActivationFactory(HStringReference(L"Windows.Data.Json.JsonObject").Get(), IID_PPV_ARGS(parser.GetAddressOf()))))
        return Error(L"Windows JSON support is unavailable.");
    HString input;
    if (FAILED(input.Set(text.data(), static_cast<UINT32>(text.size())))) return Error(L"Cannot load the report for viewing.");
    ComPtr<IJsonObject> root;
    boolean parsed = false;
    if (FAILED(parser->TryParse(input.Get(), root.GetAddressOf(), &parsed)) || !parsed || !root)
        return Error(L"The file contains invalid JSON.");
    if (!ReportShape(root.Get())) return Error(L"The JSON file does not have the structure of a Security Assessment report.");
    return Pretty(text);
}
} // namespace sa
