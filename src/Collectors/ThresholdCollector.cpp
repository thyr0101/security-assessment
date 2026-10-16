#include "ThresholdCollector.h"
#include "../RegistryReader.h"
#include "../Utilities.h"
#include <windows.h>
#include <vector>
#include <algorithm>
#include <shlobj.h>

#pragma comment(lib, "shell32.lib")

namespace sa {

std::vector<RegistryScanDefinition> DefaultRegistryScans() {
    constexpr auto run = L"Software\\Microsoft\\Windows\\CurrentVersion\\";
    std::vector<RegistryScanDefinition> scans;
    auto add = [&](const wchar_t* name, HKEY root, const std::wstring& path, size_t threshold, const wchar_t* description) {
        scans.push_back({name, root, path, threshold, KEY_WOW64_64KEY, description});
    };
    add(L"User startup", HKEY_CURRENT_USER, std::wstring(run) + L"Run", 5,
        L"Programs registered to run whenever this user signs in. Counts values without reading commands.");
    add(L"User one-time startup", HKEY_CURRENT_USER, std::wstring(run) + L"RunOnce", 5,
        L"One-time sign-in tasks for this user, often created by installers.");
    add(L"Machine startup", HKEY_LOCAL_MACHINE, std::wstring(run) + L"Run", 10,
        L"Programs registered to run at sign-in for all users.");
    add(L"Machine one-time startup", HKEY_LOCAL_MACHINE, std::wstring(run) + L"RunOnce", 5,
        L"One-time machine-wide sign-in tasks, often used to finish software setup.");
    add(L"32-bit machine startup", HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", 10,
        L"Machine-wide sign-in registrations created by 32-bit software.");
    add(L"32-bit one-time startup", HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 5,
        L"One-time machine-wide sign-in tasks created by 32-bit software.");
    add(L"User startup approvals", HKEY_CURRENT_USER, std::wstring(run) + L"Explorer\\StartupApproved\\Run", 10,
        L"Windows' approval records for user startup registrations; records may include disabled entries.");
    add(L"Machine startup approvals", HKEY_LOCAL_MACHINE, std::wstring(run) + L"Explorer\\StartupApproved\\Run", 15,
        L"Windows' approval records for machine startup registrations; this is not a count of running programs.");
    add(L"MUI Cache", HKEY_CURRENT_USER, L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache", 10,
        L"Cached application display metadata. Large counts are common and do not indicate malware.");
    return scans;
}

std::vector<RegistryFinding> RunRegistryScans(const std::vector<RegistryScanDefinition>& defs) {
    std::vector<RegistryFinding> out;
    for (auto& d : defs) {
        RegistryFinding f;
        f.name = d.name;
        f.description = d.description;
        f.path = std::wstring(d.root == HKEY_CURRENT_USER ? L"HKCU\\" : L"HKLM\\") + d.subkey;
        f.threshold = d.threshold;
        RegistryReader r;
        f.status = r.Open(d.root, d.subkey, d.view);
        if (f.status == Status::Success) {
            f.status = r.CountValues(f.valueCount);
            f.exceeded = f.status == Status::Success && f.valueCount > d.threshold;
        }
        out.push_back(std::move(f));
    }
    return out;
}

static std::wstring StartupFolder(REFKNOWNFOLDERID id, const wchar_t* fallback) {
    PWSTR path = nullptr;
    const auto result = ::SHGetKnownFolderPath(id, KF_FLAG_DONT_VERIFY, nullptr, &path);
    std::unique_ptr<wchar_t, decltype(&::CoTaskMemFree)> owner(path, &::CoTaskMemFree);
    return SUCCEEDED(result) && path ? std::wstring(path) : ExpandEnv(fallback);
}

std::vector<DirectoryScanDefinition> DefaultDirectoryScans() {
    return {
        {L"User Temp", L"%TEMP%", 1000, false, L"Temporary files used by this user's programs. Counts immediate files only."},
        {L"Local application Temp", L"%LocalAppData%\\Temp", 1000, false, L"The user's standard local temporary folder; omitted if it duplicates User Temp."},
        {L"ProgramData", L"%ProgramData%", 200, false, L"Shared application data. Counts files in the top level only, not files inside application folders."},
        {L"Windows Temp", L"%SystemRoot%\\Temp", 500, false, L"System temporary files. Administrator access may be required to read this folder."},
        {L"User Startup folder", StartupFolder(FOLDERID_Startup, L"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"), 5, false,
            L"Files and shortcuts started when this user signs in. Shortcut targets are not opened."},
        {L"Shared Startup folder", StartupFolder(FOLDERID_CommonStartup, L"%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"), 10, false,
            L"Files and shortcuts started at sign-in for all users. Counts immediate files only."},
    };
}

namespace {
std::wstring NormalizePath(const std::wstring& path) {
    const DWORD needed = ::GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (!needed) return path;
    std::wstring result(needed, L'\0');
    const DWORD size = ::GetFullPathNameW(path.c_str(), needed, result.data(), nullptr);
    if (!size || size >= needed) return path;
    result.resize(size);
    while (result.size() > 3 && result.back() == L'\\') result.pop_back();
    return result;
}
Status CountFiles(const std::wstring& root, bool recursive, unsigned long long& count) {
    const DWORD attributes = ::GetFileAttributesW(root.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) return StatusFromWin32(::GetLastError());
    if (!(attributes & FILE_ATTRIBUTE_DIRECTORY)) return Status::Error;
    std::vector<std::pair<std::wstring, unsigned>> pending{{root, 0}};
    while (!pending.empty()) {
        auto [path, depth] = std::move(pending.back()); pending.pop_back();
        const auto pattern = path + L"\\*";
        WIN32_FIND_DATAW data{};
        HANDLE raw = ::FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &data, FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH);
        if (raw == INVALID_HANDLE_VALUE) {
            const DWORD error = ::GetLastError();
            if (error == ERROR_FILE_NOT_FOUND) continue; // Empty readable directory.
            return StatusFromWin32(error);
        }
        struct Search { HANDLE value; ~Search() { ::FindClose(value); } } search{raw};
        do {
            if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) continue;
            if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) { ++count; continue; }
            if (recursive && !(data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
                if (depth == 256) return Status::Unavailable;
                pending.emplace_back(path + L"\\" + data.cFileName, depth + 1);
            }
        } while (::FindNextFileW(search.value, &data));
        const DWORD error = ::GetLastError();
        if (error != ERROR_NO_MORE_FILES) return StatusFromWin32(error);
    }
    return Status::Success;
}
} // namespace

std::vector<DirectoryFinding> RunDirectoryScans(const std::vector<DirectoryScanDefinition>& defs) {
    std::vector<DirectoryFinding> results;
    std::vector<std::pair<std::wstring, bool>> visited;
    for (const auto& definition : defs) {
        DirectoryFinding finding;
        finding.name = definition.name;
        finding.description = definition.description;
        finding.path = NormalizePath(ExpandEnv(definition.path));
        finding.threshold = definition.threshold;
        if (std::ranges::any_of(visited, [&](const auto& previous) { return previous.second == definition.recursive && IEquals(previous.first, finding.path); })) continue;
        visited.emplace_back(finding.path, definition.recursive);
        finding.status = CountFiles(finding.path, definition.recursive, finding.fileCount);
        finding.exceeded = finding.fileCount > finding.threshold;
        results.push_back(std::move(finding));
    }
    return results;
}
} // namespace sa
