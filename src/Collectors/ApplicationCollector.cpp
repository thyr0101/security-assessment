#include "ApplicationCollector.h"
#include "../Utilities.h"
#include <windows.h>
#include <algorithm>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;

namespace sa {

    // Each definition is a CATEGORY. Every entry in possiblePaths is a candidate location
    // of some application in that category; all locations that exist are reported, grouped
    // per application. An entry may be written as "Display Name|path" to force the
    // application's name ('|' cannot occur in a Windows path); otherwise the name is taken
    // from the executable's version resource (ProductName, then FileDescription) and finally
    // from the file name.
    std::vector<ApplicationDefinition> DefaultApplicationList() {
        return {
            {
                L"Browser(s)",
                {
                    L"%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe", // Edge x86
                    L"%ProgramFiles%\\imput\\Helium\\Application\\chrome.exe",       // Helium
                    L"%ProgramFiles(x86)%\\Mozilla Firefox\\firefox.exe",            // Firefox x86
                    L"%ProgramFiles%\\Mozilla Firefox\\firefox.exe"                  // Firefox
                    L"%ProgramFiles%\\BraveSoftware\\Brave-Browser\\Application\\brave.exe", // Brave
                    L"%ProgramFiles%\\LibreWolf\\librewolf.exe"                // LibreWolf
                }
            },
            {
                L"Messenger(s)",
                {
                    L"%LOCALAPPDATA%\\Programs\\signal - desktop\\signal.exe", // Signal
                    L"%LOCALAPPDATA%\\Discord\\discord.exe",                   // Discord 
                }
            },
            {
                L"Privacy Utilities",
                {
                    //L""
                }
            }
        };
    }

namespace {

// Splits an optional "Display Name|path" entry.
void SplitEntry(const std::wstring& entry, std::wstring& name, std::wstring& pattern) {
    const size_t bar = entry.find(L'|');
    if (bar == std::wstring::npos) { name.clear(); pattern = entry; return; }
    name = Trim(entry.substr(0, bar));
    pattern = Trim(entry.substr(bar + 1));
}

// Expands parts[i..] below `dir`. A part containing '*' or '?' is matched against the
// directory contents (so wildcards work in any path component, e.g. "app-*\\Discord.exe"),
// and EVERY match is followed - not just the first one.
void Glob(const fs::path& dir, const std::vector<std::wstring>& parts, size_t i,
          std::vector<std::wstring>& out) {
    if (i >= parts.size()) return;
    const std::wstring& part = parts[i];
    const bool last = (i + 1 == parts.size());

    if (part.find_first_of(L"*?") == std::wstring::npos) {
        const fs::path next = dir / part;
        std::error_code ec;
        if (!fs::exists(next, ec)) return;
        if (last) out.push_back(next.wstring());
        else      Glob(next, parts, i + 1, out);
        return;
    }

    const std::wstring pattern = (dir / part).wstring();
    WIN32_FIND_DATAW fd{};
    HANDLE h = ::FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        const fs::path next = dir / fd.cFileName;
        if (last)                                            out.push_back(next.wstring());
        else if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) Glob(next, parts, i + 1, out);
    } while (::FindNextFileW(h, &fd));
    ::FindClose(h);
}

// Returns every existing path that matches `pattern` (environment variables expanded).
std::vector<std::wstring> ResolvePaths(const std::wstring& pattern) {
    std::vector<std::wstring> found;
    const fs::path p(ExpandEnv(pattern));
    std::vector<std::wstring> parts;
    for (const auto& element : p.relative_path())
        if (!element.empty()) parts.push_back(element.wstring());
    if (parts.empty()) return found;
    Glob(p.root_path(), parts, 0, found);
    return found;
}

} // namespace

std::vector<ApplicationFinding> CollectApplications(
    const std::vector<ApplicationDefinition>& defs) {
    std::vector<ApplicationFinding> out;
    for (const auto& def : defs) {
        ApplicationFinding category;
        category.name = def.name;
        std::vector<std::wstring> seen;     // normalised, lower-cased paths already reported

        for (const auto& entry : def.possiblePaths) {
            std::wstring forcedName, pattern;
            SplitEntry(entry, forcedName, pattern);

            for (const auto& path : ResolvePaths(pattern)) {
                const std::wstring key = ToLower(fs::path(path).lexically_normal().wstring());
                if (std::find(seen.begin(), seen.end(), key) != seen.end()) continue;
                seen.push_back(key);

                ApplicationLocation loc;
                loc.path = path;
                std::wstring name = forcedName;
                if (auto vi = QueryFileVersion(path)) {
                    loc.version = vi->fileVersion.empty() ? vi->productVersion : vi->fileVersion;
                    if (name.empty()) name = Trim(vi->productName);
                    if (name.empty()) name = Trim(vi->fileDescription);
                }
                if (name.empty()) name = fs::path(path).stem().wstring();
                if (auto h = FileSha256(path)) loc.sha256 = *h;

                // Group locations of the same application (e.g. Program Files and
                // Program Files (x86)) under one entry.
                InstalledApplication* app = nullptr;
                const std::wstring nameKey = ToLower(name);
                for (auto& existing : category.apps)
                    if (ToLower(existing.name) == nameKey) { app = &existing; break; }
                if (!app) {
                    category.apps.emplace_back();
                    app = &category.apps.back();
                    app->name = name;
                }
                if (app->version.empty()) app->version = loc.version;
                app->locations.push_back(std::move(loc));
            }
        }

        category.installed = !category.apps.empty();
        category.status = category.installed ? Status::Success : Status::NotFound;
        out.push_back(std::move(category));
    }
    return out;
}

} // namespace sa
