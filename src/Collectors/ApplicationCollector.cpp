#include "ApplicationCollector.h"
#include "../Utilities.h"
#include <windows.h>
#include <filesystem>

namespace fs = std::filesystem;

namespace sa {

std::vector<ApplicationDefinition> DefaultApplicationList() {
    return {
        { L"Browser(s)",  { L"%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe",
                            L"%ProgramFiles%\\Microsoft\\Edge\\Application\\msedge.exe",
                            L"% ProgramFiles%\\Mozilla Firefox\\firefox.exe",
                            L"%ProgramFiles%\\Mozilla Firefox\\firefox.exe",
                            L"%ProgramFiles(x86)%\\Mozilla Firefox\\firefox.exe"} },
    };
}

static std::optional<std::wstring> ResolvePathWithWildcard(const std::wstring& pattern) {
    std::wstring expanded = ExpandEnv(pattern);
    // Simple glob: if contains '*', enumerate parent with FindFirstFileW
    if (expanded.find(L'*') == std::wstring::npos) {
        if (fs::exists(expanded)) return expanded;
        return std::nullopt;
    }
    fs::path p(expanded);
    fs::path parent = p.parent_path();
    std::wstring file = p.filename().wstring();
    if (!fs::exists(parent)) return std::nullopt;
    WIN32_FIND_DATAW fd{};
    HANDLE h = ::FindFirstFileW(expanded.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return std::nullopt;
    std::wstring found = (parent / fd.cFileName).wstring();
    ::FindClose(h);
    return found;
}

std::vector<ApplicationFinding> CollectApplications(
    const std::vector<ApplicationDefinition>& defs) {
    std::vector<ApplicationFinding> out;
    for (const auto& def : defs) {
        ApplicationFinding f;
        f.name = def.name;
        std::optional<std::wstring> found;
        for (const auto& p : def.possiblePaths) {
            found = ResolvePathWithWildcard(p);
            if (found) break;
        }
        if (!found) { f.status = Status::NotFound; out.push_back(std::move(f)); continue; }
        f.installed = true;
        f.path = *found;
        if (auto vi = QueryFileVersion(*found)) {
            f.version = vi->fileVersion.empty() ? vi->productVersion : vi->fileVersion;
            f.publisher = vi->companyName;
            f.architecture = vi->architecture;
        }
        if (auto h = FileSha256(*found)) f.sha256 = *h;
        f.status = Status::Success;
        out.push_back(std::move(f));
    }
    return out;
}

} // namespace sa
