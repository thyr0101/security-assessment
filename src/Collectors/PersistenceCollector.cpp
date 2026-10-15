#include "PersistenceCollector.h"
#include "../RegistryReader.h"
#include "../Utilities.h"
#include <windows.h>
#include <filesystem>
#include <vector>
#include <type_traits>
#include <shlobj.h>

#pragma comment(lib, "shell32.lib")

namespace fs = std::filesystem;

namespace sa {

// Only readability is displayed. Do not enumerate startup names or read commands.
PersistenceReport CollectPersistence() {
    PersistenceReport report;
    report.status = Status::Success;
    auto key = [&](HKEY root, const wchar_t* path) {
        RegistryReader reader;
        const auto status = reader.Open(root, path, KEY_WOW64_64KEY);
        if (status != Status::Success && status != Status::NotFound) report.status = status;
    };
    for (const auto* name : {L"Run", L"RunOnce"}) {
        const auto path = std::wstring(L"Software\\Microsoft\\Windows\\CurrentVersion\\") + name;
        key(HKEY_CURRENT_USER, path.c_str()); key(HKEY_LOCAL_MACHINE, path.c_str());
        key(HKEY_LOCAL_MACHINE, (std::wstring(L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\") + name).c_str());
    }
    for (const auto* id : {&FOLDERID_Startup, &FOLDERID_CommonStartup}) {
        PWSTR path = nullptr;
        const HRESULT result = ::SHGetKnownFolderPath(*id, KF_FLAG_DONT_VERIFY, nullptr, &path);
        struct FreePath { PWSTR value; ~FreePath() { ::CoTaskMemFree(value); } } owner{path};
        if (FAILED(result) || !path) { report.status = result == E_ACCESSDENIED ? Status::AccessDenied : Status::Unavailable; continue; }
        WinHandle directory(::CreateFileW(path, FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
        if (!directory) {
            const auto status = StatusFromWin32(::GetLastError());
            if (status != Status::NotFound) report.status = status;
        }
    }
    return report;
}

std::vector<RegistryScanDefinition> DefaultRegistryScans() {
    return {
        { L"HKCU Run", HKEY_CURRENT_USER,
          L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 5, KEY_WOW64_64KEY },

        { L"HKLM Run", HKEY_LOCAL_MACHINE,
          L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 10, KEY_WOW64_64KEY },

        { L"HKLM RunOnce", HKEY_LOCAL_MACHINE,
          L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 5, KEY_WOW64_64KEY },

        { L"MUI Cache", HKEY_CURRENT_USER, // Cached application display metadata.
          L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache", 10, KEY_WOW64_64KEY }
    };
}

std::vector<RegistryFinding> RunRegistryScans(const std::vector<RegistryScanDefinition>& defs) {
    std::vector<RegistryFinding> out;
    for (auto& d : defs) {
        RegistryFinding f;
        f.name = d.name;
        f.path = d.subkey;
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

std::vector<DirectoryScanDefinition> DefaultDirectoryScans() {
    return {
        { L"User Temp",   L"%TEMP%", 1000, false },
        { L"LocalAppData\\Temp", L"%LocalAppData%\\Temp", 1000, false },
        { L"ProgramData", L"%ProgramData%", 200, false },
        { L"Windows Temp",L"%SystemRoot%\\Temp", 500, false },
    };
}

std::vector<DirectoryFinding> RunDirectoryScans(const std::vector<DirectoryScanDefinition>& defs) {
    std::vector<DirectoryFinding> out;
    for (auto& d : defs) {
        DirectoryFinding f;
        f.name = d.name;
        f.path = ExpandEnv(d.path);
        f.threshold = d.threshold;
        const auto& path = f.path;
        std::error_code ec;
        if (!fs::exists(path, ec)) {
            f.status = ec ? StatusFromWin32(static_cast<DWORD>(ec.value())) : Status::NotFound;
            out.push_back(std::move(f)); continue;
        }
        f.status = Status::Success;
        auto count = [&](auto it) {
            const decltype(it) end;
            for (; !ec && it != end; it.increment(ec)) {
                const bool directory = it->is_directory(ec);
                if (ec) break;
                if (!directory) ++f.fileCount;
                if constexpr (std::is_same_v<decltype(it), fs::recursive_directory_iterator>) {
                    // Avoid traversing junctions/reparse points into another tree or a cycle.
                    const DWORD attrs = ::GetFileAttributesW(it->path().c_str());
                    if (attrs == INVALID_FILE_ATTRIBUTES) {
                        ec = std::error_code(::GetLastError(), std::system_category()); break;
                    }
                    if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) it.disable_recursion_pending();
                }
            }
        };
        if (d.recursive) count(fs::recursive_directory_iterator(path, ec));
        else count(fs::directory_iterator(path, ec));
        if (ec) f.status = StatusFromWin32(static_cast<DWORD>(ec.value()));
        f.exceeded = f.fileCount > d.threshold;
        out.push_back(std::move(f));
    }
    return out;
}

// ---------------- Security-relevant services ----------------
static std::wstring StateName(DWORD s) {
    switch (s) {
    case SERVICE_STOPPED: return L"Stopped";
    case SERVICE_START_PENDING: return L"StartPending";
    case SERVICE_STOP_PENDING: return L"StopPending";
    case SERVICE_RUNNING: return L"Running";
    case SERVICE_CONTINUE_PENDING: return L"ContinuePending";
    case SERVICE_PAUSE_PENDING: return L"PausePending";
    case SERVICE_PAUSED: return L"Paused";
    default: return L"Unknown";
    }
}
static std::wstring StartName(DWORD s) {
    switch (s) {
    case SERVICE_BOOT_START: return L"Boot";
    case SERVICE_SYSTEM_START: return L"System";
    case SERVICE_AUTO_START: return L"Auto";
    case SERVICE_DEMAND_START: return L"Manual";
    case SERVICE_DISABLED: return L"Disabled";
    default: return L"Unknown";
    }
}

ServiceReport CollectServices(const std::vector<std::wstring>& names) {
    ServiceReport rep;
    ServiceHandle scm(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) return rep;
    for (const auto& name : names) {
        ServiceEntry e;
        e.name = name;
        ServiceHandle svc(::OpenServiceW(scm.get(), name.c_str(), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG));
        if (!svc) {
            e.status = StatusFromWin32(::GetLastError());
            rep.entries.push_back(std::move(e)); continue;
        }
        e.status = Status::Success;
        SERVICE_STATUS_PROCESS ssp{}; DWORD needed = 0;
        if (::QueryServiceStatusEx(svc.get(), SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed))
            e.state = StateName(ssp.dwCurrentState);
        else e.status = StatusFromWin32(::GetLastError());
        DWORD cfgSz = 0;
        const BOOL sizeRead = ::QueryServiceConfigW(svc.get(), nullptr, 0, &cfgSz);
        const DWORD configError = sizeRead ? ERROR_SUCCESS : ::GetLastError();
        if (!sizeRead && configError == ERROR_INSUFFICIENT_BUFFER && cfgSz) {
            std::vector<BYTE> buf(cfgSz);
            auto* cfg = (QUERY_SERVICE_CONFIGW*)buf.data();
            if (::QueryServiceConfigW(svc.get(), cfg, cfgSz, &cfgSz)) {
                e.displayName = cfg->lpDisplayName ? cfg->lpDisplayName : L"";
                e.startType = StartName(cfg->dwStartType);
                // Resolve the canonical service key name from the SCM's display name.
                // Keep the requested name as a fallback when the mapping is unavailable.
                if (!e.displayName.empty()) {
                    DWORD nameLength = 0;
                    const BOOL nameProbe = ::GetServiceKeyNameW(scm.get(), e.displayName.c_str(), nullptr, &nameLength);
                    if (!nameProbe && ::GetLastError() == ERROR_INSUFFICIENT_BUFFER && nameLength) {
                        std::vector<wchar_t> keyName(static_cast<size_t>(nameLength) + 1);
                        nameLength = static_cast<DWORD>(keyName.size());
                        if (::GetServiceKeyNameW(scm.get(), e.displayName.c_str(), keyName.data(), &nameLength))
                            e.name.assign(keyName.data(), nameLength);
                    }
                }
            }
            else e.status = StatusFromWin32(::GetLastError());
        }
        else e.status = sizeRead ? Status::Error : StatusFromWin32(configError);
        rep.entries.push_back(std::move(e));
    }
    return rep;
}

} // namespace sa
