#include "PersistenceCollector.h"
#include "../RegistryReader.h"
#include "../Utilities.h"
#include <windows.h>
#include <filesystem>
#include <vector>
#include <type_traits>

namespace fs = std::filesystem;

namespace sa {

static void AddRunKey(PersistenceReport& rep, HKEY root, const std::wstring& path,
                      const std::wstring& display) {
    RegistryReader r;
    const Status status = r.Open(root, path, KEY_WOW64_64KEY);
    if (status != Status::Success) {
        if (status != Status::NotFound) rep.status = status;
        return;
    }
    std::vector<std::pair<std::wstring, DWORD>> vals;
    const Status enumerated = r.EnumValues(vals);
    if (enumerated != Status::Success) { rep.status = enumerated; return; }
    for (auto& [name, type] : vals) {
        if (name.empty()) continue;
        PersistenceEntry e;
        e.location = display;
        e.name = name;
        std::wstring cmd;
        if (r.GetString(name.c_str(), cmd) == Status::Success) e.command = cmd;
        else { std::vector<BYTE> b; if (r.GetBinary(name.c_str(), b) == Status::Success) e.command = L"<binary>"; }
        rep.entries.push_back(std::move(e));
    }
}

static void ScanStartupFolders(PersistenceReport& rep) {
    wchar_t buf[MAX_PATH]{};
    DWORD n = ::GetEnvironmentVariableW(L"APPDATA", buf, MAX_PATH);
    if (n && n < MAX_PATH) {
        fs::path dir = fs::path(buf) / L"Microsoft\\Windows\\Start Menu\\Programs\\Startup";
        std::error_code ec;
        if (fs::exists(dir, ec)) {
            for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
                PersistenceEntry e;
                e.location = L"Startup (user)";
                e.name = it->path().filename().wstring();
                e.command = it->path().wstring();
                rep.entries.push_back(std::move(e));
            }
        }
        if (ec) rep.status = StatusFromWin32(static_cast<DWORD>(ec.value()));
    }
    n = ::GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH);
    if (n && n < MAX_PATH) {
        fs::path dir = fs::path(buf) / L"Microsoft\\Windows\\Start Menu\\Programs\\Startup";
        std::error_code ec;
        if (fs::exists(dir, ec)) {
            for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
                PersistenceEntry e;
                e.location = L"Startup (machine)";
                e.name = it->path().filename().wstring();
                e.command = it->path().wstring();
                rep.entries.push_back(std::move(e));
            }
        }
        if (ec) rep.status = StatusFromWin32(static_cast<DWORD>(ec.value()));
    }
}

PersistenceReport CollectPersistence() {
    PersistenceReport rep;
    rep.status = Status::Success;
    AddRunKey(rep, HKEY_CURRENT_USER,
              L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKCU\\...\\Run");
    AddRunKey(rep, HKEY_CURRENT_USER,
              L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"HKCU\\...\\RunOnce");
    AddRunKey(rep, HKEY_LOCAL_MACHINE,
              L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKLM\\...\\Run");
    AddRunKey(rep, HKEY_LOCAL_MACHINE,
              L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"HKLM\\...\\RunOnce");
    AddRunKey(rep, HKEY_LOCAL_MACHINE,
              L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
              L"HKLM\\Wow6432Node\\...\\Run");
    AddRunKey(rep, HKEY_LOCAL_MACHINE,
              L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
              L"HKLM\\Wow6432Node\\...\\RunOnce");
    ScanStartupFolders(rep);
    return rep;
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
            if (f.status == Status::Success) f.status = r.CountSubkeys(f.subkeyCount);
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
                if (directory) ++f.dirCount;
                else ++f.fileCount;
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
static const wchar_t* kSecurityServices[] = {
    L"WinDefend", L"WdNisSvc", L"SecurityHealthService", L"wscsvc",
    L"MpsSvc", L"wuauserv", L"CryptSvc", L"EventLog"
};

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

ServiceReport CollectSecurityServices() {
    ServiceReport rep;
    ServiceHandle scm(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) { rep.status = StatusFromWin32(::GetLastError()); return rep; }
    for (auto* name : kSecurityServices) {
        ServiceEntry e;
        e.name = name;
        ServiceHandle svc(::OpenServiceW(scm.get(), name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG));
        if (!svc) { e.status = StatusFromWin32(::GetLastError()); rep.entries.push_back(std::move(e)); continue; }
        e.status = Status::Success;
        SERVICE_STATUS_PROCESS ssp{}; DWORD needed = 0;
        if (::QueryServiceStatusEx(svc.get(), SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed))
            e.state = StateName(ssp.dwCurrentState);
        else e.status = StatusFromWin32(::GetLastError());
        DWORD cfgSz = 0;
        ::QueryServiceConfigW(svc.get(), nullptr, 0, &cfgSz);
        if (cfgSz) {
            std::vector<BYTE> buf(cfgSz);
            auto* cfg = (QUERY_SERVICE_CONFIGW*)buf.data();
            if (::QueryServiceConfigW(svc.get(), cfg, cfgSz, &cfgSz)) {
                e.displayName = cfg->lpDisplayName ? cfg->lpDisplayName : L"";
                e.startType = StartName(cfg->dwStartType);
                e.exePath = cfg->lpBinaryPathName ? cfg->lpBinaryPathName : L"";
            }
            else e.status = StatusFromWin32(::GetLastError());
        }
        else e.status = StatusFromWin32(::GetLastError());
        rep.entries.push_back(std::move(e));
    }
    rep.status = Status::Success;
    return rep;
}

} // namespace sa
