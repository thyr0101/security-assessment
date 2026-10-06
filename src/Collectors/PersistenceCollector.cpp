#include "PersistenceCollector.h"
#include "../RegistryReader.h"
#include "../Utilities.h"
#include <windows.h>
#include <filesystem>
#include <vector>

namespace fs = std::filesystem;

namespace sa {

static void AddRunKey(PersistenceReport& rep, HKEY root, const std::wstring& path,
                      const std::wstring& display) {
    RegistryReader r;
    if (r.Open(root, path, KEY_WOW64_64KEY) != Status::Success) return;
    std::vector<std::pair<std::wstring, DWORD>> vals;
    if (r.EnumValues(vals) != Status::Success) return;
    for (auto& [name, type] : vals) {
        if (name == L"(Default)") continue;
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
            for (auto& it : fs::directory_iterator(dir, ec)) {
                PersistenceEntry e;
                e.location = L"Startup (user)";
                e.name = it.path().filename().wstring();
                e.command = it.path().wstring();
                rep.entries.push_back(std::move(e));
            }
        }
    }
    n = ::GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH);
    if (n && n < MAX_PATH) {
        fs::path dir = fs::path(buf) / L"Microsoft\\Windows\\Start Menu\\Programs\\Startup";
        std::error_code ec;
        if (fs::exists(dir, ec)) {
            for (auto& it : fs::directory_iterator(dir, ec)) {
                PersistenceEntry e;
                e.location = L"Startup (machine)";
                e.name = it.path().filename().wstring();
                e.command = it.path().wstring();
                rep.entries.push_back(std::move(e));
            }
        }
    }
}

PersistenceReport CollectPersistence() {
    PersistenceReport rep;
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
    ScanStartupFolders(rep);
    rep.status = Status::Success;
    return rep;
}

std::vector<RegistryScanDefinition> DefaultRegistryScans() {
    return {
        { L"HKCU Run",              HKEY_CURRENT_USER,
          L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 5, KEY_WOW64_64KEY },
        { L"HKLM Run",              HKEY_LOCAL_MACHINE,
          L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 10, KEY_WOW64_64KEY },
        { L"HKLM RunOnce",          HKEY_LOCAL_MACHINE,
          L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 5, KEY_WOW64_64KEY },
        { L"HKLM Wow64 Run",        HKEY_LOCAL_MACHINE,
          L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", 10, KEY_WOW64_64KEY },
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
            r.CountValues(f.valueCount);
            r.CountSubkeys(f.subkeyCount);
            f.exceeded = f.valueCount > d.threshold;
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
        f.path = d.path;
        f.threshold = d.threshold;
        std::wstring path = ExpandEnv(d.path);
        std::error_code ec;
        if (!fs::exists(path, ec)) { f.status = Status::NotFound; out.push_back(std::move(f)); continue; }
        fs::directory_iterator it(path, fs::directory_options::skip_permission_denied, ec);
        if (ec) { f.status = Status::AccessDenied; out.push_back(std::move(f)); continue; }
        unsigned long long files = 0, dirs = 0;
        for (auto& e : it) {
            std::error_code e2;
            if (e.is_directory(e2)) ++dirs;
            else ++files;
        }
        f.fileCount = files;
        f.dirCount = dirs;
        f.exceeded = files > d.threshold;
        f.status = Status::Success;
        out.push_back(std::move(f));
    }
    return out;
}

// ---------------- Security-relevant services ----------------
static const wchar_t* kSecurityServices[] = {
    L"WinDefend", L"WdNisSvc", L"SecurityHealthService", L"wscsvc",
    L"MpsSvc", L"wuauserv", L"CryptSvc", L"EventLog", L"mpssvc"
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
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) { rep.status = Status::AccessDenied; return rep; }
    for (auto* name : kSecurityServices) {
        ServiceEntry e;
        e.name = name;
        SC_HANDLE svc = ::OpenServiceW(scm, name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
        if (!svc) { e.status = Status::NotFound; rep.entries.push_back(std::move(e)); continue; }
        SERVICE_STATUS_PROCESS ssp{}; DWORD needed = 0;
        if (::QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed))
            e.state = StateName(ssp.dwCurrentState);
        DWORD cfgSz = 0;
        ::QueryServiceConfigW(svc, nullptr, 0, &cfgSz);
        if (cfgSz) {
            std::vector<BYTE> buf(cfgSz);
            auto* cfg = (QUERY_SERVICE_CONFIGW*)buf.data();
            if (::QueryServiceConfigW(svc, cfg, cfgSz, &cfgSz)) {
                e.displayName = cfg->lpDisplayName ? cfg->lpDisplayName : L"";
                e.startType = StartName(cfg->dwStartType);
                e.exePath = cfg->lpBinaryPathName ? cfg->lpBinaryPathName : L"";
            }
        }
        e.status = Status::Success;
        ::CloseServiceHandle(svc);
        rep.entries.push_back(std::move(e));
    }
    ::CloseServiceHandle(scm);
    rep.status = Status::Success;
    return rep;
}

} // namespace sa