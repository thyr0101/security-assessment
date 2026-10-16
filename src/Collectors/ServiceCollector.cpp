#include "ServiceCollector.h"
#include "../Utilities.h"

namespace sa {
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
