#include "DefenderCollector.h"
#include "../WmiHelper.h"
#include "../RegistryReader.h"
#include <windows.h>
#include <vector>

namespace sa {

namespace {

const wchar_t* kDefenderNs = L"ROOT\\Microsoft\\Windows\\Defender";
const wchar_t* kDefenderKey = L"SOFTWARE\\Microsoft\\Windows Defender";

// WinDefend service state via the SCM (works without elevation).
// Returns true if the service exists; `running` reports its state.
bool QueryWinDefend(bool& running) {
    running = false;
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    bool exists = false;
    if (SC_HANDLE svc = ::OpenServiceW(scm, L"WinDefend", SERVICE_QUERY_STATUS)) {
        exists = true;
        SERVICE_STATUS st{};
        if (::QueryServiceStatus(svc, &st)) running = (st.dwCurrentState == SERVICE_RUNNING);
        ::CloseServiceHandle(svc);
    }
    ::CloseServiceHandle(scm);
    return exists;
}

// Registry absence is not evidence that a runtime protection is active.
bool FlagNotDisabled(const std::wstring& sub, const wchar_t* value) {
    auto v = RegReadDword(HKEY_LOCAL_MACHINE, sub, value);
    return v && *v == 0;
}

// Used only when the Defender WMI provider cannot be queried.
void FillFromServiceAndRegistry(DefenderInfo& d) {
    bool running = false;
    if (!QueryWinDefend(running)) return;           // Defender service not present
    d.installed = true;
    d.enabled = running;
    if (!running) return;

    const std::wstring rtp = std::wstring(kDefenderKey) + L"\\Real-Time Protection";
    d.realTimeProtection = FlagNotDisabled(rtp, L"DisableRealtimeMonitoring");
    d.behaviorMonitor    = FlagNotDisabled(rtp, L"DisableBehaviorMonitoring");
    d.ioav               = FlagNotDisabled(rtp, L"DisableIOAVProtection");
    d.onAccessProtection = FlagNotDisabled(rtp, L"DisableOnAccessProtection");

    // Tamper Protection: 5 = on, 4 = off.
    if (auto t = RegReadDword(HKEY_LOCAL_MACHINE,
            std::wstring(kDefenderKey) + L"\\Features", L"TamperProtection"))
        d.tamperProtection = (*t == 5);

    // Cloud-delivered protection (MAPS): 0 = off, 1 = basic, 2 = advanced.
    if (auto m = RegReadDword(HKEY_LOCAL_MACHINE,
            std::wstring(kDefenderKey) + L"\\Spynet", L"SpynetReporting"))
        d.cloudProtection = (*m != 0);
}

} // namespace

Tri PeriodicScanningFromMode(const std::wstring& mode) {
    const auto normalized = Trim(mode);
    // AMRunningMode is read directly from MSFT_MpComputerStatus, without PowerShell.
    // https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows
    if (IEquals(normalized, L"SxS Passive Mode")) return Tri::Yes;
    if (IEquals(normalized, L"Normal") || IEquals(normalized, L"Passive Mode") ||
        IEquals(normalized, L"EDR Block Mode")) return Tri::No;
    return Tri::Unknown;
}

DefenderInfo CollectDefenderInfo() {
    DefenderInfo d;
    ComInit ci;
    std::wstring why;

    WmiConnection wmi;
    bool gotStatus = false;

    if (wmi.Connect(kDefenderNs, &why) == Status::Success) {
        // "SELECT *" on purpose: when a property is named explicitly and does not exist
        // on this Defender build, the whole query is rejected (WBEM_E_INVALID_QUERY)
        // and Defender then looks "not installed". The old query named ThreatsCount,
        // which MSFT_MpComputerStatus does not have.
        WmiObjects objsOwner;
        auto& objs = objsOwner.items();
        if (wmi.Query(L"SELECT * FROM MSFT_MpComputerStatus", objs, &why) == Status::Success
            && !objs.empty()) {
            gotStatus = true;
            d.installed = true;
            for (auto* o : objs) {
                bool b = false;
                if (WmiGetBool(o, L"AntivirusEnabled", b)) {
                    d.antivirusEnabled = b;
                    d.enabled = b; // A running Defender service can be passive alongside another AV.
                    d.enabledStatus = Status::Success;
                }
                auto flag = [&](const wchar_t* name, bool& value, Status& status) {
                    status = WmiGetBool(o, name, value) ? Status::Success : Status::Unavailable;
                };
                if (WmiGetBool(o, L"AntispywareEnabled", b))        d.antispywareEnabled = b;
                flag(L"RealTimeProtectionEnabled", d.realTimeProtection, d.realTimeProtectionStatus);
                flag(L"BehaviorMonitorEnabled", d.behaviorMonitor, d.behaviorMonitorStatus);
                flag(L"IoavProtectionEnabled", d.ioav, d.ioavStatus);
                if (WmiGetBool(o, L"OnAccessProtectionEnabled", b)) d.onAccessProtection = b;
                flag(L"IsTamperProtected", d.tamperProtection, d.tamperProtectionStatus);
                WmiGetString(o, L"AMEngineVersion", d.amEngineVersion);
                WmiGetString(o, L"AMProductVersion", d.amProductVersion);
                WmiGetString(o, L"AMServiceVersion", d.amServiceVersion);
                WmiGetString(o, L"AMRunningMode", d.amRunningMode);
                d.periodicScanning = PeriodicScanningFromMode(d.amRunningMode);
                WmiGetString(o, L"AntivirusSignatureVersion", d.antivirusSignatureVersion);
                WmiGetString(o, L"AntivirusSignatureLastUpdated", d.antivirusSignatureLastUpdated);
                WmiGetString(o, L"QuickScanStartTime", d.lastQuickScan);
                WmiGetString(o, L"FullScanStartTime", d.lastFullScan);
                unsigned long long age = 0;     // uint32 in WMI, so not readable as a string
                if (WmiGetUInt(o, L"QuickScanAge", age)) d.quickScanAge = std::to_wstring(age);
            }
        }
    }

    if (!gotStatus) {
        // Don't report every protection as "disabled" just because WMI failed.
        FillFromServiceAndRegistry(d);
        d.status = d.installed ? Status::Unavailable : Status::NotFound;
        d.reason = L"Defender WMI status unavailable: " + why +
                   (d.installed ? L" (values taken from service/registry)" : L"");
        if (!d.installed) return d;
    }

    // Cloud protection / sample submission live in MSFT_MpPreference.
    {
        WmiObjects prefOwner;
        auto& pref = prefOwner.items();
        if (gotStatus &&
            wmi.Query(L"SELECT * FROM MSFT_MpPreference", pref) == Status::Success) {
            for (auto* o : pref) {
                unsigned long long u = 0;
                if (WmiGetUInt(o, L"MAPSReporting", u)) {
                    d.cloudProtection = (u != 0);
                    d.cloudProtectionStatus = Status::Success;
                }
                if (WmiGetUInt(o, L"SubmitSamplesConsent", u)) d.sampleSubmission = (u == 1 || u == 3);
            }
        }
    }

    // Active threats come from MSFT_MpThreat (MSFT_MpComputerStatus has no threat count).
    if (gotStatus) {
        WmiObjects threatsOwner;
        auto& threats = threatsOwner.items();
        if (wmi.Query(L"SELECT * FROM MSFT_MpThreat", threats) == Status::Success) {
            unsigned active = 0;
            bool complete = true;
            for (auto* o : threats) {
                bool b = false;
                if (!WmiGetBool(o, L"IsActive", b)) complete = false;
                else if (b) ++active;
            }
            d.threatsCount = active;
            d.threatsKnown = complete;
        }
        d.status = Status::Success;
    }
    return d;
}

} // namespace sa
