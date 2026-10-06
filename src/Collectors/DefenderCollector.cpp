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

// True when a "Disable*" style flag is NOT set to 1 (absent => feature is on).
bool FlagNotDisabled(const std::wstring& sub, const wchar_t* value) {
    auto v = RegReadDword(HKEY_LOCAL_MACHINE, sub, value);
    return !(v && *v == 1);
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
        std::vector<IWbemClassObject*> objs;
        if (wmi.Query(L"SELECT * FROM MSFT_MpComputerStatus", objs, &why) == Status::Success
            && !objs.empty()) {
            gotStatus = true;
            d.installed = true;
            for (auto* o : objs) {
                bool b = false;
                bool haveSvc = WmiGetBool(o, L"AMServiceEnabled", b);
                if (haveSvc) d.enabled = b;
                if (WmiGetBool(o, L"AntivirusEnabled", b)) {
                    d.antivirusEnabled = b;
                    if (!haveSvc) d.enabled = b;
                }
                if (WmiGetBool(o, L"AntispywareEnabled", b))        d.antispywareEnabled = b;
                if (WmiGetBool(o, L"RealTimeProtectionEnabled", b)) d.realTimeProtection = b;
                if (WmiGetBool(o, L"BehaviorMonitorEnabled", b))    d.behaviorMonitor = b;
                if (WmiGetBool(o, L"IoavProtectionEnabled", b))     d.ioav = b;
                if (WmiGetBool(o, L"OnAccessProtectionEnabled", b)) d.onAccessProtection = b;
                if (WmiGetBool(o, L"IsTamperProtected", b))         d.tamperProtection = b;
                WmiGetString(o, L"AMEngineVersion", d.amEngineVersion);
                WmiGetString(o, L"AMProductVersion", d.amProductVersion);
                WmiGetString(o, L"AMServiceVersion", d.amServiceVersion);
                WmiGetString(o, L"AntivirusSignatureVersion", d.antivirusSignatureVersion);
                WmiGetString(o, L"AntivirusSignatureLastUpdated", d.antivirusSignatureLastUpdated);
                WmiGetString(o, L"QuickScanStartTime", d.lastQuickScan);
                WmiGetString(o, L"FullScanStartTime", d.lastFullScan);
                unsigned long long age = 0;     // uint32 in WMI, so not readable as a string
                if (WmiGetUInt(o, L"QuickScanAge", age)) d.quickScanAge = std::to_wstring(age);
                o->Release();
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
        std::vector<IWbemClassObject*> pref;
        if (gotStatus &&
            wmi.Query(L"SELECT * FROM MSFT_MpPreference", pref) == Status::Success) {
            for (auto* o : pref) {
                unsigned long long u = 0;
                if (WmiGetUInt(o, L"MAPSReporting", u))        d.cloudProtection = (u != 0);
                if (WmiGetUInt(o, L"SubmitSamplesConsent", u)) d.sampleSubmission = (u == 1 || u == 3);
                o->Release();
            }
        }
    }

    // Active threats come from MSFT_MpThreat (MSFT_MpComputerStatus has no threat count).
    if (gotStatus) {
        std::vector<IWbemClassObject*> threats;
        if (wmi.Query(L"SELECT * FROM MSFT_MpThreat", threats) == Status::Success) {
            unsigned active = 0;
            for (auto* o : threats) {
                bool b = false;
                if (WmiGetBool(o, L"IsActive", b) && b) ++active;
                o->Release();
            }
            d.threatsCount = active;
            d.threatsKnown = true;
        }
        d.status = Status::Success;
    }
    return d;
}

} // namespace sa
