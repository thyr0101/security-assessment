#include "DefenderCollector.h"
#include "../WmiHelper.h"
#include <comdef.h>
#include <wrl/client.h>
#include <windows.h>
#include <vector>

namespace sa {

namespace {

const wchar_t* kDefenderNs = L"ROOT\\Microsoft\\Windows\\Defender";
// Discover the available schema properties first so optional fields on older
// Defender builds cannot invalidate the whole projection. No SELECT * snapshot.
std::wstring StatusQuery(WmiConnection& wmi, bool registrationOnly) {
    Microsoft::WRL::ComPtr<IWbemClassObject> schema;
    _bstr_t name(L"MSFT_MpComputerStatus");
    if (FAILED(wmi.services()->GetObject(name, 0, nullptr, schema.GetAddressOf(), nullptr)) || !schema) return {};
    std::wstring query = L"SELECT ";
    bool first = true;
    for (const auto* property : {L"AntivirusEnabled", L"RealTimeProtectionEnabled", L"BehaviorMonitorEnabled",
        L"IoavProtectionEnabled", L"IsTamperProtected", L"AMEngineVersion", L"AntivirusSignatureVersion", L"AMRunningMode"}) {
        const bool mode = wcscmp(property, L"AMRunningMode") == 0;
        if (registrationOnly ? (!mode && wcscmp(property, L"AntivirusEnabled") != 0) : mode) continue;
        _variant_t value;
        if (FAILED(schema->Get(property, 0, &value, nullptr, nullptr))) continue;
        if (!first) query += L",";
        query += property; first = false;
    }
    return first ? std::wstring{} : query + L" FROM MSFT_MpComputerStatus";
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

DefenderInfo CollectDefenderInfo(bool registrationOnly) {
    DefenderInfo d;
    ComInit ci;
    std::wstring why;

    WmiConnection wmi;
    bool gotStatus = false;

    if (wmi.Connect(kDefenderNs, &why) == Status::Success) {
        const auto query = StatusQuery(wmi, registrationOnly);
        WmiObjects objsOwner;
        auto& objs = objsOwner.items();
        if (!query.empty() && wmi.Query(query.c_str(), objs, &why) == Status::Success
            && !objs.empty()) {
            gotStatus = true;
            d.installed = true;
            for (auto* o : objs) {
                bool b = false;
                if (WmiGetBool(o, L"AntivirusEnabled", b)) {
                    d.enabled = b; // A running Defender service can be passive alongside another AV.
                    d.enabledStatus = Status::Success;
                }
                auto flag = [&](const wchar_t* name, bool& value, Status& status) {
                    status = WmiGetBool(o, name, value) ? Status::Success : Status::Unavailable;
                };
                flag(L"RealTimeProtectionEnabled", d.realTimeProtection, d.realTimeProtectionStatus);
                flag(L"BehaviorMonitorEnabled", d.behaviorMonitor, d.behaviorMonitorStatus);
                flag(L"IoavProtectionEnabled", d.ioav, d.ioavStatus);
                flag(L"IsTamperProtected", d.tamperProtection, d.tamperProtectionStatus);
                WmiGetString(o, L"AMEngineVersion", d.amEngineVersion);
                WmiGetString(o, L"AMRunningMode", d.amRunningMode);
                d.periodicScanning = PeriodicScanningFromMode(d.amRunningMode);
                WmiGetString(o, L"AntivirusSignatureVersion", d.antivirusSignatureVersion);

            }
        }
    }

    if (!gotStatus) {
        d.status = Status::Unavailable;
        d.reason = L"Defender status could not be read: " + (why.empty() ? std::wstring(L"No supported status properties were available.") : why);
        return d;
    }

    // Cloud protection lives in MSFT_MpPreference.
    {
        WmiObjects prefOwner;
        auto& pref = prefOwner.items();
        if (gotStatus && !registrationOnly &&
            wmi.Query(L"SELECT MAPSReporting FROM MSFT_MpPreference", pref) == Status::Success) {
            for (auto* o : pref) {
                unsigned long long u = 0;
                if (WmiGetUInt(o, L"MAPSReporting", u)) {
                    d.cloudProtection = (u != 0);
                    d.cloudProtectionStatus = Status::Success;
                }
            }
        }
    }

    // Active threats come from MSFT_MpThreat (MSFT_MpComputerStatus has no threat count).
    if (gotStatus && !registrationOnly) {
        WmiObjects threatsOwner;
        auto& threats = threatsOwner.items();
        if (wmi.Query(L"SELECT IsActive FROM MSFT_MpThreat", threats) == Status::Success) {
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
    }
    d.status = gotStatus ? Status::Success : Status::Unavailable;
    return d;
}

} // namespace sa
