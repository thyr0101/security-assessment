#include "SecurityCollector.h"
#include "../WmiHelper.h"
#include "../RegistryReader.h"
#include "../Utilities.h"
#include <windows.h>
#include <winternl.h>
#include <vector>
#include <tbs.h>
#pragma comment(lib, "tbs.lib")

#pragma comment(lib, "advapi32.lib")

namespace sa {

    // ---------------- TPM via TBS / elevated WMI ----------------
    static void CollectTpm(TpmInfo& t) {
        if (!IsElevated()) {
            // The WMI namespace requires elevation and can delay an access-denied
            // response. TBS provides presence/version without that restricted query.
            TPM_DEVICE_INFO device{};
            const auto result = ::Tbsi_GetDeviceInfo(sizeof(device), &device);
            if (result == TBS_SUCCESS) {
                t.present = true;
                t.specVersion = device.tpmVersion == TPM_VERSION_20 ? L"2.0"
                    : device.tpmVersion == TPM_VERSION_12 ? L"1.2" : L"Unknown";
                t.status = Status::Success;
            } else t.status = result == TBS_E_TPM_NOT_FOUND ? Status::NotFound : Status::Unavailable;
            return;
        }
        ComInit ci;
        WmiConnection wmi;
        t.status = wmi.Connect(L"ROOT\\CIMV2\\Security\\MicrosoftTpm");
        if (t.status != Status::Success) {
            return;
        }
        WmiObjects objsOwner;
        auto& objs = objsOwner.items();
        auto st = wmi.Query(L"SELECT SpecVersion,ManufacturerId,ManufacturerVersion,"
            L"IsEnabled_InitialValue,IsActivated_InitialValue,"
            L"IsOwned_InitialValue FROM Win32_Tpm", objs);
        if (st != Status::Success || objs.empty()) {
            t.present = false;
            t.status = st == Status::Success ? Status::NotFound : st;
            return;
        }
        for (auto* o : objs) {
            WmiGetString(o, L"SpecVersion", t.specVersion);
            unsigned long long manufacturer = 0;
            if (WmiGetUInt(o, L"ManufacturerId", manufacturer)) {
                wchar_t id[16]{};
                swprintf_s(id, L"0x%08X", static_cast<unsigned>(manufacturer));
                t.manufacturerId = id;
            }
            WmiGetString(o, L"ManufacturerVersion", t.manufacturerVersion);

            bool b = false;
            const bool enabledKnown = WmiGetBool(o, L"IsEnabled_InitialValue", t.enabled);
            const bool activatedKnown = WmiGetBool(o, L"IsActivated_InitialValue", t.activated);
            t.readinessKnown = enabledKnown && activatedKnown;
            if (WmiGetBool(o, L"IsOwned_InitialValue", b)) t.owned = b;

            t.present = true;
        }
        t.ready = t.present && t.enabled && t.activated;
        t.status = Status::Success;
    }

    // ---------------- Secure Boot ----------------
    // Enabling a privilege only changes this process's own access token; it does not
    // change any system state.
    class SystemEnvironmentPrivilege {
        WinHandle token_;
        TOKEN_PRIVILEGES previous_{};
        bool changed_ = false;
    public:
        SystemEnvironmentPrivilege() {
            if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, token_.put())) return;
            TOKEN_PRIVILEGES tp{}; tp.PrivilegeCount = 1;
            if (!::LookupPrivilegeValueW(nullptr, SE_SYSTEM_ENVIRONMENT_NAME, &tp.Privileges[0].Luid)) return;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            DWORD size = sizeof(previous_);
            ::SetLastError(ERROR_SUCCESS);
            changed_ = ::AdjustTokenPrivileges(token_.get(), FALSE, &tp, sizeof(previous_), &previous_, &size) &&
                       ::GetLastError() == ERROR_SUCCESS;
        }
        ~SystemEnvironmentPrivilege() {
            if (changed_) ::AdjustTokenPrivileges(token_.get(), FALSE, &previous_, 0, nullptr, nullptr);
        }
    };

    static void CollectSecureBoot(SecureBootInfo& s) {
        FIRMWARE_TYPE ft = FirmwareTypeUnknown;
        if (::GetFirmwareType(&ft)) {
            s.firmwareIsUefi = (ft == FirmwareTypeUefi) ? Tri::Yes :
                (ft == FirmwareTypeBios) ? Tri::No : Tri::Unknown;
        }
        if (s.firmwareIsUefi == Tri::No) {
            s.supported = Tri::No; s.enabled = Tri::No;
            s.status = Status::Success; return;
        }

        // 1) Preferred source: the state the kernel publishes in the registry. It is
        //    readable without elevation and without any special privilege.
        if (auto sb = RegReadDword(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
                L"UEFISecureBootEnabled")) {
            s.enabled = (*sb != 0) ? Tri::Yes : Tri::No;
            if (*sb != 0) s.supported = Tri::Yes;
            s.status = Status::Success;
            return;
        }

        // 2) Fallback: read the firmware variable. This needs
        //    SeSystemEnvironmentPrivilege to be *enabled* in the token - an elevated
        //    token holds it but has it disabled by default, which is why the
        //    unmodified call fails with ERROR_PRIVILEGE_NOT_HELD.
        SystemEnvironmentPrivilege privilege;
        static const wchar_t* SB_GUID = L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}";
        BYTE buf[8]{};
        DWORD got = ::GetFirmwareEnvironmentVariableExW(L"SecureBoot", SB_GUID,
            buf, sizeof(buf), nullptr);
        if (got == sizeof(BYTE)) {
            s.supported = Tri::Yes;
            s.enabled = (buf[0] != 0) ? Tri::Yes : Tri::No;
            s.status = Status::Success;
            return;
        }
        DWORD err = ::GetLastError();
        if (err == ERROR_INVALID_FUNCTION) {
            s.supported = Tri::No; s.enabled = Tri::No; s.status = Status::Success;
        }
        else if (err == ERROR_ENVVAR_NOT_FOUND) {
            s.status = Status::Unavailable;
        }
        else if (err == ERROR_PRIVILEGE_NOT_HELD) {
            s.status = Status::AccessDenied;
        }
        else {
            s.status = Status::Unavailable;
        }
    }

    // ---------------- VBS / HVCI / Credential Guard ----------------
    static void CollectVbs(VirtualizationInfo& v) {
        ComInit ci;
        bool haveRunning = false;

        // Win32_DeviceGuard lives in its own namespace - it does NOT exist in ROOT\CIMV2,
        // so querying it there always fails and every field stays "disabled".
        WmiConnection wmi;
        if (wmi.Connect(L"ROOT\\Microsoft\\Windows\\DeviceGuard") == Status::Success) {
            WmiObjects objsOwner;
            auto& objs = objsOwner.items();
            if (wmi.Query(L"SELECT * FROM Win32_DeviceGuard", objs) == Status::Success) {
                for (auto* o : objs) {
                    unsigned long long vbs = 0;
                    if (WmiGetUInt(o, L"VirtualizationBasedSecurityStatus", vbs)) {
                        v.deviceGuardAvailable = true;
                        v.vbsEnabled = (vbs == 2);   // 0 = off, 1 = enabled but not running, 2 = running
                    }
                    // Services actually running: 1 = Credential Guard, 2 = HVCI,
                    // 3 = System Guard Secure Launch, 4 = SMM firmware measurement,
                    // 5 = Kernel-mode Hardware-enforced Stack Protection.
                    std::vector<unsigned long long> running;
                    if (WmiGetUIntArray(o, L"SecurityServicesRunning", running)) {
                        haveRunning = true;
                        v.runningServicesKnown = true;
                        for (unsigned long long id : running) {
                            if (id == 1) v.credentialGuardRunning = true;
                            if (id == 2) v.hvciEnabled = true;
                        }
                    }
                }
            }
        }
        if (v.deviceGuardAvailable) v.status = Status::Success;

        // Fallback when WMI could not report the running services: use the HVCI
        // *configured* state. (Credential Guard has no reliable registry indicator of
        // "running", so it is left false rather than guessed from LsaCfgFlags.)
        if (!haveRunning) {
            if (auto h = RegReadDword(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\"
                L"HypervisorEnforcedCodeIntegrity",
                L"Enabled"))
                v.hvciConfigured = (*h == 1) ? Tri::Yes : Tri::No;
        }
    }

    // ---------------- UAC ----------------
    static void CollectUac(UacInfo& u) {
        RegistryReader r;
        u.status = r.Open(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
        if (u.status != Status::Success) return;
        DWORD v = 0;
        auto read = [&](const wchar_t* name, DWORD& value) {
            const auto status = r.GetDword(name, value);
            if (status != Status::Success) u.status = status;
            return status == Status::Success;
        };
        if (read(L"EnableLUA", v)) u.enabled = v != 0;
        read(L"ConsentPromptBehaviorAdmin", u.consentPromptBehaviorAdmin);
        read(L"PromptOnSecureDesktop", u.promptOnSecureDesktop);
        u.consentPromptAdmin = u.consentPromptBehaviorAdmin >= 1 && u.consentPromptBehaviorAdmin <= 5;
    }

    // ---------------- DEP / SEHOP ----------------
    typedef DWORD(WINAPI* GetSystemDEPPolicyPtr)();
    static void CollectDep(DepInfo& d) {
        // Hardware NX actually in force for the OS.
        const bool nxOn = ::IsProcessorFeaturePresent(PF_NX_ENABLED) != FALSE;

        bool havePolicy = false;
        DWORD p = 0;   // 0 = AlwaysOff, 1 = AlwaysOn, 2 = OptIn, 3 = OptOut
        if (HMODULE k = ::GetModuleHandleW(L"kernel32.dll")) {
            auto f = reinterpret_cast<GetSystemDEPPolicyPtr>(
                reinterpret_cast<void*>(::GetProcAddress(k, "GetSystemDEPPolicy")));
            if (f) { p = f(); havePolicy = (p <= 3); }
        }
        if (havePolicy) {
            // OptIn is the stock Windows client setting (essential Windows components
            // are covered, and 64-bit processes always get hardware DEP), so it counts
            // as enabled. Only AlwaysOff, or no usable NX, counts as disabled.
            d.depEnabled = (p == 0 || !nxOn) ? Tri::No : Tri::Yes;
        }
        else {
            d.depEnabled = nxOn ? Tri::Yes : Tri::No;
        }

        // SEHOP is on by default on current Windows (Exploit protection reports it as
        // "On by default"); only an explicit DisableExceptionChainValidation != 0
        // turns it off. An absent value therefore means enabled, not "unknown".
        RegistryReader kernel;
        const Status opened = kernel.Open(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel");
        if (opened == Status::Success) {
            DWORD value = 0;
            const Status read = kernel.GetDword(L"DisableExceptionChainValidation", value);
            if (read == Status::Success) d.sehopEnabled = value ? Tri::No : Tri::Yes;
            else if (read == Status::NotFound) d.sehopEnabled = Tri::Yes;
        }

        d.status = Status::Success;
    }

    // ---------------- Smart App Control ----------------
    static void CollectSac(SecurityInfo& s) {
        RegistryReader r;
        if (r.Open(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy") == Status::Success) {
            DWORD v = 0;
            if (r.GetDword(L"VerifiedAndReputablePolicyState", v) == Status::Success) {
                switch (v) {
                case 0: s.smartAppControlState = Tri::No;  s.smartAppControlOn = false; break;
                case 1: s.smartAppControlState = Tri::Yes; s.smartAppControlOn = true; break;
                case 2: s.smartAppControlState = Tri::No; s.smartAppControlEvaluation = true; break;
                default: s.smartAppControlState = Tri::Unknown; break;
                }
            }
        }
    }

    // ---------------- Windows Hello ----------------
    static void CollectHello(SecurityInfo& s) {
        // Presence of the WinBio provider key indicates the Hello stack exists.
        RegistryReader r;
        if (r.Open(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WinBio")
            == Status::Success) {
            s.windowsHelloAvailable = true;
        }
    }

    SecurityInfo CollectSecurityInfo() {
        SecurityInfo s;
        // Keep the results of other checks when one provider throws.
        try { CollectTpm(s.tpm); } catch (...) { s.tpm.status = Status::Error; }
        try { CollectSecureBoot(s.secureBoot); } catch (...) { s.secureBoot.status = Status::Error; }
        try { CollectVbs(s.virt); } catch (...) { s.virt.status = Status::Error; }
        try { CollectUac(s.uac); } catch (...) { s.uac.status = Status::Error; }
        try { CollectDep(s.dep); } catch (...) { s.dep.status = Status::Error; }
        try { CollectSac(s); } catch (...) { s.smartAppControlState = Tri::Unknown; }
        try { CollectHello(s); } catch (...) { s.windowsHelloAvailable = false; }
        s.isElevated = IsElevated();
        return s;
    }

} // namespace sa
