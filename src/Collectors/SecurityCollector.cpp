#include "SecurityCollector.h"
#include "../WmiHelper.h"
#include "../RegistryReader.h"
#include "../Utilities.h"
#include <windows.h>
#include <winternl.h>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace sa {

    // ---------------- TPM via WMI ----------------
    static void CollectTpm(TpmInfo& t) {
        ComInit ci;
        WmiConnection wmi;
        if (wmi.Connect(L"ROOT\\CIMV2\\Security\\MicrosoftTpm") != Status::Success) {
            t.status = Status::Unavailable;
            return;
        }
        std::vector<IWbemClassObject*> objs;
        auto st = wmi.Query(L"SELECT SpecVersion,ManufacturerId,ManufacturerVersion,"
            L"IsEnabled_InitialValue,IsActivated_InitialValue,"
            L"IsOwned_InitialValue FROM Win32_Tpm", objs);
        if (st != Status::Success || objs.empty()) {
            t.present = false;
            t.status = Status::NotFound;
            return;
        }
        for (auto* o : objs) {
            WmiGetString(o, L"SpecVersion", t.specVersion);
            WmiGetString(o, L"ManufacturerId", t.manufacturerId);
            WmiGetString(o, L"ManufacturerVersion", t.manufacturerVersion);

            bool b = false;
            if (WmiGetBool(o, L"IsEnabled_InitialValue", b)) t.enabled = b;
            if (WmiGetBool(o, L"IsActivated_InitialValue", b)) t.activated = b;
            if (WmiGetBool(o, L"IsOwned_InitialValue", b)) t.owned = b;

            t.present = true;
            o->Release();
        }
        t.ready = t.present && t.enabled && t.activated;
        t.status = Status::Success;
    }

    // ---------------- Secure Boot ----------------
    // Enabling a privilege only changes this process's own access token; it does not
    // change any system state.
    static bool EnableSystemEnvironmentPrivilege() {
        HANDLE tok = nullptr;
        if (!::OpenProcessToken(::GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
            return false;
        WinHandle h(tok);
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        if (!::LookupPrivilegeValueW(nullptr, SE_SYSTEM_ENVIRONMENT_NAME,
                &tp.Privileges[0].Luid))
            return false;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ::SetLastError(ERROR_SUCCESS);
        if (!::AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr))
            return false;
        // AdjustTokenPrivileges "succeeds" even when the privilege is not held and
        // reports that through ERROR_NOT_ALL_ASSIGNED.
        return ::GetLastError() == ERROR_SUCCESS;
    }

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
        (void)EnableSystemEnvironmentPrivilege();
        static const wchar_t* SB_GUID = L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}";
        BYTE buf[8]{};
        DWORD got = ::GetFirmwareEnvironmentVariableExW(L"SecureBoot", SB_GUID,
            buf, sizeof(buf), nullptr);
        if (got == sizeof(BYTE) || got == sizeof(buf)) {
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
            s.supported = Tri::Yes; s.enabled = Tri::No; s.status = Status::Success;
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
            std::vector<IWbemClassObject*> objs;
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
                        for (unsigned long long id : running) {
                            if (id == 1) v.credentialGuardRunning = true;
                            if (id == 2) v.hvciEnabled = true;
                        }
                    }
                    o->Release();
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
                v.hvciEnabled = (*h == 1);
        }
    }

    // ---------------- UAC ----------------
    static void CollectUac(UacInfo& u) {
        RegistryReader r;
        if (r.Open(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System")
            != Status::Success) {
            u.status = Status::AccessDenied;
            return;
        }
        DWORD v = 0;
        if (r.GetDword(L"EnableLUA", v) == Status::Success)                   u.enabled = (v != 0);
        if (r.GetDword(L"ConsentPromptBehaviorAdmin", v) == Status::Success)  u.consentPromptBehaviorAdmin = v;
        if (r.GetDword(L"PromptOnSecureDesktop", v) == Status::Success)       u.promptOnSecureDesktop = v;
        u.consentPromptAdmin = (u.consentPromptBehaviorAdmin >= 2);
        u.status = Status::Success;
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
        auto s = RegReadDword(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel",
            L"DisableExceptionChainValidation");
        d.sehopEnabled = (s && *s != 0) ? Tri::No : Tri::Yes;

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
                case 1:
                case 2: s.smartAppControlState = Tri::Yes; s.smartAppControlOn = true;  break;
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
        if (!s.windowsHelloAvailable) {
            RegistryReader r2;
            if (r2.Open(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notifications")
                == Status::Success)
                s.windowsHelloAvailable = true;
        }
    }

    SecurityInfo CollectSecurityInfo() {
        SecurityInfo s;
        CollectTpm(s.tpm);
        CollectSecureBoot(s.secureBoot);
        CollectVbs(s.virt);
        CollectUac(s.uac);
        CollectDep(s.dep);
        CollectSac(s);
        CollectHello(s);
        s.isElevated = IsElevated();
        return s;
    }

} // namespace sa