#include "SystemCollector.h"
#include "../RegistryReader.h"
#include <windows.h>
#include <winternl.h>

namespace sa {

    // RtlGetVersion via ntdll — the only reliable programmatic version query on Win11.
    typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

    static void FillVersion(OsInfo& o) {
        HMODULE nt = ::GetModuleHandleW(L"ntdll.dll");
        if (!nt) return;
        auto fn = reinterpret_cast<RtlGetVersionPtr>(::GetProcAddress(nt, "RtlGetVersion"));
        if (!fn) return;
        RTL_OSVERSIONINFOW vi{};
        vi.dwOSVersionInfoSize = sizeof(vi);
        if (fn(&vi) == 0) {
            o.build = vi.dwBuildNumber;
        }
    }

    static std::wstring DetectProductName(DWORD build) {
        auto edition = RegReadString(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"EditionID");
        std::wstring base = L"Windows ";
        if (build >= 22000)      base += L"11";
        else if (build >= 10240) base += L"10";
        else                     base += std::to_wstring(build);

        if (edition) {
            std::wstring e = *edition;
            if (e == L"Professional")            e = L"Pro";
            else if (e == L"ProfessionalWorkstation") e = L"Pro for Workstations";
            else if (e == L"Enterprise")         e = L"Enterprise";
            else if (e == L"EnterpriseS")        e = L"Enterprise LTSC";
            else if (e == L"Education")          e = L"Education";
            else if (e == L"Core")               e = L"Home";
            else if (e == L"CoreSingleLanguage") e = L"Home Single Language";
            base += L" " + e;
        }
        return base;
    }

    OsInfo CollectOsInfo() {
        OsInfo o;
        FillVersion(o);

        o.productName = DetectProductName(o.build);

        if (auto dv = RegReadString(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"DisplayVersion"))
            o.displayVersion = *dv;

        if (auto v = RegReadDword(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"UBR"))
            o.ubr = *v;

        SYSTEM_INFO si{};
        ::GetNativeSystemInfo(&si);
        switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: o.architecture = L"x64";   break;
        case PROCESSOR_ARCHITECTURE_INTEL: o.architecture = L"x86";   break;
        case PROCESSOR_ARCHITECTURE_ARM64: o.architecture = L"ARM64"; break;
        case PROCESSOR_ARCHITECTURE_ARM:   o.architecture = L"ARM";   break;
        default:                           o.architecture = L"Unknown";
        }

        DWORD cch = MAX_COMPUTERNAME_LENGTH + 1;
        wchar_t cname[MAX_COMPUTERNAME_LENGTH + 1]{};
        if (::GetComputerNameW(cname, &cch)) o.computerName.assign(cname, cch);

        cch = 256;
        wchar_t uname[256]{};
        if (::GetUserNameW(uname, &cch)) o.userName.assign(uname, cch ? cch - 1 : 0);

        ULONGLONG ms = ::GetTickCount64();
        o.uptimeSeconds = ms / 1000ULL;
        DYNAMIC_TIME_ZONE_INFORMATION tz{};
        if (::GetDynamicTimeZoneInformation(&tz) != TIME_ZONE_ID_INVALID)
            o.timeZone = tz.TimeZoneKeyName;

        wchar_t loc[LOCALE_NAME_MAX_LENGTH]{};
        if (::GetUserDefaultLocaleName(loc, LOCALE_NAME_MAX_LENGTH)) o.locale = loc;

        o.status = o.build ? Status::Success : Status::Unavailable;
        return o;
    }

} // namespace sa
