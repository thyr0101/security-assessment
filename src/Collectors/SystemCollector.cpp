#include "SystemCollector.h"
#include "../RegistryReader.h"
#include <windows.h>
#include <chrono>

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
            o.major = vi.dwMajorVersion;
            o.minor = vi.dwMinorVersion;
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

        if (auto bl = RegReadString(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"BuildLabEx"))
            o.buildLab = *bl;

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

        wchar_t buf[MAX_PATH]{};
        if (UINT n = ::GetWindowsDirectoryW(buf, MAX_PATH)) o.systemRoot.assign(buf, n);
        if (UINT n = ::GetSystemDirectoryW(buf, MAX_PATH))  o.systemDirectory.assign(buf, n);

        DWORD cch = MAX_COMPUTERNAME_LENGTH + 1;
        wchar_t cname[MAX_COMPUTERNAME_LENGTH + 1]{};
        if (::GetComputerNameW(cname, &cch)) o.computerName.assign(cname, cch);

        cch = 256;
        wchar_t uname[256]{};
        if (::GetUserNameW(uname, &cch)) o.userName.assign(uname, cch ? cch - 1 : 0);

        if (auto d = RegReadString(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", L"Domain"))
            o.domainOrWorkgroup = *d;
        if (o.domainOrWorkgroup.empty())
            if (auto w = RegReadString(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", L"NV Domain"))
                o.domainOrWorkgroup = *w;

        if (auto v = RegReadDword(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"InstallDate")) {
            time_t t = static_cast<time_t>(*v);
            struct tm g {}; gmtime_s(&g, &t);
            wchar_t out[64]{};
            wcsftime(out, 64, L"%Y-%m-%d", &g);
            o.installDate = out;
        }

        ULONGLONG ms = ::GetTickCount64();
        o.uptimeSeconds = ms / 1000ULL;
        FILETIME now{}; ::GetSystemTimeAsFileTime(&now);
        ULARGE_INTEGER u; u.LowPart = now.dwLowDateTime; u.HighPart = now.dwHighDateTime;
        u.QuadPart -= ms * 10000ULL;
        o.bootTime.dwLowDateTime = u.LowPart;
        o.bootTime.dwHighDateTime = u.HighPart;

        DYNAMIC_TIME_ZONE_INFORMATION tz{};
        if (::GetDynamicTimeZoneInformation(&tz) != TIME_ZONE_ID_INVALID)
            o.timeZone = tz.TimeZoneKeyName;

        wchar_t loc[LOCALE_NAME_MAX_LENGTH]{};
        if (::GetUserDefaultLocaleName(loc, LOCALE_NAME_MAX_LENGTH)) o.locale = loc;

        {
            LANGID lid = ::GetUserDefaultUILanguage();
            wchar_t name[LOCALE_NAME_MAX_LENGTH]{};
            if (lid && ::LCIDToLocaleName(MAKELCID(lid, SORT_DEFAULT), name,
                LOCALE_NAME_MAX_LENGTH, 0))
                o.systemLanguage = name;
        }

        o.status = Status::Success;
        return o;
    }

} // namespace sa