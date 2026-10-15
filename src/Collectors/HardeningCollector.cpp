#include "HardeningCollector.h"
#include "../RegistryReader.h"
#include <tlhelp32.h>
#include <lm.h>
#include <memory>
#include <expected>
#include <ranges>
#include <array>
#include <algorithm>

#pragma comment(lib, "netapi32.lib")

namespace sa {
namespace {
constexpr auto kLsa = L"SYSTEM\\CurrentControlSet\\Control\\Lsa";
constexpr auto kSystemPolicy = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";

std::expected<DWORD, Status> ReadDword(const wchar_t* path, const wchar_t* name) {
    RegistryReader reader;
    auto status = reader.Open(HKEY_LOCAL_MACHINE, path);
    DWORD value = 0;
    if (status == Status::Success) status = reader.GetDword(name, value);
    if (status != Status::Success) return std::unexpected(status);
    return value;
}
SecuritySetting BooleanPolicy(const wchar_t* path, const wchar_t* name, bool inverted = false) {
    SecuritySetting setting;
    setting.source = std::wstring(L"HKLM\\") + path + L"\\" + name;
    const auto value = ReadDword(path, name);
    setting.status = value ? (*value <= 1 ? Status::Success : Status::Error) : value.error();
    if (setting.status == Status::Success)
        setting.enabled = ((*value != 0) != inverted) ? Tri::Yes : Tri::No;
    return setting;
}
void CollectLsaProtection(SecuritySetting& setting) {
    setting.source = L"GetProcessInformation(ProcessProtectionLevelInfo) for lsass.exe";
    WinHandle snapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) { setting.status = StatusFromWin32(::GetLastError()); return; }
    PROCESSENTRY32W entry{sizeof(entry)};
    if (!::Process32FirstW(snapshot.get(), &entry)) { setting.status = StatusFromWin32(::GetLastError()); return; }
    do {
        if (!IEquals(entry.szExeFile, L"lsass.exe")) continue;
        WinHandle process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID));
        if (!process) { setting.status = StatusFromWin32(::GetLastError()); return; }
        PROCESS_PROTECTION_LEVEL_INFORMATION protection{};
        if (!::GetProcessInformation(process.get(), ProcessProtectionLevelInfo, &protection, sizeof(protection))) {
            setting.status = StatusFromWin32(::GetLastError()); return;
        }
        // Treat unrecognized future protection levels as unknown, rather than unprotected.
        constexpr std::array<DWORD, 5> levels{PROTECTION_LEVEL_LSA_LIGHT, PROTECTION_LEVEL_WINTCB_LIGHT,
            PROTECTION_LEVEL_WINDOWS, PROTECTION_LEVEL_WINDOWS_LIGHT, PROTECTION_LEVEL_ANTIMALWARE_LIGHT};
        if (std::ranges::contains(levels, protection.ProtectionLevel)) setting.enabled = Tri::Yes;
        else if (protection.ProtectionLevel == PROTECTION_LEVEL_NONE) setting.enabled = Tri::No;
        setting.status = setting.enabled == Tri::Unknown ? Status::Unavailable : Status::Success;
        return;
    } while (::Process32NextW(snapshot.get(), &entry));
    setting.status = Status::Unavailable;
}
struct NetDeleter { void operator()(BYTE* value) const noexcept { if (value) ::NetApiBufferFree(value); } };
using NetBuffer = std::unique_ptr<BYTE, NetDeleter>;
void CollectAccounts(HardeningInfo& info) {
    NetBuffer policy;
    auto result = ::NetUserModalsGet(nullptr, 3, std::out_ptr(policy));
    info.lockoutStatus = StatusFromWin32(result);
    if (result == NERR_Success && policy) {
        const auto* lockout = reinterpret_cast<USER_MODALS_INFO_3*>(policy.get());
        info.lockoutThreshold = lockout->usrmod3_lockout_threshold;
        info.lockoutDuration = lockout->usrmod3_lockout_duration;
        info.lockoutWindow = lockout->usrmod3_lockout_observation_window;
    } else if (result == NERR_Success) info.lockoutStatus = Status::Unavailable;

    info.guestDisabled.source = L"Local SAM account with RID 501 (NetUserEnum)";
    DWORD resume = 0;
    for (unsigned page = 0; page < 128; ++page) {
        NetBuffer users;
        DWORD read = 0, total = 0;
        const DWORD previous = resume;
        result = ::NetUserEnum(nullptr, 20, FILTER_NORMAL_ACCOUNT, std::out_ptr(users), 65536, &read, &total, &resume);
        if (result != NERR_Success && result != ERROR_MORE_DATA) {
            info.guestDisabled.status = StatusFromWin32(result); return;
        }
        if (read && !users) { info.guestDisabled.status = Status::Error; return; }
        const auto* rows = reinterpret_cast<USER_INFO_20*>(users.get());
        for (DWORD i = 0; i < read; ++i) {
            if (rows[i].usri20_user_id != DOMAIN_USER_RID_GUEST) continue;
            info.guestDisabled.enabled = (rows[i].usri20_flags & UF_ACCOUNTDISABLE) ? Tri::Yes : Tri::No;
            info.guestDisabled.status = Status::Success;
            return;
        }
        if (result == NERR_Success) { info.guestDisabled.status = Status::NotFound; return; }
        if (resume == previous) break;
    }
    info.guestDisabled.status = Status::Unavailable;
}
} // namespace

HardeningInfo CollectHardeningInfo() {
    HardeningInfo info;
    CollectLsaProtection(info.lsaProtection);
    info.noLmHash = BooleanPolicy(kLsa, L"NoLMHash");
    const auto level = ReadDword(kLsa, L"LmCompatibilityLevel");
    info.lmCompatibilityStatus = level ? (*level <= 5 ? Status::Success : Status::Error) : level.error();
    if (level) info.lmCompatibility = *level;
    const auto inactivity = ReadDword(kSystemPolicy, L"InactivityTimeoutSecs");
    info.inactivityStatus = inactivity ? Status::Success : inactivity.error();
    if (inactivity) info.inactivitySeconds = *inactivity;
    const auto autoplay = ReadDword(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoDriveTypeAutoRun");
    info.autoPlayDisabled.source = L"Device policy: NoDriveTypeAutoRun";
    info.autoPlayDisabled.status = autoplay ? Status::Success : autoplay.error();
    if (autoplay) info.autoPlayDisabled.enabled = ((*autoplay & 255) == 255) ? Tri::Yes : Tri::No;
    info.remoteAssistanceDisabled = BooleanPolicy(L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services", L"fAllowToGetHelp", true);
    if (info.remoteAssistanceDisabled.status == Status::NotFound)
        info.remoteAssistanceDisabled = BooleanPolicy(L"SYSTEM\\CurrentControlSet\\Control\\Remote Assistance", L"fAllowToGetHelp", true);
    CollectAccounts(info);
    return info;
}
} // namespace sa
