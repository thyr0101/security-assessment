#pragma once
#include <windows.h>
#include <shellapi.h>
#include <string>
#include <string_view>

#pragma comment(lib, "shell32.lib")
namespace sa {
struct SettingsPage { std::wstring_view id, title; const wchar_t* uri; };
inline constexpr SettingsPage settingsPages[] = {
    {L"system", L"System / About", L"ms-settings:about"},
    {L"security", L"Windows Security", L"ms-settings:windowsdefender"},
    {L"update", L"Windows Update", L"ms-settings:windowsupdate"},
    {L"network", L"Network", L"ms-settings:network-status"},
    {L"accounts", L"Sign-in options", L"ms-settings:signinoptions"},
    {L"storage", L"Storage", L"ms-settings:storagesense"},
    {L"encryption", L"Device encryption", L"ms-settings:deviceencryption"},
    {L"rdp", L"Remote Desktop", L"ms-settings:remotedesktop"},
    {L"autoplay", L"AutoPlay", L"ms-settings:autoplay"},
    {L"users", L"Other users", L"ms-settings:otherusers"},
    {L"lockscreen", L"Lock screen", L"ms-settings:lockscreen"},
};
inline const SettingsPage* FindSettingsPage(std::wstring_view id) {
    for (const auto& page : settingsPages) if (page.id == id) return &page;
    return nullptr;
}
// Labels are compiled into the viewer. Never open URIs taken from a backup.
inline const SettingsPage* SettingsFor(std::wstring_view label) {
    std::wstring_view id;
    if (label == L"System") id = L"system";
    else if (label == L"Windows Update" || label == L"Pending Updates" || label == L"Update Services") id = L"update";
    else if (label == L"Hardware Security" || label == L"Protection" || label == L"Microsoft Defender" ||
        label == L"Windows Firewall" || label == L"TPM" || label == L"Secure Boot" || label == L"Credential Guard" ||
        label == L"Memory integrity" || label == L"Periodic scanning" || label == L"Registered Antivirus (Windows Security Center)") id = L"security";
    else if (label == L"Network Security" || label == L"File Sharing & Authentication") id = L"network";
    else if (label == L"Device & Account Security" || label == L"Local Account Policies") id = L"accounts";
    else if (label == L"Storage") id = L"storage";
    else if (label == L"BitLocker") id = L"encryption";
    else if (label == L"Remote Desktop" || label == L"RDP authentication") id = L"rdp";
    else if (label == L"AutoPlay (all drives)") id = L"autoplay";
    else if (label == L"Built-in Guest") id = L"users";
    else if (label == L"Device inactivity lock") id = L"lockscreen";
    return FindSettingsPage(id);
}
inline bool OpenSettingsPage(const SettingsPage& page) {
    return reinterpret_cast<INT_PTR>(::ShellExecuteW(nullptr, L"open", page.uri, nullptr, nullptr, SW_SHOWNORMAL)) > 32;
}
} // namespace sa
