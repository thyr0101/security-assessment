#include "PrivacyCollector.h"
#include "../RegistryReader.h"

namespace sa {
namespace {
constexpr auto systemPolicy = L"SOFTWARE\\Policies\\Microsoft\\Windows\\System";
constexpr auto appPolicy = L"SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy";
constexpr auto consent = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\";

Status Dword(HKEY root, const std::wstring& path, const wchar_t* name, DWORD& value) {
    RegistryReader reader;
    const auto status = reader.Open(root, path);
    return status == Status::Success ? reader.GetDword(name, value) : status;
}
Status String(HKEY root, const std::wstring& path, std::wstring& value) {
    RegistryReader reader;
    const auto status = reader.Open(root, path);
    return status == Status::Success ? reader.GetString(L"Value", value) : status;
}
std::wstring Missing(Status status) {
    return status == Status::NotFound ? L"Not configured" : L"Unknown (" + std::wstring(ToW(status)) + L")";
}
}

std::vector<PrivacyFinding> CollectPrivacyFindings() {
    std::vector<PrivacyFinding> out;
    auto add = [&](const wchar_t* name, std::wstring value, Status status,
                   const wchar_t* scope, const wchar_t* group, const wchar_t* explanation) {
        PrivacyFinding finding;
        finding.name = name;
        finding.value = status == Status::Success ? std::move(value) : Missing(status);
        finding.status = status;
        finding.scope = scope;
        finding.group = group;
        finding.explanation = explanation;
        out.push_back(std::move(finding));
    };
    auto flag = [&](const wchar_t* name, HKEY root, const wchar_t* path, const wchar_t* key,
                    const wchar_t* scope, const wchar_t* group, const wchar_t* explanation) {
        DWORD value = 0;
        auto status = Dword(root, path, key, value);
        if (status == Status::Success && value > 1) status = Status::Error;
        add(name, value ? L"Enabled" : L"Disabled", status, scope, group, explanation);
    };
    DWORD value = 0;
    auto status = Dword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", L"AllowTelemetry", value);
    const wchar_t* levels[] = {L"Security (edition dependent)", L"Required / Basic", L"Enhanced (legacy)", L"Optional / Full"};
    if (status == Status::Success && value > 3) status = Status::Error;
    add(L"Diagnostic data level", value <= 3 ? levels[value] : L"Unknown", status, L"Device policy", L"Data & personalization",
        L"Policy limit on diagnostic data; supported levels depend on Windows version and edition. Absence does not mean collection is disabled.");

    status = Dword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo", L"DisabledByGroupPolicy", value);
    if (status == Status::Success && value == 1)
        add(L"Advertising ID", L"Disabled", status, L"Device policy", L"Data & personalization", L"Advertising identifier blocked by device policy.");
    else if (status == Status::NotFound || (status == Status::Success && value == 0))
        flag(L"Advertising ID", HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo", L"Enabled",
            L"User preference", L"Data & personalization", L"Controls app use of the current user's advertising identifier.");
    else add(L"Advertising ID", L"Unknown", status == Status::Success ? Status::Error : status,
        L"Device policy", L"Data & personalization", L"Advertising policy could not be interpreted.");

    status = Dword(HKEY_CURRENT_USER, L"SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent", L"DisableTailoredExperiencesWithDiagnosticData", value);
    if (status == Status::Success && value == 1)
        add(L"Personalized tips", L"Disabled", status, L"User policy", L"Data & personalization", L"Diagnostic data cannot be used for tailored experiences.");
    else if (status == Status::NotFound || (status == Status::Success && value == 0))
        flag(L"Personalized tips", HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Privacy", L"TailoredExperiencesWithDiagnosticDataEnabled",
            L"User preference", L"Data & personalization", L"Use of diagnostic data for personalized tips and recommendations.");
    else add(L"Personalized tips", L"Unknown", status == Status::Success ? Status::Error : status,
        L"User policy", L"Data & personalization", L"Tailored-experiences policy could not be interpreted.");
    flag(L"Online speech consent", HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Speech_OneCore\\Settings\\OnlineSpeechPrivacy", L"HasAccepted",
        L"User consent", L"Data & personalization", L"Stored consent for online speech recognition; device policies can further restrict the feature.");
    flag(L"Typing / inking collection", HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\TextInput", L"AllowLinguisticDataCollection",
        L"Device policy", L"Data & personalization", L"Policy permission to collect linguistic data; does not establish whether collection is currently active.");

    struct Permission { const wchar_t* name; const wchar_t* capability; const wchar_t* policy; };
    const Permission permissions[] = {
        {L"Location Services", L"location", L"LetAppsAccessLocation"},
        {L"Camera access", L"webcam", L"LetAppsAccessCamera"},
        {L"Microphone access", L"microphone", L"LetAppsAccessMicrophone"},
        {L"Contacts access", L"contacts", L"LetAppsAccessContacts"},
        {L"Calendar access", L"appointments", L"LetAppsAccessCalendar"},
        {L"Account information access", L"userAccountInformation", L"LetAppsAccessAccountInfo"},
        {L"Email access", L"email", L"LetAppsAccessEmail"}
    };
    for (const auto& permission : permissions) {
        auto policyStatus = Dword(HKEY_LOCAL_MACHINE, appPolicy, permission.policy, value);
        std::wstring text;
        const wchar_t* scope = L"Device policy default";
        status = policyStatus;
        if (policyStatus == Status::Success && (value == 1 || value == 2)) text = value == 1 ? L"Allow" : L"Deny";
        else if (policyStatus == Status::NotFound || (policyStatus == Status::Success && value == 0)) {
            const std::wstring path = std::wstring(consent) + permission.capability;
            std::wstring deviceText;
            const auto deviceStatus = String(HKEY_LOCAL_MACHINE, path, deviceText);
            if (deviceStatus == Status::Success && IEquals(deviceText, L"Deny")) {
                text = L"Deny"; status = deviceStatus; scope = L"Device consent";
            } else if (deviceStatus != Status::Success && deviceStatus != Status::NotFound) {
                status = deviceStatus; scope = L"Device consent";
            } else {
                status = String(HKEY_CURRENT_USER, path, text);
                scope = L"User default";
                if (status == Status::NotFound) { status = deviceStatus; text = deviceText; scope = L"Device default"; }
            }
            if (status == Status::Success && !IEquals(text, L"Allow") && !IEquals(text, L"Deny")) status = Status::Error;
        } else if (policyStatus == Status::Success) status = Status::Error;
        add(permission.name, text, status, scope, L"App permissions",
            L"Default app permission, not a record of active access. Per-app policy/consent overrides and desktop-app exceptions can apply.");
    }
    flag(L"Publish user activities", HKEY_LOCAL_MACHINE, systemPolicy, L"PublishUserActivities", L"Device policy", L"Sharing & access",
        L"Legacy activity-history publishing policy; availability depends on Windows version.");
    flag(L"Clipboard history", HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Clipboard", L"EnableClipboardHistory", L"User preference", L"Sharing & access",
        L"Stored clipboard-history preference; device policy can restrict it.");
    flag(L"Clipboard history allowed", HKEY_LOCAL_MACHINE, systemPolicy, L"AllowClipboardHistory", L"Device policy", L"Sharing & access",
        L"Permission to use clipboard history, not proof that it is enabled.");
    flag(L"Clipboard cloud sync", HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Clipboard", L"EnableCloudClipboard", L"User preference", L"Sharing & access",
        L"Stored cross-device clipboard preference; account and policy restrictions can apply.");
    flag(L"Clipboard sync allowed", HKEY_LOCAL_MACHINE, systemPolicy, L"AllowCrossDeviceClipboard", L"Device policy", L"Sharing & access",
        L"Permission to synchronize clipboard contents, not proof of active synchronization.");
    flag(L"Remote Assistance", HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Remote Assistance", L"fAllowToGetHelp", L"Device setting", L"Sharing & access",
        L"Whether Remote Assistance invitations are allowed.");
    status = Dword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization", L"DODownloadMode", value);
    const wchar_t* scope = L"Device policy";
    if (status == Status::NotFound) {
        status = Dword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config", L"DODownloadMode", value);
        scope = L"Device setting";
    }
    std::wstring mode;
    switch (value) {
    case 0: mode = L"HTTP only"; break;
    case 1: mode = L"Local network peers"; break;
    case 2: mode = L"Private group peers"; break;
    case 3: mode = L"Internet peers"; break;
    case 99: mode = L"Simple download"; break;
    case 100: mode = L"Bypass (legacy)"; break;
    default: mode = L"Unrecognized"; break;
    }
    add(L"Delivery Optimization mode", mode + L" (" + std::to_wstring(value) + L")", status, scope, L"Sharing & access",
        L"Configured update-download sharing mode; peer availability and other policies can limit actual sharing.");
    return out;
}
} // namespace sa
