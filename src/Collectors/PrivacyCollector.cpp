#include "PrivacyCollector.h"
#include "../RegistryReader.h"
#include <array>
#include <expected>
#include <string_view>

namespace sa {
namespace {
constexpr auto kData = L"Data & personalization";
constexpr auto kPermissions = L"App permissions";
constexpr auto kSharing = L"Sharing & access";
constexpr auto kSystemPolicy = L"SOFTWARE\\Policies\\Microsoft\\Windows\\System";
constexpr auto kAppPolicy = L"SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy";
constexpr auto kConsent = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\";

struct RegistryValue {
    HKEY root;
    std::wstring path;
    const wchar_t* name;
};
struct Reading {
    std::wstring text;
    Status status = Status::Unavailable;
    const wchar_t* scope;
};
struct FlagSpec {
    const wchar_t* name;
    RegistryValue registry;
    const wchar_t* scope;
    const wchar_t* group;
    const wchar_t* explanation;
};
struct PermissionSpec {
    const wchar_t* name;
    const wchar_t* capability;
    const wchar_t* policy;
};

std::expected<DWORD, Status> ReadDword(const RegistryValue& value) {
    RegistryReader reader;
    auto status = reader.Open(value.root, value.path);
    DWORD number = 0;
    if (status == Status::Success) status = reader.GetDword(value.name, number);
    if (status != Status::Success) return std::unexpected(status);
    return number;
}
Reading ReadFlag(const RegistryValue& value, const wchar_t* scope) {
    const auto number = ReadDword(value);
    if (!number) return {L"", number.error(), scope};
    if (*number > 1) return {L"", Status::Error, scope};
    return {*number ? L"Enabled" : L"Disabled", Status::Success, scope};
}
Reading ReadConsent(HKEY root, const std::wstring& path, const wchar_t* scope) {
    RegistryReader reader;
    Reading result{L"", reader.Open(root, path), scope};
    if (result.status == Status::Success) result.status = reader.GetString(L"Value", result.text);
    if (result.status == Status::Success && !IEquals(result.text, L"Allow") && !IEquals(result.text, L"Deny"))
        result.status = Status::Error;
    return result;
}
Reading RestrictedPreference(const RegistryValue& policy, const RegistryValue& preference,
                             const wchar_t* policyScope) {
    const auto restriction = ReadDword(policy);
    if (!restriction) {
        if (restriction.error() != Status::NotFound) return {L"", restriction.error(), policyScope};
    } else {
        if (*restriction == 1) return {L"Disabled", Status::Success, policyScope};
        if (*restriction > 1) return {L"", Status::Error, policyScope};
    }
    return ReadFlag(preference, L"User preference");
}
Reading DiagnosticData(HKEY machineRoot) {
    const auto level = ReadDword({machineRoot,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", L"AllowTelemetry"});
    constexpr std::array labels{L"Security (edition dependent)", L"Required / Basic", L"Enhanced (legacy)", L"Optional / Full"};
    if (!level) return {L"", level.error(), L"Device policy"};
    if (*level >= labels.size()) return {L"", Status::Error, L"Device policy"};
    return {labels[*level], Status::Success, L"Device policy"};
}
Reading AppPermission(const PermissionSpec& spec, HKEY machineRoot, HKEY userRoot) {
    const auto policy = ReadDword({machineRoot, kAppPolicy, spec.policy});
    if (policy) {
        if (*policy == 1 || *policy == 2)
            return {*policy == 1 ? L"Allow" : L"Deny", Status::Success, L"Device policy default"};
        if (*policy != 0) return {L"", Status::Error, L"Device policy default"};
    } else if (policy.error() != Status::NotFound)
        return {L"", policy.error(), L"Device policy default"};

    const auto path = std::wstring(kConsent) + spec.capability;
    auto device = ReadConsent(machineRoot, path, L"Device default");
    if (device.status == Status::Success && IEquals(device.text, L"Deny")) return device;
    if (device.status != Status::Success && device.status != Status::NotFound) return device;
    auto user = ReadConsent(userRoot, path, L"User default");
    return user.status == Status::NotFound ? device : user;
}
Reading DeliveryOptimization(HKEY machineRoot) {
    auto mode = ReadDword({machineRoot,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization", L"DODownloadMode"});
    const wchar_t* scope = L"Device policy";
    if (!mode && mode.error() == Status::NotFound) {
        mode = ReadDword({machineRoot,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config", L"DODownloadMode"});
        scope = L"Device setting";
    }
    if (!mode) return {L"", mode.error(), scope};
    const wchar_t* label = L"Unrecognized";
    switch (*mode) {
    case 0: label = L"HTTP only"; break;
    case 1: label = L"Local network peers"; break;
    case 2: label = L"Private group peers"; break;
    case 3: label = L"Internet peers"; break;
    case 99: label = L"Simple download"; break;
    case 100: label = L"Bypass (legacy)"; break;
    }
    return {std::wstring(label) + L" (" + std::to_wstring(*mode) + L")", Status::Success, scope};
}
void Add(std::vector<PrivacyFinding>& findings, const wchar_t* name, Reading reading,
         const wchar_t* group, const wchar_t* explanation) {
    PrivacyFinding finding;
    finding.name = name;
    finding.status = reading.status;
    finding.scope = reading.scope;
    finding.group = group;
    finding.explanation = explanation;
    finding.value = reading.status == Status::Success ? std::move(reading.text)
        : reading.status == Status::NotFound ? L"Not configured"
        : L"Unknown (" + std::wstring(ToW(reading.status)) + L")";
    findings.push_back(std::move(finding));
}
} // namespace

std::vector<PrivacyFinding> CollectPrivacyFindings(HKEY machineRoot, HKEY userRoot) {
    std::vector<PrivacyFinding> findings;
    findings.reserve(20);

    // Data collection: explicit restrictions take precedence over user preferences.
    Add(findings, L"Diagnostic data level", DiagnosticData(machineRoot), kData,
        L"Policy limit on diagnostic data; supported levels depend on Windows version and edition. Absence does not mean collection is disabled.");
    Add(findings, L"Advertising ID", RestrictedPreference(
        {machineRoot, L"SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo", L"DisabledByGroupPolicy"},
        {userRoot, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo", L"Enabled"}, L"Device policy"), kData,
        L"Controls app use of the current user's advertising identifier; a device restriction takes precedence.");
    Add(findings, L"Personalized tips", RestrictedPreference(
        {userRoot, L"SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent", L"DisableTailoredExperiencesWithDiagnosticData"},
        {userRoot, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Privacy", L"TailoredExperiencesWithDiagnosticDataEnabled"}, L"User policy"), kData,
        L"Use of diagnostic data for personalized tips and recommendations; a user policy restriction takes precedence.");

    const FlagSpec flags[] = {
        {L"Online speech consent",
            {userRoot, L"SOFTWARE\\Microsoft\\Speech_OneCore\\Settings\\OnlineSpeechPrivacy", L"HasAccepted"},
            L"User consent", kData, L"Stored consent for online speech recognition; device policies can further restrict the feature."},
        {L"Typing / inking collection",
            {machineRoot, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\TextInput", L"AllowLinguisticDataCollection"},
            L"Device policy", kData, L"Policy permission to collect linguistic data; does not establish whether collection is currently active."},
        {L"Publish user activities", {machineRoot, kSystemPolicy, L"PublishUserActivities"},
            L"Device policy", kSharing, L"Legacy activity-history publishing policy; availability depends on Windows version."},
        {L"Clipboard history", {userRoot, L"SOFTWARE\\Microsoft\\Clipboard", L"EnableClipboardHistory"},
            L"User preference", kSharing, L"Stored clipboard-history preference; device policy can restrict it."},
        {L"Clipboard history allowed", {machineRoot, kSystemPolicy, L"AllowClipboardHistory"},
            L"Device policy", kSharing, L"Permission to use clipboard history, not proof that it is enabled."},
        {L"Clipboard cloud sync", {userRoot, L"SOFTWARE\\Microsoft\\Clipboard", L"EnableCloudClipboard"},
            L"User preference", kSharing, L"Stored cross-device clipboard preference; account and policy restrictions can apply."},
        {L"Clipboard sync allowed", {machineRoot, kSystemPolicy, L"AllowCrossDeviceClipboard"},
            L"Device policy", kSharing, L"Permission to synchronize clipboard contents, not proof of active synchronization."},
        {L"Remote Assistance", {machineRoot, L"SYSTEM\\CurrentControlSet\\Control\\Remote Assistance", L"fAllowToGetHelp"},
            L"Device setting", kSharing, L"Whether Remote Assistance invitations are allowed."}
    };
    // Keep related groups adjacent in the returned model, as well as in the console.
    for (const auto& flag : flags)
        if (std::wstring_view(flag.group) == kData)
            Add(findings, flag.name, ReadFlag(flag.registry, flag.scope), flag.group, flag.explanation);

    constexpr PermissionSpec permissions[] = {
        {L"Location Services", L"location", L"LetAppsAccessLocation"},
        {L"Camera access", L"webcam", L"LetAppsAccessCamera"},
        {L"Microphone access", L"microphone", L"LetAppsAccessMicrophone"},
        {L"Contacts access", L"contacts", L"LetAppsAccessContacts"},
        {L"Calendar access", L"appointments", L"LetAppsAccessCalendar"},
        {L"Account information access", L"userAccountInformation", L"LetAppsAccessAccountInfo"},
        {L"Email access", L"email", L"LetAppsAccessEmail"}
    };
    for (const auto& permission : permissions)
        Add(findings, permission.name, AppPermission(permission, machineRoot, userRoot), kPermissions,
            L"Default app permission, not a record of active access. Per-app policy/consent overrides and desktop-app exceptions can apply.");
    for (const auto& flag : flags)
        if (std::wstring_view(flag.group) == kSharing)
            Add(findings, flag.name, ReadFlag(flag.registry, flag.scope), flag.group, flag.explanation);
    Add(findings, L"Delivery Optimization mode", DeliveryOptimization(machineRoot), kSharing,
        L"Configured update-download sharing mode; peer availability and other policies can limit actual sharing.");
    return findings;
}
} // namespace sa
