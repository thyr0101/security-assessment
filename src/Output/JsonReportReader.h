#pragma once
#include "../Models.h"
#include <windows.data.json.h>
#include <wrl/client.h>
#include <wrl/wrappers/corewrappers.h>
#include <cmath>
#include <concepts>
#include <limits>
#include <type_traits>

namespace sa::json_detail {
using Microsoft::WRL::ComPtr;
using Microsoft::WRL::Wrappers::HString;
using Microsoft::WRL::Wrappers::HStringReference;
using namespace ABI::Windows::Data::Json;

// A missing optional member keeps the model's unknown/default value. A present
// member with the wrong type rejects the report instead of inventing a reading.
class Object {
public:
    Object(ComPtr<IJsonObject> value, bool& valid) : value_(std::move(value)), valid_(valid) {}
    Object Child(const wchar_t* key) const {
        ComPtr<IJsonObject> child;
        if (auto value = Member(key); value && FAILED(value->GetObject(child.GetAddressOf()))) valid_ = false;
        return Object(std::move(child), valid_);
    }
    template<typename T> void Field(const wchar_t* key, T& target) const {
        if (auto value = Member(key)) Read(value.Get(), target);
    }
    template<typename T, typename F> void Items(const wchar_t* key, std::vector<T>& target, F read) const {
        if (auto value = Member(key)) {
            ComPtr<ABI::Windows::Foundation::Collections::IVector<IJsonValue*>> array;
            ComPtr<IJsonArray> jsonArray;
            UINT32 size = 0;
            if (FAILED(value->GetArray(jsonArray.GetAddressOf())) || FAILED(jsonArray.As(&array)) ||
                FAILED(array->get_Size(&size)) || size > 100000) { valid_ = false; return; }
            target.reserve(size);
            for (UINT32 i = 0; i < size && valid_; ++i) {
                ComPtr<IJsonObject> object;
                if (FAILED(jsonArray->GetObjectAt(i, object.GetAddressOf()))) { valid_ = false; break; }
                target.emplace_back();
                read(Object(std::move(object), valid_), target.back());
            }
        }
    }
private:
    ComPtr<IJsonObject> value_;
    bool& valid_;

    ComPtr<IJsonValue> Member(const wchar_t* key) const {
        ComPtr<IJsonValue> value;
        if (!value_ || !valid_) return value;
        ComPtr<ABI::Windows::Foundation::Collections::IMap<HSTRING, IJsonValue*>> map;
        boolean present = false;
        if (FAILED(value_.As(&map)) || FAILED(map->HasKey(HStringReference(key).Get(), &present))) {
            valid_ = false;
            return {};
        }
        if (!present) return {};
        const HRESULT hr = value_->GetNamedValue(HStringReference(key).Get(), value.GetAddressOf());
        if (FAILED(hr)) {
            valid_ = false;
            return {};
        }
        JsonValueType type{};
        if (FAILED(value->get_ValueType(&type))) { valid_ = false; return {}; }
        // Null is used for unavailable numeric readings in app exports.
        return type == JsonValueType_Null ? ComPtr<IJsonValue>{} : value;
    }
    void Read(IJsonValue* value, std::wstring& target) const {
        HString text;
        if (FAILED(value->GetString(text.GetAddressOf()))) { valid_ = false; return; }
        UINT32 size = 0;
        const auto data = ::WindowsGetStringRawBuffer(text.Get(), &size);
        target.clear();
        // Render file-provided controls visibly: an export must not be able to
        // erase the offline notice or inject terminal escape sequences.
        constexpr wchar_t hex[] = L"0123456789ABCDEF";
        for (UINT32 i = 0; i < size; ++i) {
            const wchar_t c = data[i];
            if (c < 0x20 || (c >= 0x7f && c <= 0x9f) || (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069)) {
                target += L"\\u";
                for (int shift = 12; shift >= 0; shift -= 4) target += hex[(c >> shift) & 15];
            } else target += c;
        }
    }
    void Read(IJsonValue* value, std::string& target) const {
        std::wstring text;
        Read(value, text);
        target = WideToUtf8(text);
    }
    void Read(IJsonValue* value, bool& target) const {
        boolean result = false;
        if (FAILED(value->GetBoolean(&result))) valid_ = false;
        else target = result != false;
    }
    template<std::integral T> requires (!std::same_as<T, bool>)
    void Read(IJsonValue* value, T& target) const {
        double number = 0;
        // Upper bound is exclusive, avoiding a rounded UINT64_MAX -> 2^64 cast.
        const double upper = std::ldexp(1.0, std::numeric_limits<T>::digits);
        if (FAILED(value->GetNumber(&number)) || !std::isfinite(number) || number < 0 ||
            number >= upper || std::floor(number) != number) { valid_ = false; return; }
        target = static_cast<T>(number);
    }
    template<typename E> requires std::is_enum_v<E>
    void Read(IJsonValue* value, E& target) const {
        std::wstring text;
        Read(value, text);
        if constexpr (std::same_as<E, Status>) {
            for (const auto item : {Status::Success, Status::NotFound, Status::AccessDenied, Status::Unsupported, Status::Unavailable, Status::Error})
                if (text == ToW(item)) { target = item; return; }
        } else if constexpr (std::same_as<E, Tri>) {
            for (const auto item : {Tri::Unknown, Tri::Yes, Tri::No, Tri::NotApplicable})
                if (text == ToW(item)) { target = item; return; }
        } else if constexpr (std::same_as<E, AntivirusState>) {
            for (const auto item : {AntivirusState::Unknown, AntivirusState::Enabled, AntivirusState::Disabled, AntivirusState::Snoozed, AntivirusState::Expired})
                if (text == ToW(item)) { target = item; return; }
        }
        valid_ = false;
    }
    template<typename T> void Read(IJsonValue* value, std::vector<T>& target) const {
        ComPtr<IJsonArray> jsonArray;
        ComPtr<ABI::Windows::Foundation::Collections::IVector<IJsonValue*>> array;
        UINT32 size = 0;
        if (FAILED(value->GetArray(jsonArray.GetAddressOf())) || FAILED(jsonArray.As(&array)) ||
            FAILED(array->get_Size(&size)) || size > 100000) { valid_ = false; return; }
        target.reserve(size);
        for (UINT32 i = 0; i < size && valid_; ++i) {
            ComPtr<IJsonValue> item;
            if (FAILED(array->GetAt(i, item.GetAddressOf()))) { valid_ = false; break; }
            target.emplace_back();
            Read(item.Get(), target.back());
        }
    }
};

inline void ReadSetting(const Object& object, SecuritySetting& setting) {
    object.Field(L"enabled", setting.enabled);
    object.Field(L"status", setting.status);
}
inline void ReadService(const Object& object, ServiceEntry& service) {
    object.Field(L"name", service.name);
    object.Field(L"displayName", service.displayName);
    object.Field(L"state", service.state);
}
inline void ReadRule(const Object& object, ScoreRuleResult& rule) {
    object.Field(L"id", rule.id);
    object.Field(L"description", rule.description);
    object.Field(L"maxPoints", rule.maxPoints);
    object.Field(L"awardedPoints", rule.awardedPoints);
    object.Field(L"category", rule.category);
    object.Field(L"state", rule.state);
}

// Restore recorded data only. Scoring and collection deliberately stay outside
// this path, and warning arrays from older exports are deliberately ignored.
inline AssessmentResult ReadReport(const Object& root) {
    AssessmentResult result;
    {
        const auto object = root.Child(L"system");
        object.Field(L"productName", result.os.productName);
        object.Field(L"displayVersion", result.os.displayVersion);
        object.Field(L"build", result.os.build);
        object.Field(L"ubr", result.os.ubr);
        object.Field(L"architecture", result.os.architecture);
        object.Field(L"computerName", result.os.computerName);
        object.Field(L"userName", result.os.userName);
        object.Field(L"timeZone", result.os.timeZone);
        object.Field(L"locale", result.os.locale);
        object.Field(L"uptimeSeconds", result.os.uptimeSeconds);
    }
    {
        const auto object = root.Child(L"hardware").Child(L"cpu");
        object.Field(L"brand", result.cpu.brand);
        object.Field(L"logicalProcessors", result.cpu.logicalProcessors);
        object.Field(L"physicalCores", result.cpu.physicalCores);
        object.Field(L"status", result.cpu.status);
    }
    {
        const auto object = root.Child(L"hardware").Child(L"cpu").Child(L"features");
        object.Field(L"aesni", result.cpu.aesni);
        object.Field(L"nx", result.cpu.nx);
        object.Field(L"virtualizationAvailable", result.cpu.virtualizationAvailable);
    }
    // Original compact backups exposed three separate CPUID facts.
    bool vmx = false, svm = false, hypervisor = false;
    const auto features = root.Child(L"hardware").Child(L"cpu").Child(L"features");
    features.Field(L"vmx", vmx); features.Field(L"svm", svm); features.Field(L"hypervisorPresent", hypervisor);
    result.cpu.virtualizationAvailable |= vmx || svm || hypervisor;
    {
        const auto object = root.Child(L"hardware").Child(L"memory");
        object.Field(L"totalBytes", result.memory.totalBytes);
        object.Field(L"availableBytes", result.memory.availableBytes);
    }
    {
        const auto object = root.Child(L"security");
        object.Field(L"elevated", result.security.isElevated);
    }
    {
        const auto object = root.Child(L"security").Child(L"tpm");
        object.Field(L"present", result.security.tpm.present);
        object.Field(L"ready", result.security.tpm.ready);
        object.Field(L"readinessKnown", result.security.tpm.readinessKnown);
        object.Field(L"specVersion", result.security.tpm.specVersion);
        object.Field(L"status", result.security.tpm.status);
    }
    {
        const auto object = root.Child(L"security").Child(L"secureBoot");
        object.Field(L"enabled", result.security.secureBoot.enabled);
    }
    {
        const auto object = root.Child(L"security").Child(L"virtualization");
        object.Field(L"vbsEnabled", result.security.virt.vbsEnabled);
        object.Field(L"hvciEnabled", result.security.virt.hvciEnabled);
        object.Field(L"credentialGuardRunning", result.security.virt.credentialGuardRunning);
        object.Field(L"hvciConfigured", result.security.virt.hvciConfigured);
        object.Field(L"runningServicesKnown", result.security.virt.runningServicesKnown);
        object.Field(L"status", result.security.virt.status);
    }
    {
        const auto object = root.Child(L"security").Child(L"uac");
        object.Field(L"enabled", result.security.uac.enabled);
        object.Field(L"promptOnSecureDesktop", result.security.uac.promptOnSecureDesktop);
        object.Field(L"status", result.security.uac.status);
    }
    {
        const auto object = root.Child(L"defender");
        object.Field(L"enabled", result.defender.enabled);
        object.Field(L"enabledStatus", result.defender.enabledStatus);
        object.Field(L"realTimeProtection", result.defender.realTimeProtection);
        object.Field(L"realTimeProtectionStatus", result.defender.realTimeProtectionStatus);
        object.Field(L"behaviorMonitor", result.defender.behaviorMonitor);
        object.Field(L"behaviorMonitorStatus", result.defender.behaviorMonitorStatus);
        object.Field(L"ioav", result.defender.ioav);
        object.Field(L"ioavStatus", result.defender.ioavStatus);
        object.Field(L"cloudProtection", result.defender.cloudProtection);
        object.Field(L"cloudProtectionStatus", result.defender.cloudProtectionStatus);
        object.Field(L"tamperProtection", result.defender.tamperProtection);
        object.Field(L"tamperProtectionStatus", result.defender.tamperProtectionStatus);
        object.Field(L"amEngineVersion", result.defender.amEngineVersion);
        object.Field(L"amRunningMode", result.defender.amRunningMode);
        object.Field(L"periodicScanning", result.defender.periodicScanning);
        object.Field(L"antivirusSignatureVersion", result.defender.antivirusSignatureVersion);
        object.Field(L"status", result.defender.status);
        object.Field(L"reason", result.defender.reason);
    }
    {
        const auto object = root.Child(L"antivirus");
        object.Field(L"status", result.antivirus.status);
        object.Field(L"reason", result.antivirus.reason);
    }
    root.Child(L"antivirus").Items(L"products", result.antivirus.products, [](const Object& object, auto& item) {
        object.Field(L"name", item.name);
        object.Field(L"state", item.state);
        object.Field(L"status", item.status);
        object.Field(L"isDefender", item.isDefender);
        object.Field(L"signaturesUpToDate", item.signaturesUpToDate);
    });
    {
        const auto object = root.Child(L"firewall");
        object.Field(L"serviceRunning", result.firewall.serviceRunning);
        object.Field(L"serviceStatus", result.firewall.serviceStatus);
        object.Field(L"activeProfiles", result.firewall.activeProfiles);
        object.Field(L"activeProfilesStatus", result.firewall.activeProfilesStatus);
    }
    root.Child(L"firewall").Items(L"profiles", result.firewall.profiles, [](const Object& object, auto& item) {
        object.Field(L"name", item.name);
        object.Field(L"enabled", item.enabled);
        object.Field(L"defaultInbound", item.defaultInbound);
        object.Field(L"defaultOutbound", item.defaultOutbound);
        object.Field(L"status", item.status);
    });
    {
        const auto object = root.Child(L"storage");
        object.Field(L"status", result.storage.status);
    }
    root.Child(L"storage").Items(L"disks", result.storage.disks, [](const Object& object, auto& item) {
        object.Field(L"index", item.index);
        object.Field(L"model", item.model);
        object.Field(L"vendor", item.vendor);
        object.Field(L"sizeBytes", item.sizeBytes);
        object.Field(L"busType", item.busType);
        object.Field(L"mediaType", item.mediaType);
    });
    root.Child(L"storage").Items(L"volumes", result.storage.volumes, [](const Object& object, auto& item) {
        object.Field(L"diskMappingStatus", item.diskMappingStatus);
        object.Field(L"diskIndices", item.diskIndices);
        object.Field(L"mountPoint", item.mountPoint);
        object.Field(L"volumeLabel", item.volumeLabel);
        object.Field(L"filesystem", item.filesystem);
        object.Field(L"totalBytes", item.totalBytes);
        object.Field(L"freeBytes", item.freeBytes);
        object.Field(L"bitLockerState", item.bitLockerState);
        object.Field(L"bitLockerNote", item.bitLockerNote);
        object.Field(L"encryptionMethod", item.encryptionMethod);
    });
    {
        const auto object = root.Child(L"windowsUpdate");
        object.Field(L"pendingStatus", result.windowsUpdate.pendingStatus);
        object.Field(L"pendingReason", result.windowsUpdate.pendingReason);
        object.Field(L"lastInstallationError", result.windowsUpdate.lastInstallationError);
    }
    root.Child(L"windowsUpdate").Items(L"services", result.windowsUpdate.services.entries, ReadService);
    root.Child(L"windowsUpdate").Items(L"updates", result.windowsUpdate.updates, [](const Object& object, auto& item) {
        object.Field(L"title", item.title);
        object.Field(L"optional", item.optional);
        object.Field(L"downloaded", item.downloaded);
        object.Field(L"updateType", item.updateType);
        object.Field(L"severity", item.severity);
        object.Field(L"classifications", item.classifications);
        object.Field(L"products", item.products);
        object.Field(L"kbArticles", item.kbArticles);
    });
    ReadSetting(root.Child(L"network").Child(L"security").Child(L"smb1Server"), result.network.smb1Server);
    ReadSetting(root.Child(L"network").Child(L"security").Child(L"smb1Client"), result.network.smb1Client);
    ReadSetting(root.Child(L"network").Child(L"security").Child(L"smbServerSigning"), result.network.smbServerSigning);
    ReadSetting(root.Child(L"network").Child(L"security").Child(L"smbClientSigning"), result.network.smbClientSigning);
    ReadSetting(root.Child(L"network").Child(L"security").Child(L"smbGuestLogons"), result.network.smbGuestLogons);
    ReadSetting(root.Child(L"network").Child(L"security").Child(L"smbEncryption"), result.network.smbEncryption);
    ReadSetting(root.Child(L"network").Child(L"security").Child(L"smbRejectUnencrypted"), result.network.smbRejectUnencrypted);
    ReadSetting(root.Child(L"network").Child(L"security").Child(L"llmnr"), result.network.llmnr);
    ReadSetting(root.Child(L"network").Child(L"security").Child(L"rdp"), result.network.rdp);
    ReadSetting(root.Child(L"network").Child(L"security").Child(L"rdpNla"), result.network.rdpNla);
    ReadSetting(root.Child(L"hardening").Child(L"lsaProtection"), result.hardening.lsaProtection);
    ReadSetting(root.Child(L"hardening").Child(L"noLmHash"), result.hardening.noLmHash);
    ReadSetting(root.Child(L"hardening").Child(L"autoPlayDisabled"), result.hardening.autoPlayDisabled);
    ReadSetting(root.Child(L"hardening").Child(L"guestDisabled"), result.hardening.guestDisabled);
    ReadSetting(root.Child(L"hardening").Child(L"remoteAssistanceDisabled"), result.hardening.remoteAssistanceDisabled);
    {
        const auto object = root.Child(L"hardening");
        object.Field(L"inactivitySeconds", result.hardening.inactivitySeconds);
        object.Field(L"inactivityStatus", result.hardening.inactivityStatus);
        object.Field(L"lmCompatibility", result.hardening.lmCompatibility);
        object.Field(L"lmCompatibilityStatus", result.hardening.lmCompatibilityStatus);
        object.Field(L"lockoutThreshold", result.hardening.lockoutThreshold);
        object.Field(L"lockoutDuration", result.hardening.lockoutDuration);
        object.Field(L"lockoutWindow", result.hardening.lockoutWindow);
        object.Field(L"lockoutStatus", result.hardening.lockoutStatus);
    }
    root.Items(L"registryFindings", result.registryFindings, [](const Object& object, auto& item) {
        object.Field(L"name", item.name);
        object.Field(L"path", item.path);
        object.Field(L"valueCount", item.valueCount);
        object.Field(L"threshold", item.threshold);
        object.Field(L"exceeded", item.exceeded);
        object.Field(L"status", item.status);
    });
    root.Items(L"directoryFindings", result.directoryFindings, [](const Object& object, auto& item) {
        object.Field(L"name", item.name);
        object.Field(L"path", item.path);
        object.Field(L"fileCount", item.fileCount);
        object.Field(L"threshold", item.threshold);
        object.Field(L"exceeded", item.exceeded);
        object.Field(L"status", item.status);
    });
    {
        const auto object = root.Child(L"score");
        object.Field(L"total", result.score.total);
        object.Field(L"maximum", result.score.maximum);
        object.Field(L"registeredAntivirusScoring", result.score.registeredAntivirusScoring);
    }
    root.Child(L"score").Items(L"rules", result.score.rules, ReadRule);
    root.Child(L"score").Items(L"antivirusScores", result.score.antivirusScores, [](const Object& object, auto& item) {
        object.Field(L"maxPoints", item.maxPoints);
        object.Field(L"awardedPoints", item.awardedPoints);
    });
    return result;
}
} // namespace sa::json_detail
