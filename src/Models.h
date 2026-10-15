#pragma once
#include "Common.h"
#include "Utilities.h"
#include <string>
#include <vector>
#include <optional>

namespace sa {

struct OsInfo {
    std::wstring productName, displayVersion, architecture, computerName, userName, timeZone, locale;
    DWORD build = 0, ubr = 0;
    unsigned long long uptimeSeconds = 0;
    Status status = Status::Error;
};

struct CpuInfo {
    std::wstring brand;
    unsigned logicalProcessors = 0, physicalCores = 0;
    bool nx = false, aesni = false, virtualizationAvailable = false;
    Status status = Status::Error;
};

// True when the CPU exposes VMX/SVM, or when a hypervisor is already running.
// With VBS/Hyper-V active, Windows itself runs on top of the hypervisor and the
// VMX/SVM bits are masked from CPUID, so the raw bits alone under-report.
inline bool CpuVirtualizationAvailable(const CpuInfo& c) {
    return c.virtualizationAvailable;
}

struct MemoryInfo {
    unsigned long long totalBytes = 0, availableBytes = 0;
    Status status = Status::Error;
};

struct TpmInfo {
    bool present = false, ready = false, readinessKnown = false;
    std::wstring specVersion;
    Status status = Status::Error;
};

struct SecureBootInfo {
    Tri enabled = Tri::Unknown;
    Status status = Status::Error;
};

struct VirtualizationInfo {
    bool vbsEnabled = false, hvciEnabled = false, credentialGuardRunning = false, runningServicesKnown = false;
    Tri hvciConfigured = Tri::Unknown;
    Status status = Status::Error;
};

struct UacInfo {
    bool enabled = false, consentPromptAdmin = false;
    DWORD promptOnSecureDesktop = 0;
    Status status = Status::Error;
};

struct DepInfo {
    Tri depEnabled = Tri::Unknown;      // DEP policy
    Tri sehopEnabled = Tri::Unknown;    // SEHOP
    Status status = Status::Error;
};

struct SecurityInfo {
    TpmInfo tpm;
    SecureBootInfo secureBoot;
    VirtualizationInfo virt;
    UacInfo uac;
    DepInfo dep;
    bool smartAppControlOn = false;
    Tri smartAppControlState = Tri::Unknown;
    bool smartAppControlEvaluation = false;
    bool isElevated = false;
};

struct DefenderInfo {
    bool installed = false;
    bool enabled = false;
    bool realTimeProtection = false;
    bool behaviorMonitor = false;
    bool ioav = false;
    bool cloudProtection = false;
    bool tamperProtection = false;
    // Individual property reads can fail while the status query itself succeeds.
    Status enabledStatus = Status::Unavailable;
    Status realTimeProtectionStatus = Status::Unavailable;
    Status behaviorMonitorStatus = Status::Unavailable;
    Status ioavStatus = Status::Unavailable;
    Status cloudProtectionStatus = Status::Unavailable;
    Status tamperProtectionStatus = Status::Unavailable;
    std::wstring amEngineVersion;
    std::wstring antivirusSignatureVersion;
    std::wstring amRunningMode;
    Tri periodicScanning = Tri::Unknown; // Informational only; never used for scoring.
    unsigned threatsCount = 0;      // active threats; only meaningful if threatsKnown
    bool threatsKnown = false;
    Status status = Status::Error;
    std::wstring reason;
};

enum class AntivirusState { Unknown, Enabled, Disabled, Snoozed, Expired };

inline const wchar_t* ToW(AntivirusState state) {
    switch (state) {
    case AntivirusState::Enabled: return L"Enabled";
    case AntivirusState::Disabled: return L"Disabled";
    case AntivirusState::Snoozed: return L"Snoozed";
    case AntivirusState::Expired: return L"Expired";
    default: return L"Unknown";
    }
}

struct AntivirusProduct {
    std::wstring name;
    std::wstring id;
    AntivirusState state = AntivirusState::Unknown;
    Tri signaturesUpToDate = Tri::Unknown;
    bool isDefender = false;
    Status status = Status::Error;
};

struct AntivirusInfo {
    std::vector<AntivirusProduct> products;
    Status status = Status::Error;
    std::wstring reason;
};

inline bool HasThirdPartyAntivirus(const AntivirusInfo& info) {
    for (const auto& product : info.products)
        if (!product.isDefender) return true;
    return false;
}

struct FirewallProfile {
    std::wstring name;
    bool enabled = false;
    DWORD defaultInbound = 2;   // 0=block,1=allow,2=unknown/notconfigured
    DWORD defaultOutbound = 2;
    Status status = Status::Error;
};

struct FirewallInfo {
    std::vector<FirewallProfile> profiles;
    bool serviceRunning = false;
    Status serviceStatus = Status::Error;
    Status status = Status::Error;
    DWORD activeProfiles = 0;
    Status activeProfilesStatus = Status::Unavailable;
};

struct StorageVolume {
    std::wstring volumeId;       // Volume GUID path, also used to match BitLocker instances.
    std::wstring mountPoint;      // C:
    std::wstring volumeLabel;     // renamed from `label` to avoid macro collision
    std::wstring filesystem;
    unsigned long long totalBytes = 0;
    unsigned long long freeBytes = 0;
    std::wstring driveType;       // Fixed/Removable/Network/...
    Status bitLockerStatus = Status::Unavailable;
    std::wstring bitLockerState;  // "On", "Off", "Unknown"
    std::wstring encryptionMethod;   // e.g. "XTS-AES 256"; empty if not encrypted/unknown
    std::wstring bitLockerNote;      // why the state is Unknown (diagnostic)
    std::vector<unsigned> diskIndices; // PhysicalDrive numbers returned by volume extents.
    Status diskMappingStatus = Status::Unavailable;
};

struct StorageDisk {
    unsigned index = 0;
    std::wstring model;
    std::wstring vendor;
    unsigned long long sizeBytes = 0;
    std::wstring busType;
    std::wstring mediaType;      // SSD/HDD
};

struct StorageInfo {
    std::vector<StorageDisk> disks;
    std::vector<StorageVolume> volumes;
    Status status = Status::Error;
};

struct NetworkAdapterInfo {
    // Only applicable active IPv4 adapters are represented; no identity or addresses.
    DWORD netbiosOptions = 3;
    Status netbiosStatus = Status::Unavailable;
};

struct SecuritySetting {
    Tri enabled = Tri::Unknown;
    Status status = Status::Unavailable;
};

using NetworkSetting = SecuritySetting;

struct NetworkInfo {
    std::vector<NetworkAdapterInfo> adapters;
    Status status = Status::Error;
    NetworkSetting smb1Server, smb1Client;
    NetworkSetting smbServerSigning, smbClientSigning, smbGuestLogons;
    NetworkSetting smbEncryption, smbRejectUnencrypted;
    NetworkSetting llmnr, rdp, rdpNla;
};

struct HardeningInfo {
    SecuritySetting lsaProtection, noLmHash, autoPlayDisabled, guestDisabled, remoteAssistanceDisabled;
    DWORD inactivitySeconds = 0;
    Status inactivityStatus = Status::Unavailable;
    DWORD lmCompatibility = 0;
    Status lmCompatibilityStatus = Status::Unavailable;
    DWORD lockoutThreshold = 0, lockoutDuration = 0, lockoutWindow = 0;
    Status lockoutStatus = Status::Unavailable;
};

// Describe absence separately from collection failures; never infer a secure
// effective policy from an absent registry value.
inline const wchar_t* NetworkSignInState(const HardeningInfo& info) {
    switch (info.lmCompatibilityStatus) {
    case Status::NotFound: return L"Not configured";
    case Status::AccessDenied: return L"Access denied";
    case Status::Unsupported: return L"Invalid value type";
    case Status::Unavailable: return L"Unavailable";
    case Status::Error: return info.lmCompatibility > 5 ? L"Invalid policy value" : L"Read error";
    case Status::Success:
        return info.lmCompatibility > 5 ? L"Invalid policy value"
            : info.lmCompatibility >= 3 ? L"Modern responses only" : L"Legacy allowed";
    }
    return L"Read error";
}
inline std::wstring NetworkSignInReason(const HardeningInfo& info) {
    switch (info.lmCompatibilityStatus) {
    case Status::NotFound: return L"The network sign-in policy is not explicitly configured (LmCompatibilityLevel is absent). Windows defaults were not verified; this does not mean older sign-in methods are active.";
    case Status::AccessDenied: return L"Windows denied access while reading the network sign-in policy. Run as administrator and try again.";
    case Status::Unsupported: return L"The network sign-in policy has an invalid registry type; a DWORD value from 0 to 5 is required.";
    case Status::Unavailable: return L"The network sign-in policy could not be queried on this system.";
    case Status::Error:
        return info.lmCompatibility > 5 ? L"The network sign-in policy contains an invalid value (expected 0 to 5)."
            : L"Windows returned an error while reading the network sign-in policy; its configuration could not be verified.";
    case Status::Success:
        if (info.lmCompatibility > 5) return L"The recorded network sign-in policy is outside the supported range (0 to 5).";
        return info.lmCompatibility >= 3
            ? L"The configured policy sends modern NTLMv2 responses only (level " + std::to_wstring(info.lmCompatibility) + L"). This does not prove that all incoming older sign-in methods are blocked."
            : L"The configured policy permits older network sign-in responses (level " + std::to_wstring(info.lmCompatibility) + L").";
    }
    return L"The network sign-in policy could not be verified.";
}

struct ServiceEntry {
    std::wstring name;
    std::wstring displayName;
    std::wstring state;      // Running/Stopped/Paused/...
    std::wstring startType;  // Boot/System/Auto/Manual/Disabled
    Status status = Status::Error;
};

struct ServiceReport {
    std::vector<ServiceEntry> entries;
    Status status = Status::Error;
};

struct WindowsUpdateItem {
    std::wstring title;
    std::vector<std::wstring> kbArticles;
    std::vector<std::wstring> classifications;
    std::vector<std::wstring> products;
    std::wstring updateType;
    std::wstring severity;
    Tri optional = Tri::Unknown;
    Tri downloaded = Tri::Unknown;
};

struct WindowsUpdateInfo {
    // Offline WUA search reads locally cached applicability data only.
    std::vector<WindowsUpdateItem> updates;
    Status pendingStatus = Status::Unavailable;
    std::wstring pendingReason;
    Tri rebootRequired = Tri::Unknown;
    std::wstring lastInstallationError;
    Tri lastInstallationSucceeded = Tri::Unknown;
    Status historyStatus = Status::Unavailable;
    ServiceReport services;
    Status status = Status::Unavailable;
};

struct RegistryScanDefinition {
    std::wstring name;
    HKEY root;
    std::wstring subkey;
    size_t threshold;
    REGSAM view = KEY_WOW64_64KEY;
};

struct RegistryFinding {
    std::wstring name;
    std::wstring path;
    DWORD valueCount = 0;
    size_t threshold = 0;
    bool exceeded = false;
    Status status = Status::Error;
};

struct DirectoryScanDefinition {
    std::wstring name;
    std::wstring path;      // env vars allowed
    size_t threshold;
    bool recursive = false;
};

struct DirectoryFinding {
    std::wstring name;
    std::wstring path;
    unsigned long long fileCount = 0;
    size_t threshold = 0;
    bool exceeded = false;
    Status status = Status::Error;
};

struct PersistenceReport {
    Status status = Status::Error;
};

struct ScoreRuleResult {
    std::string id;
    std::string description;
    int maxPoints = 0;
    int awardedPoints = 0;
    std::string category;
    std::string reason;
    std::string state;   // Enabled/Disabled/Unknown/etc.
};

struct SecurityWarning {
    std::string ruleId;
    Severity severity = Severity::Low;
    std::string title;
    std::string detail;
    std::string recommendation;
    bool verificationOnly = false;
};

struct ScoreReport {
    int total = 0;
    int maximum = 1000;
    std::vector<ScoreRuleResult> rules;
    std::vector<SecurityWarning> warnings;
    // Independent product scores, excluded from the overall sum.
    std::vector<ScoreRuleResult> antivirusScores;
    bool registeredAntivirusScoring = false;
};

struct AssessmentResult {
    OsInfo os;
    CpuInfo cpu;
    MemoryInfo memory;
    SecurityInfo security;
    DefenderInfo defender;
    AntivirusInfo antivirus;
    FirewallInfo firewall;
    StorageInfo storage;
    NetworkInfo network;
    HardeningInfo hardening;
    WindowsUpdateInfo windowsUpdate;
    std::vector<RegistryFinding> registryFindings;
    std::vector<DirectoryFinding> directoryFindings;
    PersistenceReport persistence;
    ScoreReport score;
};

} // namespace sa