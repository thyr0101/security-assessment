#pragma once
#include "Common.h"
#include "Utilities.h"
#include <string>
#include <vector>
#include <optional>

namespace sa {

struct OsInfo {
    std::wstring productName;      // e.g. "Windows 11 Pro"
    std::wstring displayVersion;   // e.g. "24H2"
    std::wstring buildLab;         // e.g. "26100.1.amd64fre..."
    DWORD major = 0, minor = 0, build = 0, ubr = 0;
    std::wstring architecture;
    std::wstring systemRoot;
    std::wstring systemDirectory;
    std::wstring computerName;
    std::wstring userName;
    std::wstring domainOrWorkgroup;
    std::wstring installDate;
    FILETIME bootTime{};
    unsigned long long uptimeSeconds = 0;
    std::wstring timeZone;
    std::wstring locale;
    std::wstring systemLanguage;
    Status status = Status::Error;
};

struct CpuInfo {
    std::wstring vendor;
    std::wstring brand;
    unsigned logicalProcessors = 0;
    unsigned physicalCores = 0;
    unsigned processorGroups = 0;
    unsigned maxMhz = 0;
    unsigned currentMhz = 0;
    unsigned l2CacheKB = 0;
    unsigned l3CacheKB = 0;
    bool nx = false;
    bool sse = false, sse2 = false, sse3 = false, ssse3 = false;
    bool sse41 = false, sse42 = false;
    bool avx = false, avx2 = false, avx512f = false;
    bool aesni = false, sha = false;
    bool vmx = false, svm = false;
    bool hypervisorPresent = false;
    Status status = Status::Error;
};

// True when the CPU exposes VMX/SVM, or when a hypervisor is already running.
// With VBS/Hyper-V active, Windows itself runs on top of the hypervisor and the
// VMX/SVM bits are masked from CPUID, so the raw bits alone under-report.
inline bool CpuVirtualizationAvailable(const CpuInfo& c) {
    return c.vmx || c.svm || c.hypervisorPresent;
}

struct MemoryModule {
    unsigned long long capacity = 0;
    unsigned speed = 0;
    unsigned configuredSpeed = 0;
    std::wstring manufacturer;
    std::wstring partNumber;
    std::wstring serialNumber;
    unsigned memoryType = 0;
    unsigned formFactor = 0;
    bool ecc = false;
};

struct MemoryInfo {
    unsigned long long totalBytes = 0;
    unsigned long long availableBytes = 0;
    unsigned loadPercent = 0;
    unsigned long long totalPageFile = 0;
    std::vector<MemoryModule> modules;
    Status status = Status::Error;
};

struct TpmInfo {
    bool present = false;
    bool enabled = false;
    bool activated = false;
    bool owned = false;
    bool ready = false;
    std::wstring specVersion;
    std::wstring manufacturerId;
    std::wstring manufacturerVersion;
    Status status = Status::Error;
};

struct SecureBootInfo {
    Tri firmwareIsUefi = Tri::Unknown;
    Tri supported = Tri::Unknown;
    Tri enabled = Tri::Unknown;
    Status status = Status::Error;
};

struct VirtualizationInfo {
    bool cpuVmxSupported = false;
    bool firmwareEnabled = false;   // if detectable
    bool hypervisorRunning = false;
    bool vbsEnabled = false;
    bool hvciEnabled = false;
    bool credentialGuardRunning = false;
    bool deviceGuardAvailable = false;
    bool sandboxAvailable = false;
    Status status = Status::Error;
};

struct UacInfo {
    bool enabled = false;
    bool consentPromptAdmin = false;
    DWORD consentPromptBehaviorAdmin = 0;
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
    bool windowsHelloAvailable = false;
    bool isElevated = false;
};

struct DefenderInfo {
    bool installed = false;
    bool enabled = false;
    bool realTimeProtection = false;
    bool behaviorMonitor = false;
    bool ioav = false;
    bool onAccessProtection = false;
    bool cloudProtection = false;
    bool sampleSubmission = false;
    bool tamperProtection = false;
    bool antispywareEnabled = false;
    bool antivirusEnabled = false;
    std::wstring amEngineVersion;
    std::wstring amProductVersion;
    std::wstring amServiceVersion;
    std::wstring antivirusSignatureVersion;
    std::wstring antivirusSignatureLastUpdated;
    std::wstring lastQuickScan;
    std::wstring lastFullScan;
    std::wstring quickScanAge;
    unsigned threatsCount = 0;      // active threats; only meaningful if threatsKnown
    bool threatsKnown = false;
    Status status = Status::Error;
    std::wstring reason;
};

struct FirewallProfile {
    std::wstring name;
    bool enabled = false;
    DWORD defaultInbound = 0;   // 0=block,1=allow,2=notconfigured
    DWORD defaultOutbound = 0;
    bool notificationsEnabled = false;
};

struct FirewallInfo {
    std::vector<FirewallProfile> profiles;
    bool serviceRunning = false;
    Status status = Status::Error;
};

struct StorageVolume {
    std::wstring mountPoint;      // C:
    std::wstring volumeLabel;     // renamed from `label` to avoid macro collision
    std::wstring filesystem;
    unsigned long long totalBytes = 0;
    unsigned long long freeBytes = 0;
    std::wstring driveType;       // Fixed/Removable/Network/...
    Status bitLockerStatus = Status::Unavailable;
    std::wstring bitLockerState;  // "On", "Off", "Unknown"
    std::wstring protectionMethod;
    std::wstring encryptionPercentage;
    std::wstring encryptionMethod;   // e.g. "XTS-AES 256"; empty if not encrypted/unknown
    std::wstring bitLockerNote;      // why the state is Unknown (diagnostic)
};

struct StorageDisk {
    unsigned index = 0;
    std::wstring model;
    std::wstring vendor;
    std::wstring serial;
    std::wstring firmware;
    unsigned long long sizeBytes = 0;
    std::wstring busType;
    std::wstring mediaType;      // SSD/HDD
    bool isNvme = false;
};

struct StorageInfo {
    std::vector<StorageDisk> disks;
    std::vector<StorageVolume> volumes;
    Status status = Status::Error;
};

struct NetworkAdapterInfo {
    std::wstring name;
    std::wstring description;
    std::wstring guid;
    std::wstring macAddress;
    bool up = false;
    std::wstring ifType;
    std::vector<std::wstring> ipv4;
    std::vector<std::wstring> ipv6;
    std::vector<std::wstring> gateways;
    std::vector<std::wstring> dns;
    bool dhcp = false;
    std::wstring dhcpServer;
    bool isLoopback = false;
    bool isVirtual = false;
    bool isVpn = false;
};

struct NetworkInfo {
    std::vector<NetworkAdapterInfo> adapters;
    Status status = Status::Error;
};

struct ServiceEntry {
    std::wstring name;
    std::wstring displayName;
    std::wstring state;      // Running/Stopped/Paused/...
    std::wstring startType;  // Boot/System/Auto/Manual/Disabled
    std::wstring exePath;
    Status status = Status::Error;
};

struct ServiceReport {
    std::vector<ServiceEntry> entries;
    Status status = Status::Error;
};

struct ApplicationDefinition {
    std::wstring name;
    std::vector<std::wstring> possiblePaths; // may include env vars
};

struct ApplicationFinding {
    std::wstring name;
    bool installed = false;
    std::wstring path;
    std::wstring version;
    std::wstring publisher;
    std::wstring architecture;
    std::wstring sha256;    // only if installed
    Status status = Status::NotFound;
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
    DWORD subkeyCount = 0;
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
    unsigned long long dirCount = 0;
    size_t threshold = 0;
    bool exceeded = false;
    Status status = Status::Error;
};

struct PrivacyFinding {
    std::wstring name;
    std::wstring value;
    Category category = Category::Privacy;
    Severity severity = Severity::Informational;
    std::wstring explanation;
};

struct PersistenceEntry {
    std::wstring location;   // e.g. "HKCU\\...\\Run"
    std::wstring name;
    std::wstring command;
};

struct PersistenceReport {
    std::vector<PersistenceEntry> entries;
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

struct ScoreReport {
    int total = 0;
    int maximum = 1000;
    std::vector<ScoreRuleResult> rules;
};

struct AssessmentResult {
    OsInfo os;
    CpuInfo cpu;
    MemoryInfo memory;
    SecurityInfo security;
    DefenderInfo defender;
    FirewallInfo firewall;
    StorageInfo storage;
    NetworkInfo network;
    ServiceReport services;
    std::vector<ApplicationFinding> applications;
    std::vector<RegistryFinding> registryFindings;
    std::vector<DirectoryFinding> directoryFindings;
    std::vector<PrivacyFinding> privacyFindings;
    PersistenceReport persistence;
    ScoreReport score;
};

} // namespace sa