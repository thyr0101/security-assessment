#include "JsonRenderer.h"
#include "../Utilities.h"
#include <sstream>
#include <cstdio>
#include <locale>

namespace sa {

static std::string Esc(const std::string& s) {
    std::string o; o.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '"': o += "\\\""; break;
        case '\\': o += "\\\\"; break;
        case '\b': o += "\\b"; break;
        case '\f': o += "\\f"; break;
        case '\n': o += "\\n"; break;
        case '\r': o += "\\r"; break;
        case '\t': o += "\\t"; break;
        default:
            if ((unsigned char)c < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                o += buf;
            } else o += c;
        }
    }
    return o;
}
static std::string Q(const std::string& s) { return "\"" + Esc(s) + "\""; }
static std::string Q(const std::wstring& w) { return Q(WideToUtf8(w)); }
static std::string B(bool b) { return b ? "true" : "false"; }
static std::string TriS(Tri t) {
    switch (t) { case Tri::Yes: return "\"Yes\""; case Tri::No: return "\"No\"";
                 case Tri::NotApplicable: return "\"N/A\""; default: return "\"Unknown\""; }
}
static std::string StatusS(Status s) { return "\"" + std::string(WideToUtf8(ToW(s))) + "\""; }
static std::string SettingJson(const SecuritySetting& setting) {
    return "{\"enabled\":" + TriS(setting.enabled) + ",\"status\":" + StatusS(setting.status) +
        ",\"source\":" + Q(setting.source) + ",\"reason\":" + Q(setting.reason) + "}";
}


std::string RenderJson(const AssessmentResult& r) {
    std::ostringstream o;
    o.imbue(std::locale::classic());
    o << "{";

    // system
    o << "\"system\":{"
      << "\"productName\":"    << Q(r.os.productName)     << ","
      << "\"displayVersion\":" << Q(r.os.displayVersion)  << ","
      << "\"build\":"          << r.os.build              << ","
      << "\"ubr\":"            << r.os.ubr                << ","
      << "\"architecture\":"   << Q(r.os.architecture)    << ","
      << "\"computerName\":"   << Q(r.os.computerName)    << ","
      << "\"userName\":"       << Q(r.os.userName)        << ","
      << "\"timeZone\":"       << Q(r.os.timeZone)        << ","
      << "\"locale\":"         << Q(r.os.locale)          << ","
      << "\"uptimeSeconds\":"  << r.os.uptimeSeconds
      << ",\"status\":" << StatusS(r.os.status)
      << "},";

    // Windows Update: null counts mean unavailable, not zero pending updates.
    const auto& update = r.windowsUpdate;
    o << "\"windowsUpdate\":{\"status\":" << StatusS(update.status)
      << ",\"cachedOnly\":true,\"pendingStatus\":" << StatusS(update.pendingStatus)
      << ",\"pendingReason\":" << Q(update.pendingReason)
      << ",\"pendingCount\":" << (update.pendingStatus == Status::Success ? std::to_string(update.pendingCount) : "null")
      << ",\"optionalCount\":" << (update.pendingStatus == Status::Success ? std::to_string(update.optionalCount) : "null")
      << ",\"lastSearchUtc\":" << Q(update.lastSearchUtc)
      << ",\"rebootRequired\":" << TriS(update.rebootRequired)
      << ",\"historyStatus\":" << StatusS(update.historyStatus)
      << ",\"lastInstallationUtc\":" << Q(update.lastInstallationUtc)
      << ",\"lastInstallationTitle\":" << Q(update.lastInstallationTitle)
      << ",\"lastInstallationResult\":" << Q(update.lastInstallationResult)
      << ",\"lastInstallationError\":" << Q(update.lastInstallationError)
      << ",\"lastInstallationSucceeded\":" << TriS(update.lastInstallationSucceeded)
      << ",\"updates\":[";
    for (size_t i = 0; i < update.updates.size(); ++i) {
        if (i) o << ",";
        const auto& item = update.updates[i];
        o << "{\"title\":" << Q(item.title) << ",\"id\":" << Q(item.id)
          << ",\"optional\":" << TriS(item.optional) << ",\"downloaded\":" << TriS(item.downloaded)
          << ",\"updateType\":" << Q(item.updateType) << ",\"severity\":" << Q(item.severity)
          << ",\"classifications\":[";
        for (size_t j = 0; j < item.classifications.size(); ++j) { if (j) o << ","; o << Q(item.classifications[j]); }
        o << "],\"products\":[";
        for (size_t j = 0; j < item.products.size(); ++j) { if (j) o << ","; o << Q(item.products[j]); }
        o << "]"
          << ",\"kbArticles\":[";
        for (size_t j = 0; j < item.kbArticles.size(); ++j) { if (j) o << ","; o << Q(item.kbArticles[j]); }
        o << "]}";
    }
    o << "],\"servicesStatus\":" << StatusS(update.services.status) << ",\"services\":[";
    for (size_t i = 0; i < update.services.entries.size(); ++i) {
        if (i) o << ",";
        const auto& service = update.services.entries[i];
        o << "{\"name\":" << Q(service.name) << ",\"displayName\":" << Q(service.displayName)
          << ",\"state\":" << Q(service.state) << ",\"startType\":" << Q(service.startType)
          << ",\"status\":" << StatusS(service.status) << "}";
    }
    o << "]},";

    // hardware
    o << "\"hardware\":{"
      << "\"cpu\":{"
      <<   "\"vendor\":" << Q(r.cpu.vendor) << ","
      <<   "\"brand\":" << Q(r.cpu.brand) << ","
      <<   "\"logicalProcessors\":" << r.cpu.logicalProcessors << ","
      <<   "\"physicalCores\":" << r.cpu.physicalCores << ","
      <<   "\"processorGroups\":" << r.cpu.processorGroups << ","
      <<   "\"maxMhz\":" << r.cpu.maxMhz << ","
      <<   "\"status\":" << StatusS(r.cpu.status) << ","
      <<   "\"features\":{"
      <<     "\"sse\":" << B(r.cpu.sse) << ",\"sse2\":" << B(r.cpu.sse2)
              << ",\"sse3\":" << B(r.cpu.sse3) << ",\"ssse3\":" << B(r.cpu.ssse3)
              << ",\"sse41\":" << B(r.cpu.sse41) << ",\"sse42\":" << B(r.cpu.sse42)
              << ",\"avx\":" << B(r.cpu.avx) << ",\"avx2\":" << B(r.cpu.avx2)
              << ",\"avx512f\":" << B(r.cpu.avx512f) << ",\"aesni\":" << B(r.cpu.aesni)
              << ",\"sha\":" << B(r.cpu.sha) << ",\"vmx\":" << B(r.cpu.vmx)
              << ",\"hypervisorPresent\":" << B(r.cpu.hypervisorPresent)
              << ",\"svm\":" << B(r.cpu.svm) << ",\"nx\":" << B(r.cpu.nx)
      <<   "}"
      << "},"
      << "\"memory\":{"
      <<   "\"totalBytes\":" << r.memory.totalBytes << ","
      <<   "\"availableBytes\":" << r.memory.availableBytes << ","
      <<   "\"loadPercent\":" << r.memory.loadPercent << ","
      <<   "\"status\":" << StatusS(r.memory.status) << ","
      <<   "\"modules\":[";
    for (size_t i = 0; i < r.memory.modules.size(); ++i) {
        auto& m = r.memory.modules[i];
        if (i) o << ",";
        o << "{"
          << "\"capacity\":" << m.capacity << ","
          << "\"speed\":" << m.speed << ","
          << "\"configuredSpeed\":" << m.configuredSpeed << ","
          << "\"manufacturer\":" << Q(m.manufacturer) << ","
          << "\"partNumber\":" << Q(m.partNumber) << ","
          << "\"ecc\":" << B(m.ecc) << "}";
    }
    o << "]}},";

    // security
    o << "\"security\":{"
      << "\"tpm\":{"
      <<   "\"present\":" << B(r.security.tpm.present) << ","
      <<   "\"enabled\":" << B(r.security.tpm.enabled) << ","
      <<   "\"ready\":" << B(r.security.tpm.ready) << ","
      <<   "\"readinessKnown\":" << B(r.security.tpm.readinessKnown) << ","
      <<   "\"specVersion\":" << Q(r.security.tpm.specVersion) << ","
      <<   "\"manufacturerId\":" << Q(r.security.tpm.manufacturerId)
      <<   ",\"status\":" << StatusS(r.security.tpm.status)
      << "},"
      << "\"secureBoot\":{"
      <<   "\"firmwareIsUefi\":" << TriS(r.security.secureBoot.firmwareIsUefi) << ","
      <<   "\"enabled\":" << TriS(r.security.secureBoot.enabled)
      <<   ",\"status\":" << StatusS(r.security.secureBoot.status)
      << "},"
      << "\"virtualization\":{"
      <<   "\"vbsEnabled\":" << B(r.security.virt.vbsEnabled) << ","
      <<   "\"hvciEnabled\":" << B(r.security.virt.hvciEnabled) << ","
      <<   "\"credentialGuardRunning\":" << B(r.security.virt.credentialGuardRunning)
      <<   ",\"hvciConfigured\":" << TriS(r.security.virt.hvciConfigured)
      <<   ",\"runningServicesKnown\":" << B(r.security.virt.runningServicesKnown)
      <<   ",\"status\":" << StatusS(r.security.virt.status)
      << "},"
      << "\"uac\":{"
      <<   "\"enabled\":" << B(r.security.uac.enabled)
      <<   ",\"status\":" << StatusS(r.security.uac.status)
      << "},"
      << "\"smartAppControl\":"
      <<   "\"" << WideToUtf8(ToW(r.security.smartAppControlState)) << "\","
      << "\"smartAppControlEvaluation\":" << B(r.security.smartAppControlEvaluation) << ","
      << "\"elevated\":" << B(r.security.isElevated)
      << "},";

    // defender
    o << "\"defender\":{"
      << "\"installed\":" << B(r.defender.installed) << ","
      << "\"enabled\":" << B(r.defender.enabled) << ","
      << "\"enabledStatus\":" << StatusS(r.defender.enabledStatus) << ","
      << "\"realTimeProtection\":" << B(r.defender.realTimeProtection) << ","
      << "\"realTimeProtectionStatus\":" << StatusS(r.defender.realTimeProtectionStatus) << ","
      << "\"behaviorMonitor\":" << B(r.defender.behaviorMonitor) << ","
      << "\"behaviorMonitorStatus\":" << StatusS(r.defender.behaviorMonitorStatus) << ","
      << "\"ioav\":" << B(r.defender.ioav) << ","
      << "\"ioavStatus\":" << StatusS(r.defender.ioavStatus) << ","
      << "\"cloudProtection\":" << B(r.defender.cloudProtection) << ","
      << "\"cloudProtectionStatus\":" << StatusS(r.defender.cloudProtectionStatus) << ","
      << "\"threatsKnown\":" << B(r.defender.threatsKnown) << ","
      << "\"threatsCount\":" << r.defender.threatsCount << ","
      << "\"tamperProtection\":" << B(r.defender.tamperProtection) << ","
      << "\"tamperProtectionStatus\":" << StatusS(r.defender.tamperProtectionStatus) << ","
      << "\"amEngineVersion\":" << Q(r.defender.amEngineVersion) << ","
      << "\"amRunningMode\":" << Q(r.defender.amRunningMode) << ","
      << "\"periodicScanning\":" << TriS(r.defender.periodicScanning) << ","
      << "\"antivirusSignatureVersion\":" << Q(r.defender.antivirusSignatureVersion) << ","
      << "\"status\":" << StatusS(r.defender.status)
      << ",\"reason\":" << Q(r.defender.reason)
      << "},";

    o << "\"antivirus\":{\"status\":" << StatusS(r.antivirus.status)
      << ",\"reason\":" << Q(r.antivirus.reason)
      << ",\"hasThirdParty\":" << B(HasThirdPartyAntivirus(r.antivirus))
      << ",\"products\":[";
    for (size_t i = 0; i < r.antivirus.products.size(); ++i) {
        if (i) o << ",";
        const auto& av = r.antivirus.products[i];
        o << "{\"name\":" << Q(av.name) << ",\"id\":" << Q(av.id)
          << ",\"state\":" << Q(std::wstring(ToW(av.state)))
          << ",\"status\":" << StatusS(av.status)
          << ",\"isDefender\":" << B(av.isDefender)
          << ",\"signaturesUpToDate\":" << TriS(av.signaturesUpToDate) << "}";
    }
    o << "]},";

    // firewall
    o << "\"firewall\":{"
      << "\"status\":" << StatusS(r.firewall.status) << ","
      << "\"serviceRunning\":" << B(r.firewall.serviceRunning) << ","
      << "\"serviceStatus\":" << StatusS(r.firewall.serviceStatus) << ","
      << "\"activeProfiles\":" << r.firewall.activeProfiles << ","
      << "\"activeProfilesStatus\":" << StatusS(r.firewall.activeProfilesStatus) << ","
      << "\"profiles\":[";
    for (size_t i = 0; i < r.firewall.profiles.size(); ++i) {
        auto& p = r.firewall.profiles[i];
        if (i) o << ",";
        o << "{\"name\":" << Q(p.name)
          << ",\"enabled\":" << B(p.enabled)
          << ",\"defaultInbound\":" << p.defaultInbound
          << ",\"defaultOutbound\":" << p.defaultOutbound
          << ",\"status\":" << StatusS(p.status) << "}";
    }
    o << "]},";

    // storage
    o << "\"storage\":{"
      << "\"status\":" << StatusS(r.storage.status) << ","
      << "\"disks\":[";
    for (size_t i = 0; i < r.storage.disks.size(); ++i) {
        auto& d = r.storage.disks[i];
        if (i) o << ",";
        o << "{\"index\":" << d.index
          << ",\"model\":" << Q(d.model)
          << ",\"vendor\":" << Q(d.vendor)
          << ",\"sizeBytes\":" << d.sizeBytes
          << ",\"busType\":" << Q(d.busType)
          << ",\"mediaType\":" << Q(d.mediaType)
          << ",\"isNvme\":" << B(d.isNvme) << "}";
    }
    o << "],\"volumes\":[";
    for (size_t i = 0; i < r.storage.volumes.size(); ++i) {
        auto& v = r.storage.volumes[i];
        if (i) o << ",";
        o << "{\"volumeId\":" << Q(v.volumeId) << ",\"diskMappingStatus\":" << StatusS(v.diskMappingStatus)
          << ",\"diskIndices\":[";
        for (size_t j = 0; j < v.diskIndices.size(); ++j) { if (j) o << ","; o << v.diskIndices[j]; }
        o << "],\"mountPoint\":" << Q(v.mountPoint)
            << ",\"volumeLabel\":" << Q(v.volumeLabel)     // <-- renamed member
            << ",\"filesystem\":" << Q(v.filesystem)
            << ",\"totalBytes\":" << v.totalBytes
            << ",\"freeBytes\":" << v.freeBytes
            << ",\"driveType\":" << Q(v.driveType)
            << ",\"bitLockerState\":" << Q(v.bitLockerState)
            << ",\"bitLockerStatus\":" << StatusS(v.bitLockerStatus)
            << ",\"bitLockerNote\":" << Q(v.bitLockerNote)
            << ",\"encryptionMethod\":" << Q(v.encryptionMethod)
            << ",\"protectionMethod\":" << Q(v.protectionMethod)
            << ",\"encryptionPercentage\":" << Q(v.encryptionPercentage)
            << "}";
    }
    o << "]},";
    // network
    o << "\"network\":{\"status\":" << StatusS(r.network.status) << ",\"adapters\":[";
    for (size_t i = 0; i < r.network.adapters.size(); ++i) {
        auto& a = r.network.adapters[i];
        if (i) o << ",";
        o << "{\"name\":" << Q(a.name)
          << ",\"description\":" << Q(a.description)
          << ",\"mac\":" << Q(a.macAddress)
          << ",\"up\":" << B(a.up)
          << ",\"ifType\":" << Q(a.ifType)
          << ",\"guid\":" << Q(a.guid)
          << ",\"dhcpServer\":" << Q(a.dhcpServer)
          << ",\"netbiosOptions\":" << a.netbiosOptions
          << ",\"netbiosStatus\":" << StatusS(a.netbiosStatus)
          << ",\"dhcp\":" << B(a.dhcp)
          << ",\"ipv4\":[";
        for (size_t j = 0; j < a.ipv4.size(); ++j) { if (j) o << ","; o << Q(a.ipv4[j]); }
        o << "],\"ipv6\":[";
        for (size_t j = 0; j < a.ipv6.size(); ++j) { if (j) o << ","; o << Q(a.ipv6[j]); }
        o << "],\"gateways\":[";
        for (size_t j = 0; j < a.gateways.size(); ++j) { if (j) o << ","; o << Q(a.gateways[j]); }
        o << "],\"dns\":[";
        for (size_t j = 0; j < a.dns.size(); ++j) { if (j) o << ","; o << Q(a.dns[j]); }
        o << "]}";
    }
    o << "],\"security\":{";
    const auto& network = r.network;
    const std::pair<const char*, const NetworkSetting*> settings[] = {
        {"smb1Server", &network.smb1Server}, {"smb1Client", &network.smb1Client},
        {"smbServerSigning", &network.smbServerSigning}, {"smbClientSigning", &network.smbClientSigning},
        {"smbGuestLogons", &network.smbGuestLogons}, {"smbEncryption", &network.smbEncryption},
        {"smbRejectUnencrypted", &network.smbRejectUnencrypted}, {"llmnr", &network.llmnr},
        {"rdp", &network.rdp}, {"rdpNla", &network.rdpNla}
    };
    for (size_t i = 0; i < std::size(settings); ++i) {
        if (i) o << ",";
        const auto& [name, setting] = settings[i];
        o << Q(std::string(name)) << ":{\"enabled\":" << TriS(setting->enabled)
          << ",\"status\":" << StatusS(setting->status)
          << ",\"source\":" << Q(setting->source) << ",\"reason\":" << Q(setting->reason) << "}";
    }
    o << ",\"rdpPort\":" << network.rdpPort << ",\"rdpPortStatus\":" << StatusS(network.rdpPortStatus)
      << "},\"tcp4Status\":" << StatusS(network.tcp4Status) << ",\"tcp6Status\":" << StatusS(network.tcp6Status)
      << ",\"udp4Status\":" << StatusS(network.udp4Status) << ",\"udp6Status\":" << StatusS(network.udp6Status)
      << ",\"endpointScope\":\"All TCP listeners and UDP port 69 only\",\"endpoints\":[";
    for (size_t i = 0; i < network.endpoints.size(); ++i) {
        if (i) o << ",";
        const auto& endpoint = network.endpoints[i];
        o << "{\"protocol\":" << Q(endpoint.protocol) << ",\"family\":" << Q(endpoint.family)
          << ",\"address\":" << Q(endpoint.address) << ",\"port\":" << endpoint.port
          << ",\"processId\":" << endpoint.processId << ",\"processName\":" << Q(endpoint.processName)
          << ",\"processStatus\":" << StatusS(endpoint.processStatus) << ",\"binding\":" << Q(endpoint.binding)
          << ",\"reviewNote\":" << Q(endpoint.reviewNote) << "}";
    }
    o << "]},";

    const auto& hardening = r.hardening;
    auto number = [](DWORD value, Status status) { return status == Status::Success ? std::to_string(value) : "null"; };
    o << "\"hardening\":{\"lsaProtection\":" << SettingJson(hardening.lsaProtection)
      << ",\"noLmHash\":" << SettingJson(hardening.noLmHash)
      << ",\"autoPlayDisabled\":" << SettingJson(hardening.autoPlayDisabled)
      << ",\"guestDisabled\":" << SettingJson(hardening.guestDisabled)
      << ",\"remoteAssistanceDisabled\":" << SettingJson(hardening.remoteAssistanceDisabled)
      << ",\"inactivitySeconds\":" << number(hardening.inactivitySeconds, hardening.inactivityStatus)
      << ",\"inactivityStatus\":" << StatusS(hardening.inactivityStatus)
      << ",\"lmCompatibility\":" << number(hardening.lmCompatibility, hardening.lmCompatibilityStatus)
      << ",\"lmCompatibilityStatus\":" << StatusS(hardening.lmCompatibilityStatus)
      << ",\"lockoutThreshold\":" << number(hardening.lockoutThreshold, hardening.lockoutStatus)
      << ",\"lockoutDuration\":" << number(hardening.lockoutDuration, hardening.lockoutStatus)
      << ",\"lockoutWindow\":" << number(hardening.lockoutWindow, hardening.lockoutStatus)
      << ",\"lockoutStatus\":" << StatusS(hardening.lockoutStatus) << "},";

    // services
    o << "\"services\":[";
    for (size_t i = 0; i < r.services.entries.size(); ++i) {
        auto& s = r.services.entries[i];
        if (i) o << ",";
        o << "{\"name\":" << Q(s.name)
          << ",\"displayName\":" << Q(s.displayName)
          << ",\"state\":" << Q(s.state)
          << ",\"startType\":" << Q(s.startType)
          << ",\"status\":" << StatusS(s.status) << "}";
    }
    o << "],\"servicesStatus\":" << StatusS(r.services.status) << ",";

    // applications
    o << "\"applications\":[";
    for (size_t i = 0; i < r.applications.size(); ++i) {
        auto& a = r.applications[i];
        if (i) o << ",";
        o << "{\"name\":" << Q(a.name)
          << ",\"installed\":" << B(a.installed)
          << ",\"status\":" << StatusS(a.status)
          << ",\"apps\":[";
        for (size_t j = 0; j < a.apps.size(); ++j) {
            auto& app = a.apps[j];
            if (j) o << ",";
            o << "{\"name\":" << Q(app.name)
              << ",\"version\":" << Q(app.version)
              << ",\"locations\":[";
            for (size_t k = 0; k < app.locations.size(); ++k) {
                auto& loc = app.locations[k];
                if (k) o << ",";
                o << "{\"path\":" << Q(loc.path)
                  << ",\"version\":" << Q(loc.version)
                  << ",\"sha256\":" << Q(loc.sha256) << "}";
            }
            o << "]}";
        }
        o << "]}";
    }
    o << "],";

    // registryFindings
    o << "\"registryFindings\":[";
    for (size_t i = 0; i < r.registryFindings.size(); ++i) {
        auto& f = r.registryFindings[i];
        if (i) o << ",";
        o << "{\"name\":" << Q(f.name)
          << ",\"path\":" << Q(f.path)
          << ",\"valueCount\":" << f.valueCount
          << ",\"subkeyCount\":" << f.subkeyCount
          << ",\"threshold\":" << f.threshold
          << ",\"exceeded\":" << B(f.exceeded)
          << ",\"status\":" << StatusS(f.status) << "}";
    }
    o << "],";

    // directoryFindings
    o << "\"directoryFindings\":[";
    for (size_t i = 0; i < r.directoryFindings.size(); ++i) {
        auto& f = r.directoryFindings[i];
        if (i) o << ",";
        o << "{\"name\":" << Q(f.name)
          << ",\"path\":" << Q(f.path)
          << ",\"fileCount\":" << f.fileCount
          << ",\"dirCount\":" << f.dirCount
          << ",\"threshold\":" << f.threshold
          << ",\"exceeded\":" << B(f.exceeded)
          << ",\"status\":" << StatusS(f.status) << "}";
    }
    o << "],";

    // persistence
    o << "\"persistence\":[";
    for (size_t i = 0; i < r.persistence.entries.size(); ++i) {
        auto& e = r.persistence.entries[i];
        if (i) o << ",";
        o << "{\"location\":" << Q(e.location)
          << ",\"name\":" << Q(e.name)
          << ",\"command\":" << Q(e.command) << "}";
    }
    o << "],\"persistenceStatus\":" << StatusS(r.persistence.status) << ",";

    // score
    o << "\"score\":{"
      << "\"total\":" << r.score.total << ","
      << "\"maximum\":" << r.score.maximum << ","
      << "\"registeredAntivirusScoring\":" << B(r.score.registeredAntivirusScoring) << ","
      << "\"rules\":[";
    for (size_t i = 0; i < r.score.rules.size(); ++i) {
        auto& s = r.score.rules[i];
        if (i) o << ",";
        o << "{\"id\":" << Q(s.id)
          << ",\"description\":" << Q(s.description)
          << ",\"maxPoints\":" << s.maxPoints
          << ",\"awardedPoints\":" << s.awardedPoints
          << ",\"category\":" << Q(s.category)
          << ",\"state\":" << Q(s.state)
          << ",\"reason\":" << Q(s.reason)
          << "}";
    }
    o << "],\"antivirusScores\":[";
    for (size_t i = 0; i < r.score.antivirusScores.size(); ++i) {
        if (i) o << ",";
        const auto& score = r.score.antivirusScores[i];
        o << "{\"id\":" << Q(score.id) << ",\"name\":" << Q(score.description)
          << ",\"state\":" << Q(score.state) << ",\"maxPoints\":" << score.maxPoints
          << ",\"awardedPoints\":" << score.awardedPoints << ",\"reason\":" << Q(score.reason) << "}";
    }
    o << "]}}";
    return o.str();
}

} // namespace sa