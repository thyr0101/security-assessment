#include "JsonRenderer.h"
#include "../Utilities.h"
#include <sstream>

namespace sa {

static std::string Esc(const std::wstring& w) {
    std::string s = WideToUtf8(w);
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
static std::string Q(const std::wstring& w) { return "\"" + Esc(w) + "\""; }
static std::string B(bool b) { return b ? "true" : "false"; }
static std::string N(unsigned long long v) { return std::to_string(v); }
static std::string TriS(Tri t) {
    switch (t) { case Tri::Yes: return "\"Yes\""; case Tri::No: return "\"No\"";
                 case Tri::NotApplicable: return "\"N/A\""; default: return "\"Unknown\""; }
}
static std::string StatusS(Status s) { return "\"" + std::string(WideToUtf8(ToW(s))) + "\""; }

std::string RenderJson(const AssessmentResult& r) {
    std::ostringstream o;
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
      << "},";

    // hardware
    o << "\"hardware\":{"
      << "\"cpu\":{"
      <<   "\"vendor\":" << Q(r.cpu.vendor) << ","
      <<   "\"brand\":" << Q(r.cpu.brand) << ","
      <<   "\"logicalProcessors\":" << r.cpu.logicalProcessors << ","
      <<   "\"physicalCores\":" << r.cpu.physicalCores << ","
      <<   "\"processorGroups\":" << r.cpu.processorGroups << ","
      <<   "\"maxMhz\":" << r.cpu.maxMhz << ","
      <<   "\"features\":{"
      <<     "\"sse\":" << B(r.cpu.sse) << ",\"sse2\":" << B(r.cpu.sse2)
              << ",\"sse3\":" << B(r.cpu.sse3) << ",\"ssse3\":" << B(r.cpu.ssse3)
              << ",\"sse41\":" << B(r.cpu.sse41) << ",\"sse42\":" << B(r.cpu.sse42)
              << ",\"avx\":" << B(r.cpu.avx) << ",\"avx2\":" << B(r.cpu.avx2)
              << ",\"avx512f\":" << B(r.cpu.avx512f) << ",\"aesni\":" << B(r.cpu.aesni)
              << ",\"sha\":" << B(r.cpu.sha) << ",\"vmx\":" << B(r.cpu.vmx)
              << ",\"svm\":" << B(r.cpu.svm) << ",\"nx\":" << B(r.cpu.nx)
      <<   "}"
      << "},"
      << "\"memory\":{"
      <<   "\"totalBytes\":" << r.memory.totalBytes << ","
      <<   "\"availableBytes\":" << r.memory.availableBytes << ","
      <<   "\"loadPercent\":" << r.memory.loadPercent << ","
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
      <<   "\"specVersion\":" << Q(r.security.tpm.specVersion) << ","
      <<   "\"manufacturerId\":" << Q(r.security.tpm.manufacturerId)
      << "},"
      << "\"secureBoot\":{"
      <<   "\"firmwareIsUefi\":" << TriS(r.security.secureBoot.firmwareIsUefi) << ","
      <<   "\"enabled\":" << TriS(r.security.secureBoot.enabled)
      << "},"
      << "\"virtualization\":{"
      <<   "\"vbsEnabled\":" << B(r.security.virt.vbsEnabled) << ","
      <<   "\"hvciEnabled\":" << B(r.security.virt.hvciEnabled) << ","
      <<   "\"credentialGuardRunning\":" << B(r.security.virt.credentialGuardRunning)
      << "},"
      << "\"uac\":{"
      <<   "\"enabled\":" << B(r.security.uac.enabled)
      << "},"
      << "\"smartAppControl\":"
      <<   "\"" << WideToUtf8(ToW(r.security.smartAppControlState)) << "\","
      << "\"elevated\":" << B(r.security.isElevated)
      << "},";

    // defender
    o << "\"defender\":{"
      << "\"installed\":" << B(r.defender.installed) << ","
      << "\"enabled\":" << B(r.defender.enabled) << ","
      << "\"realTimeProtection\":" << B(r.defender.realTimeProtection) << ","
      << "\"behaviorMonitor\":" << B(r.defender.behaviorMonitor) << ","
      << "\"ioav\":" << B(r.defender.ioav) << ","
      << "\"cloudProtection\":" << B(r.defender.cloudProtection) << ","
      << "\"threatsKnown\":" << B(r.defender.threatsKnown) << ","
      << "\"threatsCount\":" << r.defender.threatsCount << ","
      << "\"tamperProtection\":" << B(r.defender.tamperProtection) << ","
      << "\"amEngineVersion\":" << Q(r.defender.amEngineVersion) << ","
      << "\"antivirusSignatureVersion\":" << Q(r.defender.antivirusSignatureVersion) << ","
      << "\"status\":" << StatusS(r.defender.status)
      << "},";

    // firewall
    o << "\"firewall\":{"
      << "\"serviceRunning\":" << B(r.firewall.serviceRunning) << ","
      << "\"profiles\":[";
    for (size_t i = 0; i < r.firewall.profiles.size(); ++i) {
        auto& p = r.firewall.profiles[i];
        if (i) o << ",";
        o << "{\"name\":" << Q(p.name)
          << ",\"enabled\":" << B(p.enabled)
          << ",\"defaultInbound\":" << p.defaultInbound
          << ",\"defaultOutbound\":" << p.defaultOutbound << "}";
    }
    o << "]},";

    // storage
    o << "\"storage\":{"
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
        o << "{\"mountPoint\":" << Q(v.mountPoint)
            << ",\"volumeLabel\":" << Q(v.volumeLabel)     // <-- renamed member
            << ",\"filesystem\":" << Q(v.filesystem)
            << ",\"totalBytes\":" << v.totalBytes
            << ",\"freeBytes\":" << v.freeBytes
            << ",\"driveType\":" << Q(v.driveType)
            << ",\"bitLockerState\":" << Q(v.bitLockerState)
            << ",\"encryptionMethod\":" << Q(v.encryptionMethod)
            << ",\"protectionMethod\":" << Q(v.protectionMethod)
            << ",\"encryptionPercentage\":" << Q(v.encryptionPercentage)
            << "}";
    }
    o << "]},";
    // network
    o << "\"network\":{\"adapters\":[";
    for (size_t i = 0; i < r.network.adapters.size(); ++i) {
        auto& a = r.network.adapters[i];
        if (i) o << ",";
        o << "{\"name\":" << Q(a.name)
          << ",\"description\":" << Q(a.description)
          << ",\"mac\":" << Q(a.macAddress)
          << ",\"up\":" << B(a.up)
          << ",\"ifType\":" << Q(a.ifType)
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
    o << "]},";

    // services
    o << "\"services\":[";
    for (size_t i = 0; i < r.services.entries.size(); ++i) {
        auto& s = r.services.entries[i];
        if (i) o << ",";
        o << "{\"name\":" << Q(s.name)
          << ",\"displayName\":" << Q(s.displayName)
          << ",\"state\":" << Q(s.state)
          << ",\"startType\":" << Q(s.startType) << "}";
    }
    o << "],";

    // applications
    o << "\"applications\":[";
    for (size_t i = 0; i < r.applications.size(); ++i) {
        auto& a = r.applications[i];
        if (i) o << ",";
        o << "{\"name\":" << Q(a.name)
          << ",\"installed\":" << B(a.installed)
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
    o << "],";

    // privacy
    o << "\"privacy\":[";
    for (size_t i = 0; i < r.privacyFindings.size(); ++i) {
        auto& p = r.privacyFindings[i];
        if (i) o << ",";
        o << "{\"name\":" << Q(p.name)
          << ",\"value\":" << Q(p.value)
          << ",\"explanation\":" << Q(p.explanation) << "}";
    }
    o << "],";

    // score
    o << "\"score\":{"
      << "\"total\":" << r.score.total << ","
      << "\"maximum\":" << r.score.maximum << ","
      << "\"rules\":[";
    for (size_t i = 0; i < r.score.rules.size(); ++i) {
        auto& s = r.score.rules[i];
        if (i) o << ",";
        o << "{\"id\":\"" << s.id << "\""
          << ",\"description\":\"" << s.description << "\""
          << ",\"maxPoints\":" << s.maxPoints
          << ",\"awardedPoints\":" << s.awardedPoints
          << ",\"category\":\"" << s.category << "\""
          << ",\"state\":\"" << s.state << "\""
          << ",\"reason\":\"" << s.reason << "\""
          << "}";
    }
    o << "]}}";
    return o.str();
}

} // namespace sa
