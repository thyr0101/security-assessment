#include "JsonRenderer.h"
#include "JsonCompact.h"
#include "JsonWriter.h"

namespace sa {
using namespace json_writer;

std::string RenderJson(const AssessmentResult& r, JsonFormat format) {
    JsonObject root;
    JsonObject system;
    system.Text("productName", r.os.productName); system.Text("displayVersion", r.os.displayVersion);
    system.Set("build", std::to_string(r.os.build)); system.Set("ubr", std::to_string(r.os.ubr));
    system.Text("architecture", r.os.architecture); system.Text("computerName", r.os.computerName);
    system.Text("userName", r.os.userName); system.Text("timeZone", r.os.timeZone); system.Text("locale", r.os.locale);
    system.Set("uptimeSeconds", std::to_string(r.os.uptimeSeconds));
    root.Set("system", system.Finish());

    JsonObject cpu, features, memory, hardware;
    cpu.Text("brand", r.cpu.brand); cpu.Set("physicalCores", std::to_string(r.cpu.physicalCores));
    cpu.Set("logicalProcessors", std::to_string(r.cpu.logicalProcessors)); cpu.Set("status", StatusS(r.cpu.status));
    features.Set("aesni", B(r.cpu.aesni)); features.Set("nx", B(r.cpu.nx));
    features.Set("virtualizationAvailable", B(r.cpu.virtualizationAvailable));
    cpu.Set("features", features.Finish()); hardware.Set("cpu", cpu.Finish());
    memory.Set("totalBytes", std::to_string(r.memory.totalBytes)); memory.Set("availableBytes", std::to_string(r.memory.availableBytes));
    hardware.Set("memory", memory.Finish()); root.Set("hardware", hardware.Finish());

    JsonObject security, tpm, boot, virt, uac;
    tpm.Set("present", B(r.security.tpm.present)); tpm.Set("ready", B(r.security.tpm.ready));
    tpm.Set("readinessKnown", B(r.security.tpm.readinessKnown)); tpm.Text("specVersion", r.security.tpm.specVersion);
    tpm.Set("status", StatusS(r.security.tpm.status)); security.Set("tpm", tpm.Finish());
    boot.Set("enabled", TriS(r.security.secureBoot.enabled)); security.Set("secureBoot", boot.Finish());
    virt.Set("vbsEnabled", B(r.security.virt.vbsEnabled)); virt.Set("hvciEnabled", B(r.security.virt.hvciEnabled));
    virt.Set("credentialGuardRunning", B(r.security.virt.credentialGuardRunning)); virt.Set("runningServicesKnown", B(r.security.virt.runningServicesKnown));
    virt.Set("hvciConfigured", TriS(r.security.virt.hvciConfigured)); virt.Set("status", StatusS(r.security.virt.status));
    security.Set("virtualization", virt.Finish());
    uac.Set("enabled", B(r.security.uac.enabled)); uac.Set("promptOnSecureDesktop", std::to_string(r.security.uac.promptOnSecureDesktop));
    uac.Set("status", StatusS(r.security.uac.status)); security.Set("uac", uac.Finish());
    security.Set("elevated", B(r.security.isElevated)); root.Set("security", security.Finish());

    JsonObject defender;
    defender.Set("enabled", B(r.defender.enabled)); defender.Set("enabledStatus", StatusS(r.defender.enabledStatus));
    defender.Set("status", StatusS(r.defender.status)); defender.Text("reason", r.defender.reason);
    if (r.score.registeredAntivirusScoring) defender.Text("amRunningMode", r.defender.amRunningMode);
    else {
        const std::pair<const char*, const bool*> flags[] = {{"realTimeProtection", &r.defender.realTimeProtection},
            {"behaviorMonitor", &r.defender.behaviorMonitor}, {"ioav", &r.defender.ioav},
            {"cloudProtection", &r.defender.cloudProtection}, {"tamperProtection", &r.defender.tamperProtection}};
        for (const auto& [name, value] : flags) defender.Set(name, B(*value));
        defender.Set("realTimeProtectionStatus", StatusS(r.defender.realTimeProtectionStatus));
        defender.Set("behaviorMonitorStatus", StatusS(r.defender.behaviorMonitorStatus));
        defender.Set("ioavStatus", StatusS(r.defender.ioavStatus)); defender.Set("cloudProtectionStatus", StatusS(r.defender.cloudProtectionStatus));
        defender.Set("tamperProtectionStatus", StatusS(r.defender.tamperProtectionStatus));
        defender.Text("amEngineVersion", r.defender.amEngineVersion); defender.Text("antivirusSignatureVersion", r.defender.antivirusSignatureVersion);
    }
    if (HasThirdPartyAntivirus(r.antivirus)) defender.Set("periodicScanning", TriS(r.defender.periodicScanning));
    root.Set("defender", defender.Finish());
    JsonObject antivirus;
    antivirus.Set("status", StatusS(r.antivirus.status)); antivirus.Text("reason", r.antivirus.reason);
    if (r.score.registeredAntivirusScoring) antivirus.Set("products", Array(r.antivirus.products, [](const auto& value) {
        JsonObject item; item.Text("name", value.name); item.Set("state", Q(std::wstring(ToW(value.state))));
        item.Set("status", StatusS(value.status)); item.Set("isDefender", B(value.isDefender));
        item.Set("signaturesUpToDate", TriS(value.signaturesUpToDate)); return item.Finish();
    }));
    root.Set("antivirus", antivirus.Finish());

    JsonObject firewall;
    firewall.Set("serviceRunning", B(r.firewall.serviceRunning)); firewall.Set("serviceStatus", StatusS(r.firewall.serviceStatus));
    firewall.Set("activeProfiles", std::to_string(r.firewall.activeProfiles)); firewall.Set("activeProfilesStatus", StatusS(r.firewall.activeProfilesStatus));
    firewall.Set("profiles", Array(r.firewall.profiles, [](const auto& value) {
        JsonObject item; item.Text("name", value.name); item.Set("enabled", B(value.enabled));
        item.Set("defaultInbound", std::to_string(value.defaultInbound)); item.Set("defaultOutbound", std::to_string(value.defaultOutbound));
        item.Set("status", StatusS(value.status)); return item.Finish();
    })); root.Set("firewall", firewall.Finish());
    JsonObject network, policies;
    const std::pair<const char*, const SecuritySetting*> settings[] = {{"smb1Server", &r.network.smb1Server}, {"smb1Client", &r.network.smb1Client},
        {"smbServerSigning", &r.network.smbServerSigning}, {"smbClientSigning", &r.network.smbClientSigning},
        {"smbGuestLogons", &r.network.smbGuestLogons}, {"smbEncryption", &r.network.smbEncryption},
        {"smbRejectUnencrypted", &r.network.smbRejectUnencrypted}, {"llmnr", &r.network.llmnr}, {"rdp", &r.network.rdp}, {"rdpNla", &r.network.rdpNla}};
    for (const auto& [name, value] : settings) policies.Set(name, SettingJson(*value));
    network.Set("security", policies.Finish()); root.Set("network", network.Finish());
    JsonObject hardening;
    const std::pair<const char*, const SecuritySetting*> protections[] = {{"lsaProtection", &r.hardening.lsaProtection}, {"noLmHash", &r.hardening.noLmHash},
        {"autoPlayDisabled", &r.hardening.autoPlayDisabled}, {"guestDisabled", &r.hardening.guestDisabled}, {"remoteAssistanceDisabled", &r.hardening.remoteAssistanceDisabled}};
    for (const auto& [name, value] : protections) hardening.Set(name, SettingJson(*value));
    hardening.Set("inactivitySeconds", std::to_string(r.hardening.inactivitySeconds)); hardening.Set("inactivityStatus", StatusS(r.hardening.inactivityStatus));
    hardening.Set("lmCompatibility", std::to_string(r.hardening.lmCompatibility)); hardening.Set("lmCompatibilityStatus", StatusS(r.hardening.lmCompatibilityStatus));
    hardening.Set("lockoutThreshold", std::to_string(r.hardening.lockoutThreshold)); hardening.Set("lockoutDuration", std::to_string(r.hardening.lockoutDuration));
    hardening.Set("lockoutWindow", std::to_string(r.hardening.lockoutWindow)); hardening.Set("lockoutStatus", StatusS(r.hardening.lockoutStatus));
    root.Set("hardening", hardening.Finish());

    JsonObject updates;
    updates.Set("pendingStatus", StatusS(r.windowsUpdate.pendingStatus)); updates.Text("pendingReason", r.windowsUpdate.pendingReason);
    updates.Text("lastInstallationError", r.windowsUpdate.lastInstallationError);
    updates.Set("updates", Array(r.windowsUpdate.updates, [](const auto& value) {
        JsonObject item; item.Text("title", value.title); item.Set("optional", TriS(value.optional)); item.Set("downloaded", TriS(value.downloaded));
        item.Text("updateType", value.updateType); item.Text("severity", value.severity);
        item.Set("classifications", Strings(value.classifications)); item.Set("products", Strings(value.products)); item.Set("kbArticles", Strings(value.kbArticles));
        return item.Finish();
    }));
    updates.Set("services", Array(r.windowsUpdate.services.entries, [](const auto& value) {
        JsonObject item; item.Text("name", value.name); item.Text("displayName", value.displayName); item.Text("state", value.state); return item.Finish();
    })); root.Set("windowsUpdate", updates.Finish());

    JsonObject storage;
    storage.Set("status", StatusS(r.storage.status));
    storage.Set("disks", Array(r.storage.disks, [](const auto& value) {
        JsonObject item; item.Set("index", std::to_string(value.index)); item.Text("model", value.model); item.Text("vendor", value.vendor);
        item.Set("sizeBytes", std::to_string(value.sizeBytes)); item.Text("busType", value.busType); item.Text("mediaType", value.mediaType); return item.Finish();
    }));
    storage.Set("volumes", Array(r.storage.volumes, [](const auto& value) {
        JsonObject item; item.Text("mountPoint", value.mountPoint); item.Text("volumeLabel", value.volumeLabel); item.Text("filesystem", value.filesystem);
        item.Set("totalBytes", std::to_string(value.totalBytes)); item.Set("freeBytes", std::to_string(value.freeBytes));
        item.Text("bitLockerState", value.bitLockerState); item.Text("encryptionMethod", value.encryptionMethod);
        if (value.bitLockerState == L"Unknown") item.Text("bitLockerNote", value.bitLockerNote);
        item.Set("diskMappingStatus", StatusS(value.diskMappingStatus));
        item.Set("diskIndices", Array(value.diskIndices, [](auto index) { return std::to_string(index); })); return item.Finish();
    })); root.Set("storage", storage.Finish());
    std::vector<RegistryFinding> registry;
    for (const auto& value : r.registryFindings)
        if (value.exceeded || (value.status != Status::Success && value.status != Status::NotFound)) registry.push_back(value);
    root.Set("registryFindings", Array(registry, [](const auto& value) {
        JsonObject item; item.Text("name", value.name); item.Set("status", StatusS(value.status)); item.Set("exceeded", B(value.exceeded));
        if (value.exceeded) { item.Text("path", value.path); item.Set("valueCount", std::to_string(value.valueCount)); item.Set("threshold", std::to_string(value.threshold)); }
        return item.Finish();
    }));
    std::vector<DirectoryFinding> directories;
    for (const auto& value : r.directoryFindings)
        if (value.exceeded || (value.status != Status::Success && value.status != Status::NotFound)) directories.push_back(value);
    root.Set("directoryFindings", Array(directories, [](const auto& value) {
        JsonObject item; item.Text("name", value.name); item.Set("status", StatusS(value.status)); item.Set("exceeded", B(value.exceeded));
        if (value.exceeded) { item.Text("path", value.path); item.Set("fileCount", std::to_string(value.fileCount)); item.Set("threshold", std::to_string(value.threshold)); }
        return item.Finish();
    }));
    JsonObject score;
    score.Set("total", std::to_string(r.score.total)); score.Set("maximum", std::to_string(r.score.maximum));
    score.Set("registeredAntivirusScoring", B(r.score.registeredAntivirusScoring));
    score.Set("rules", Array(r.score.rules, [](const auto& value) {
        JsonObject item; item.Set("id", Q(value.id)); item.Set("description", Q(value.description)); item.Set("category", Q(value.category));
        item.Set("maxPoints", std::to_string(value.maxPoints)); item.Set("awardedPoints", std::to_string(value.awardedPoints));
        item.Set("state", Q(value.state)); return item.Finish();
    }));
    if (r.score.registeredAntivirusScoring) score.Set("antivirusScores", Array(r.score.antivirusScores, [](const auto& value) {
        JsonObject item; item.Set("maxPoints", std::to_string(value.maxPoints)); item.Set("awardedPoints", std::to_string(value.awardedPoints)); return item.Finish();
    }));
    root.Set("score", score.Finish());
    auto json = root.Finish();
    return format == JsonFormat::Compact ? CompactJson(json) : json;
}
} // namespace sa