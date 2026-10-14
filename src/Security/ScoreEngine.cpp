#include "ScoreEngine.h"
#include <algorithm>

namespace sa {

namespace {
struct R {
    const char* id;
    const char* desc;
    int points;
    Category cat;
};

ScoreRuleResult Make(const R& r, bool passed, const std::string& state,
                     const std::string& reason) {
    ScoreRuleResult s;
    s.id = r.id;
    s.description = r.desc;
    s.maxPoints = r.points;
    s.awardedPoints = passed ? r.points : 0;
    s.category = WideToUtf8(ToW(r.cat));
    s.reason = reason;
    s.state = state;
    return s;
}

ScoreRuleResult Full(const R& r, const std::string& reason,
                     const std::string& state = "Enabled") {
    return Make(r, true, state, reason);
}
ScoreRuleResult Zero(const R& r, const std::string& state, const std::string& reason) {
    return Make(r, false, state, reason);
}
ScoreRuleResult Partial(const R& r, int pts, const std::string& state, const std::string& reason) {
    ScoreRuleResult s;
    s.id = r.id; s.description = r.desc; s.maxPoints = r.points;
    s.awardedPoints = pts; s.category = WideToUtf8(ToW(r.cat));
    s.state = state; s.reason = reason;
    return s;
}
} // namespace

ScoreReport ComputeScore(const AssessmentResult& a) {
    ScoreReport rep;
    rep.maximum = 1000;
    rep.rules.reserve(32 + a.privacyFindings.size());

    auto& S = a.security;
    auto& D = a.defender;
    auto& F = a.firewall;
    auto& O = a.os;
    auto& C = a.cpu;

    // ---- Hardware Security (max 215) ----
    rep.rules.push_back(S.secureBoot.enabled == Tri::Yes
        ? Full({ "hw.secureboot", "Secure Boot", 50, Category::HardwareSecurity },
               "Secure Boot is enabled and UEFI is the firmware.")
        : Zero({ "hw.secureboot", "Secure Boot", 50, Category::HardwareSecurity },
               S.secureBoot.enabled == Tri::No ? "Disabled" : "Unknown",
               "Secure Boot is not enabled or could not be verified."));

    if (S.tpm.present && S.tpm.ready) {
        const bool v2 = Trim(Split(S.tpm.specVersion, L',').front()) == L"2.0";
        rep.rules.push_back(v2
            ? Full({ "hw.tpm2", "TPM 2.0 security chip ready", 50, Category::HardwareSecurity }, "TPM 2.0 is present and ready.", "Ready")
            : Partial({ "hw.tpm2", "TPM 2.0 security chip ready", 50, Category::HardwareSecurity }, 20,
                      "Version unverified", "TPM is ready, but version 2.0 could not be confirmed."));
    } else if (S.tpm.present) {
        rep.rules.push_back(Partial({ "hw.tpm2", "TPM 2.0 security chip ready", 50, Category::HardwareSecurity },
                                    20, "Not ready",
                                    "TPM is present but not enabled/ready."));
    } else {
        rep.rules.push_back(Zero({ "hw.tpm2", "TPM 2.0 security chip ready", 50, Category::HardwareSecurity },
                                 S.tpm.status == Status::Unavailable ? "Unavailable" : "Absent",
                                 "No usable TPM detected."));
    }

    rep.rules.push_back(CpuVirtualizationAvailable(C)
        ? Full({ "hw.virt", "CPU virtualization support", 15, Category::HardwareSecurity },
               "CPU virtualization support is available.", "Supported")
        : Zero({ "hw.virt", "CPU virtualization support", 15, Category::HardwareSecurity }, "Absent",
               "CPU virtualization extensions not reported."));

    rep.rules.push_back(C.aesni
        ? Full({ "hw.aes", "Hardware encryption support (AES-NI)", 10, Category::HardwareSecurity },
               "The CPU supports hardware acceleration for AES encryption.", "Supported")
        : Zero({ "hw.aes", "Hardware encryption support (AES-NI)", 10, Category::HardwareSecurity }, "Absent", "AES-NI not reported."));

    rep.rules.push_back(C.nx
        ? Full({ "hw.nx", "CPU memory protection (NX/XD)", 10, Category::HardwareSecurity },
               "The CPU can prevent code execution in memory areas reserved for data.", "Supported")
        : Zero({ "hw.nx", "CPU memory protection (NX/XD)", 10, Category::HardwareSecurity }, "Absent", "NX/XD not reported."));

    if (S.virt.vbsEnabled)
        rep.rules.push_back(Full({ "hw.vbs", "Virtualization security (VBS)", 40, Category::HardwareSecurity },
                                 "Windows uses virtualization to isolate security functions.", "Running"));
    else
        rep.rules.push_back(Zero({ "hw.vbs", "Virtualization security (VBS)", 40, Category::HardwareSecurity },
                                 S.virt.deviceGuardAvailable ? "Not running" : "Unknown",
                                 "VBS not detected as running."));

    if (S.virt.hvciEnabled)
        rep.rules.push_back(Full({ "hw.hvci", "Memory integrity (HVCI)", 40, Category::HardwareSecurity },
                                 "Memory integrity protects Windows kernel code using virtualization.", "Running"));
    else
        rep.rules.push_back(Zero({ "hw.hvci", "Memory integrity (HVCI)", 40, Category::HardwareSecurity }, "Disabled",
                                 "HVCI is not enabled."));

    // ---- OS Security (max 175) ----
    rep.rules.push_back(O.build >= 22000
        ? Full({ "os.win11", "Windows 11 or newer", 30, Category::OsSecurity },
               "The installed operating system is Windows 11 or newer.", "Detected")
        : Partial({ "os.win11", "Windows 11 or newer", 30, Category::OsSecurity }, 10,
                  "Older Windows", "The installed Windows version is older than Windows 11."));

    if (S.uac.enabled)
        rep.rules.push_back(Full({ "os.uac", "User Account Control (UAC)", 30, Category::OsSecurity },
                                 "User Account Control is enabled."));
    else
        rep.rules.push_back(Zero({ "os.uac", "User Account Control (UAC)", 30, Category::OsSecurity }, "Disabled",
                                 "UAC is disabled."));

    if (S.dep.depEnabled == Tri::Yes)
        rep.rules.push_back(Full({ "os.dep", "Data Execution Prevention (DEP)", 20, Category::OsSecurity },
                                 "Data Execution Prevention is active."));
    else
        rep.rules.push_back(Zero({ "os.dep", "Data Execution Prevention (DEP)", 20, Category::OsSecurity }, "Disabled",
                                 "DEP is not enforced."));

    if (S.dep.sehopEnabled == Tri::Yes)
        rep.rules.push_back(Full({ "os.sehop", "Memory overwrite protection (SEHOP)", 15, Category::OsSecurity },
                                 "Windows protects exception handling data against memory overwrite attacks."));
    else
        rep.rules.push_back(Zero({ "os.sehop", "Memory overwrite protection (SEHOP)", 15, Category::OsSecurity },
                                 S.dep.sehopEnabled == Tri::Unknown ? "Unknown" : "Disabled",
                                 "SEHOP is not enabled."));

    if (S.smartAppControlOn)
        rep.rules.push_back(Full({ "os.sac", "Smart App Control", 50, Category::OsSecurity },
                                 "Smart App Control is enforcing."));
    else if (S.smartAppControlEvaluation)
        rep.rules.push_back(Partial({ "os.sac", "Smart App Control", 50, Category::OsSecurity },
                                    25, "Evaluation",
                                    "Smart App Control is evaluating applications without blocking them."));
    else
        rep.rules.push_back(Zero({ "os.sac", "Smart App Control", 50, Category::OsSecurity },
                                 S.smartAppControlState == Tri::No ? "Off" : "Unknown",
                                 "Smart App Control not enforcing."));

    // UBR identifies the installed update revision; it does not establish recency.
    rep.rules.push_back(O.ubr > 0
        ? Full({ "os.patch", "Windows update details available", 30, Category::OsSecurity },
               "Windows reported its installed update revision. This does not verify that the latest updates are installed.", "Available")
        : Zero({ "os.patch", "Windows update details available", 30, Category::OsSecurity }, "Unknown",
               "Windows update revision could not be read."));

    // ---- Malware Protection (max 195) ----
    bool anyAvEnabled = false, anyAvUnknown = false;
    for (size_t i = 0; i < a.antivirus.products.size(); ++i) {
        const auto& av = a.antivirus.products[i];
        const bool enabled = av.status == Status::Success && av.state == AntivirusState::Enabled;
        const bool known = av.status == Status::Success && av.state != AntivirusState::Unknown;
        anyAvEnabled |= enabled;
        anyAvUnknown |= !known;
        ScoreRuleResult score;
        score.id = "av." + (av.id.empty() ? std::to_string(i) : WideToUtf8(av.id));
        score.description = WideToUtf8(av.name);
        score.maxPoints = kMalwareProtectionMaxPoints;
        score.awardedPoints = enabled ? kMalwareProtectionMaxPoints : 0;
        score.category = WideToUtf8(ToW(Category::MalwareProtection));
        score.state = known ? WideToUtf8(ToW(av.state)) : "Unknown";
        score.reason = enabled ? "Windows Security Center reports this antivirus enabled."
            : known ? "Windows Security Center does not report this antivirus actively protecting the computer."
            : "Windows Security Center could not report this antivirus state.";
        rep.antivirusScores.push_back(std::move(score));
    }
    rep.registeredAntivirusScoring = HasThirdPartyAntivirus(a.antivirus) ||
        (!a.antivirus.products.empty() && (D.status != Status::Success || !D.enabled));
    if (rep.registeredAntivirusScoring) {
        const R rule{"mp.registered", "Registered antivirus protection", kMalwareProtectionMaxPoints, Category::MalwareProtection};
        rep.rules.push_back(anyAvEnabled
            ? Full(rule, "At least one registered antivirus is enabled. Independent product scores are shown separately.")
            : Zero(rule, (anyAvUnknown || a.antivirus.status != Status::Success) ? "Unknown" : "Disabled",
                   "No registered antivirus could be confirmed enabled."));
    } else {
        if (D.installed && D.enabled)
            rep.rules.push_back(Full({ "mp.defender", "Microsoft Defender antivirus", 40,
                                       Category::MalwareProtection },
                                     "Microsoft Defender is active.", "Active"));
        else
            rep.rules.push_back(Zero({ "mp.defender", "Microsoft Defender antivirus", 40, Category::MalwareProtection },
                                     D.installed ? "Inactive" : "Unavailable",
                                     "Defender could not be confirmed active."));

        if (D.realTimeProtection)
            rep.rules.push_back(Full({ "mp.rtp", "Real-time protection", 60, Category::MalwareProtection },
                                     "Real-time protection is enabled."));
        else
            rep.rules.push_back(Zero({ "mp.rtp", "Real-time protection", 60, Category::MalwareProtection }, "Disabled",
                                     "Real-time protection is off."));

        if (D.behaviorMonitor)
            rep.rules.push_back(Full({ "mp.bm", "Suspicious behavior monitoring", 20, Category::MalwareProtection },
                                     "Behavior monitoring enabled."));
        else
            rep.rules.push_back(Zero({ "mp.bm", "Suspicious behavior monitoring", 20, Category::MalwareProtection }, "Disabled",
                                     "Behavior monitoring not enabled."));

        if (D.ioav)
            rep.rules.push_back(Full({ "mp.ioav", "Downloaded file scanning", 15, Category::MalwareProtection },
                                     "Downloaded-file scanning enabled."));
        else
            rep.rules.push_back(Zero({ "mp.ioav", "Downloaded file scanning", 15, Category::MalwareProtection }, "Disabled",
                                     "IOAV scanning not enabled."));

        if (D.cloudProtection)
            rep.rules.push_back(Full({ "mp.cloud", "Cloud malware detection", 20, Category::MalwareProtection },
                                     "Cloud-delivered protection enabled."));
        else
            rep.rules.push_back(Zero({ "mp.cloud", "Cloud malware detection", 20, Category::MalwareProtection }, "Disabled",
                                     "Cloud-delivered protection not enabled."));

        if (D.tamperProtection)
            rep.rules.push_back(Full({ "mp.tamper", "Antivirus settings protection", 20, Category::MalwareProtection },
                                     "Defender protects its security settings against unauthorized changes."));
        else
            rep.rules.push_back(Zero({ "mp.tamper", "Antivirus settings protection", 20, Category::MalwareProtection }, "Disabled",
                                     "Defender settings protection is disabled or unavailable."));

        if (D.installed && D.threatsKnown && D.threatsCount == 0)
            rep.rules.push_back(Full({ "mp.threats", "Defender reports no active threats", 20, Category::MalwareProtection },
                                     "No active threats reported by Defender.", "Clear"));
        else
            rep.rules.push_back(Zero({ "mp.threats", "Defender reports no active threats", 20, Category::MalwareProtection },
                                     (D.installed && D.threatsKnown) ? "Threats found" : "Unknown",
                                     (D.installed && D.threatsKnown)
                                         ? "Active threats reported by Defender."
                                         : "Threat status could not be read."));
    }

    // ---- Network Security (max 100) ----
    bool anyEnabled = false, allEnabled = F.profiles.size() == 3;
    for (auto& p : F.profiles) {
        anyEnabled |= p.enabled && p.status == Status::Success;
        allEnabled &= p.enabled && p.status == Status::Success;
    }
    if (allEnabled && !F.profiles.empty())
        rep.rules.push_back(Full({ "net.fw", "Firewall on all network profiles", 60,
                                   Category::NetworkSecurity },
                                 "Firewall enabled on Domain, Private, and Public profiles."));
    else if (anyEnabled)
        rep.rules.push_back(Partial({ "net.fw", "Firewall on all network profiles", 60, Category::NetworkSecurity },
                                    25, "Partial",
                                    "Firewall enabled on some but not all profiles."));
    else
        rep.rules.push_back(Zero({ "net.fw", "Firewall on all network profiles", 60, Category::NetworkSecurity }, "Disabled",
                                 "Firewall not enabled on any profile."));

    bool defInBlock = F.profiles.size() == 3;
    for (auto& p : F.profiles) if (p.defaultInbound != 0 || p.status != Status::Success) { defInBlock = false; break; }
    if (defInBlock && !F.profiles.empty())
        rep.rules.push_back(Full({ "net.in", "Block incoming traffic by default", 20, Category::NetworkSecurity },
                                 "Incoming traffic is blocked by default unless a firewall rule allows it.", "Blocking"));
    else
        rep.rules.push_back(Zero({ "net.in", "Block incoming traffic by default", 20, Category::NetworkSecurity }, "Allowing or unknown",
                                 "Not all profiles default-block inbound."));

    if (F.serviceRunning)
        rep.rules.push_back(Full({ "net.svc", "Windows Firewall service", 20,
                                   Category::NetworkSecurity },
                                 "The Windows Firewall service is running.", "Running"));
    else
        rep.rules.push_back(Zero({ "net.svc", "Windows Firewall service", 20, Category::NetworkSecurity }, "Stopped",
                                 "Firewall service not running."));

    // ---- Encryption (max 175) ----
    bool anyBitlockerOn = false, allFixedOn = a.storage.status == Status::Success;
    bool anyBitlockerUnknown = a.storage.status != Status::Success;
    int fixedCount = 0;
    for (auto& v : a.storage.volumes) {
        if (v.driveType == L"Unknown" || v.driveType.empty()) {
            allFixedOn = false;
            anyBitlockerUnknown = true;
        }
        if (v.driveType != L"Fixed") continue;
        ++fixedCount;
        const bool known = v.bitLockerStatus == Status::Success;
        if (known && v.bitLockerState == L"On") anyBitlockerOn = true;
        else allFixedOn = false;
        if (!known || (v.bitLockerState != L"On" && v.bitLockerState != L"Off")) anyBitlockerUnknown = true;
    }
    if (fixedCount == 0)
        rep.rules.push_back(Zero({ "enc.bl", "BitLocker on all fixed drives", 100,
                                   Category::Encryption }, anyBitlockerUnknown ? "Unknown" : "No fixed drives",
                                 "No fixed volumes could be verified."));
    else if (allFixedOn)
        rep.rules.push_back(Full({ "enc.bl", "BitLocker on all fixed drives", 100,
                                   Category::Encryption },
                                 "All detected fixed drives have BitLocker protection active.", "Protected"));
    else if (anyBitlockerOn)
        rep.rules.push_back(Partial({ "enc.bl", "BitLocker on all fixed drives", 100, Category::Encryption },
                                    50, "Some drives protected",
                                    "BitLocker protection confirmed on some volumes; full coverage could not be verified."));
    else
        rep.rules.push_back(Zero({ "enc.bl", "BitLocker on all fixed drives", 100, Category::Encryption },
                                 anyBitlockerUnknown ? "Unknown" : "Disabled",
                                 anyBitlockerUnknown
                                     ? "BitLocker status could not be read (needs elevation)."
                                     : "BitLocker not enabled on any fixed volume."));

    rep.rules.push_back(S.tpm.present
        ? Full({ "enc.tpm", "TPM available to protect keys", 75, Category::Encryption },
               "A TPM security chip is available to store and protect encryption keys.", "Available")
        : Zero({ "enc.tpm", "TPM available to protect keys", 75, Category::Encryption }, "Absent",
               "No TPM available for key protection."));

    // ---- Account Security (max 100) ----
    if (S.uac.enabled && S.uac.consentPromptAdmin)
        rep.rules.push_back(Full({ "acc.uac2", "Admin actions require a UAC prompt", 50,
                                   Category::AccountSecurity },
                                 "Administrator actions require a UAC consent or credentials prompt.", "Required"));
    else
        rep.rules.push_back(Zero({ "acc.uac2", "Admin actions require a UAC prompt", 50, Category::AccountSecurity },
                                 "Not required",
                                 "UAC prompt not required for admin actions."));

    rep.rules.push_back(S.isElevated
        ? Full({ "acc.elev", "Assessment has administrator access", 25,
                 Category::AccountSecurity },
               "The assessment is running with administrator access to read restricted system information.", "Granted")
        : Partial({ "acc.elev", "Assessment has administrator access", 25, Category::AccountSecurity }, 0,
                  "Not granted",
                  "Run as administrator to allow restricted system checks."));

    if (S.windowsHelloAvailable)
        rep.rules.push_back(Full({ "acc.hello", "Windows Hello sign-in support", 25,
                                   Category::AccountSecurity },
                                 "Windows Hello sign-in components were detected.", "Available"));
    else
        rep.rules.push_back(Zero({ "acc.hello", "Windows Hello sign-in support", 25, Category::AccountSecurity }, "Unknown",
                                 "Windows Hello availability not detected."));

    // ---- Privacy (informational; no score weight) ----
    for (auto& p : a.privacyFindings) {
        ScoreRuleResult s;
        s.id = "priv." + WideToUtf8(p.name);
        s.description = WideToUtf8(p.name);
        s.maxPoints = 0;
        s.awardedPoints = 0;
        s.category = WideToUtf8(ToW(Category::Privacy));
        s.reason = WideToUtf8(p.explanation);
        s.state = WideToUtf8(p.value);
        rep.rules.push_back(std::move(s));
    }

    // ---- Hardening / Software Hygiene (max 40) ----
    rep.rules.push_back(a.persistence.status != Status::Success
        ? Zero({ "hyg.startup", "Startup application scan", 20, Category::SoftwareHygiene },
               "Unknown", "Startup inventory could not be completed.")
        : a.persistence.entries.empty()
        ? Full({ "hyg.startup", "Startup application scan", 20, Category::SoftwareHygiene },
               "The selected startup locations were checked; no entries were found.", "Complete")
        : Full({ "hyg.startup", "Startup application scan", 20, Category::SoftwareHygiene },
               std::to_string(a.persistence.entries.size()) + " startup entries found in the selected locations.", "Complete"));

    const bool inventoryComplete = !a.applications.empty() && std::all_of(
        a.applications.begin(), a.applications.end(), [](const ApplicationFinding& app) {
            return app.status == Status::Success || app.status == Status::NotFound;
        });
    rep.rules.push_back(inventoryComplete ? Full({ "hyg.appinv", "Selected application scan", 20,
                               Category::SoftwareHygiene },
                             "Installation status was checked for every application in the configured list.", "Complete")
        : Zero({ "hyg.appinv", "Selected application scan", 20, Category::SoftwareHygiene },
               "Unknown", "Application inventory could not be completed."));

    // Failed collection must not become a definite disabled/absent state or earn points.
    for (auto& rule : rep.rules) {
        bool unknown = false;
        if (rule.id.starts_with("mp.") && rule.id != "mp.registered") unknown = D.status != Status::Success;
        else if (rule.id.starts_with("os.win") || rule.id == "os.patch") unknown = O.status != Status::Success;
        else if (rule.id == "os.uac" || rule.id == "acc.uac2") unknown = S.uac.status != Status::Success;
        else if (rule.id == "hw.virt" || rule.id == "hw.aes" || rule.id == "hw.nx") unknown = C.status != Status::Success;
        else if (rule.id == "hw.tpm2" || rule.id == "enc.tpm")
            unknown = S.tpm.status != Status::Success && S.tpm.status != Status::NotFound;
        else if (rule.id == "hw.vbs") unknown = S.virt.status != Status::Success;
        else if (rule.id == "hw.hvci") unknown = S.virt.status != Status::Success || !S.virt.runningServicesKnown;
        else if (rule.id == "hw.secureboot") unknown = S.secureBoot.status != Status::Success;
        else if (rule.id == "os.dep") unknown = S.dep.depEnabled == Tri::Unknown;
        else if (rule.id == "net.fw") unknown = F.status != Status::Success && !anyEnabled;
        else if (rule.id == "net.svc") unknown = F.serviceStatus != Status::Success;
        if (rule.id == "mp.defender") unknown |= D.enabledStatus != Status::Success;
        else if (rule.id == "mp.rtp") unknown |= D.realTimeProtectionStatus != Status::Success;
        else if (rule.id == "mp.bm") unknown |= D.behaviorMonitorStatus != Status::Success;
        else if (rule.id == "mp.ioav") unknown |= D.ioavStatus != Status::Success;
        else if (rule.id == "mp.cloud") unknown |= D.cloudProtectionStatus != Status::Success;
        else if (rule.id == "mp.tamper") unknown |= D.tamperProtectionStatus != Status::Success;
        if (unknown) {
            rule.awardedPoints = 0;
            rule.state = "Unknown";
            rule.reason = "The required system data could not be read reliably.";
        }
    }

    // ---- Sum ----
    int total = 0, maximum = 0;
    for (auto& r : rep.rules) {
        total += r.awardedPoints;
        maximum += r.maxPoints;
    }
    rep.total = total;
    rep.maximum = maximum;
    return rep;
}

} // namespace sa
