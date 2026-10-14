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
        ? Full({ "hw.secureboot", "Secure Boot enabled", 50, Category::HardwareSecurity },
               "Secure Boot is enabled and UEFI is the firmware.")
        : Zero({ "hw.secureboot", "Secure Boot enabled", 50, Category::HardwareSecurity },
               S.secureBoot.enabled == Tri::No ? "Disabled" : "Unknown",
               "Secure Boot is not enabled or could not be verified."));

    if (S.tpm.present && S.tpm.ready) {
        const bool v2 = Trim(Split(S.tpm.specVersion, L',').front()) == L"2.0";
        rep.rules.push_back(v2
            ? Full({ "hw.tpm2", "TPM 2.0 present & ready", 50, Category::HardwareSecurity }, "TPM 2.0 is present and ready.")
            : Partial({ "hw.tpm2", "TPM 2.0 present & ready", 50, Category::HardwareSecurity }, 20,
                      "VersionUnverified", "TPM is ready, but version 2.0 could not be confirmed."));
    } else if (S.tpm.present) {
        rep.rules.push_back(Partial({ "hw.tpm2", "TPM 2.0 present & ready", 50, Category::HardwareSecurity },
                                    20, "PresentNotReady",
                                    "TPM is present but not enabled/ready."));
    } else {
        rep.rules.push_back(Zero({ "hw.tpm2", "TPM 2.0 present & ready", 50, Category::HardwareSecurity },
                                 S.tpm.status == Status::Unavailable ? "Unavailable" : "Absent",
                                 "No usable TPM detected."));
    }

    rep.rules.push_back(CpuVirtualizationAvailable(C)
        ? Full({ "hw.virt", "CPU virtualization support", 15, Category::HardwareSecurity },
               "CPU exposes virtualization extensions.")
        : Zero({ "hw.virt", "CPU virtualization support", 15, Category::HardwareSecurity }, "Absent",
               "CPU virtualization extensions not reported."));

    rep.rules.push_back(C.aesni
        ? Full({ "hw.aes", "CPU AES-NI", 10, Category::HardwareSecurity },
               "AES-NI instructions available.")
        : Zero({ "hw.aes", "CPU AES-NI", 10, Category::HardwareSecurity }, "Absent", "AES-NI not reported."));

    rep.rules.push_back(C.nx
        ? Full({ "hw.nx", "CPU NX/XD", 10, Category::HardwareSecurity },
               "NX/XD supported by CPU.")
        : Zero({ "hw.nx", "CPU NX/XD", 10, Category::HardwareSecurity }, "Absent", "NX/XD not reported."));

    if (S.virt.vbsEnabled)
        rep.rules.push_back(Full({ "hw.vbs", "VBS enabled", 40, Category::HardwareSecurity },
                                 "Virtualization-Based Security is running."));
    else
        rep.rules.push_back(Zero({ "hw.vbs", "VBS enabled", 40, Category::HardwareSecurity },
                                 S.virt.deviceGuardAvailable ? "Disabled" : "Unknown",
                                 "VBS not detected as running."));

    if (S.virt.hvciEnabled)
        rep.rules.push_back(Full({ "hw.hvci", "HVCI enabled", 40, Category::HardwareSecurity },
                                 "Hypervisor-enforced Code Integrity is enabled."));
    else
        rep.rules.push_back(Zero({ "hw.hvci", "HVCI enabled", 40, Category::HardwareSecurity }, "Disabled",
                                 "HVCI is not enabled."));

    // ---- OS Security (max 170) ----
    rep.rules.push_back(O.build >= 22000
        ? Full({ "os.win11", "Windows 11 or newer", 30, Category::OsSecurity },
               "Running a modern Windows build.")
        : Partial({ "os.win11", "Windows 11 or newer", 30, Category::OsSecurity }, 10,
                  "Older", "Running an older Windows build."));

    if (S.uac.enabled)
        rep.rules.push_back(Full({ "os.uac", "UAC enabled", 30, Category::OsSecurity },
                                 "User Account Control is enabled."));
    else
        rep.rules.push_back(Zero({ "os.uac", "UAC enabled", 30, Category::OsSecurity }, "Disabled",
                                 "UAC is disabled."));

    if (S.dep.depEnabled == Tri::Yes)
        rep.rules.push_back(Full({ "os.dep", "DEP enabled", 20, Category::OsSecurity },
                                 "Data Execution Prevention is active."));
    else
        rep.rules.push_back(Zero({ "os.dep", "DEP enabled", 20, Category::OsSecurity }, "Disabled",
                                 "DEP is not enforced."));

    if (S.dep.sehopEnabled == Tri::Yes)
        rep.rules.push_back(Full({ "os.sehop", "SEHOP enabled", 15, Category::OsSecurity },
                                 "Structured Exception Handling Overwrite Protection is on."));
    else
        rep.rules.push_back(Zero({ "os.sehop", "SEHOP enabled", 15, Category::OsSecurity },
                                 S.dep.sehopEnabled == Tri::Unknown ? "Unknown" : "Disabled",
                                 "SEHOP is not enabled."));

    if (S.smartAppControlOn)
        rep.rules.push_back(Full({ "os.sac", "Smart App Control", 45, Category::OsSecurity },
                                 "Smart App Control is enforcing."));
    else
        rep.rules.push_back(Zero({ "os.sac", "Smart App Control", 45, Category::OsSecurity },
                                 S.smartAppControlEvaluation ? "Evaluation" : (S.smartAppControlState == Tri::No ? "Off" : "Unknown"),
                                 "Smart App Control not enforcing."));

    // Update recency based on UBR present (best-effort)
    rep.rules.push_back(O.ubr > 0
        ? Full({ "os.patch", "OS patch level readable", 30, Category::OsSecurity },
               "Build UBR indicates servicing stack data is present.")
        : Zero({ "os.patch", "OS patch level readable", 30, Category::OsSecurity }, "Unknown",
               "Could not determine servicing revision."));

    // ---- Malware Protection (max 200) ----
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
        score.maxPoints = 200;
        score.awardedPoints = enabled ? 200 : 0;
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
        const R rule{"mp.registered", "Registered antivirus protection", 200, Category::MalwareProtection};
        rep.rules.push_back(anyAvEnabled
            ? Full(rule, "At least one registered antivirus is enabled. Independent product scores are shown separately.")
            : Zero(rule, (anyAvUnknown || a.antivirus.status != Status::Success) ? "Unknown" : "Disabled",
                   "No registered antivirus could be confirmed enabled."));
    } else {
        if (D.installed && D.enabled)
            rep.rules.push_back(Full({ "mp.defender", "Defender installed & enabled", 40,
                                       Category::MalwareProtection },
                                     "Microsoft Defender is active."));
        else
            rep.rules.push_back(Zero({ "mp.defender", "Defender installed & enabled", 40, Category::MalwareProtection },
                                     D.installed ? "Disabled" : "Unavailable",
                                     "Defender could not be confirmed active."));

        if (D.realTimeProtection)
            rep.rules.push_back(Full({ "mp.rtp", "Real-time protection", 60, Category::MalwareProtection },
                                     "Real-time protection is enabled."));
        else
            rep.rules.push_back(Zero({ "mp.rtp", "Real-time protection", 60, Category::MalwareProtection }, "Disabled",
                                     "Real-time protection is off."));

        if (D.behaviorMonitor)
            rep.rules.push_back(Full({ "mp.bm", "Behavior monitoring", 20, Category::MalwareProtection },
                                     "Behavior monitoring enabled."));
        else
            rep.rules.push_back(Zero({ "mp.bm", "Behavior monitoring", 20, Category::MalwareProtection }, "Disabled",
                                     "Behavior monitoring not enabled."));

        if (D.ioav)
            rep.rules.push_back(Full({ "mp.ioav", "IOAV protection", 15, Category::MalwareProtection },
                                     "Downloaded-file scanning enabled."));
        else
            rep.rules.push_back(Zero({ "mp.ioav", "IOAV protection", 15, Category::MalwareProtection }, "Disabled",
                                     "IOAV scanning not enabled."));

        if (D.cloudProtection)
            rep.rules.push_back(Full({ "mp.cloud", "Cloud protection", 20, Category::MalwareProtection },
                                     "Cloud-delivered protection enabled."));
        else
            rep.rules.push_back(Zero({ "mp.cloud", "Cloud protection", 20, Category::MalwareProtection }, "Disabled",
                                     "Cloud-delivered protection not enabled."));

        if (D.tamperProtection)
            rep.rules.push_back(Full({ "mp.tamper", "Tamper protection", 20, Category::MalwareProtection },
                                     "Tamper protection is on."));
        else
            rep.rules.push_back(Zero({ "mp.tamper", "Tamper protection", 20, Category::MalwareProtection }, "Disabled",
                                     "Tamper protection off or unavailable."));

        if (D.installed && D.threatsKnown && D.threatsCount == 0)
            rep.rules.push_back(Full({ "mp.threats", "No active threats", 25, Category::MalwareProtection },
                                     "No active threats reported by Defender."));
        else
            rep.rules.push_back(Zero({ "mp.threats", "No active threats", 25, Category::MalwareProtection },
                                     (D.installed && D.threatsKnown) ? "ThreatsPresent" : "Unknown",
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
        rep.rules.push_back(Full({ "net.fw", "Firewall enabled on all profiles", 60,
                                   Category::NetworkSecurity },
                                 "Firewall enabled on Domain, Private, and Public profiles."));
    else if (anyEnabled)
        rep.rules.push_back(Partial({ "net.fw", "Firewall enabled on all profiles", 60, Category::NetworkSecurity },
                                    25, "Partial",
                                    "Firewall enabled on some but not all profiles."));
    else
        rep.rules.push_back(Zero({ "net.fw", "Firewall enabled on all profiles", 60, Category::NetworkSecurity }, "Disabled",
                                 "Firewall not enabled on any profile."));

    bool defInBlock = F.profiles.size() == 3;
    for (auto& p : F.profiles) if (p.defaultInbound != 0 || p.status != Status::Success) { defInBlock = false; break; }
    if (defInBlock && !F.profiles.empty())
        rep.rules.push_back(Full({ "net.in", "Inbound default block", 20, Category::NetworkSecurity },
                                 "All profiles default-block inbound traffic."));
    else
        rep.rules.push_back(Zero({ "net.in", "Inbound default block", 20, Category::NetworkSecurity }, "AllowOrUnknown",
                                 "Not all profiles default-block inbound."));

    if (F.serviceRunning)
        rep.rules.push_back(Full({ "net.svc", "Firewall service running", 20,
                                   Category::NetworkSecurity },
                                 "Windows Defender Firewall service is running."));
    else
        rep.rules.push_back(Zero({ "net.svc", "Firewall service running", 20, Category::NetworkSecurity }, "Stopped",
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
        rep.rules.push_back(Zero({ "enc.bl", "BitLocker on all fixed volumes", 100,
                                   Category::Encryption }, anyBitlockerUnknown ? "Unknown" : "NoVolumes",
                                 "No fixed volumes could be verified."));
    else if (allFixedOn)
        rep.rules.push_back(Full({ "enc.bl", "BitLocker on all fixed volumes", 100,
                                   Category::Encryption },
                                 "All fixed volumes are BitLocker-protected."));
    else if (anyBitlockerOn)
        rep.rules.push_back(Partial({ "enc.bl", "BitLocker on all fixed volumes", 100, Category::Encryption },
                                    50, "Partial",
                                    "BitLocker protection confirmed on some volumes; full coverage could not be verified."));
    else
        rep.rules.push_back(Zero({ "enc.bl", "BitLocker on all fixed volumes", 100, Category::Encryption },
                                 anyBitlockerUnknown ? "Unknown" : "Disabled",
                                 anyBitlockerUnknown
                                     ? "BitLocker status could not be read (needs elevation)."
                                     : "BitLocker not enabled on any fixed volume."));

    rep.rules.push_back(S.tpm.present
        ? Full({ "enc.tpm", "TPM protects keys", 75, Category::Encryption },
               "TPM available for key protection.")
        : Zero({ "enc.tpm", "TPM protects keys", 75, Category::Encryption }, "Absent",
               "No TPM available for key protection."));

    // ---- Account Security (max 100) ----
    if (S.uac.enabled && S.uac.consentPromptAdmin)
        rep.rules.push_back(Full({ "acc.uac2", "UAC prompts on elevation", 50,
                                   Category::AccountSecurity },
                                 "UAC prompts for admin consent."));
    else
        rep.rules.push_back(Zero({ "acc.uac2", "UAC prompts on elevation", 50, Category::AccountSecurity },
                                 S.uac.enabled ? "Weakened" : "Disabled",
                                 "UAC prompt not required for admin actions."));

    rep.rules.push_back(S.isElevated
        ? Full({ "acc.elev", "Process can read privileged data", 25,
                 Category::AccountSecurity },
               "Running elevated (improves assessment fidelity).")
        : Partial({ "acc.elev", "Process can read privileged data", 25, Category::AccountSecurity }, 0,
                  "NotElevated",
                  "Not running elevated; privileged checks may be unavailable."));

    if (S.windowsHelloAvailable)
        rep.rules.push_back(Full({ "acc.hello", "Windows Hello available", 25,
                                   Category::AccountSecurity },
                                 "Windows Hello infrastructure available."));
    else
        rep.rules.push_back(Zero({ "acc.hello", "Windows Hello available", 25, Category::AccountSecurity }, "Unknown",
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
        ? Zero({ "hyg.startup", "Startup items enumerated", 20, Category::SoftwareHygiene },
               "Unknown", "Startup inventory could not be completed.")
        : a.persistence.entries.empty()
        ? Full({ "hyg.startup", "Startup items enumerated", 20, Category::SoftwareHygiene },
               "No entries found in the configured startup locations.")
        : Full({ "hyg.startup", "Startup items enumerated", 20, Category::SoftwareHygiene },
               std::to_string(a.persistence.entries.size()) + " startup entries enumerated."));

    const bool inventoryComplete = !a.applications.empty() && std::all_of(
        a.applications.begin(), a.applications.end(), [](const ApplicationFinding& app) {
            return app.status == Status::Success || app.status == Status::NotFound;
        });
    rep.rules.push_back(inventoryComplete ? Full({ "hyg.appinv", "Application inventory complete", 20,
                               Category::SoftwareHygiene },
                             "Application presence determined for all configured apps.")
        : Zero({ "hyg.appinv", "Application inventory complete", 20, Category::SoftwareHygiene },
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
