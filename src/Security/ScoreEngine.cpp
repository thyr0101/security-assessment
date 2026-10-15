#include "ScoreEngine.h"
#include <algorithm>
#include <ranges>
#include <string_view>

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
struct WarningPolicy {
    std::string_view id;
    Severity severity;
    std::string_view recommendation;
};
void BuildWarnings(const AssessmentResult& assessment, ScoreReport& report) {
    constexpr WarningPolicy policies[] = {
        {"mp.threats", Severity::Critical, "Open Windows Security and review/remediate the reported active threats."},
        {"mp.registered", Severity::Critical, "Enable a trusted antivirus and verify its state in Windows Security."},
        {"mp.defender", Severity::Critical, "Verify that a trusted antivirus is actively protecting the device."},
        {"mp.rtp", Severity::High, "Enable real-time antivirus protection."},
        {"mp.tamper", Severity::High, "Enable tamper protection in Windows Security when supported."},
        {"net.fw", Severity::High, "Enable the firewall for every network profile."},
        {"net.in", Severity::High, "Use default inbound blocking and narrowly scoped allow rules."},
        {"net.svc", Severity::High, "Restore the Windows Firewall service and verify firewall operation."},
        {"net.smb1.server", Severity::High, "Disable the legacy SMB1 server after checking file-sharing compatibility."},
        {"net.smb1.client", Severity::High, "Remove or disable the legacy SMB1 client when no longer needed."},
        {"net.smb.sign.server", Severity::High, "Require signing for incoming SMB connections after checking compatibility."},
        {"net.smb.sign.client", Severity::High, "Require signing for outgoing SMB connections after checking compatibility."},
        {"net.smb.guest", Severity::High, "Use authenticated SMB access and block insecure guest logons."},
        {"net.rdp", Severity::High, "Require Network Level Authentication for RDP, or disable RDP when unused."},
        {"net.ntlm", Severity::High, "Use modern network sign-in responses and check compatibility with older devices."},
        {"enc.bl", Severity::High, "Review unprotected fixed volumes and enable BitLocker where appropriate; retain recovery keys."},
        {"os.uac", Severity::High, "Enable User Account Control."},
        {"os.lsa", Severity::High, "Enable protection for the Windows sign-in service and confirm that it is running in protected mode."},
        {"os.lmhash", Severity::High, "Disable old password-hash storage; this takes effect when existing account passwords change."},
        {"acc.guest", Severity::High, "Disable the built-in Guest account if it is not explicitly required."},
        {"acc.lockout", Severity::Medium, "Use a local account lockout threshold of 1-10 attempts with lockout/reset windows of at least 15 minutes."},
        {"acc.securedesktop", Severity::Medium, "Require UAC prompts on the secure desktop."},
        {"acc.assistance", Severity::Low, "Block solicited Remote Assistance invitations when the feature is unused."},
        {"os.autolock", Severity::Medium, "Review device and user locking policies; configure an inactivity limit of 15 minutes or less."},
        {"os.autoplay", Severity::Low, "Disable AutoPlay for all drive types through device policy."},
        {"hw.credentialguard", Severity::Medium, "Enable Credential Guard when supported by the Windows edition and hardware."},
        {"hw.hvci", Severity::Medium, "Enable Memory integrity if drivers and hardware support it."},
        {"os.sac", Severity::Medium, "Review Smart App Control in Windows Security; evaluation mode does not block apps."},
        {"wu.restart", Severity::Medium, "Restart Windows to finish applying updates."},
        {"wu.history", Severity::Medium, "Review Windows Update installation history and resolve the latest recorded failure."}
    };
    std::vector<std::string> unverified;
    for (const auto& rule : report.rules) {
        if (!rule.maxPoints || rule.awardedPoints >= rule.maxPoints) continue;
        const auto state = ToLower(Utf8ToWide(rule.state));
        bool verification = state.find(L"unknown") != std::wstring::npos || state == L"unavailable" ||
            state == L"version unverified" || state == L"dhcp controlled" || state == L"no fixed drives" ||
            (state == L"not configured" && rule.id != "acc.lockout" && rule.id != "os.autolock");
        if (rule.id == "net.ntlm" && (assessment.hardening.lmCompatibilityStatus != Status::Success ||
            assessment.hardening.lmCompatibility > 5)) verification = true;
        if (rule.id == "net.fw" && !std::ranges::any_of(assessment.firewall.profiles,
            [](const auto& profile) { return profile.status == Status::Success && !profile.enabled; })) verification = true;
        if (rule.id == "enc.bl" && !std::ranges::any_of(assessment.storage.volumes,
            [](const auto& volume) { return volume.driveType == L"Fixed" && volume.bitLockerStatus == Status::Success && volume.bitLockerState == L"Off"; })) verification = true;
        if (verification) { unverified.push_back(rule.description + " [" + rule.state + "]"); continue; }
        const auto policy = std::ranges::find(policies, rule.id, &WarningPolicy::id);
        SecurityWarning warning;
        warning.ruleId = rule.id;
        warning.title = rule.description;
        warning.detail = rule.state + ": " + rule.reason;
        warning.severity = policy == std::end(policies) ? Severity::Medium : policy->severity;
        warning.recommendation = policy == std::end(policies)
            ? "Review this setting in Windows Security or the applicable device policy."
            : std::string(policy->recommendation);
        report.warnings.push_back(std::move(warning));
    }
    if (!unverified.empty()) {
        SecurityWarning coverage;
        coverage.ruleId = "assessment.coverage";
        coverage.severity = Severity::Low;
        coverage.title = "Some security checks could not be verified";
        coverage.verificationOnly = true;
        for (const auto& check : unverified) {
            if (!coverage.detail.empty()) coverage.detail += "; ";
            coverage.detail += check;
        }
        coverage.recommendation = assessment.security.isElevated
            ? "Review missing policies, provider support, and access permissions. Unverified checks are not confirmed vulnerabilities."
            : "Run as administrator to verify restricted checks. Missing policies or unsupported features can remain unknown; they are not confirmed vulnerabilities.";
        report.warnings.push_back(std::move(coverage));
    }
    std::ranges::stable_sort(report.warnings, std::greater{}, &SecurityWarning::severity);
}
} // namespace

ScoreReport ComputeScore(const AssessmentResult& a) {
    ScoreReport rep;
    rep.maximum = 1000;
    rep.rules.reserve(64);

    auto& S = a.security;
    auto& D = a.defender;
    auto& F = a.firewall;
    auto& O = a.os;

    // ---- Hardware Security (max 150) ----
    rep.rules.push_back(S.secureBoot.enabled == Tri::Yes
        ? Full({ "hw.secureboot", "Secure Boot", 40, Category::HardwareSecurity },
               "Secure Boot is enabled and UEFI is the firmware.")
        : Zero({ "hw.secureboot", "Secure Boot", 40, Category::HardwareSecurity },
               S.secureBoot.enabled == Tri::No ? "Disabled" : "Unknown",
               "Secure Boot is not enabled or could not be verified."));

    if (S.tpm.present && S.tpm.ready) {
        const bool v2 = Trim(S.tpm.specVersion.substr(0, S.tpm.specVersion.find(L','))) == L"2.0";
        rep.rules.push_back(v2
            ? Full({ "hw.tpm2", "Security chip ready (TPM 2.0)", 30, Category::HardwareSecurity }, "TPM 2.0 is present and ready.", "Ready")
            : Partial({ "hw.tpm2", "Security chip ready (TPM 2.0)", 30, Category::HardwareSecurity }, 15,
                      "Version unverified", "TPM is ready, but version 2.0 could not be confirmed."));
    } else if (S.tpm.present) {
        rep.rules.push_back(Partial({ "hw.tpm2", "Security chip ready (TPM 2.0)", 30, Category::HardwareSecurity },
                                    15, S.tpm.readinessKnown ? "Not ready" : "Readiness unknown",
                                    "TPM presence is confirmed; readiness is not confirmed."));
    } else {
        rep.rules.push_back(Zero({ "hw.tpm2", "Security chip ready (TPM 2.0)", 30, Category::HardwareSecurity },
                                 S.tpm.status == Status::Unavailable ? "Unavailable" : "Absent",
                                 "No usable TPM detected."));
    }

    if (S.virt.vbsEnabled)
        rep.rules.push_back(Full({ "hw.vbs", "Security features isolated from Windows", 30, Category::HardwareSecurity },
                                 "Windows uses virtualization to isolate security functions.", "Running"));
    else
        rep.rules.push_back(Zero({ "hw.vbs", "Security features isolated from Windows", 30, Category::HardwareSecurity },
                                 (S.virt.status == Status::Success) ? "Not running" : "Unknown",
                                 "VBS not detected as running."));

    if (S.virt.hvciEnabled)
        rep.rules.push_back(Full({ "hw.hvci", "Memory integrity protection", 30, Category::HardwareSecurity },
                                 "Memory integrity protects Windows kernel code using virtualization.", "Running"));
    else
        rep.rules.push_back(Zero({ "hw.hvci", "Memory integrity protection", 30, Category::HardwareSecurity }, "Disabled",
                                 "HVCI is not enabled."));

    // ---- OS Security (max 200) ----
    rep.rules.push_back(O.build >= 22000
        ? Full({ "os.win11", "Windows 11 or newer", 10, Category::OsSecurity },
               "The installed operating system is Windows 11 or newer.", "Detected")
        : Partial({ "os.win11", "Windows 11 or newer", 10, Category::OsSecurity }, 0,
                  "Older Windows", "The installed Windows version is older than Windows 11."));

    if (S.uac.enabled)
        rep.rules.push_back(Full({ "os.uac", "User Account Control (UAC)", 20, Category::OsSecurity },
                                 "User Account Control is enabled."));
    else
        rep.rules.push_back(Zero({ "os.uac", "User Account Control (UAC)", 20, Category::OsSecurity }, "Disabled",
                                 "UAC is disabled."));

    if (S.dep.depEnabled == Tri::Yes)
        rep.rules.push_back(Full({ "os.dep", "Code execution blocked in data memory", 20, Category::OsSecurity },
                                 "Data Execution Prevention is active."));
    else
        rep.rules.push_back(Zero({ "os.dep", "Code execution blocked in data memory", 20, Category::OsSecurity }, "Disabled",
                                 "DEP is not enforced."));

    if (S.dep.sehopEnabled == Tri::Yes)
        rep.rules.push_back(Full({ "os.sehop", "Protection against memory overwrite attacks", 15, Category::OsSecurity },
                                 "Windows protects exception handling data against memory overwrite attacks."));
    else
        rep.rules.push_back(Zero({ "os.sehop", "Protection against memory overwrite attacks", 15, Category::OsSecurity },
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

    // ---- Windows Update (max 60; pending updates are informational) ----
    const auto& U = a.windowsUpdate;
    for (const auto& [name, label] : {std::pair{L"wuauserv", "Windows Update service available"},
             std::pair{L"BITS", "Update download service available"},
             std::pair{L"UsoSvc", "Update scheduling service available"}}) {
        const auto found = std::find_if(U.services.entries.begin(), U.services.entries.end(),
            [&](const ServiceEntry& service) { return IEquals(service.name, name); });
        const std::string id = "wu.service." + WideToUtf8(name);
        const R rule{id.c_str(), label, 10, Category::WindowsUpdate};
        if (found == U.services.entries.end() || found->status != Status::Success)
            rep.rules.push_back(Zero(rule, found != U.services.entries.end() && found->status == Status::NotFound
                ? "Missing" : "Unknown", "The update service's state and configuration could not be verified."));
        else if (found->startType == L"Disabled")
            rep.rules.push_back(Zero(rule, "Disabled", "The update service is disabled."));
        else if (found->state == L"Paused" || found->state == L"StopPending")
            rep.rules.push_back(Zero(rule, "Not ready", "The update service is paused or stopping."));
        else if ((found->startType == L"Auto" || found->startType == L"Manual") &&
            (found->state == L"Running" || found->state == L"Stopped" || found->state == L"StartPending"))
            rep.rules.push_back(Full(rule, "The service is enabled. Windows update services can stop when idle and start on demand.",
                found->state == L"Running" ? "Running" : "Available on demand"));
        else rep.rules.push_back(Zero(rule, "Unknown", "The update service configuration could not be interpreted."));
    }
    const R restart{"wu.restart", "Update restart completed", 15, Category::WindowsUpdate};
    rep.rules.push_back(U.rebootRequired == Tri::No
        ? Full(restart, "Windows Update does not require a restart.", "Complete")
        : Zero(restart, U.rebootRequired == Tri::Yes ? "Restart required" : "Unknown",
            U.rebootRequired == Tri::Yes ? "Restart Windows to finish applying updates." : "Update restart status could not be read."));
    const R history{"wu.history", "Latest update installation", 15, Category::WindowsUpdate};
    rep.rules.push_back(U.historyStatus == Status::Success && U.lastInstallationSucceeded == Tri::Yes
        ? Full(history, "The latest recorded update installation succeeded.", "Succeeded")
        : Zero(history, U.historyStatus == Status::Success && U.lastInstallationSucceeded == Tri::No
            ? "Needs attention" : "Unknown", "The latest installation failed, was incomplete, or its result could not be verified."));

    // ---- Malware Protection (max 180) ----
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
            rep.rules.push_back(Full({ "mp.rtp", "Real-time protection", 45, Category::MalwareProtection },
                                     "Real-time protection is enabled."));
        else
            rep.rules.push_back(Zero({ "mp.rtp", "Real-time protection", 45, Category::MalwareProtection }, "Disabled",
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

    // ---- Network Security (max 200) ----
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

    const auto& N = a.network;
    auto settingRule = [&](const char* id, const char* label, const NetworkSetting& setting,
                           bool required, const char* pass, const char* fail, const char* explanation) {
        const R rule{id, label, 10, Category::NetworkSecurity};
        const bool known = setting.status == Status::Success &&
            (setting.enabled == Tri::Yes || setting.enabled == Tri::No);
        const bool satisfied = known && setting.enabled == (required ? Tri::Yes : Tri::No);
        rep.rules.push_back(satisfied ? Full(rule, explanation, pass)
            : Zero(rule, known ? fail : setting.status == Status::NotFound ? "Not configured" : "Unknown",
                known ? explanation : "The required configuration could not be verified; no default is assumed."));
    };
    settingRule("net.smb1.server", "Old file-sharing server disabled (SMB1)", N.smb1Server, false, "Disabled", "Enabled",
        "SMB1 server configuration; disabling this legacy protocol reduces file-sharing attack surface.");
    settingRule("net.smb1.client", "Old file-sharing client disabled (SMB1)", N.smb1Client, false, "Disabled", "Available",
        "SMB1 client driver availability; an absent or disabled redirector cannot be used for legacy SMB1 connections.");
    settingRule("net.smb.sign.server", "Incoming file-sharing integrity checks", N.smbServerSigning, true, "Required", "Not required",
        "Requiring SMB server signing protects the integrity of incoming file-sharing traffic.");
    settingRule("net.smb.sign.client", "Outgoing file-sharing integrity checks", N.smbClientSigning, true, "Required", "Not required",
        "Requiring SMB client signing protects the integrity of outgoing file-sharing traffic.");
    settingRule("net.smb.guest", "Outgoing file sharing requires sign-in", N.smbGuestLogons, false, "Blocked", "Allowed",
        "Insecure guest logons bypass normal SMB authentication.");
    settingRule("net.llmnr", "Local name-lookup fallback disabled", N.llmnr, false, "Disabled", "Allowed",
        "Disabling multicast name-resolution fallback reduces local name-spoofing opportunities.");
    bool haveAdapter = false, netbiosUnknown = N.status != Status::Success;
    bool netbiosEnabled = false, netbiosDhcp = false;
    for (const auto& adapter : N.adapters) {
        haveAdapter = true;
        if (adapter.netbiosStatus != Status::Success || adapter.netbiosOptions > 2) netbiosUnknown = true;
        else if (adapter.netbiosOptions == 1) netbiosEnabled = true;
        else if (adapter.netbiosOptions == 0) netbiosDhcp = true;
    }
    const R netbios{"net.netbios", "Old network discovery disabled", 10, Category::NetworkSecurity};
    rep.rules.push_back(netbiosUnknown ? Zero(netbios, "Unknown", "Not every applicable adapter's NetBIOS configuration could be read.")
        : netbiosEnabled ? Zero(netbios, "Enabled", "At least one active IPv4 adapter explicitly enables NetBIOS.")
        : netbiosDhcp ? Zero(netbios, "DHCP controlled", "DHCP-controlled settings do not prove NetBIOS is disabled.")
        : Full(netbios, haveAdapter ? "NetBIOS is explicitly disabled on every active IPv4 adapter."
            : "No active non-loopback IPv4 adapters require this check.", haveAdapter ? "Disabled" : "Not applicable"));
    const R rdp{"net.rdp", "RDP disabled or authentication required", 10, Category::NetworkSecurity};
    const bool rdpKnown = N.rdp.status == Status::Success && (N.rdp.enabled == Tri::Yes || N.rdp.enabled == Tri::No);
    const bool nlaKnown = N.rdpNla.status == Status::Success && (N.rdpNla.enabled == Tri::Yes || N.rdpNla.enabled == Tri::No);
    rep.rules.push_back(rdpKnown && N.rdp.enabled == Tri::No
        ? Full(rdp, "Remote Desktop connections are disabled by configuration.", "RDP disabled")
        : rdpKnown && nlaKnown && N.rdpNla.enabled == Tri::Yes
        ? Full(rdp, "Remote Desktop is configured to require Network Level Authentication; firewall scope is a separate control.", "NLA required")
        : Zero(rdp, rdpKnown && nlaKnown ? "NLA not required" : "Unknown",
            "Enabled Remote Desktop must require Network Level Authentication to receive these points."));

    // ---- Encryption (max 90) ----
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
        rep.rules.push_back(Zero({ "enc.bl", "BitLocker on all fixed drives", 50,
                                   Category::Encryption }, anyBitlockerUnknown ? "Unknown" : "No fixed drives",
                                 "No fixed volumes could be verified."));
    else if (allFixedOn)
        rep.rules.push_back(Full({ "enc.bl", "BitLocker on all fixed drives", 50,
                                   Category::Encryption },
                                 "All detected fixed drives have BitLocker protection active.", "Protected"));
    else if (anyBitlockerOn)
        rep.rules.push_back(Partial({ "enc.bl", "BitLocker on all fixed drives", 50, Category::Encryption },
                                    25, "Some drives protected",
                                    "BitLocker protection confirmed on some volumes; full coverage could not be verified."));
    else
        rep.rules.push_back(Zero({ "enc.bl", "BitLocker on all fixed drives", 50, Category::Encryption },
                                 anyBitlockerUnknown ? "Unknown" : "Disabled",
                                 anyBitlockerUnknown
                                     ? "BitLocker status could not be read (needs elevation)."
                                     : "BitLocker not enabled on any fixed volume."));

    rep.rules.push_back(S.tpm.present
        ? Full({ "enc.tpm", "TPM available to protect keys", 40, Category::Encryption },
               "A TPM security chip is available to store and protect encryption keys.", "Available")
        : Zero({ "enc.tpm", "TPM available to protect keys", 40, Category::Encryption }, "Absent",
               "No TPM available for key protection."));

    // ---- Account Security (max 120) ----
    if (S.uac.enabled && S.uac.consentPromptAdmin)
        rep.rules.push_back(Full({ "acc.uac2", "Admin actions require a UAC prompt", 20,
                                   Category::AccountSecurity },
                                 "Administrator actions require a UAC consent or credentials prompt.", "Required"));
    else
        rep.rules.push_back(Zero({ "acc.uac2", "Admin actions require a UAC prompt", 20, Category::AccountSecurity },
                                 "Not required",
                                 "UAC prompt not required for admin actions."));

    const auto& H = a.hardening;
    auto protection = [&](const char* id, const char* label, int points, Category category,
                          const SecuritySetting& value, const char* success, const char* failure,
                          const char* reason) {
        const R rule{id, label, points, category};
        const bool known = value.status == Status::Success && (value.enabled == Tri::Yes || value.enabled == Tri::No);
        rep.rules.push_back(known && value.enabled == Tri::Yes ? Full(rule, reason, success)
            : Zero(rule, known ? failure : value.status == Status::NotFound ? "Not configured" : "Unknown", reason));
    };
    SecuritySetting guard;
    guard.status = S.virt.status == Status::Success && S.virt.runningServicesKnown ? Status::Success : Status::Unavailable;
    if (guard.status == Status::Success) guard.enabled = S.virt.credentialGuardRunning ? Tri::Yes : Tri::No;
    protection("hw.credentialguard", "Sign-in secrets isolated (Credential Guard)", 20, Category::HardwareSecurity, guard,
        "Running", "Not running", "Credential Guard isolates sign-in secrets using virtualization.");
    protection("os.lsa", "Sign-in service protected from tampering", 25, Category::OsSecurity, H.lsaProtection,
        "Protected", "Unprotected", "Reports the running LSASS process protection level, not merely a registry configuration.");
    protection("os.lmhash", "Old password storage disabled", 20, Category::OsSecurity, H.noLmHash,
        "Blocked", "Allowed", "NoLMHash prevents LM hashes being stored at the next password change; it does not prove older hashes were removed.");
    protection("os.autoplay", "AutoPlay off on all drive types", 20, Category::OsSecurity, H.autoPlayDisabled,
        "Blocked", "Not blocked", "The device AutoPlay policy must cover all drive types.");
    const R lock{"os.autolock", "Automatic device lock within 15 minutes", 20, Category::OsSecurity};
    rep.rules.push_back(H.inactivityStatus == Status::Success && H.inactivitySeconds > 0 && H.inactivitySeconds <= 900
        ? Full(lock, "An explicit device inactivity policy locks sessions within 15 minutes.", "Configured")
        : Zero(lock, H.inactivityStatus == Status::Success ? (H.inactivitySeconds ? "Long timeout" : "Not configured") : "Unknown",
            "Checks the device inactivity policy; user screen-saver policies can impose additional locking."));
    const R ntlm{"net.ntlm", "Modern network sign-in protection", 20, Category::NetworkSecurity};
    rep.rules.push_back(H.lmCompatibilityStatus == Status::Success && H.lmCompatibility >= 3 && H.lmCompatibility <= 5
        ? Full(ntlm, WideToUtf8(NetworkSignInReason(H)), WideToUtf8(NetworkSignInState(H)))
        : Zero(ntlm, WideToUtf8(NetworkSignInState(H)), WideToUtf8(NetworkSignInReason(H))));
    SecuritySetting desktop;
    desktop.status = S.uac.status;
    if (desktop.status == Status::Success && S.uac.promptOnSecureDesktop <= 1)
        desktop.enabled = S.uac.enabled && S.uac.promptOnSecureDesktop == 1 ? Tri::Yes : Tri::No;
    protection("acc.securedesktop", "UAC prompts use the secure desktop", 25, Category::AccountSecurity, desktop,
        "Required", "Not required", "UAC prompts should run on the isolated secure desktop.");
    protection("acc.guest", "Built-in Guest account disabled", 30, Category::AccountSecurity, H.guestDisabled,
        "Disabled", "Enabled", "Identifies the built-in Guest account by RID 501, even if it was renamed.");
    protection("acc.assistance", "Remote Assistance invitations blocked", 20, Category::AccountSecurity, H.remoteAssistanceDisabled,
        "Blocked", "Allowed", "Checks policy/local permission for solicited Remote Assistance invitations, not third-party remote support tools.");
    const R lockout{"acc.lockout", "Local account lockout protection", 25, Category::AccountSecurity};
    const bool threshold = H.lockoutThreshold > 0 && H.lockoutThreshold <= 10;
    const bool duration = H.lockoutDuration >= 900 && H.lockoutWindow >= 900;
    rep.rules.push_back(H.lockoutStatus != Status::Success ? Zero(lockout, "Unknown", "Local SAM lockout policy could not be read.")
        : threshold && duration ? Full(lockout, "Local accounts lock after 1-10 failed attempts, with a lockout and reset window of at least 15 minutes.", "Configured")
        : threshold ? Partial(lockout, 12, "Short lockout", "The local lockout duration or reset window is shorter than 15 minutes.")
        : Zero(lockout, H.lockoutThreshold ? "High threshold" : "Not configured", "The local account lockout threshold is absent or exceeds 10 failed attempts."));

    // ---- Hardening / Software Hygiene (informational) ----
    rep.rules.push_back(a.persistence.status == Status::Success
        ? Full({"hyg.startup", "Startup locations readable", 0, Category::SoftwareHygiene},
            "The selected startup locations are readable.", "Available")
        : Zero({"hyg.startup", "Startup locations readable", 0, Category::SoftwareHygiene},
            "Unknown", "The selected startup locations could not all be checked."));

    // Failed collection must not become a definite disabled/absent state or earn points.
    for (auto& rule : rep.rules) {
        bool unknown = false;
        if (rule.id.starts_with("mp.") && rule.id != "mp.registered") unknown = D.status != Status::Success;
        else if (rule.id.starts_with("os.win")) unknown = O.status != Status::Success;
        else if (rule.id == "os.uac" || rule.id == "acc.uac2") unknown = S.uac.status != Status::Success;
        else if (rule.id == "hw.tpm2" || rule.id == "enc.tpm")
            unknown = S.tpm.status != Status::Success && S.tpm.status != Status::NotFound;
        else if (rule.id == "hw.vbs") unknown = S.virt.status != Status::Success;
        else if (rule.id == "hw.hvci") unknown = S.virt.status != Status::Success || !S.virt.runningServicesKnown;
        else if (rule.id == "hw.secureboot") unknown = S.secureBoot.status != Status::Success;
        else if (rule.id == "os.dep") unknown = S.dep.depEnabled == Tri::Unknown;
        else if (rule.id == "net.fw") unknown = F.status != Status::Success && !anyEnabled;
        else if (rule.id == "net.in") unknown = F.status != Status::Success;
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
    BuildWarnings(a, rep);
    return rep;
}

} // namespace sa
