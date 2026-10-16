#include "ScoreEngine.h"
#include "../Warnings.h"
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
} // namespace

ScoreReport ComputeScore(const AssessmentResult& a, bool includeWarnings) {
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
               warnings::contextSecureBootIsEnabledAndUEFIIs)
        : Zero({ "hw.secureboot", "Secure Boot", 40, Category::HardwareSecurity },
               S.secureBoot.enabled == Tri::No ? "Disabled" : "Unknown",
               warnings::contextSecureBootIsNotEnabledOrCould));

    if (S.tpm.present && S.tpm.ready) {
        const bool v2 = Trim(S.tpm.specVersion.substr(0, S.tpm.specVersion.find(L','))) == L"2.0";
        rep.rules.push_back(v2
            ? Full({ "hw.tpm2", "Security chip ready (TPM 2.0)", 30, Category::HardwareSecurity }, warnings::contextTPM20IsPresentAndReady, "Ready")
            : Partial({ "hw.tpm2", "Security chip ready (TPM 2.0)", 30, Category::HardwareSecurity }, 15,
                      "Version unverified", warnings::contextTPMIsReadyButVersion20));
    } else if (S.tpm.present) {
        rep.rules.push_back(Partial({ "hw.tpm2", "Security chip ready (TPM 2.0)", 30, Category::HardwareSecurity },
                                    15, S.tpm.readinessKnown ? "Not ready" : "Readiness unknown",
                                    warnings::contextTPMPresenceIsConfirmedReadinessIsNot));
    } else {
        rep.rules.push_back(Zero({ "hw.tpm2", "Security chip ready (TPM 2.0)", 30, Category::HardwareSecurity },
                                 S.tpm.status == Status::Unavailable ? "Unavailable" : "Absent",
                                 warnings::contextNoUsableTPMDetected));
    }

    if (S.virt.vbsEnabled)
        rep.rules.push_back(Full({ "hw.vbs", "Security features isolated from Windows", 30, Category::HardwareSecurity },
                                 warnings::contextWindowsUsesVirtualizationToIsolateSecurityFunctions, "Running"));
    else
        rep.rules.push_back(Zero({ "hw.vbs", "Security features isolated from Windows", 30, Category::HardwareSecurity },
                                 (S.virt.status == Status::Success) ? "Not running" : "Unknown",
                                 warnings::contextVBSNotDetectedAsRunning));

    if (S.virt.hvciEnabled)
        rep.rules.push_back(Full({ "hw.hvci", "Memory integrity protection", 30, Category::HardwareSecurity },
                                 warnings::contextMemoryIntegrityProtectsWindowsKernelCodeUsing, "Running"));
    else
        rep.rules.push_back(Zero({ "hw.hvci", "Memory integrity protection", 30, Category::HardwareSecurity }, "Disabled",
                                 warnings::contextHVCIIsNotEnabled));

    // ---- OS Security (max 200) ----
    rep.rules.push_back(O.build >= 22000
        ? Full({ "os.win11", "Windows 11 or newer", 10, Category::OsSecurity },
               warnings::contextTheInstalledOperatingSystemIsWindows11, "Detected")
        : Partial({ "os.win11", "Windows 11 or newer", 10, Category::OsSecurity }, 0,
                  "Older Windows", warnings::contextTheInstalledWindowsVersionIsOlderThan));

    if (S.uac.enabled)
        rep.rules.push_back(Full({ "os.uac", "User Account Control (UAC)", 20, Category::OsSecurity },
                                 warnings::contextUserAccountControlIsEnabled));
    else
        rep.rules.push_back(Zero({ "os.uac", "User Account Control (UAC)", 20, Category::OsSecurity }, "Disabled",
                                 warnings::contextUACIsDisabled));

    if (S.dep.depEnabled == Tri::Yes)
        rep.rules.push_back(Full({ "os.dep", "Code execution blocked in data memory", 20, Category::OsSecurity },
                                 warnings::contextDataExecutionPreventionIsActive));
    else
        rep.rules.push_back(Zero({ "os.dep", "Code execution blocked in data memory", 20, Category::OsSecurity }, "Disabled",
                                 warnings::contextDEPIsNotEnforced));

    if (S.dep.sehopEnabled == Tri::Yes)
        rep.rules.push_back(Full({ "os.sehop", "Protection against memory overwrite attacks", 15, Category::OsSecurity },
                                 warnings::contextWindowsProtectsExceptionHandlingDataAgainstMemory));
    else
        rep.rules.push_back(Zero({ "os.sehop", "Protection against memory overwrite attacks", 15, Category::OsSecurity },
                                 S.dep.sehopEnabled == Tri::Unknown ? "Unknown" : "Disabled",
                                 warnings::contextSEHOPIsNotEnabled));

    if (S.smartAppControlOn)
        rep.rules.push_back(Full({ "os.sac", "Smart App Control", 50, Category::OsSecurity },
                                 warnings::contextSmartAppControlIsEnforcing));
    else if (S.smartAppControlEvaluation)
        rep.rules.push_back(Partial({ "os.sac", "Smart App Control", 50, Category::OsSecurity },
                                    25, "Evaluation",
                                    warnings::contextSmartAppControlIsEvaluatingApplicationsWithout));
    else
        rep.rules.push_back(Zero({ "os.sac", "Smart App Control", 50, Category::OsSecurity },
                                 S.smartAppControlState == Tri::No ? "Off" : "Unknown",
                                 warnings::contextSmartAppControlNotEnforcing));

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
                ? "Missing" : "Unknown", warnings::contextTheUpdateServiceSStateAndConfiguration));
        else if (found->startType == L"Disabled")
            rep.rules.push_back(Zero(rule, "Disabled", warnings::contextTheUpdateServiceIsDisabled));
        else if (found->state == L"Paused" || found->state == L"StopPending")
            rep.rules.push_back(Zero(rule, "Not ready", warnings::contextTheUpdateServiceIsPausedOrStopping));
        else if ((found->startType == L"Auto" || found->startType == L"Manual") &&
            (found->state == L"Running" || found->state == L"Stopped" || found->state == L"StartPending"))
            rep.rules.push_back(Full(rule, warnings::contextTheServiceIsEnabledWindowsUpdateServices,
                found->state == L"Running" ? "Running" : "Available on demand"));
        else rep.rules.push_back(Zero(rule, "Unknown", warnings::contextTheUpdateServiceConfigurationCouldNotBe));
    }
    const R restart{"wu.restart", "Update restart completed", 15, Category::WindowsUpdate};
    rep.rules.push_back(U.rebootRequired == Tri::No
        ? Full(restart, warnings::contextWindowsUpdateDoesNotRequireARestart, "Complete")
        : Zero(restart, U.rebootRequired == Tri::Yes ? "Restart required" : "Unknown",
            U.rebootRequired == Tri::Yes ? warnings::contextRestartWindowsToFinishApplyingUpdates : warnings::contextUpdateRestartStatusCouldNotBeRead));
    const R history{"wu.history", "Latest update installation", 15, Category::WindowsUpdate};
    rep.rules.push_back(U.historyStatus == Status::Success && U.lastInstallationSucceeded == Tri::Yes
        ? Full(history, warnings::contextTheLatestRecordedUpdateInstallationSucceeded, "Succeeded")
        : Zero(history, U.historyStatus == Status::Success && U.lastInstallationSucceeded == Tri::No
            ? "Needs attention" : "Unknown", warnings::contextTheLatestInstallationFailedWasIncompleteOr));

    // ---- Malware Protection (max 180) ----
    const bool thirdParty = HasThirdPartyAntivirus(a.antivirus);
    bool anyAvEnabled = false, anyAvUnknown = false;
    for (size_t i = 0; i < a.antivirus.products.size(); ++i) {
        const auto& av = a.antivirus.products[i];
        const bool enabled = av.status == Status::Success && av.state == AntivirusState::Enabled;
        const bool known = av.status == Status::Success && av.state != AntivirusState::Unknown;
        const bool excludedDefender = thirdParty && av.isDefender;
        if (!excludedDefender) { anyAvEnabled |= enabled; anyAvUnknown |= !known; }
        ScoreRuleResult score;
        score.id = "av." + (av.id.empty() ? std::to_string(i) : WideToUtf8(av.id));
        score.description = WideToUtf8(av.name);
        score.maxPoints = excludedDefender ? 0 : kMalwareProtectionMaxPoints;
        score.awardedPoints = !excludedDefender && enabled ? kMalwareProtectionMaxPoints : 0;
        score.category = WideToUtf8(ToW(Category::MalwareProtection));
        score.state = excludedDefender ? "Not applicable" : known ? WideToUtf8(ToW(av.state)) : "Unknown";
        score.reason = excludedDefender ? warnings::contextDefenderIsNotScoredWhileAThird : enabled ? warnings::contextWindowsSecurityCenterReportsThisAntivirusEnabled
            : known ? warnings::contextWindowsSecurityCenterDoesNotReportThis
            : warnings::contextWindowsSecurityCenterCouldNotReportThis;
        rep.antivirusScores.push_back(std::move(score));
    }
    rep.registeredAntivirusScoring = HasThirdPartyAntivirus(a.antivirus) ||
        (!a.antivirus.products.empty() && (D.status != Status::Success || !D.enabled));
    if (rep.registeredAntivirusScoring) {
        const R rule{"mp.registered", "Registered antivirus protection", kMalwareProtectionMaxPoints, Category::MalwareProtection};
        rep.rules.push_back(anyAvEnabled
            ? Full(rule, warnings::contextAtLeastOneRegisteredAntivirusIsEnabled)
            : Zero(rule, (anyAvUnknown || a.antivirus.status != Status::Success) ? "Unknown" : "Disabled",
                   warnings::contextNoRegisteredAntivirusCouldBeConfirmedEnabled));
    } else {
        if (D.installed && D.enabled)
            rep.rules.push_back(Full({ "mp.defender", "Microsoft Defender antivirus", 40,
                                       Category::MalwareProtection },
                                     warnings::contextMicrosoftDefenderIsActive, "Active"));
        else
            rep.rules.push_back(Zero({ "mp.defender", "Microsoft Defender antivirus", 40, Category::MalwareProtection },
                                     D.installed ? "Inactive" : "Unavailable",
                                     warnings::contextDefenderCouldNotBeConfirmedActive));

        if (D.realTimeProtection)
            rep.rules.push_back(Full({ "mp.rtp", "Real-time protection", 45, Category::MalwareProtection },
                                     warnings::contextRealTimeProtectionIsEnabled));
        else
            rep.rules.push_back(Zero({ "mp.rtp", "Real-time protection", 45, Category::MalwareProtection }, "Disabled",
                                     warnings::contextRealTimeProtectionIsOff));

        if (D.behaviorMonitor)
            rep.rules.push_back(Full({ "mp.bm", "Suspicious behavior monitoring", 20, Category::MalwareProtection },
                                     warnings::contextBehaviorMonitoringEnabled));
        else
            rep.rules.push_back(Zero({ "mp.bm", "Suspicious behavior monitoring", 20, Category::MalwareProtection }, "Disabled",
                                     warnings::contextBehaviorMonitoringNotEnabled));

        if (D.ioav)
            rep.rules.push_back(Full({ "mp.ioav", "Downloaded file scanning", 15, Category::MalwareProtection },
                                     warnings::contextDownloadedFileScanningEnabled));
        else
            rep.rules.push_back(Zero({ "mp.ioav", "Downloaded file scanning", 15, Category::MalwareProtection }, "Disabled",
                                     warnings::contextIOAVScanningNotEnabled));

        if (D.cloudProtection)
            rep.rules.push_back(Full({ "mp.cloud", "Cloud malware detection", 20, Category::MalwareProtection },
                                     warnings::contextCloudDeliveredProtectionEnabled));
        else
            rep.rules.push_back(Zero({ "mp.cloud", "Cloud malware detection", 20, Category::MalwareProtection }, "Disabled",
                                     warnings::contextCloudDeliveredProtectionNotEnabled));

        if (D.tamperProtection)
            rep.rules.push_back(Full({ "mp.tamper", "Antivirus settings protection", 20, Category::MalwareProtection },
                                     warnings::contextDefenderProtectsItsSecuritySettingsAgainstUnauthorized));
        else
            rep.rules.push_back(Zero({ "mp.tamper", "Antivirus settings protection", 20, Category::MalwareProtection }, "Disabled",
                                     warnings::contextDefenderSettingsProtectionIsDisabledOrUnavailable));

        if (D.installed && D.threatsKnown && D.threatsCount == 0)
            rep.rules.push_back(Full({ "mp.threats", "Defender reports no active threats", 20, Category::MalwareProtection },
                                     warnings::contextNoActiveThreatsReportedByDefender, "Clear"));
        else
            rep.rules.push_back(Zero({ "mp.threats", "Defender reports no active threats", 20, Category::MalwareProtection },
                                     (D.installed && D.threatsKnown) ? "Threats found" : "Unknown",
                                     (D.installed && D.threatsKnown)
                                         ? warnings::contextActiveThreatsReportedByDefender
                                         : warnings::contextThreatStatusCouldNotBeRead));
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
                                 warnings::contextFirewallEnabledOnDomainPrivateAndPublic));
    else if (anyEnabled)
        rep.rules.push_back(Partial({ "net.fw", "Firewall on all network profiles", 60, Category::NetworkSecurity },
                                    25, "Partial",
                                    warnings::contextFirewallEnabledOnSomeButNotAll));
    else
        rep.rules.push_back(Zero({ "net.fw", "Firewall on all network profiles", 60, Category::NetworkSecurity }, "Disabled",
                                 warnings::contextFirewallNotEnabledOnAnyProfile));

    bool defInBlock = F.profiles.size() == 3;
    for (auto& p : F.profiles) if (p.defaultInbound != 0 || p.status != Status::Success) { defInBlock = false; break; }
    if (defInBlock && !F.profiles.empty())
        rep.rules.push_back(Full({ "net.in", "Block incoming traffic by default", 20, Category::NetworkSecurity },
                                 warnings::contextIncomingTrafficIsBlockedByDefaultUnless, "Blocking"));
    else
        rep.rules.push_back(Zero({ "net.in", "Block incoming traffic by default", 20, Category::NetworkSecurity }, "Allowing or unknown",
                                 warnings::contextNotAllProfilesDefaultBlockInbound));

    if (F.serviceRunning)
        rep.rules.push_back(Full({ "net.svc", "Windows Firewall service", 20,
                                   Category::NetworkSecurity },
                                 warnings::contextTheWindowsFirewallServiceIsRunning, "Running"));
    else
        rep.rules.push_back(Zero({ "net.svc", "Windows Firewall service", 20, Category::NetworkSecurity }, "Stopped",
                                 warnings::contextFirewallServiceNotRunning));

    const auto& N = a.network;
    auto settingRule = [&](const char* id, const char* label, const NetworkSetting& setting,
                           bool required, const char* pass, const char* fail, const char* explanation) {
        const R rule{id, label, 10, Category::NetworkSecurity};
        const bool known = setting.status == Status::Success &&
            (setting.enabled == Tri::Yes || setting.enabled == Tri::No);
        const bool satisfied = known && setting.enabled == (required ? Tri::Yes : Tri::No);
        rep.rules.push_back(satisfied ? Full(rule, explanation, pass)
            : Zero(rule, known ? fail : setting.status == Status::NotFound ? "Not configured" : "Unknown",
                known ? explanation : warnings::contextTheRequiredConfigurationCouldNotBeVerified));
    };
    settingRule("net.smb1.server", "Old file-sharing server disabled (SMB1)", N.smb1Server, false, "Disabled", "Enabled",
        warnings::contextSMB1ServerConfigurationDisablingThisLegacyProtocol);
    settingRule("net.smb1.client", "Old file-sharing client disabled (SMB1)", N.smb1Client, false, "Disabled", "Available",
        warnings::contextSMB1ClientDriverAvailabilityAnAbsentOr);
    settingRule("net.smb.sign.server", "Incoming file-sharing integrity checks", N.smbServerSigning, true, "Required", "Not required",
        warnings::contextRequiringSMBServerSigningProtectsTheIntegrity);
    settingRule("net.smb.sign.client", "Outgoing file-sharing integrity checks", N.smbClientSigning, true, "Required", "Not required",
        warnings::contextRequiringSMBClientSigningProtectsTheIntegrity);
    settingRule("net.smb.guest", "Outgoing file sharing requires sign-in", N.smbGuestLogons, false, "Blocked", "Allowed",
        warnings::contextInsecureGuestLogonsBypassNormalSMBAuthentication);
    settingRule("net.llmnr", "Local name-lookup fallback disabled", N.llmnr, false, "Disabled", "Allowed",
        warnings::contextDisablingMulticastNameResolutionFallbackReducesLocal);
    bool haveAdapter = false, netbiosUnknown = N.status != Status::Success;
    bool netbiosEnabled = false, netbiosDhcp = false;
    for (const auto& adapter : N.adapters) {
        haveAdapter = true;
        if (adapter.netbiosStatus != Status::Success || adapter.netbiosOptions > 2) netbiosUnknown = true;
        else if (adapter.netbiosOptions == 1) netbiosEnabled = true;
        else if (adapter.netbiosOptions == 0) netbiosDhcp = true;
    }
    const R netbios{"net.netbios", "Old network discovery disabled", 10, Category::NetworkSecurity};
    rep.rules.push_back(netbiosUnknown ? Zero(netbios, "Unknown", warnings::contextNotEveryApplicableAdapterSNetBIOSConfiguration)
        : netbiosEnabled ? Zero(netbios, "Enabled", warnings::contextAtLeastOneActiveIPv4AdapterExplicitly)
        : netbiosDhcp ? Zero(netbios, "DHCP controlled", warnings::contextDHCPControlledSettingsDoNotProveNetBIOS)
        : Full(netbios, haveAdapter ? warnings::contextNetBIOSIsExplicitlyDisabledOnEveryActive
            : warnings::contextNoActiveNonLoopbackIPv4AdaptersRequire, haveAdapter ? "Disabled" : "Not applicable"));
    const R rdp{"net.rdp", "RDP disabled or authentication required", 10, Category::NetworkSecurity};
    const bool rdpKnown = N.rdp.status == Status::Success && (N.rdp.enabled == Tri::Yes || N.rdp.enabled == Tri::No);
    const bool nlaKnown = N.rdpNla.status == Status::Success && (N.rdpNla.enabled == Tri::Yes || N.rdpNla.enabled == Tri::No);
    rep.rules.push_back(rdpKnown && N.rdp.enabled == Tri::No
        ? Full(rdp, warnings::contextRemoteDesktopConnectionsAreDisabledByConfiguration, "RDP disabled")
        : rdpKnown && nlaKnown && N.rdpNla.enabled == Tri::Yes
        ? Full(rdp, warnings::contextRemoteDesktopIsConfiguredToRequireNetwork, "NLA required")
        : Zero(rdp, rdpKnown && nlaKnown ? "NLA not required" : "Unknown",
            warnings::contextEnabledRemoteDesktopMustRequireNetworkLevel));

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
                                 warnings::contextNoFixedVolumesCouldBeVerified));
    else if (allFixedOn)
        rep.rules.push_back(Full({ "enc.bl", "BitLocker on all fixed drives", 50,
                                   Category::Encryption },
                                 warnings::contextAllDetectedFixedDrivesHaveBitLockerProtection, "Protected"));
    else if (anyBitlockerOn)
        rep.rules.push_back(Partial({ "enc.bl", "BitLocker on all fixed drives", 50, Category::Encryption },
                                    25, "Some drives protected",
                                    warnings::contextBitLockerProtectionConfirmedOnSomeVolumesFull));
    else
        rep.rules.push_back(Zero({ "enc.bl", "BitLocker on all fixed drives", 50, Category::Encryption },
                                 anyBitlockerUnknown ? "Unknown" : "Disabled",
                                 anyBitlockerUnknown
                                     ? warnings::contextBitLockerStatusCouldNotBeReadNeeds
                                     : warnings::contextBitLockerNotEnabledOnAnyFixedVolume));

    rep.rules.push_back(S.tpm.present
        ? Full({ "enc.tpm", "TPM available to protect keys", 40, Category::Encryption },
               warnings::contextATPMSecurityChipIsAvailableTo, "Available")
        : Zero({ "enc.tpm", "TPM available to protect keys", 40, Category::Encryption }, "Absent",
               warnings::contextNoTPMAvailableForKeyProtection));

    // ---- Account Security (max 120) ----
    if (S.uac.enabled && S.uac.consentPromptAdmin)
        rep.rules.push_back(Full({ "acc.uac2", "Admin actions require a UAC prompt", 20,
                                   Category::AccountSecurity },
                                 warnings::contextAdministratorActionsRequireAUACConsentOr, "Required"));
    else
        rep.rules.push_back(Zero({ "acc.uac2", "Admin actions require a UAC prompt", 20, Category::AccountSecurity },
                                 "Not required",
                                 warnings::contextUACPromptNotRequiredForAdminActions));

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
        "Running", "Not running", warnings::contextCredentialGuardIsolatesSignInSecretsUsing);
    protection("os.lsa", "Sign-in service protected from tampering", 25, Category::OsSecurity, H.lsaProtection,
        "Protected", "Unprotected", warnings::contextReportsTheRunningLSASSProcessProtectionLevel);
    protection("os.lmhash", "Old password storage disabled", 20, Category::OsSecurity, H.noLmHash,
        "Blocked", "Allowed", warnings::contextNoLMHashPreventsLMHashesBeingStoredAt);
    protection("os.autoplay", "AutoPlay off on all drive types", 20, Category::OsSecurity, H.autoPlayDisabled,
        "Blocked", "Not blocked", warnings::contextTheDeviceAutoPlayPolicyMustCoverAll);
    const R lock{"os.autolock", "Automatic device lock within 15 minutes", 20, Category::OsSecurity};
    rep.rules.push_back(H.inactivityStatus == Status::Success && H.inactivitySeconds > 0 && H.inactivitySeconds <= 900
        ? Full(lock, warnings::contextAnExplicitDeviceInactivityPolicyLocksSessions, "Configured")
        : Zero(lock, H.inactivityStatus == Status::Success ? (H.inactivitySeconds ? "Long timeout" : "Not configured") : "Unknown",
            warnings::contextChecksTheDeviceInactivityPolicyUserScreen));
    const R ntlm{"net.ntlm", "Modern network sign-in protection", 20, Category::NetworkSecurity};
    rep.rules.push_back(H.lmCompatibilityStatus == Status::Success && H.lmCompatibility >= 3 && H.lmCompatibility <= 5
        ? Full(ntlm, WideToUtf8(NetworkSignInReason(H)), WideToUtf8(NetworkSignInState(H)))
        : Zero(ntlm, WideToUtf8(NetworkSignInState(H)), WideToUtf8(NetworkSignInReason(H))));
    SecuritySetting desktop;
    desktop.status = S.uac.status;
    if (desktop.status == Status::Success && S.uac.promptOnSecureDesktop <= 1)
        desktop.enabled = S.uac.enabled && S.uac.promptOnSecureDesktop == 1 ? Tri::Yes : Tri::No;
    protection("acc.securedesktop", "UAC prompts use the secure desktop", 25, Category::AccountSecurity, desktop,
        "Required", "Not required", warnings::contextUACPromptsShouldRunOnTheIsolated);
    protection("acc.guest", "Built-in Guest account disabled", 30, Category::AccountSecurity, H.guestDisabled,
        "Disabled", "Enabled", warnings::contextIdentifiesTheBuiltInGuestAccountBy);
    protection("acc.assistance", "Remote Assistance invitations blocked", 20, Category::AccountSecurity, H.remoteAssistanceDisabled,
        "Blocked", "Allowed", warnings::contextChecksPolicyLocalPermissionForSolicitedRemote);
    const R lockout{"acc.lockout", "Local account lockout protection", 25, Category::AccountSecurity};
    const bool threshold = H.lockoutThreshold > 0 && H.lockoutThreshold <= 10;
    const bool duration = H.lockoutDuration >= 900 && H.lockoutWindow >= 900;
    rep.rules.push_back(H.lockoutStatus != Status::Success ? Zero(lockout, "Unknown", warnings::contextLocalSAMLockoutPolicyCouldNotBe)
        : threshold && duration ? Full(lockout, warnings::contextLocalAccountsLockAfter110Failed, "Configured")
        : threshold ? Partial(lockout, 12, "Short lockout", warnings::contextTheLocalLockoutDurationOrResetWindow)
        : Zero(lockout, H.lockoutThreshold ? "High threshold" : "Not configured", warnings::contextTheLocalAccountLockoutThresholdIsAbsent));

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
            rule.reason = warnings::contextTheRequiredSystemDataCouldNotBe;
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
    if (includeWarnings) warnings::BuildWarnings(a, rep);
    return rep;
}

} // namespace sa
