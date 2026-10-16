#include "ConsoleLayout.h"
#include <algorithm>
#include <ranges>

// Report composition only. ConsoleLayout owns reusable framing and formatting.
namespace sa {

void console_detail::ConsoleLayout::Render(const AssessmentResult& r, ReportView view) {

    Banner(L"Windows Security Assessment");
    if (view == ReportView::Export) Notice(warnings::backupTitle, warnings::backup);
    else if (!r.security.isElevated) Notice(warnings::nonAdminTitle, warnings::nonAdmin);

    // ------------------------------------------------------------ System
    Section(L"System");
    KV(L"OS", r.os.productName + L" (" + r.os.displayVersion + L")");
    Pair(L"Build", Num(r.os.build) + L"." + Num(r.os.ubr), L"Architecture", r.os.architecture, Cyn());
    Pair(L"Computer", r.os.computerName, L"User", r.os.userName);
    KV(L"CPU", r.cpu.brand);
    KV(L"Cores / Logical", Num(r.cpu.physicalCores) + L" / " + Num(r.cpu.logicalProcessors), Cyn());
    KV(L"RAM", FormatBytes(r.memory.totalBytes) + L"   (available " +
                   FormatBytes(r.memory.availableBytes) + L")", Cyn());
    KV(L"Elevated", r.security.isElevated ? L"Yes" : L"No",
       r.security.isElevated ? Grn() : Yel());
    KV(L"Uptime", Num(r.os.uptimeSeconds / 3600) + L"h " +
                      Num((r.os.uptimeSeconds % 3600) / 60) + L"m", Cyn());
    Pair(L"Timezone", r.os.timeZone, L"Locale", r.os.locale);

    // ------------------------------------------------------------ Hardware security
    Section(L"Hardware Security");
    {
        const bool tpmKnown = r.security.tpm.status == Status::Success || r.security.tpm.status == Status::NotFound;
        const std::wstring tpmText =
            (r.security.tpm.present
                ? (r.security.tpm.specVersion.empty() ? std::wstring(L"Present")
                                                      : r.security.tpm.specVersion)
                : std::wstring(L"Absent"))
            + L" / " + (r.security.tpm.ready ? L"Ready" : r.security.tpm.readinessKnown ? L"Not ready" : L"Readiness unknown");
        KV(L"TPM", tpmKnown ? tpmText : L"Unknown (" + std::wstring(ToW(r.security.tpm.status)) + L")",
           !tpmKnown ? Yel() : (r.security.tpm.present && r.security.tpm.ready) ? Grn() : Red());
    }
    {
        const Tri sb = r.security.secureBoot.enabled;
        KV(L"Secure Boot",
           sb == Tri::Yes ? L"ENABLED" : (sb == Tri::No ? L"DISABLED" : L"Unknown"),
           sb == Tri::Yes ? Grn() : (sb == Tri::No ? Red() : Yel()));
    }
    {
        const bool virt = r.cpu.virtualizationAvailable;
        KV(L"Virtualization", virt ? L"Supported" : L"Unsupported", virt ? Grn() : Red());
    }
    const Status runningStatus = r.security.virt.runningServicesKnown ? Status::Success : Status::Unavailable;
    FlagPair(L"Isolated security", r.security.virt.vbsEnabled, r.security.virt.status,
             L"Memory integrity", r.security.virt.hvciEnabled, runningStatus);
    Flag(L"Credential Guard", r.security.virt.credentialGuardRunning, runningStatus);
    Pair(L"AES acceleration", r.cpu.status != Status::Success ? L"Unknown" : r.cpu.aesni ? L"Supported" : L"Unsupported",
         L"CPU memory protection", r.cpu.status != Status::Success ? L"Unknown" : r.cpu.nx ? L"Supported" : L"Unsupported", Cyn());
    if (r.security.virt.hvciConfigured != Tri::Unknown)
        KV(L"Memory integrity setup", ToW(r.security.virt.hvciConfigured), Yel());

    // ------------------------------------------------------------ Protection
    Section(L"Protection");
    SubHeader(L"Microsoft Defender", L"", Dim());
    if (r.score.registeredAntivirusScoring) {
        KV(L"Defender", r.defender.status == Status::Success && r.defender.enabledStatus == Status::Success
            ? (r.defender.enabled ? L"Enabled" : L"Inactive") : L"Unknown", Dim());
        if (!r.defender.amRunningMode.empty()) KV(L"Running mode", r.defender.amRunningMode);
    } else {
        auto known = [&](Status status) { return r.defender.status == Status::Success ? status : r.defender.status; };
        FlagPair(L"Defender", r.defender.enabled, known(r.defender.enabledStatus),
                 L"Real-Time", r.defender.realTimeProtection, known(r.defender.realTimeProtectionStatus));
        FlagPair(L"Behavior Monitoring", r.defender.behaviorMonitor, known(r.defender.behaviorMonitorStatus),
                 L"Download scanning", r.defender.ioav, known(r.defender.ioavStatus));
        FlagPair(L"Cloud Protection", r.defender.cloudProtection, known(r.defender.cloudProtectionStatus),
                 L"Tamper Protection", r.defender.tamperProtection, known(r.defender.tamperProtectionStatus));
        Pair(L"Engine Version", r.defender.amEngineVersion, L"Signatures Version", r.defender.antivirusSignatureVersion, Cyn());
    }
    if (HasThirdPartyAntivirus(r.antivirus)) {
        const Tri periodic = r.defender.periodicScanning;
        KV(L"Periodic scanning", periodic == Tri::Yes ? L"Enabled" : periodic == Tri::No ? L"Disabled" : L"Unknown",
           periodic == Tri::Unknown ? Yel() : Wht());
        KV(L"Scoring", L"Periodic scanning is informational only", Dim());
        if (periodic == Tri::Unknown)
            KV(L"Periodic scan note", warnings::periodicUnknown, Yel());
    }
    if (!r.defender.reason.empty())
        KV(L"Note", r.defender.reason, Yel());

    if (r.score.registeredAntivirusScoring) {
        SubHeader(L"Registered Antivirus (Windows Security Center)", L"", Dim());
        for (size_t i = 0; i < r.antivirus.products.size(); ++i) {
            const auto& av = r.antivirus.products[i];
            const bool enabled = av.status == Status::Success && av.state == AntivirusState::Enabled;
            const bool known = av.status == Status::Success && av.state != AntivirusState::Unknown;
            SubHeader(av.name, known ? ToW(av.state) : L"Unknown", enabled ? Grn() : known ? Red() : Yel());
            if (i < r.score.antivirusScores.size()) {
                const auto& score = r.score.antivirusScores[i];
                if (HasThirdPartyAntivirus(r.antivirus) && av.isDefender)
                    KV(L"Antivirus score", warnings::defenderExcluded, Dim());
                else KV(L"Antivirus score", Num(score.awardedPoints) + L" / " + Num(score.maxPoints),
                   OutcomeColor(score.awardedPoints, score.maxPoints));
            }
            KV(L"Signatures current", ToW(av.signaturesUpToDate));
        }
        KV(L"Overall contribution", L"At most " + Num(kMalwareProtectionMaxPoints) +
            L" points; product scores are independent.", Dim());
    }
    if (r.antivirus.status != Status::Success && !r.antivirus.reason.empty())
        KV(L"Antivirus query", r.antivirus.reason, Yel());

    // ------------------------------------------------------------ Network security
    Section(L"Network Security");
    const auto& network = r.network;
    struct SettingView {
        const wchar_t* label;
        const SecuritySetting& value;
        const wchar_t* yes = L"Enabled";
        const wchar_t* no = L"Disabled";
        bool favorable = true;
        bool informational = false;
    };
    auto settingText = [](const SettingView& view) {
        const auto& value = view.value;
        const bool known = value.status == Status::Success && (value.enabled == Tri::Yes || value.enabled == Tri::No);
        return known ? std::wstring(value.enabled == Tri::Yes ? view.yes : view.no)
            : value.status == Status::NotFound ? std::wstring(L"Not configured")
            : L"Unknown (" + std::wstring(ToW(value.status)) + L")";
    };
    auto settingColor = [this](const SettingView& view) {
        const bool known = view.value.status == Status::Success && (view.value.enabled == Tri::Yes || view.value.enabled == Tri::No);
        return !known ? Yel() : view.informational ? Cyn()
            : ((view.value.enabled == Tri::Yes) == view.favorable) ? Grn() : Yel();
    };
    auto settings = [&](const SettingView& first, const SettingView& second) {
        Pair(first.label, settingText(first), second.label, settingText(second), settingColor(first), settingColor(second));
    };
    SubHeader(L"Windows Firewall", L"", Dim());
    Flag(L"Firewall service", r.firewall.serviceRunning, r.firewall.serviceStatus);
    for (size_t i = 0; i < r.firewall.profiles.size(); ++i) {
        const auto& profile = r.firewall.profiles[i];
        const DWORD mask = profile.name == L"Domain" ? 1 : profile.name == L"Private" ? 2 : profile.name == L"Public" ? 4 : 0;
        out() << L"    " << Dim() << (i + 1 == r.firewall.profiles.size() ? GCorner() : GTee()) << L" "
              << Wht() << profile.name << Rst();
        if (r.firewall.activeProfilesStatus == Status::Success && (r.firewall.activeProfiles & mask))
            out() << Cyn() << L" (active)" << Rst();
        out() << L"  " << (profile.status != Status::Success ? Yel() : profile.enabled ? Grn() : Red())
              << (profile.status != Status::Success ? L"Unknown" : profile.enabled ? L"ENABLED" : L"DISABLED")
              << Dim() << L"  |  Inbound " << Cyn()
              << (profile.status != Status::Success || profile.defaultInbound > 1 ? L"Unknown" : profile.defaultInbound == 0 ? L"Block" : L"Allow")
              << Dim() << L"  |  Outbound " << Cyn()
              << (profile.status != Status::Success || profile.defaultOutbound > 1 ? L"Unknown" : profile.defaultOutbound == 0 ? L"Block" : L"Allow")
              << Rst() << L"\n";
    }
    if (r.firewall.profiles.empty()) KV(L"Firewall profiles", L"Unknown", Yel());
    if (r.firewall.activeProfilesStatus != Status::Success) KV(L"Active profiles", L"Unknown", Yel());

    SubHeader(L"File Sharing & Authentication", L"", Dim());
    settings({L"SMB1 server", network.smb1Server, L"Enabled", L"Disabled", false},
             {L"SMB1 client", network.smb1Client, L"Available", L"Disabled / absent", false});
    settings({L"Incoming file integrity", network.smbServerSigning, L"Required", L"Not required"},
             {L"Outgoing file integrity", network.smbClientSigning, L"Required", L"Not required"});
    settings({L"SMB guest logons", network.smbGuestLogons, L"Allowed", L"Blocked", false},
             {L"Local lookup fallback", network.llmnr, L"Allowed", L"Disabled", false});
    const auto& hardening = r.hardening;
    const bool modernSignIn = hardening.lmCompatibilityStatus == Status::Success &&
        hardening.lmCompatibility >= 3 && hardening.lmCompatibility <= 5;
    KV(L"Network sign-in", NetworkSignInState(hardening), modernSignIn ? Grn() : Yel());
    if (hardening.lmCompatibilityStatus != Status::Success || hardening.lmCompatibility > 5)
        Paragraph(NetworkSignInReason(hardening), 6, Yel());
    SubHeader(L"SMB Encryption & Remote Access", L"", Dim());
    settings({L"Global SMB encryption", network.smbEncryption, L"Enabled", L"Disabled", true, true},
             {L"Reject unencrypted SMB", network.smbRejectUnencrypted, L"Yes", L"No", true, true});
    KV(L"Encryption scope", L"Shares can require encryption independently of the global setting.", Dim());
    settings({L"Remote Desktop", network.rdp, L"Enabled", L"Disabled", false, true},
             {L"RDP authentication", network.rdpNla, L"NLA required", L"NLA not required"});

    Section(L"Device & Account Security");
    SubHeader(L"Credential & Device Protection", L"", Dim());
    settings({L"Sign-in service", hardening.lsaProtection, L"Protected", L"Unprotected"},
             {L"Old password storage", hardening.noLmHash, L"Blocked", L"Allowed"});
    settings({L"AutoPlay (all drives)", hardening.autoPlayDisabled, L"Blocked", L"Not blocked"},
             {L"Assistance invitations", hardening.remoteAssistanceDisabled, L"Blocked", L"Allowed"});
    const auto unknown = [](Status status) { return status == Status::NotFound ? std::wstring(L"Not configured")
        : L"Unknown (" + std::wstring(ToW(status)) + L")"; };
    KV(L"Device inactivity lock", hardening.inactivityStatus != Status::Success ? unknown(hardening.inactivityStatus)
        : hardening.inactivitySeconds ? Num(hardening.inactivitySeconds) + L" seconds" : L"Not configured",
        hardening.inactivityStatus == Status::Success && hardening.inactivitySeconds && hardening.inactivitySeconds <= 900 ? Grn() : Yel());
    SubHeader(L"Local Account Policies", L"", Dim());
    FlagPair(L"UAC", r.security.uac.enabled, r.security.uac.status,
             L"UAC secure desktop", r.security.uac.enabled && r.security.uac.promptOnSecureDesktop == 1, r.security.uac.status);
    KV(L"Built-in Guest", settingText({L"", hardening.guestDisabled, L"Disabled", L"Enabled"}),
        settingColor({L"", hardening.guestDisabled, L"Disabled", L"Enabled"}));
    KV(L"Account lockout", hardening.lockoutStatus != Status::Success ? unknown(hardening.lockoutStatus)
        : !hardening.lockoutThreshold ? L"Not configured"
        : Num(hardening.lockoutThreshold) + L" attempts; duration " +
            (hardening.lockoutDuration == MAXDWORD ? L"until administrator unlock" : Num(hardening.lockoutDuration) + L"s") +
            L"; reset window " + Num(hardening.lockoutWindow) + L"s", Cyn());
    KV(L"Account policy scope", L"Local SAM accounts; domain and Microsoft accounts may use different policies.", Dim());

    // ------------------------------------------------------------ Windows Update
    Section(L"Windows Update");
    const auto& update = r.windowsUpdate;
    const bool pendingKnown = update.pendingStatus == Status::Success;
    SubHeader(L"Pending Updates", update.updates.empty() ? (pendingKnown ? L"(None)" : L"(Unknown)")
        : L"(" + Num(update.updates.size()) + (pendingKnown ? L")" : L" listed; incomplete)"),
        pendingKnown ? Dim() : Yel());
    for (size_t i = 0; i < update.updates.size(); ++i) {
        const auto& item = update.updates[i];
        const bool last = i + 1 == update.updates.size();
        out() << L"    " << Dim() << (last ? GCorner() : GTee()) << Rst() << L" "
              << Wht() << item.title << Rst() << L"  " << Cyn() << L"[" << UpdateTypes(item) << L"]" << Rst() << L"\n";
        const std::wstring branch = last ? L"   " : GBranch();
        if (!item.products.empty()) {
            std::wstring products;
            for (const auto& product : item.products) {
                if (!products.empty()) products += L", ";
                products += product;
            }
            out() << L"    " << Dim() << branch << GTee() << Rst() << L" "
                  << Lbl() << L"Products: " << Dim() << products << Rst() << L"\n";
        }
        if (!item.kbArticles.empty()) {
            std::wstring articles;
            for (const auto& kb : item.kbArticles) {
                if (!articles.empty()) articles += L", ";
                articles += L"KB" + kb;
            }
            out() << L"    " << Dim() << branch << GTee() << Rst() << L" "
                  << Lbl() << L"Update reference: " << Blu() << articles << Rst() << L"\n";
        }
        out() << L"    " << Dim() << branch << GCorner() << Rst() << L" "
              << Lbl() << L"Downloaded: " << (item.downloaded == Tri::Unknown ? Yel() : Cyn())
              << ToW(item.downloaded) << Rst() << L"\n";
    }
    if (!update.pendingReason.empty()) KV(L"Update query", update.pendingReason, Yel());
    if (!update.lastInstallationError.empty()) KV(L"Installation error", update.lastInstallationError, Yel());
    SubHeader(L"Update Services", update.services.entries.empty() ? L"(Unavailable)" : L"", Dim());
    for (size_t i = 0; i < update.services.entries.size(); ++i) {
        const auto& service = update.services.entries[i];
        out() << L"    " << Dim() << (i + 1 == update.services.entries.size() ? GCorner() : GTee()) << Rst()
              << L" " << Blu() << service.name << Rst();
        if (!service.displayName.empty() && !IEquals(service.name, service.displayName))
            out() << Dim() << L" - " << Rst() << Wht() << service.displayName << Rst();
        out() << L"  " << Dim() << L"[" << Cyn() << (service.state.empty() ? L"Unknown" : service.state)
              << Dim() << L"]" << Rst() << L"\n";
    }

    // ------------------------------------------------------------ Storage
    Section(L"Storage");
    auto renderVolume = [&](const StorageVolume& v, bool last) {
        const std::wstring indent = last ? L"     " : L"  " + std::wstring(GBranch());
        out() << L"  " << Dim() << (last ? GCorner() : GTee()) << L" " << Bold() << Blu()
              << v.mountPoint << Rst();
        if (!v.volumeLabel.empty()) out() << Wht() << L"  " << v.volumeLabel << Rst();
        out() << Dim() << L"  " << v.filesystem << L"  |  Free " << Cyn() << FormatBytes(v.freeBytes)
              << Dim() << L" / " << Cyn() << FormatBytes(v.totalBytes) << Rst();
        if (v.totalBytes) {
            const auto free = (std::min)(v.freeBytes, v.totalBytes);
            const double used = static_cast<double>(v.totalBytes - free) / static_cast<double>(v.totalBytes);
            const auto color = used < .75 ? Grn() : used < .90 ? Yel() : Red();
            out() << L"  " << Bar(used, 10, color) << L" " << Num(static_cast<unsigned>(used * 100 + .5)) << L"% used";
        }
        out() << L"\n" << Dim() << indent << L"BitLocker "
              << (v.bitLockerState == L"On" ? Grn() : v.bitLockerState == L"Off" ? Red() : Yel())
              << v.bitLockerState << Rst() << Button(L"BitLocker");
        if (!v.encryptionMethod.empty()) out() << Dim() << L"  |  Encryption " << Cyn() << v.encryptionMethod << Rst();
        if (v.diskIndices.size() > 1) {
            out() << Dim() << L"  |  Spans ";
            for (size_t i = 0; i < v.diskIndices.size(); ++i)
                out() << (i ? L", " : L"") << Blu() << L"Disk" << v.diskIndices[i] << Rst();
        }
        out() << L"\n";
        if (v.bitLockerState == L"Unknown" && !v.bitLockerNote.empty())
            out() << Dim() << indent << L"Note: " << Yel() << v.bitLockerNote << Rst() << L"\n";
        if (v.diskIndices.empty())
            out() << Dim() << indent << L"Disk mapping: " << Yel() << ToW(v.diskMappingStatus) << Rst() << L"\n";
    };
    std::vector<unsigned> indices;
    for (const auto& disk : r.storage.disks) indices.push_back(disk.index);
    for (const auto& volume : r.storage.volumes)
        indices.insert(indices.end(), volume.diskIndices.begin(), volume.diskIndices.end());
    std::sort(indices.begin(), indices.end());
    indices.erase(std::unique(indices.begin(), indices.end()), indices.end());
    for (const auto index : indices) {
        const auto found = std::find_if(r.storage.disks.begin(), r.storage.disks.end(),
            [&](const auto& disk) { return disk.index == index; });
        out() << L"  " << Bold() << Blu() << L"Disk" << index << Rst();
        if (found != r.storage.disks.end()) {
            const auto& d = *found;
            out() << L"  " << Wht() << (d.vendor.empty() ? d.model : d.vendor + L" " + d.model)
                  << Dim() << L"  |  " << Cyn() << FormatBytes(d.sizeBytes)
                  << Dim() << L"  |  " << Cyn() << d.busType << Dim() << L"  " << d.mediaType << Rst();
        } else out() << Yel() << L"  Details unavailable" << Rst();
        out() << L"\n";
        std::vector<const StorageVolume*> volumes;
        for (const auto& volume : r.storage.volumes)
            if (std::find(volume.diskIndices.begin(), volume.diskIndices.end(), index) != volume.diskIndices.end())
                volumes.push_back(&volume);
        for (size_t i = 0; i < volumes.size(); ++i) renderVolume(*volumes[i], i + 1 == volumes.size());
        if (volumes.empty()) out() << L"    " << Dim() << L"No mounted volumes" << Rst() << L"\n";
    }
    std::vector<const StorageVolume*> unmapped;
    for (const auto& volume : r.storage.volumes) if (volume.diskIndices.empty()) unmapped.push_back(&volume);
    if (!unmapped.empty()) SubHeader(L"Unmapped volumes", L"", Yel());
    for (size_t i = 0; i < unmapped.size(); ++i) renderVolume(*unmapped[i], i + 1 == unmapped.size());
    if (indices.empty() && unmapped.empty()) KV(L"Storage query", ToW(r.storage.status), Yel());

    // ------------------------------------------------------------ Threshold findings
    Section(L"Threshold Findings");
    Paragraph(warnings::thresholdScope, 2, Dim());
    SubHeader(L"Registry", L"", Dim());
    for (const auto& f : r.registryFindings) {
        SubHeader(f.name, f.status == Status::Success ? Num(f.valueCount) + L" / " + Num(f.threshold) + L" values" : ToW(f.status),
            f.exceeded ? Yel() : f.status == Status::Success || f.status == Status::NotFound ? Cyn() : Yel());
        KV(L"Key", f.path, Dim());
        if (!f.description.empty()) Paragraph(f.description, 4, Dim());
        if (f.exceeded) KV(L"Review", warnings::thresholdReview, Yel());
    }
    if (r.registryFindings.empty()) KV(L"Registry scans", L"No recorded results", Dim());
    SubHeader(L"Directories", L"", Dim());
    for (const auto& f : r.directoryFindings) {
        SubHeader(f.name, f.status == Status::Success ? Num(f.fileCount) + L" / " + Num(f.threshold) + L" files" : ToW(f.status),
            f.exceeded ? Yel() : f.status == Status::Success || f.status == Status::NotFound ? Cyn() : Yel());
        KV(L"Directory", f.path, Dim());
        if (!f.description.empty()) Paragraph(f.description, 4, Dim());
        if (f.exceeded) KV(L"Review", warnings::thresholdReview, Yel());
    }
    if (r.directoryFindings.empty()) KV(L"Directory scans", L"No recorded results", Dim());

    // ------------------------------------------------------------ Rule breakdown
    Section(L"Rule breakdown (awarded / max)");

    // Group by category so a rule can move without changing its stable ID.
    std::vector<std::string> categories;
    size_t descriptionWidth = 36;
    for (auto& rl : r.score.rules) {
        if (rl.maxPoints == 0) continue;               // informational-only entries
        descriptionWidth = (std::max)(descriptionWidth, Utf8ToWide(rl.description).size() + 2);
        const std::string& p = rl.category;
        bool seen = false;
        for (auto& q : categories) if (q == p) { seen = true; break; }
        if (!seen) categories.push_back(p);
    }
    for (auto& category : categories) {
        int gAwarded = 0, gMax = 0;
        for (auto& rl : r.score.rules) {
            if (rl.maxPoints == 0) continue;
            if (rl.category != category) continue;
            gAwarded += rl.awardedPoints;
            gMax += rl.maxPoints;
        }
        SubHeader(GroupName(category),
                  PadLeft(Num(gAwarded), 3) + L" / " + PadLeft(Num(gMax), 3),
                  OutcomeColor(gAwarded, gMax));
        for (auto& rl : r.score.rules) {
            if (rl.maxPoints == 0) continue;
            if (rl.category != category) continue;
            const wchar_t* c = rl.state == "Unknown" || rl.state == "Unavailable" ? Yel()
                : OutcomeColor(rl.awardedPoints, rl.maxPoints);
            out() << L"    " << c << PadLeft(Num(rl.awardedPoints), 3) << Rst() << Dim() << L" / " << Rst()
                  << Lbl() << PadLeft(Num(rl.maxPoints), 3) << Rst() << L"   "
                  << Wht() << PadRight(Utf8ToWide(rl.description), descriptionWidth) << Rst()
                  << c << L"[" << Utf8ToWide(rl.state) << L"]" << Rst() << L"\n";
        }
    }

    // ------------------------------------------------------------ Score
    Section(L"SECURITY SCORE");
    {
        const double frac = r.score.maximum > 0
            ? static_cast<double>(r.score.total) / static_cast<double>(r.score.maximum) : 0.0;
        const wchar_t* c = frac >= 0.80 ? Grn() : (frac >= 0.50 ? Yel() : Red());
        out() << L"  " << Bold() << c << r.score.total << Rst()
              << Lbl() << L" / " << r.score.maximum << Rst() << L"     "
              << Bar(frac, 28, c) << L"  " << c
              << static_cast<unsigned>(frac * 100.0 + 0.5) << L"%" << Rst() << L"\n";
    }

    Section(L"Warnings");
    if (view == ReportView::Export)
        KV(L"Findings", warnings::exported, Dim());
    else if (r.score.warnings.empty()) KV(L"Findings", warnings::clear, Grn());
    for (const auto severity : {Severity::Critical, Severity::High, Severity::Medium, Severity::Low}) {
        if (view == ReportView::Export) break;
        const auto count = std::ranges::count(r.score.warnings, severity, &SecurityWarning::severity);
        if (!count) continue;
        const auto color = severity >= Severity::High ? Red() : severity == Severity::Medium ? Yel() : Cyn();
        SubHeader(ToW(severity), Num(count) + L" warning(s)", color);
        for (const auto& warning : r.score.warnings) {
            if (warning.severity != severity) continue;
            out() << L"    " << color << L"[!] " << Bold() << Utf8ToWide(warning.title) << Rst();
            if (warning.verificationOnly) out() << Dim() << warnings::verificationGap << Rst();
            out() << L"\n";
            Paragraph(Utf8ToWide(warning.detail), 8, Dim());
            Paragraph(std::wstring(warnings::action) + Utf8ToWide(warning.recommendation), 8, color);
        }
    }

    EndSection();
    if (console_) out() << L"\n  " << Dim() << warnings::settingsHint << Rst() << L"\n";
    out() << L"\n  " << Dim()
          << warnings::disclaimer
          << Rst() << L"\n";
}

void RenderConsole(const AssessmentResult& result, ReportView view) {
    console_detail::ConsoleLayout layout;
    layout.Render(result, view);
}

} // namespace sa
