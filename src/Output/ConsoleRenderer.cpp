#include "ConsoleRenderer.h"
#include "../Utilities.h"
#include <iostream>
#include <iomanip>

namespace sa {

    static void Line() { std::wcout << L"------------------------------------------------------------\n"; }
    static void Section(const wchar_t* t) {
        std::wcout << L"\n" << t << L"\n";
        Line();
    }

    void RenderConsole(const AssessmentResult& r) {
        std::wcout << L"============================================================\n";
        std::wcout << L" Windows Security & Privacy Assessment\n";
        std::wcout << L"============================================================\n";

        Section(L"System");
        std::wcout << L"OS:              " << r.os.productName
            << L" (" << r.os.displayVersion << L")\n";
        std::wcout << L"Build:           " << r.os.build << L"." << r.os.ubr << L"\n";
        std::wcout << L"Architecture:    " << r.os.architecture << L"\n";
        std::wcout << L"Computer:        " << r.os.computerName
            << L"   User: " << r.os.userName << L"\n";
        std::wcout << L"CPU:             " << r.cpu.brand << L"\n";
        std::wcout << L"Cores/Logical:   " << r.cpu.physicalCores << L"/"
            << r.cpu.logicalProcessors << L"\n";
        std::wcout << L"RAM:             " << FormatBytes(r.memory.totalBytes)
            << L"  (Available " << FormatBytes(r.memory.availableBytes) << L")\n";
        std::wcout << L"Elevated:        " << (r.security.isElevated ? L"Yes" : L"No") << L"\n";
        std::wcout << L"Uptime:          " << r.os.uptimeSeconds / 3600 << L"h "
            << (r.os.uptimeSeconds % 3600) / 60 << L"m\n";
        std::wcout << L"Timezone:        " << r.os.timeZone
            << L"   Locale: " << r.os.locale << L"\n";

        Section(L"Hardware Security");
        std::wcout << L"TPM:             "
            << (r.security.tpm.present
                ? (r.security.tpm.specVersion.empty() ? L"Present"
                    : r.security.tpm.specVersion)
                : L"Absent")
            << L" / " << (r.security.tpm.ready ? L"Ready" : L"NotReady") << L"\n";
        std::wcout << L"Secure Boot:     "
            << (r.security.secureBoot.enabled == Tri::Yes ? L"ENABLED"
              : r.security.secureBoot.enabled == Tri::No  ? L"DISABLED" : L"Unknown") << L"\n";
        std::wcout << L"Virtualization:  "
            << (CpuVirtualizationAvailable(r.cpu) ? L"Supported" : L"Unsupported") << L"\n";
        std::wcout << L"VBS:             " << (r.security.virt.vbsEnabled ? L"ENABLED" : L"DISABLED") << L"\n";
        std::wcout << L"HVCI:            " << (r.security.virt.hvciEnabled ? L"ENABLED" : L"DISABLED") << L"\n";
        std::wcout << L"Cred Guard:      " << (r.security.virt.credentialGuardRunning ? L"ENABLED" : L"DISABLED") << L"\n";

        Section(L"Protection");
        std::wcout << L"Microsoft Defender:        " << (r.defender.enabled ? L"ENABLED" : L"DISABLED") << L"\n";
        std::wcout << L"Real-Time Protection:      " << (r.defender.realTimeProtection ? L"ENABLED" : L"DISABLED") << L"\n";
        std::wcout << L"Behavior Monitoring:       " << (r.defender.behaviorMonitor ? L"ENABLED" : L"DISABLED") << L"\n";
        std::wcout << L"IOAV Protection:           " << (r.defender.ioav ? L"ENABLED" : L"DISABLED") << L"\n";
        std::wcout << L"Cloud Protection:          " << (r.defender.cloudProtection ? L"ENABLED" : L"DISABLED") << L"\n";
        std::wcout << L"Tamper Protection:         " << (r.defender.tamperProtection ? L"ENABLED" : L"DISABLED") << L"\n";
        std::wcout << L"AM Engine Version:         " << r.defender.amEngineVersion << L"\n";
        std::wcout << L"Signatures Version:        " << r.defender.antivirusSignatureVersion << L"\n";
        if (!r.defender.reason.empty())
            std::wcout << L"Defender note:             " << r.defender.reason << L"\n";
        for (auto& p : r.firewall.profiles)
            std::wcout << L"Firewall (" << p.name << L"):         "
            << (p.enabled ? L"ENABLED" : L"DISABLED") << L"\n";

        Section(L"Storage");
        for (auto& v : r.storage.volumes) {
            std::wcout << v.mountPoint << L"  " << v.filesystem
                << L"  Free " << FormatBytes(v.freeBytes) << L" / "
                << FormatBytes(v.totalBytes) << L"\n";
            std::wcout << L"    BitLocker: " << v.bitLockerState << L"\n";
            if (!v.encryptionMethod.empty())
                std::wcout << L"    Encryption: " << v.encryptionMethod << L"\n";
            if (v.bitLockerState == L"Unknown" && !v.bitLockerNote.empty())
                std::wcout << L"    Note: " << v.bitLockerNote << L"\n";
        }
        for (auto& d : r.storage.disks)
            std::wcout << L"  Disk" << d.index << L": " << d.vendor << L" " << d.model
            << L"  " << FormatBytes(d.sizeBytes)
            << L"  " << d.busType
            << L"  " << d.mediaType << L"\n";

        Section(L"Applications");
        for (auto& a : r.applications) {
            if (a.installed) {
                std::wcout << L"[+] " << a.name << L"\n";
                std::wcout << L"    Path:    " << a.path << L"\n";
                if (!a.version.empty())      std::wcout << L"    Version: " << a.version << L"\n";
                if (!a.publisher.empty())    std::wcout << L"    Publisher: " << a.publisher << L"\n";
                if (!a.architecture.empty()) std::wcout << L"    Arch:    " << a.architecture << L"\n";
            }
            else {
                std::wcout << L"[-] " << a.name << L"  (not installed)\n";
            }
        }

        Section(L"Threshold Findings");
        std::wcout << L"Registry:\n";
        bool anyReg = false;
        for (auto& f : r.registryFindings) {
            if (f.exceeded) {
                anyReg = true;
                std::wcout << L"[!] " << f.name << L": " << f.path
                    << L" contains " << f.valueCount << L" values (threshold: "
                    << f.threshold << L")\n";
            }
        }
        if (!anyReg) std::wcout << L"    (none exceeded)\n";

        std::wcout << L"Directories:\n";
        bool anyDir = false;
        for (auto& f : r.directoryFindings) {
            if (f.exceeded) {
                anyDir = true;
                std::wcout << L"[!] " << f.path << L" contains " << f.fileCount
                    << L" files (threshold: " << f.threshold << L")\n";
            }
        }
        if (!anyDir) std::wcout << L"    (none exceeded)\n";

        Section(L"Privacy (informational)");
        for (auto& p : r.privacyFindings)
            std::wcout << L"  " << p.name << L": " << p.value << L"\n";

        std::wcout << L"\n============================================================\n";
        std::wcout << L" SECURITY SCORE\n";
        std::wcout << L"============================================================\n\n";
        std::wcout << L"                         " << r.score.total
            << L" / " << r.score.maximum << L"\n\n";
        std::wcout << L"Rule breakdown (awarded / max):\n";

        // --- everything below must be wcout; the rule fields are UTF-8 std::string ---
        for (auto& rl : r.score.rules) {
            if (rl.maxPoints == 0) continue; // informational-only entries (privacy)
            std::wstring desc = Utf8ToWide(rl.description);
            std::wstring state = Utf8ToWide(rl.state);
            std::wstring cat = Utf8ToWide(rl.category);
            std::wcout << L"  "
                << std::setw(4) << rl.awardedPoints << L" / "
                << std::setw(4) << rl.maxPoints << L"  "
                << desc << L"   [" << state << L"]\n";
            (void)cat;
        }

        std::wcout << L"\nThis is a hardening posture score. It does not guarantee security.\n";
    }

} // namespace sa
