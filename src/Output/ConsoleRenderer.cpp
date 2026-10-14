#include "ConsoleRenderer.h"
#include "../Utilities.h"
#include <windows.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>

// Presentation only: this file formats values that were already collected and scored.
// Colors use ANSI escape sequences, enabled only when stdout is a real console that
// accepts them (and NO_COLOR is not set). Redirected output stays plain text.

namespace sa {

namespace {

constexpr size_t kWidth = 62;     // total width of banners / section rules
constexpr size_t kLabel = 22;     // width of the label column (label + at least one space)

bool g_color = false;             // ANSI colors active?

// ---- palette (empty strings when color is off) ----
const wchar_t* K(const wchar_t* code) { return g_color ? code : L""; }
const wchar_t* Rst()  { return K(L"\x1b[0m");  }
const wchar_t* Bold() { return K(L"\x1b[1m");  }
const wchar_t* Dim()  { return K(L"\x1b[90m"); }
const wchar_t* Lbl()  { return K(L"\x1b[37m"); }
const wchar_t* Red()  { return K(L"\x1b[91m"); }
const wchar_t* Grn()  { return K(L"\x1b[92m"); }
const wchar_t* Yel()  { return K(L"\x1b[93m"); }
const wchar_t* Cyn()  { return K(L"\x1b[96m"); }
const wchar_t* Blu()  { return K(L"\x1b[94m"); }
const wchar_t* Wht()  { return K(L"\x1b[97m"); }

// ---- glyphs: Unicode on a color console, ASCII otherwise (safe for log files) ----
const wchar_t* GHLine()  { return g_color ? L"\u2500" : L"-"; }
const wchar_t* GFull()   { return g_color ? L"\u2588" : L"#"; }
const wchar_t* GEmpty()  { return g_color ? L"\u2591" : L"."; }
const wchar_t* GTee()    { return g_color ? L"\u251C\u2500" : L"|-"; }
const wchar_t* GCorner() { return g_color ? L"\u2514\u2500" : L"`-"; }
const wchar_t* GBranch() { return g_color ? L"\u2502  " : L"|  "; }

std::wostream& out() { return std::wcout; }

std::wstring Repeat(const wchar_t* s, size_t n) {
    std::wstring r;
    for (size_t i = 0; i < n; ++i) r += s;
    return r;
}

std::wstring PadRight(const std::wstring& s, size_t w) {
    return s.size() >= w ? s : s + std::wstring(w - s.size(), L' ');
}
std::wstring PadLeft(const std::wstring& s, size_t w) {
    return s.size() >= w ? s : std::wstring(w - s.size(), L' ') + s;
}

template <typename T>
std::wstring Num(T v) {
    std::wostringstream o;
    o << v;
    return o.str();
}

// Progress bar: `frac` in [0,1].
std::wstring Bar(double frac, size_t width, const wchar_t* color) {
    if (frac < 0) frac = 0;
    if (frac > 1) frac = 1;
    const size_t filled = static_cast<size_t>(frac * static_cast<double>(width) + 0.5);
    std::wstring s;
    s += color;
    s += Repeat(GFull(), filled);
    s += Dim();
    s += Repeat(GEmpty(), width - filled);
    s += Rst();
    return s;
}

// ---- layout helpers ----
void Banner(const wchar_t* title) {
    out() << Bold() << Cyn() << title << Rst() << L"\n";
    out() << Dim() << Repeat(GHLine(), kWidth) << Rst() << L"\n";
}

void Section(const wchar_t* title) {
    const std::wstring t = title;
    const size_t used = 3 + t.size() + 1;
    out() << L"\n" << Dim() << Repeat(GHLine(), 2) << L" " << Rst()
          << Bold() << Cyn() << t << Rst()
          << Dim() << L" " << Repeat(GHLine(), kWidth > used ? kWidth - used : 1) << Rst()
          << L"\n";
}

void SubHeader(const std::wstring& title, const std::wstring& right, const wchar_t* rightColor) {
    out() << L"  " << Bold() << Wht() << title << Rst();
    if (!right.empty()) out() << L"  " << rightColor << right << Rst();
    out() << L"\n";
}

// "  Label ............ value"
void KV(const wchar_t* label, const std::wstring& value, const wchar_t* color = nullptr) {
    out() << L"  " << Lbl() << PadRight(std::wstring(label) + L" ", kLabel) << Rst()
          << (color ? color : Wht()) << value << Rst() << L"\n";
}

// Pair short facts only when their full values fit; never truncate report data.
void Pair(const wchar_t* first, const std::wstring& value, const wchar_t* second,
          const std::wstring& other, const wchar_t* color = nullptr, const wchar_t* otherColor = nullptr) {
    CONSOLE_SCREEN_BUFFER_INFO info{};
    size_t width = 100; // plain reports have a predictable, readable width
    if (::GetConsoleScreenBufferInfo(::GetStdHandle(STD_OUTPUT_HANDLE), &info))
        width = static_cast<size_t>(info.srWindow.Right - info.srWindow.Left + 1);
    const size_t cell = (std::max)(kLabel, std::wstring(first).size() + 1) + value.size();
    const size_t secondCell = (std::max)(kLabel, std::wstring(second).size() + 1) + other.size();
    const size_t column = (std::max)(size_t{46}, cell + 3);
    if (column + secondCell + 2 > width) {
        KV(first, value, color); KV(second, other, otherColor ? otherColor : color); return;
    }
    out() << L"  " << Lbl() << PadRight(std::wstring(first) + L" ", kLabel) << Rst()
          << (color ? color : Wht()) << value << Rst() << std::wstring(column - cell, L' ')
          << Lbl() << PadRight(std::wstring(second) + L" ", kLabel) << Rst()
          << (otherColor ? otherColor : color ? color : Wht()) << other << Rst() << L"\n";
}

void Flag(const wchar_t* label, bool on) {
    KV(label, on ? L"ENABLED" : L"DISABLED", on ? Grn() : Red());
}

void Flag(const wchar_t* label, bool on, Status status) {
    if (status == Status::Success) Flag(label, on);
    else KV(label, L"Unknown (" + std::wstring(ToW(status)) + L")", Yel());
}

void FlagPair(const wchar_t* first, bool enabled, Status status,
              const wchar_t* second, bool otherEnabled, Status otherStatus) {
    auto text = [](bool on, Status known) {
        return known == Status::Success ? std::wstring(on ? L"ENABLED" : L"DISABLED")
            : L"Unknown (" + std::wstring(ToW(known)) + L")";
    };
    // Keep an explicit status word; color is supplementary and never the only signal.
    Pair(first, text(enabled, status), second, text(otherEnabled, otherStatus),
        status != Status::Success ? Yel() : enabled ? Grn() : Red(),
        otherStatus != Status::Success ? Yel() : otherEnabled ? Grn() : Red());
}

std::wstring UpdateTypes(const WindowsUpdateItem& item) {
    std::vector<std::wstring> labels;
    auto add = [&](const std::wstring& label) {
        if (!label.empty() && std::none_of(labels.begin(), labels.end(), [&](const auto& existing) { return IEquals(existing, label); }))
            labels.push_back(label);
    };
    if (item.optional == Tri::Yes) add(L"Optional");
    for (const auto& classification : item.classifications) add(classification);
    if (item.classifications.empty()) add(item.updateType.empty() ? L"Type unknown" : item.updateType);
    if (!item.severity.empty()) add(L"Severity: " + item.severity);
    std::wstring text;
    for (const auto& label : labels) { if (!text.empty()) text += L"; "; text += label; }
    return text;
}

// ---- ANSI mode RAII ----
class ConsoleStyle {
public:
    ConsoleStyle() {
        wchar_t buffer[1]{};
        if (::GetEnvironmentVariableW(L"NO_COLOR", buffer, _countof(buffer)) != 0) return;

        h_ = ::GetStdHandle(STD_OUTPUT_HANDLE);
        if (h_ == INVALID_HANDLE_VALUE || h_ == nullptr) return;
        if (!::GetConsoleMode(h_, &orig_)) return;           // redirected to file/pipe
        if (::SetConsoleMode(h_, orig_ | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        changed_ = true;
        g_color = true;
        }
    }
    ~ConsoleStyle() {
        if (g_color) out() << Rst();
        out().flush();
        if (changed_) ::SetConsoleMode(h_, orig_);
        g_color = false;
    }
    ConsoleStyle(const ConsoleStyle&) = delete;
    ConsoleStyle& operator=(const ConsoleStyle&) = delete;
private:
    HANDLE h_ = nullptr;
    DWORD orig_ = 0;
    bool changed_ = false;
};

std::wstring GroupName(const std::string& category) {
    return category == "OS Security" ? L"Operating System" : Utf8ToWide(category);
}

const wchar_t* OutcomeColor(int awarded, int max) {
    return awarded >= max ? Grn() : (awarded <= 0 ? Red() : Yel());
}

} // namespace

void RenderConsole(const AssessmentResult& r) {
    ConsoleStyle style;

    Banner(L"Windows Security & Privacy Assessment");

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
            + L" / " + (r.security.tpm.ready ? L"Ready" : L"NotReady");
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
        const bool virt = CpuVirtualizationAvailable(r.cpu);
        KV(L"Virtualization", virt ? L"Supported" : L"Unsupported", virt ? Grn() : Red());
    }
    const Status runningStatus = r.security.virt.runningServicesKnown ? Status::Success : Status::Unavailable;
    FlagPair(L"VBS", r.security.virt.vbsEnabled, r.security.virt.status,
             L"HVCI", r.security.virt.hvciEnabled, runningStatus);
    Flag(L"Credential Guard", r.security.virt.credentialGuardRunning, runningStatus);
    if (r.security.virt.hvciConfigured != Tri::Unknown)
        KV(L"HVCI configured", ToW(r.security.virt.hvciConfigured), Yel());

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
            KV(L"Periodic scan note", L"Defender did not report a recognized running mode.", Yel());
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
                KV(L"Antivirus score", Num(score.awardedPoints) + L" / " + Num(score.maxPoints),
                   OutcomeColor(score.awardedPoints, score.maxPoints));
            }
            KV(L"Signatures current", ToW(av.signaturesUpToDate));
        }
        KV(L"Overall contribution", L"At most " + Num(kMalwareProtectionMaxPoints) +
            L" points; product scores are independent.", Dim());
    }
    if (r.antivirus.status != Status::Success && !r.antivirus.reason.empty())
        KV(L"Antivirus query", r.antivirus.reason, Yel());

    SubHeader(L"Windows Firewall", L"", Dim());
    for (auto& p : r.firewall.profiles)
        Flag((p.name).c_str(), p.enabled, p.status);

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
              << v.bitLockerState << Rst();
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

    // ------------------------------------------------------------ Applications
    Section(L"Applications");
    for (auto& category : r.applications) {
        const bool complete = category.status == Status::Success || category.status == Status::NotFound;
        SubHeader(category.name,
                  !complete ? L"Incomplete (" + std::wstring(ToW(category.status)) + L")"
                  : category.apps.empty() ? std::wstring(L"none found")
                                        : Num(category.apps.size()) + L" found",
                  !complete ? Yel() : category.apps.empty() ? Dim() : Grn());
        for (auto& app : category.apps) {
            out() << L"    " << Grn() << L"[+] " << Rst() << Bold() << Wht() << app.name << Rst();
            if (!app.version.empty()) out() << L"  " << Cyn() << app.version << Rst();
            out() << L"\n";
            for (size_t i = 0; i < app.locations.size(); ++i) {
                const auto& loc = app.locations[i];
                const bool lastLoc = (i + 1 == app.locations.size());
                out() << L"        " << Dim() << (lastLoc ? GCorner() : GTee()) << Rst() << L" "
                      << Dim() << loc.path << Rst();
                // Only mention a version here when it differs from the one shown above.
                if (!loc.version.empty() && loc.version != app.version)
                    out() << L"  " << Dim() << L"(" << loc.version << L")" << Rst();
                out() << L"\n";
            }
        }
    }

    // ------------------------------------------------------------ Threshold findings
    Section(L"Threshold Findings");
    SubHeader(L"Registry", L"", Dim());
    bool anyReg = false;
    for (auto& f : r.registryFindings) {
        if (f.status != Status::Success && f.status != Status::NotFound) {
            anyReg = true;
            KV(f.name.c_str(), ToW(f.status), Yel());
        }
        if (f.exceeded) {
            anyReg = true;
            out() << L"  " << Yel() << L"[!] " << Rst() << Bold() << f.name << Rst() << L": " << f.path
                  << L" contains " << f.valueCount << L" values (threshold: "
                  << f.threshold << L")\n";
        }
    }
    if (!anyReg) out() << L"  " << Grn() << L"none exceeded" << Rst() << L"\n";

    SubHeader(L"Directories", L"", Dim());
    bool anyDir = false;
    for (auto& f : r.directoryFindings) {
        if (f.status != Status::Success && f.status != Status::NotFound) {
            anyDir = true;
            KV(f.name.c_str(), ToW(f.status), Yel());
        }
        if (f.exceeded) {
            anyDir = true;
            out() << L"  " << Yel() << L"[!] " << Rst() << f.path << L" contains " << f.fileCount
                  << L" files (threshold: " << f.threshold << L")\n";
        }
    }
    if (!anyDir) out() << L"  " << Grn() << L"none exceeded" << Rst() << L"\n";

    // ------------------------------------------------------------ Privacy
    Section(L"Privacy (informational)");
    std::vector<std::wstring> privacyGroups;
    for (const auto& finding : r.privacyFindings)
        if (std::find(privacyGroups.begin(), privacyGroups.end(), finding.group) == privacyGroups.end())
            privacyGroups.push_back(finding.group);
    for (const auto& group : privacyGroups) {
        if (!group.empty()) SubHeader(group, L"", Dim());
        for (const auto& finding : r.privacyFindings) {
            if (finding.group != group) continue;
            out() << L"    " << Lbl() << PadRight(finding.name + L" ", 29) << Rst()
                  << (finding.status == Status::Success ? Cyn() : finding.status == Status::NotFound ? Dim() : Yel())
                  << finding.value << Rst();
            if (!finding.scope.empty()) out() << Dim() << L"  [" << finding.scope << L"]" << Rst();
            out() << L"\n";
        }
    }
    KV(L"Permission scope", L"Defaults only; per-app overrides and desktop-app exceptions can apply.", Dim());

    // ------------------------------------------------------------ Score
    out() << L"\n";
    Banner(L"SECURITY SCORE");
    {
        const double frac = r.score.maximum > 0
            ? static_cast<double>(r.score.total) / static_cast<double>(r.score.maximum) : 0.0;
        const wchar_t* c = frac >= 0.80 ? Grn() : (frac >= 0.50 ? Yel() : Red());
        out() << L"  " << Bold() << c << r.score.total << Rst()
              << Lbl() << L" / " << r.score.maximum << Rst() << L"     "
              << Bar(frac, 28, c) << L"  " << c
              << static_cast<unsigned>(frac * 100.0 + 0.5) << L"%" << Rst() << L"\n";
    }

    out() << L"\n  " << Dim() << L"Rule breakdown (awarded / max)" << Rst() << L"\n";

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

    out() << L"\n  " << Dim()
          << L"This is a hardening posture score. It does not guarantee security."
          << Rst() << L"\n";
}

} // namespace sa
