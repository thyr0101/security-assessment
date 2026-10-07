#include "ConsoleRenderer.h"
#include "../Utilities.h"
#include <windows.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

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
const wchar_t* Wht()  { return K(L"\x1b[97m"); }

// ---- glyphs: Unicode on a color console, ASCII otherwise (safe for log files) ----
const wchar_t* GHLine()  { return g_color ? L"\u2500" : L"-"; }
const wchar_t* GHeavy()  { return g_color ? L"\u2550" : L"="; }
const wchar_t* GTL()     { return g_color ? L"\u2554" : L"+"; }
const wchar_t* GTR()     { return g_color ? L"\u2557" : L"+"; }
const wchar_t* GBL()     { return g_color ? L"\u255A" : L"+"; }
const wchar_t* GBR()     { return g_color ? L"\u255D" : L"+"; }
const wchar_t* GVert()   { return g_color ? L"\u2551" : L"|"; }
const wchar_t* GFull()   { return g_color ? L"\u2588" : L"#"; }
const wchar_t* GEmpty()  { return g_color ? L"\u2591" : L"."; }
const wchar_t* GTee()    { return g_color ? L"\u251C\u2500" : L"|-"; }
const wchar_t* GCorner() { return g_color ? L"\u2514\u2500" : L"`-"; }

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
    const size_t inner = kWidth - 2;
    const std::wstring t = title;
    const size_t left = (inner - t.size()) / 2;
    const size_t right = inner - t.size() - left;
    out() << Cyn() << GTL() << Repeat(GHeavy(), inner) << GTR() << Rst() << L"\n"
          << Cyn() << GVert() << Rst() << std::wstring(left, L' ')
          << Bold() << Wht() << t << Rst() << std::wstring(right, L' ')
          << Cyn() << GVert() << Rst() << L"\n"
          << Cyn() << GBL() << Repeat(GHeavy(), inner) << GBR() << Rst() << L"\n";
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
    out() << L"\n  " << Bold() << Wht() << title << Rst();
    if (!right.empty()) out() << L"  " << rightColor << right << Rst();
    out() << L"\n";
}

// "  Label ............ value"
void KV(const wchar_t* label, const std::wstring& value, const wchar_t* color = nullptr) {
    out() << L"  " << Lbl() << PadRight(std::wstring(label) + L" ", kLabel) << Rst()
          << (color ? color : Wht()) << value << Rst() << L"\n";
}

void Flag(const wchar_t* label, bool on) {
    KV(label, on ? L"ENABLED" : L"DISABLED", on ? Grn() : Red());
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

const wchar_t* GroupName(const std::string& id) {
    const std::string p = id.substr(0, id.find('.'));
    if (p == "hw")  return L"Hardware Security";
    if (p == "os")  return L"Operating System";
    if (p == "mp")  return L"Malware Protection";
    if (p == "net") return L"Network Security";
    if (p == "enc") return L"Encryption";
    if (p == "acc") return L"Account Security";
    if (p == "hyg") return L"Software Hygiene";
    return L"Other";
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
    KV(L"Build", Num(r.os.build) + L"." + Num(r.os.ubr));
    KV(L"Architecture", r.os.architecture);
    KV(L"Computer", r.os.computerName);
    KV(L"User", r.os.userName);
    KV(L"CPU", r.cpu.brand);
    KV(L"Cores / Logical", Num(r.cpu.physicalCores) + L" / " + Num(r.cpu.logicalProcessors));
    KV(L"RAM", FormatBytes(r.memory.totalBytes) + L"   (available " +
                   FormatBytes(r.memory.availableBytes) + L")");
    KV(L"Elevated", r.security.isElevated ? L"Yes" : L"No",
       r.security.isElevated ? Grn() : Yel());
    KV(L"Uptime", Num(r.os.uptimeSeconds / 3600) + L"h " +
                      Num((r.os.uptimeSeconds % 3600) / 60) + L"m");
    KV(L"Timezone", r.os.timeZone);
    KV(L"Locale", r.os.locale);

    // ------------------------------------------------------------ Hardware security
    Section(L"Hardware Security");
    {
        const std::wstring tpmText =
            (r.security.tpm.present
                ? (r.security.tpm.specVersion.empty() ? std::wstring(L"Present")
                                                      : r.security.tpm.specVersion)
                : std::wstring(L"Absent"))
            + L" / " + (r.security.tpm.ready ? L"Ready" : L"NotReady");
        KV(L"TPM", tpmText,
           (r.security.tpm.present && r.security.tpm.ready) ? Grn() : Red());
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
    Flag(L"VBS", r.security.virt.vbsEnabled);
    Flag(L"HVCI", r.security.virt.hvciEnabled);
    Flag(L"Credential Guard", r.security.virt.credentialGuardRunning);

    // ------------------------------------------------------------ Protection
    Section(L"Protection");
    SubHeader(L"Microsoft Defender", L"", Dim());
    Flag(L"Defender", r.defender.enabled);
    Flag(L"Real-Time", r.defender.realTimeProtection);
    Flag(L"Behavior Monitoring", r.defender.behaviorMonitor);
    Flag(L"IOAV Protection", r.defender.ioav);
    Flag(L"Cloud Protection", r.defender.cloudProtection);
    Flag(L"Tamper Protection", r.defender.tamperProtection);
    KV(L"Engine Version", r.defender.amEngineVersion);
    KV(L"Signatures Version", r.defender.antivirusSignatureVersion);
    if (!r.defender.reason.empty())
        KV(L"Note", r.defender.reason, Yel());

    SubHeader(L"Windows Firewall", L"", Dim());
    for (auto& p : r.firewall.profiles)
        Flag((p.name).c_str(), p.enabled);

    // ------------------------------------------------------------ Storage
    Section(L"Storage");
    SubHeader(L"Volumes", L"", Dim());
    for (auto& v : r.storage.volumes) {
        const std::wstring freeTxt = FormatBytes(v.freeBytes);
        const std::wstring totalTxt = FormatBytes(v.totalBytes);
        const size_t sizeCol = 28;                                   // keeps the usage bars aligned
        const size_t shown = 6 + freeTxt.size() + 3 + totalTxt.size(); // " Free " + a + " / " + b
        out() << L"  " << Bold() << Wht() << PadRight(v.mountPoint, 5) << Rst()
              << Lbl() << PadRight(v.filesystem, 6) << Rst()
              << L" Free " << Wht() << freeTxt << Rst()
              << L" / " << Wht() << totalTxt << Rst()
              << std::wstring(sizeCol > shown ? sizeCol - shown : 0, L' ');
        if (v.totalBytes > 0) {
            const unsigned long long freeB = v.freeBytes > v.totalBytes ? v.totalBytes : v.freeBytes;
            const double used = static_cast<double>(v.totalBytes - freeB) /
                                static_cast<double>(v.totalBytes);
            const wchar_t* c = used < 0.75 ? Grn() : (used < 0.90 ? Yel() : Red());
            out() << L"  " << Bar(used, 20, c) << L" "
                  << PadLeft(Num(static_cast<unsigned>(used * 100.0 + 0.5)), 3) << L"% used";
        }
        out() << L"\n";

        const wchar_t* blc = v.bitLockerState == L"On" ? Grn()
                           : (v.bitLockerState == L"Off" ? Red() : Yel());
        out() << L"        " << Lbl() << PadRight(L"BitLocker", 12) << Rst()
              << blc << v.bitLockerState << Rst() << L"\n";
        if (!v.encryptionMethod.empty())
            out() << L"        " << Lbl() << PadRight(L"Encryption", 12) << Rst()
                  << Cyn() << v.encryptionMethod << Rst() << L"\n";
        if (v.bitLockerState == L"Unknown" && !v.bitLockerNote.empty())
            out() << L"        " << Lbl() << PadRight(L"Note", 12) << Rst()
                  << Yel() << v.bitLockerNote << Rst() << L"\n";
    }

    SubHeader(L"Physical Disks", L"", Dim());
    for (auto& d : r.storage.disks) {
        const std::wstring name = d.vendor.empty() ? d.model : d.vendor + L" " + d.model;
        out() << L"  " << Bold() << Wht() << PadRight(L"Disk" + Num(d.index), 7) << Rst()
              << Wht() << PadRight(name, 26) << Rst()
              << PadLeft(FormatBytes(d.sizeBytes), 9) << L"   "
              << Cyn() << PadRight(d.busType, 7) << Rst()
              << Lbl() << d.mediaType << Rst() << L"\n";
    }

    // ------------------------------------------------------------ Applications
    Section(L"Applications");
    for (auto& category : r.applications) {
        SubHeader(category.name,
                  category.apps.empty() ? std::wstring(L"none found")
                                        : Num(category.apps.size()) + L" found",
                  category.apps.empty() ? Dim() : Grn());
        for (auto& app : category.apps) {
            out() << L"    " << Grn() << L"[+] " << Rst() << Bold() << Wht() << app.name << Rst();
            if (!app.version.empty()) out() << L"  " << Cyn() << app.version << Rst();
            out() << L"\n";
            for (size_t i = 0; i < app.locations.size(); ++i) {
                const auto& loc = app.locations[i];
                const bool lastLoc = (i + 1 == app.locations.size());
                out() << L"        " << Dim() << (lastLoc ? GCorner() : GTee()) << Rst() << L" "
                      << Lbl() << loc.path << Rst();
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
        if (f.exceeded) {
            anyDir = true;
            out() << L"  " << Yel() << L"[!] " << Rst() << f.path << L" contains " << f.fileCount
                  << L" files (threshold: " << f.threshold << L")\n";
        }
    }
    if (!anyDir) out() << L"  " << Grn() << L"none exceeded" << Rst() << L"\n";

    // ------------------------------------------------------------ Privacy
    Section(L"Privacy (informational)");
    for (auto& p : r.privacyFindings)
        KV(p.name.c_str(), p.value);

    // ------------------------------------------------------------ Score
    out() << L"\n";
    Banner(L"SECURITY SCORE");
    {
        const double frac = r.score.maximum > 0
            ? static_cast<double>(r.score.total) / static_cast<double>(r.score.maximum) : 0.0;
        const wchar_t* c = frac >= 0.80 ? Grn() : (frac >= 0.50 ? Yel() : Red());
        out() << L"\n      " << Bold() << c << r.score.total << Rst()
              << Lbl() << L" / " << r.score.maximum << Rst() << L"     "
              << Bar(frac, 28, c) << L"  " << c
              << static_cast<unsigned>(frac * 100.0 + 0.5) << L"%" << Rst() << L"\n";
    }

    out() << L"\n  " << Dim() << L"Rule breakdown (awarded / max)" << Rst() << L"\n";

    // Rules arrive grouped by id prefix; keep their order and add a sub-heading per group.
    std::vector<std::string> prefixes;
    for (auto& rl : r.score.rules) {
        if (rl.maxPoints == 0) continue;               // informational-only entries
        const std::string p = rl.id.substr(0, rl.id.find('.'));
        bool seen = false;
        for (auto& q : prefixes) if (q == p) { seen = true; break; }
        if (!seen) prefixes.push_back(p);
    }
    for (auto& prefix : prefixes) {
        int gAwarded = 0, gMax = 0;
        for (auto& rl : r.score.rules) {
            if (rl.maxPoints == 0) continue;
            if (rl.id.substr(0, rl.id.find('.')) != prefix) continue;
            gAwarded += rl.awardedPoints;
            gMax += rl.maxPoints;
        }
        SubHeader(GroupName(prefix + "."),
                  PadLeft(Num(gAwarded), 3) + L" / " + PadLeft(Num(gMax), 3),
                  OutcomeColor(gAwarded, gMax));
        for (auto& rl : r.score.rules) {
            if (rl.maxPoints == 0) continue;
            if (rl.id.substr(0, rl.id.find('.')) != prefix) continue;
            const wchar_t* c = OutcomeColor(rl.awardedPoints, rl.maxPoints);
            out() << L"    " << c << PadLeft(Num(rl.awardedPoints), 3) << Rst() << Dim() << L" / " << Rst()
                  << Lbl() << PadLeft(Num(rl.maxPoints), 3) << Rst() << L"   "
                  << PadRight(Utf8ToWide(rl.description), 36)
                  << c << L"[" << Utf8ToWide(rl.state) << L"]" << Rst() << L"\n";
        }
    }

    out() << L"\n  " << Dim()
          << L"This is a hardening posture score. It does not guarantee security."
          << Rst() << L"\n";
}

} // namespace sa
