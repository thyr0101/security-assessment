#pragma once
#include "ConsoleRenderer.h"
#include "../Utilities.h"
#include <algorithm>
#include <concepts>
#include <iostream>
#include <sstream>
#include <string_view>

namespace sa::console_detail {

// One renderer owns terminal mode, palette and section buffers. Helpers stay
// independent of collection/scoring, and every category follows the same layout.
class ConsoleLayout {
public:
    ConsoleLayout() {
        h_ = ::GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO info{};
        const size_t columns = ::GetConsoleScreenBufferInfo(h_, &info)
            ? static_cast<size_t>((std::max)(12, int(info.srWindow.Right - info.srWindow.Left + 1))) : 100;
        width_ = columns - 7; // Leave margins, border and rightmost console cell.
        const bool console = ::GetConsoleMode(h_, &orig_) != FALSE;
        wchar_t noColor[1]{};
        if (!console || ::GetEnvironmentVariableW(L"NO_COLOR", noColor, 1)) return;
        changed_ = ::SetConsoleMode(h_, orig_ | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != FALSE;
        color_ = changed_;
    }
    // Explicit capabilities also support deterministic rendering into a capture.
    ConsoleLayout(size_t columns, bool color)
        : width_((std::max)(size_t{12}, columns) - 7), color_(color) {}
    ~ConsoleLayout() {
        // Render closes all sections explicitly, including the last one.
        if (changed_) ::SetConsoleMode(h_, orig_);
    }
    ConsoleLayout(const ConsoleLayout&) = delete;
    ConsoleLayout& operator=(const ConsoleLayout&) = delete;
    void Render(const AssessmentResult& result, ReportView view);
private:
    HANDLE h_ = nullptr;
    DWORD orig_ = 0;
    bool changed_ = false;
    bool sectionOpen_ = false;
    bool sectionWarning_ = false;
    std::wstring sectionTitle_;
    std::wostringstream section_;

    static constexpr size_t kLabel = 22;     // width of the label column (label + at least one space)

    size_t width_ = 93;
    bool color_ = false;             // ANSI colors active?

    // ---- palette (empty strings when color is off) ----
    const wchar_t* K(const wchar_t* code) { return color_ ? code : L""; }
    const wchar_t* Rst()  { return K(L"\x1b[0m");  }
    const wchar_t* Bold() { return K(L"\x1b[1m");  }
    const wchar_t* Dim()  { return K(L"\x1b[90m"); }
    const wchar_t* Lbl()  { return K(L"\x1b[37m"); }
    const wchar_t* Red()  { return K(L"\x1b[91m"); }
    const wchar_t* Grn()  { return K(L"\x1b[92m"); }
    const wchar_t* Yel()  { return K(L"\x1b[93m"); }
    const wchar_t* Purple() { return K(L"\x1b[38;2;190;128;255m"); }
    const wchar_t* Orange() { return K(L"\x1b[38;2;255;165;0m"); }
    const wchar_t* LightYellow() { return K(L"\x1b[38;2;255;235;153m"); }
    const wchar_t* Cyn()  { return K(L"\x1b[96m"); }
    const wchar_t* Blu()  { return K(L"\x1b[94m"); }
    const wchar_t* Wht()  { return K(L"\x1b[97m"); }

    // ---- glyphs: Unicode on a color console, ASCII otherwise (safe for log files) ----
    const wchar_t* GHLine()  { return color_ ? L"\u2500" : L"-"; }
    const wchar_t* GFull()   { return color_ ? L"\u2588" : L"#"; }
    const wchar_t* GEmpty()  { return color_ ? L"\u2591" : L"."; }
    const wchar_t* GTee()    { return color_ ? L"\u251C\u2500" : L"|-"; }
    const wchar_t* GCorner() { return color_ ? L"\u2514\u2500" : L"`-"; }
    const wchar_t* GBranch() { return color_ ? L"\u2502  " : L"|  "; }
    const wchar_t* GDot()    { return color_ ? L"\u00B7" : L"."; }

    std::wostream& out() { return sectionOpen_ ? section_ : std::wcout; }

    std::wstring Repeat(const wchar_t* s, size_t n) {
        std::wstring r;
        const auto length = std::char_traits<wchar_t>::length(s);
        r.reserve(length * n);
        for (size_t i = 0; i < n; ++i) r += s;
        return r;
    }

    std::wstring PadRight(const std::wstring& s, size_t w) {
        const auto columns = Columns(s);
        return columns >= w ? s : s + std::wstring(w - columns, L' ');
    }
    std::wstring PadLeft(const std::wstring& s, size_t w) {
        const auto columns = Columns(s);
        return columns >= w ? s : std::wstring(w - columns, L' ') + s;
    }

    template <std::integral T>
    std::wstring Num(T v) {
        return std::to_wstring(v);
    }

    // Progress bar: `frac` in [0,1].
    std::wstring Bar(double frac, size_t width, const wchar_t* color) {
        frac = std::clamp(frac, 0.0, 1.0);
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
    }

    // Notices use the same wrapping and borders, highlighted in red.
    void Notice(const wchar_t* title, const wchar_t* message) {
        Section(title);
        sectionWarning_ = true;
        Paragraph(message, 2, Red());
        EndSection();
    }

    // Start a category; flush the previous category as one framed block.
    void Section(const wchar_t* title) {
        EndSection();
        sectionTitle_ = title;
        sectionOpen_ = true;
    }

    void SubHeader(const std::wstring& title, const std::wstring& right, const wchar_t* rightColor, const wchar_t* titleColor = nullptr) {
        out() << L"\n  " << Purple() << L"[+] " << Rst() << Bold() << (titleColor ? titleColor : Wht()) << title << Rst();
        if (!right.empty()) out() << L"  " << rightColor << right << Rst();
        out() << L"\n";
    }

    // Indented facts use a subtle dot; headings and trees show the hierarchy.
    void KV(const wchar_t* label, const std::wstring& value, const wchar_t* color = nullptr) {
        out() << L"    " << Dim() << GDot() << L" " << Lbl() << PadRight(std::wstring(label) + L" ", kLabel) << Rst()
              << (color ? color : Wht()) << value << Rst() << L"\n";
    }

    // Pair short facts only when their full values fit; never truncate report data.
    void Pair(const wchar_t* first, const std::wstring& value, const wchar_t* second,
              const std::wstring& other, const wchar_t* color = nullptr, const wchar_t* otherColor = nullptr) {
        const size_t width = width_;
        const size_t cell = (std::max)(kLabel, Columns(first) + 1) + Columns(value);
        const size_t secondCell = (std::max)(kLabel, Columns(second) + 1) + Columns(other);
        const size_t column = (std::max)(size_t{46}, cell + 3);
        if (column + secondCell + 8 > width) {
            KV(first, value, color); KV(second, other, otherColor ? otherColor : color); return;
        }
        out() << L"    " << Dim() << GDot() << L" " << Lbl() << PadRight(std::wstring(first) + L" ", kLabel) << Rst()
              << (color ? color : Wht()) << value << Rst() << std::wstring(column - cell, L' ')
              << Dim() << GDot() << L" " << Lbl() << PadRight(std::wstring(second) + L" ", kLabel) << Rst()
              << (otherColor ? otherColor : color ? color : Wht()) << other << Rst() << L"\n";
    }

    void Paragraph(std::wstring_view text, size_t indent, const wchar_t* color) {
        // The box handles wrapping once, preserving Unicode character boundaries.
        if (!text.empty()) out() << std::wstring(indent, L' ') << color << text << Rst() << L"\n";
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

    std::wstring GroupName(const std::string& category) {
        return category == "OS Security" ? L"Operating System" : Utf8ToWide(category);
    }

    const wchar_t* CategoryScoreColor(int awarded, int maximum) {
        if (maximum > 0 && awarded >= maximum) return Grn();
        return maximum > 0 && static_cast<double>(awarded) / maximum > 0.5 ? Orange() : Yel();
    }

    const wchar_t* OutcomeColor(int awarded, int max) {
        return awarded >= max ? Grn() : (awarded <= 0 ? Red() : Yel());
    }


    // Skip ANSI styles when measuring cells.
    static size_t EscapeLength(std::wstring_view text, size_t at) {
        if (text[at] != L'\x1b' || at + 1 >= text.size()) return 0;
        if (text[at + 1] == L'[') {
            const auto end = text.find(L'm', at + 2);
            return end == text.npos ? 0 : end - at + 1;
        }
        return 0;
    }
    static size_t GlyphLength(std::wstring_view text, size_t at) {
        return text[at] >= 0xD800 && text[at] <= 0xDBFF && at + 1 < text.size() &&
            text[at + 1] >= 0xDC00 && text[at + 1] <= 0xDFFF ? 2 : 1;
    }
    static size_t GlyphWidth(std::wstring_view text, size_t at) {
        if (text[at] < 0x80) return 1;
        if (GlyphLength(text, at) == 2) return 2;
        WORD type = 0;
        if (::GetStringTypeW(CT_CTYPE3, text.data() + at, 1, &type)) {
            if ((type & C3_NONSPACING) || (text[at] >= 0xFE00 && text[at] <= 0xFE0F)) return 0;
            if (type & (C3_FULLWIDTH | C3_IDEOGRAPH)) return 2;
        }
        return 1;
    }
    static size_t Columns(std::wstring_view text) {
        size_t width = 0;
        for (size_t at = 0; at < text.size();) {
            if (const size_t escape = EscapeLength(text, at)) at += escape;
            else { width += GlyphWidth(text, at); at += GlyphLength(text, at); }
        }
        return width;
    }
    void Edge(bool top, std::wstring_view title = {}) {
        auto& target = std::wcout;
        target << L"  " << (sectionWarning_ ? Red() : Dim()) << (color_ ? (top ? L"\u250C" : L"\u2514") : L"+");
        const auto titleWidth = Columns(title);
        if (!title.empty() && titleWidth + 1 <= width_) {
            target << GHLine() << L" " << Bold() << (sectionWarning_ ? Red() : Cyn()) << title << Rst() << (sectionWarning_ ? Red() : Dim()) << L" "
                   << Repeat(GHLine(), width_ - titleWidth - 1);
        } else target << Repeat(GHLine(), width_ + 2);
        target << (color_ ? (top ? L"\u2510" : L"\u2518") : L"+") << Rst() << L"\n";
    }
    void Rows(std::wstring_view text) {
        const auto vertical = color_ ? L"\u2502" : L"|";
        std::wstring active;
        const auto leading = text.find_first_not_of(L' ');
        const size_t continuationIndent = (std::min)(leading == text.npos ? size_t{0} : leading, width_ / 3);
        bool continuation = false;
        do {
            const size_t indent = continuation ? continuationIndent : 0;
            const size_t available = width_ - indent;
            size_t at = 0, width = 0, space = 0;
            while (at < text.size()) {
                if (const size_t escape = EscapeLength(text, at)) { at += escape; continue; }
                const auto cells = GlyphWidth(text, at);
                if (width + cells > available) break;
                width += cells;
                if (text[at] == L' ' && width > available / 2) space = at;
                at += GlyphLength(text, at);
            }
            if (at < text.size() && space) at = space;
            const auto part = text.substr(0, at);
            width = Columns(part);
            std::wcout << (sectionWarning_ ? Red() : Dim()) << L"  " << vertical << Rst() << L" " << std::wstring(indent, L' ') << active << part;
            // Reapply the content's style after each border; borders never inherit it.
            for (size_t i = 0; i < part.size();) {
                const auto escape = EscapeLength(part, i);
                if (!escape) { i += GlyphLength(part, i); continue; }
                const auto code = part.substr(i, escape);
                if (code == L"\x1b[0m") active.clear();
                else active += code;
                i += escape;
            }
            std::wcout << Rst() << std::wstring(width_ - indent - width, L' ')
                       << L" " << (sectionWarning_ ? Red() : Dim()) << vertical << Rst() << L"\n";
            text.remove_prefix(at);
            if (space && at == space && !text.empty()) text.remove_prefix(1);
            continuation = true;
        } while (!text.empty());
    }
    void EndSection() {
        if (!sectionOpen_) return;
        sectionOpen_ = false;
        std::wcout << L"\n";
        const bool titleFits = Columns(sectionTitle_) + 1 <= width_;
        Edge(true, titleFits ? std::wstring_view(sectionTitle_) : std::wstring_view{});
        if (!titleFits) Rows(std::wstring(Bold()) + (sectionWarning_ ? Red() : Cyn()) + sectionTitle_ + Rst());
        auto text = section_.view();
        while (!text.empty() && text.front() == L'\n') text.remove_prefix(1);
        while (!text.empty() && text.back() == L'\n') text.remove_suffix(1);
        while (!text.empty()) {
            const auto end = text.find(L'\n');
            Rows(text.substr(0, end));
            if (end == text.npos) break;
            text.remove_prefix(end + 1);
        }
        Edge(false);
        section_.str(L"");
        section_.clear();
        sectionWarning_ = false;
    }

};
} // namespace sa::console_detail
