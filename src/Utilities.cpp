#include "Utilities.h"
#include <vector>
#include <cwctype>
#include <limits>
#include <sstream>
#include <iomanip>

namespace sa {

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty() || w.size() > static_cast<size_t>((std::numeric_limits<int>::max)())) return {};
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                  nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(n, '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                          out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty() || s.size() > static_cast<size_t>((std::numeric_limits<int>::max)())) return {};
    int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(n, L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n);
    return out;
}

std::wstring ExpandEnv(const std::wstring& in) {
    DWORD need = ::ExpandEnvironmentStringsW(in.c_str(), nullptr, 0);
    if (!need) return in;
    std::wstring out(need, L'\0');
    DWORD got = ::ExpandEnvironmentStringsW(in.c_str(), out.data(), need);
    if (!got || got > need) return in;
    out.resize(got ? got - 1 : 0);
    return out;
}

std::wstring FormatBytes(unsigned long long bytes) {
    const wchar_t* units[] = { L"B", L"KB", L"MB", L"GB", L"TB", L"PB" };
    double v = (double)bytes; int i = 0;
    while (v >= 1024.0 && i < 5) { v /= 1024.0; ++i; }
    std::wostringstream ss;
    ss << std::fixed << std::setprecision(v < 10 ? 2 : (v < 100 ? 1 : 0)) << v << L' ' << units[i];
    return ss.str();
}

std::wstring FormatWinError(DWORD err) {
    LPWSTR buf = nullptr;
    DWORD n = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&buf, 0, nullptr);
    std::wstring out;
    if (n && buf) { out.assign(buf, n); while (!out.empty() && (out.back() == L'\r' || out.back() == L'\n')) out.pop_back(); }
    if (buf) ::LocalFree(buf);
    if (out.empty()) out = L"error " + std::to_wstring(err);
    return out;
}

std::wstring Trim(const std::wstring& s) {
    size_t a = 0, b = s.size();
    while (a < b && iswspace(s[a])) ++a;
    while (b > a && iswspace(s[b - 1])) --b;
    return s.substr(a, b - a);
}

std::wstring ToLower(const std::wstring& s) {
    std::wstring r = s;
    for (auto& c : r) c = (wchar_t)towlower(c);
    return r;
}

bool IEquals(const std::wstring& a, const std::wstring& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (towlower(a[i]) != towlower(b[i])) return false;
    return true;
}

bool IsElevated() {
    HANDLE tok = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    WinHandle h(tok);
    TOKEN_ELEVATION el{};
    DWORD cb = sizeof(el);
    if (!::GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &cb)) return false;
    return el.TokenIsElevated != 0;
}

} // namespace sa
