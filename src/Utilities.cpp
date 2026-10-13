#include "Utilities.h"
#include <shlwapi.h>
#include <bcrypt.h>
#include <vector>
#include <cwctype>
#include <limits>
#pragma comment(lib, "version.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shlwapi.lib")

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

std::vector<std::wstring> Split(const std::wstring& s, wchar_t delim) {
    std::vector<std::wstring> out;
    std::wstring cur;
    for (wchar_t c : s) {
        if (c == delim) { out.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    out.push_back(cur);
    return out;
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

std::optional<FileVersionInfo> QueryFileVersion(const std::wstring& path) {
    DWORD handle = 0;
    DWORD sz = ::GetFileVersionInfoSizeW(path.c_str(), &handle);
    if (!sz) return std::nullopt;
    std::vector<BYTE> buf(sz);
    if (!::GetFileVersionInfoW(path.c_str(), 0, sz, buf.data())) return std::nullopt;

    FileVersionInfo info;
    struct L { const wchar_t* name; std::wstring* out; };
    L fields[] = {
        { L"FileVersion",     &info.fileVersion },
        { L"ProductVersion",  &info.productVersion },
        { L"CompanyName",     &info.companyName },
        { L"ProductName",     &info.productName },
        { L"FileDescription", &info.fileDescription },
        { L"OriginalFilename",&info.originalFilename },
    };
    struct Translation { WORD language; WORD codepage; };
    Translation* translations = nullptr;
    UINT translationBytes = 0;
    ::VerQueryValueW(buf.data(), L"\\VarFileInfo\\Translation",
                    reinterpret_cast<void**>(&translations), &translationBytes);
    const Translation fallback{0x0409, 0x04b0};
    if (!translations || translationBytes < sizeof(Translation)) {
        translations = const_cast<Translation*>(&fallback);
        translationBytes = sizeof(Translation);
    }
    for (auto& f : fields) {
        for (size_t i = 0; i < translationBytes / sizeof(Translation); ++i) {
            wchar_t prefix[64]{};
            swprintf_s(prefix, L"\\StringFileInfo\\%04x%04x\\",
                       translations[i].language, translations[i].codepage);
            LPWSTR p = nullptr; UINT len = 0;
            if (::VerQueryValueW(buf.data(), (std::wstring(prefix) + f.name).c_str(),
                                 reinterpret_cast<void**>(&p), &len) && p && len) {
                size_t count = len;
                while (count && p[count - 1] == L'\0') --count;
                f.out->assign(p, count);
                if (!f.out->empty()) break;
            }
        }
    }

    VS_FIXEDFILEINFO* fixed = nullptr; UINT fixedSize = 0;
    if (::VerQueryValueW(buf.data(), L"\\", reinterpret_cast<void**>(&fixed), &fixedSize) &&
        fixed && fixedSize >= sizeof(*fixed) && fixed->dwSignature == 0xfeef04bd) {
        auto version = [](DWORD hi, DWORD lo) {
            return std::to_wstring(HIWORD(hi)) + L"." + std::to_wstring(LOWORD(hi)) +
                   L"." + std::to_wstring(HIWORD(lo)) + L"." + std::to_wstring(LOWORD(lo));
        };
        if (info.fileVersion.empty()) info.fileVersion = version(fixed->dwFileVersionMS, fixed->dwFileVersionLS);
        if (info.productVersion.empty()) info.productVersion = version(fixed->dwProductVersionMS, fixed->dwProductVersionLS);
    }

    // Architecture via PE header
    WinHandle f(::CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (f) {
        IMAGE_DOS_HEADER dos{};
        DWORD read = 0;
        LARGE_INTEGER size{};
        if (::GetFileSizeEx(f.get(), &size) &&
            ::ReadFile(f.get(), &dos, sizeof(dos), &read, nullptr) && read == sizeof(dos) &&
            dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew >= sizeof(dos) &&
            static_cast<LONGLONG>(dos.e_lfanew) + static_cast<LONGLONG>(sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)) <= size.QuadPart) {
            LARGE_INTEGER offset{}; offset.QuadPart = dos.e_lfanew;
            DWORD signature = 0;
            IMAGE_FILE_HEADER header{};
            if (::SetFilePointerEx(f.get(), offset, nullptr, FILE_BEGIN) &&
                ::ReadFile(f.get(), &signature, sizeof(signature), &read, nullptr) && read == sizeof(signature) &&
                signature == IMAGE_NT_SIGNATURE &&
                ::ReadFile(f.get(), &header, sizeof(header), &read, nullptr) && read == sizeof(header)) {
                        switch (header.Machine) {
                        case IMAGE_FILE_MACHINE_I386:  info.architecture = L"x86"; break;
                        case IMAGE_FILE_MACHINE_AMD64: info.architecture = L"x64"; break;
                        case IMAGE_FILE_MACHINE_ARM64: info.architecture = L"ARM64"; break;
                        case IMAGE_FILE_MACHINE_ARM:   info.architecture = L"ARM"; break;
                        default: info.architecture = L"Unknown"; break;
                        }
            }
        }
    }
    return info;
}

std::optional<std::wstring> FileSha256(const std::wstring& path) {
    WinHandle f(::CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!f.valid()) return std::nullopt;

    BCRYPT_ALG_HANDLE alg = nullptr;
    if (!BCRYPT_SUCCESS(::BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return std::nullopt;
    struct AlgCloser { BCRYPT_ALG_HANDLE h; ~AlgCloser(){ if (h) BCryptCloseAlgorithmProvider(h,0);} } ac{alg};

    DWORD objSz = 0, cb = 0, hashLen = 0;
    if (!BCRYPT_SUCCESS(::BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objSz, sizeof(objSz), &cb, 0)) ||
        !BCRYPT_SUCCESS(::BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &cb, 0)) ||
        hashLen != 32) return std::nullopt;
    std::vector<BYTE> obj(objSz), hash(hashLen);

    BCRYPT_HASH_HANDLE hh = nullptr;
    if (!BCRYPT_SUCCESS(::BCryptCreateHash(alg, &hh, obj.data(), objSz, nullptr, 0, 0)))
        return std::nullopt;
    struct HashCloser { BCRYPT_HASH_HANDLE h; ~HashCloser(){ if (h) BCryptDestroyHash(h);} } hc{hh};

    std::vector<BYTE> buf(1 << 16);
    for (;;) {
        DWORD rd = 0;
        if (!::ReadFile(f.get(), buf.data(), (DWORD)buf.size(), &rd, nullptr)) return std::nullopt;
        if (rd == 0) break;
        if (!BCRYPT_SUCCESS(::BCryptHashData(hh, buf.data(), rd, 0))) return std::nullopt;
    }
    if (!BCRYPT_SUCCESS(::BCryptFinishHash(hh, hash.data(), hashLen, 0))) return std::nullopt;

    static const wchar_t* hex = L"0123456789abcdef";
    std::wstring out;
    out.reserve(hashLen * 2);
    for (BYTE b : hash) { out.push_back(hex[b >> 4]); out.push_back(hex[b & 0xF]); }
    return out;
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
