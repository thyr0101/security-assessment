#pragma once
#include "Common.h"
#include <windows.h>
#include <objbase.h>          // <-- COINIT_MULTITHREADED, CoInitializeEx, CoUninitialize
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <sstream>
#include <iomanip>

namespace sa {

    // ---------- RAII Windows handle ----------
    class WinHandle {
        HANDLE h_ = nullptr;
    public:
        WinHandle() = default;
        explicit WinHandle(HANDLE h) : h_(h) {}
        WinHandle(const WinHandle&) = delete;
        WinHandle& operator=(const WinHandle&) = delete;
        WinHandle(WinHandle&& o) noexcept : h_(o.h_) { o.h_ = nullptr; }
        WinHandle& operator=(WinHandle&& o) noexcept {
            if (this != &o) { reset(); h_ = o.h_; o.h_ = nullptr; }
            return *this;
        }
        ~WinHandle() { reset(); }
        void reset(HANDLE h = nullptr) noexcept {
            if (h_ && h_ != INVALID_HANDLE_VALUE) ::CloseHandle(h_);
            h_ = h;
        }
        HANDLE get() const noexcept { return h_; }
        bool valid() const noexcept { return h_ && h_ != INVALID_HANDLE_VALUE; }
        explicit operator bool() const noexcept { return valid(); }
        HANDLE* put() noexcept { reset(); return &h_; }
    };

    // ---------- Registry key RAII ----------
    class RegKey {
        HKEY h_ = nullptr;
    public:
        RegKey() = default;
        ~RegKey() { close(); }
        RegKey(const RegKey&) = delete;
        RegKey& operator=(const RegKey&) = delete;
        RegKey(RegKey&& o) noexcept : h_(o.h_) { o.h_ = nullptr; }
        RegKey& operator=(RegKey&& o) noexcept {
            if (this != &o) { close(); h_ = o.h_; o.h_ = nullptr; }
            return *this;
        }
        void close() noexcept { if (h_) { ::RegCloseKey(h_); h_ = nullptr; } }
        HKEY get() const noexcept { return h_; }
        HKEY* put() noexcept { close(); return &h_; }
        bool valid() const noexcept { return h_ != nullptr; }
    };

    // ---------- COM init RAII ----------
    class ComInit {
        HRESULT hr_;
    public:
        explicit ComInit(DWORD coinit = COINIT_MULTITHREADED) {
            hr_ = ::CoInitializeEx(nullptr, coinit);
            if (hr_ == RPC_E_CHANGED_MODE) hr_ = S_OK; // already init in another mode
        }
        ~ComInit() { if (SUCCEEDED(hr_)) ::CoUninitialize(); }
        bool ok() const noexcept { return SUCCEEDED(hr_); }
    };

    // ---------- String helpers ----------
    std::string  WideToUtf8(const std::wstring& w);
    std::wstring Utf8ToWide(const std::string& s);
    std::wstring ExpandEnv(const std::wstring& in);
    std::wstring FormatBytes(unsigned long long bytes);
    std::wstring FormatWinError(DWORD err);
    std::wstring Trim(const std::wstring& s);
    std::vector<std::wstring> Split(const std::wstring& s, wchar_t delim);
    bool IEquals(const std::wstring& a, const std::wstring& b);
    std::wstring ToLower(const std::wstring& s);

    // ---------- Filesystem / version helpers ----------
    struct FileVersionInfo {
        std::wstring fileVersion;
        std::wstring productVersion;
        std::wstring companyName;
        std::wstring productName;
        std::wstring fileDescription;
        std::wstring originalFilename;
        std::wstring architecture;
    };
    std::optional<FileVersionInfo> QueryFileVersion(const std::wstring& path);

    std::optional<std::wstring> FileSha256(const std::wstring& path);

    bool IsElevated();

} // namespace sa