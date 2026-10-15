#pragma once
#include "Common.h"
#include <windows.h>
#include <objbase.h>          // <-- COINIT_MULTITHREADED, CoInitializeEx, CoUninitialize
#include <string>
#include <vector>
#include <memory>
#include <optional>

namespace sa {

    inline Status StatusFromWin32(DWORD error) {
        switch (error) {
        case ERROR_SUCCESS: return Status::Success;
        case ERROR_FILE_NOT_FOUND: case ERROR_PATH_NOT_FOUND:
        case ERROR_SERVICE_DOES_NOT_EXIST: return Status::NotFound;
        case ERROR_ACCESS_DENIED: case ERROR_PRIVILEGE_NOT_HELD: return Status::AccessDenied;
        case ERROR_NOT_SUPPORTED: return Status::Unsupported;
        default: return Status::Error;
        }
    }

    class ServiceHandle {
        SC_HANDLE h_;
    public:
        explicit ServiceHandle(SC_HANDLE h) noexcept : h_(h) {}
        ~ServiceHandle() { if (h_) ::CloseServiceHandle(h_); }
        ServiceHandle(const ServiceHandle&) = delete;
        ServiceHandle& operator=(const ServiceHandle&) = delete;
        SC_HANDLE get() const noexcept { return h_; }
        explicit operator bool() const noexcept { return h_ != nullptr; }
    };

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
        }
        ~ComInit() { if (SUCCEEDED(hr_)) ::CoUninitialize(); }
        bool ok() const noexcept { return SUCCEEDED(hr_) || hr_ == RPC_E_CHANGED_MODE; }
        ComInit(const ComInit&) = delete;
        ComInit& operator=(const ComInit&) = delete;
    };

    // ---------- String helpers ----------
    std::string  WideToUtf8(const std::wstring& w);
    std::wstring Utf8ToWide(const std::string& s);
    std::wstring ExpandEnv(const std::wstring& in);
    std::wstring FormatBytes(unsigned long long bytes);
    std::wstring FormatWinError(DWORD err);
    std::wstring Trim(const std::wstring& s);
    bool IEquals(const std::wstring& a, const std::wstring& b);
    std::wstring ToLower(const std::wstring& s);

    bool IsElevated();

} // namespace sa
