#pragma once
#include "Common.h"
#include <windows.h>
#include <oleauto.h>
#include <string>
#include <cwchar>

namespace sa {
// Owns strings returned through COM out parameters, including embedded NULs.
struct Bstr {
    BSTR value = nullptr;
    Bstr() = default;
    ~Bstr() { ::SysFreeString(value); }
    Bstr(const Bstr&) = delete;
    Bstr& operator=(const Bstr&) = delete;
    std::wstring str() const {
        return value ? std::wstring(value, ::SysStringLen(value)) : std::wstring{};
    }
};

inline Status ComStatus(HRESULT hr) {
    return hr == E_ACCESSDENIED ? Status::AccessDenied : Status::Unavailable;
}
inline std::wstring ErrorCode(HRESULT hr) {
    wchar_t code[11]{};
    swprintf_s(code, L"0x%08X", static_cast<unsigned>(hr));
    return code;
}
} // namespace sa
