#pragma once
#include "Common.h"
#include "Utilities.h"
#include <windows.h>
#include <string>
#include <vector>
#include <optional>

namespace sa {

class RegistryReader {
public:
    RegistryReader() = default;

    // Subkey of a predefined HKEY. view = KEY_WOW64_64KEY / KEY_WOW64_32KEY / 0
    Status Open(HKEY root, const std::wstring& subkey, REGSAM view = KEY_WOW64_64KEY,
                std::wstring* reason = nullptr);

    Status GetString(const wchar_t* name, std::wstring& out) const;
    Status GetDword (const wchar_t* name, DWORD& out) const;
    Status GetQword (const wchar_t* name, unsigned long long& out) const;
    Status GetBool  (const wchar_t* name, bool& out) const; // DWORD != 0
    Status GetMultiSz(const wchar_t* name, std::vector<std::wstring>& out) const;
    Status GetBinary(const wchar_t* name, std::vector<BYTE>& out) const;

    // Enumerate immediate values (name/type). Empty value name returned as L"(Default)".
    Status EnumValues(std::vector<std::pair<std::wstring, DWORD>>& out) const;
    // Count immediate values.
    Status CountValues(DWORD& out) const;
    Status CountSubkeys(DWORD& out) const;

    HKEY get() const noexcept { return key_.get(); }
    bool valid() const noexcept { return key_.valid(); }

private:
    RegKey key_;
    std::wstring path_;
};

// Convenience free functions
std::optional<std::wstring> RegReadString(HKEY root, const std::wstring& sub,
                                          const wchar_t* value, REGSAM view = KEY_WOW64_64KEY);
std::optional<DWORD>        RegReadDword (HKEY root, const std::wstring& sub,
                                          const wchar_t* value, REGSAM view = KEY_WOW64_64KEY);

} // namespace sa