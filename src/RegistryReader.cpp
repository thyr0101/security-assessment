#include "RegistryReader.h"
#include <algorithm>
#include <cstring>

namespace sa {

Status RegistryReader::Open(HKEY root, const std::wstring& sub, REGSAM view,
                            std::wstring* reason) {
    key_.close();
    if (reason) reason->clear();
    path_ = sub;
    LSTATUS st = ::RegOpenKeyExW(root, sub.c_str(), 0, KEY_READ | view, key_.put());
    if (st == ERROR_SUCCESS) return Status::Success;
    if (st == ERROR_FILE_NOT_FOUND || st == ERROR_PATH_NOT_FOUND) return Status::NotFound;
    if (st == ERROR_ACCESS_DENIED) { if (reason) *reason = L"Access denied"; return Status::AccessDenied; }
    if (reason) *reason = FormatWinError((DWORD)st);
    return Status::Error;
}

static Status ReadRaw(HKEY k, const wchar_t* name, DWORD wantType, std::vector<BYTE>& buf) {
    if (!k) return Status::Error;
    for (unsigned attempt = 0; attempt < 4; ++attempt) {
    DWORD type = 0, cb = 0;
    LSTATUS st = ::RegQueryValueExW(k, name, nullptr, &type, nullptr, &cb);
    if (st == ERROR_FILE_NOT_FOUND) return Status::NotFound;
    if (st == ERROR_ACCESS_DENIED) return Status::AccessDenied;
    if (st != ERROR_SUCCESS) return Status::Error;
    if (wantType && type != wantType) return Status::Unsupported;
    buf.resize(cb ? cb : 1);
    st = ::RegQueryValueExW(k, name, nullptr, &type, buf.data(), &cb);
    if (st == ERROR_MORE_DATA) continue; // Value grew between the size and data reads.
    if (st == ERROR_FILE_NOT_FOUND) return Status::NotFound;
    if (st == ERROR_ACCESS_DENIED) return Status::AccessDenied;
    if (st != ERROR_SUCCESS) return Status::Error;
    if (wantType && type != wantType) return Status::Unsupported;
    buf.resize(cb);
    return Status::Success;
    }
    return Status::Error;
}

Status RegistryReader::GetString(const wchar_t* name, std::wstring& out) const {
    std::vector<BYTE> buf;
    Status s = ReadRaw(key_.get(), name, REG_SZ, buf);
    if (s == Status::Unsupported) {
        s = ReadRaw(key_.get(), name, REG_EXPAND_SZ, buf);
        if (s != Status::Success) return s;
    }
    if (s != Status::Success) return s;
    if (buf.size() % sizeof(wchar_t)) return Status::Error;
    out.resize(buf.size() / sizeof(wchar_t));
    if (!buf.empty()) std::memcpy(out.data(), buf.data(), buf.size());
    if (const size_t end = out.find(L'\0'); end != std::wstring::npos) out.resize(end);
    return Status::Success;
}

Status RegistryReader::GetDword(const wchar_t* name, DWORD& out) const {
    std::vector<BYTE> buf;
    Status s = ReadRaw(key_.get(), name, REG_DWORD, buf);
    if (s != Status::Success) return s;
    if (buf.size() != sizeof(DWORD)) return Status::Error;
    std::memcpy(&out, buf.data(), sizeof(out));
    return Status::Success;
}

Status RegistryReader::GetQword(const wchar_t* name, unsigned long long& out) const {
    std::vector<BYTE> buf;
    Status s = ReadRaw(key_.get(), name, REG_QWORD, buf);
    if (s != Status::Success) return s;
    if (buf.size() != sizeof(unsigned long long)) return Status::Error;
    std::memcpy(&out, buf.data(), sizeof(out));
    return Status::Success;
}

Status RegistryReader::GetBool(const wchar_t* name, bool& out) const {
    DWORD v = 0;
    Status s = GetDword(name, v);
    if (s != Status::Success) return s;
    out = (v != 0);
    return Status::Success;
}

Status RegistryReader::GetMultiSz(const wchar_t* name, std::vector<std::wstring>& out) const {
    std::vector<BYTE> buf;
    Status s = ReadRaw(key_.get(), name, REG_MULTI_SZ, buf);
    if (s != Status::Success) return s;
    if (buf.size() % sizeof(wchar_t)) return Status::Error;
    std::wstring data(buf.size() / sizeof(wchar_t), L'\0');
    if (!buf.empty()) std::memcpy(data.data(), buf.data(), buf.size());
    if (data.size() < 2 || data[data.size() - 1] != L'\0' || data[data.size() - 2] != L'\0')
        return Status::Error;
    std::vector<std::wstring> values;
    for (size_t start = 0; start < data.size() && data[start];) {
        const size_t end = data.find(L'\0', start);
        if (end == std::wstring::npos) return Status::Error;
        values.emplace_back(data, start, end - start);
        start = end + 1;
    }
    out = std::move(values);
    return Status::Success;
}

Status RegistryReader::GetBinary(const wchar_t* name, std::vector<BYTE>& out) const {
    return ReadRaw(key_.get(), name, REG_BINARY, out);
}

Status RegistryReader::EnumValues(std::vector<std::pair<std::wstring, DWORD>>& out) const {
    out.clear();
    if (!key_.valid()) return Status::Error;
    DWORD idx = 0;
    std::vector<wchar_t> name(16384);
    for (;;) {
        DWORD nameLen = static_cast<DWORD>(name.size());
        DWORD type = 0;
        LSTATUS st = ::RegEnumValueW(key_.get(), idx, name.data(), &nameLen, nullptr, &type, nullptr, nullptr);
        if (st == ERROR_NO_MORE_ITEMS) break;
        if (st == ERROR_MORE_DATA) { ++idx; continue; }
        if (st != ERROR_SUCCESS) {
            if (st == ERROR_ACCESS_DENIED) return Status::AccessDenied;
            return Status::Error;
        }
        std::wstring n(name.data(), nameLen);
        out.emplace_back(std::move(n), type);
        ++idx;
    }
    return Status::Success;
}

Status RegistryReader::CountValues(DWORD& out) const {
    if (!key_.valid()) return Status::Error;
    DWORD subkeys = 0, values = 0;
    LSTATUS st = ::RegQueryInfoKeyW(key_.get(), nullptr, nullptr, nullptr,
                                    &subkeys, nullptr, nullptr, &values, nullptr, nullptr, nullptr, nullptr);
    if (st != ERROR_SUCCESS) return st == ERROR_ACCESS_DENIED ? Status::AccessDenied : Status::Error;
    out = values;
    return Status::Success;
}

Status RegistryReader::CountSubkeys(DWORD& out) const {
    if (!key_.valid()) return Status::Error;
    DWORD subkeys = 0, values = 0;
    LSTATUS st = ::RegQueryInfoKeyW(key_.get(), nullptr, nullptr, nullptr,
                                    &subkeys, nullptr, nullptr, &values, nullptr, nullptr, nullptr, nullptr);
    if (st != ERROR_SUCCESS) return st == ERROR_ACCESS_DENIED ? Status::AccessDenied : Status::Error;
    out = subkeys;
    return Status::Success;
}

std::optional<std::wstring> RegReadString(HKEY root, const std::wstring& sub,
                                          const wchar_t* value, REGSAM view) {
    RegistryReader r;
    if (r.Open(root, sub, view) != Status::Success) return std::nullopt;
    std::wstring out;
    if (r.GetString(value, out) != Status::Success) return std::nullopt;
    return out;
}
std::optional<DWORD> RegReadDword(HKEY root, const std::wstring& sub,
                                  const wchar_t* value, REGSAM view) {
    RegistryReader r;
    if (r.Open(root, sub, view) != Status::Success) return std::nullopt;
    DWORD out = 0;
    if (r.GetDword(value, out) != Status::Success) return std::nullopt;
    return out;
}

} // namespace sa
