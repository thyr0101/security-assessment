#pragma once
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <utility>

namespace sa {

enum class Status {
    Success, NotFound, AccessDenied, Unsupported, Unavailable, Error
};

enum class Tri { Unknown, Yes, No, NotApplicable };

enum class Severity { Informational, Low, Medium, High, Critical };

enum class Category {
    HardwareSecurity, OsSecurity, MalwareProtection, NetworkSecurity,
    Encryption, AccountSecurity, Privacy, Hardening, SoftwareHygiene, Informational
};

inline const wchar_t* ToW(Status s) {
    switch (s) {
    case Status::Success:     return L"Success";
    case Status::NotFound:    return L"NotFound";
    case Status::AccessDenied:return L"AccessDenied";
    case Status::Unsupported: return L"Unsupported";
    case Status::Unavailable: return L"Unavailable";
    case Status::Error:       return L"Error";
    }
    return L"Error";
}
inline const wchar_t* ToW(Tri t) {
    switch (t) {
    case Tri::Unknown:      return L"Unknown";
    case Tri::Yes:          return L"Yes";
    case Tri::No:           return L"No";
    case Tri::NotApplicable:return L"N/A";
    }
    return L"Unknown";
}
inline const wchar_t* ToW(Severity s) {
    switch (s) {
    case Severity::Informational: return L"Informational";
    case Severity::Low:           return L"Low";
    case Severity::Medium:        return L"Medium";
    case Severity::High:          return L"High";
    case Severity::Critical:      return L"Critical";
    }
    return L"Informational";
}
inline const wchar_t* ToW(Category c) {
    switch (c) {
    case Category::HardwareSecurity:  return L"Hardware Security";
    case Category::OsSecurity:        return L"OS Security";
    case Category::MalwareProtection: return L"Malware Protection";
    case Category::NetworkSecurity:   return L"Network Security";
    case Category::Encryption:        return L"Encryption";
    case Category::AccountSecurity:   return L"Account Security";
    case Category::Privacy:           return L"Privacy";
    case Category::Hardening:         return L"Hardening";
    case Category::SoftwareHygiene:   return L"Software Hygiene";
    case Category::Informational:     return L"Informational";
    }
    return L"Informational";
}

template <typename T>
struct Result {
    Status status = Status::Error;
    T value{};
    std::wstring reason;

    static Result Ok(T v) {
        Result r; r.status = Status::Success; r.value = std::move(v); return r;
    }
    static Result Err(Status s, std::wstring why = {}) {
        Result r; r.status = s; r.reason = std::move(why); return r;
    }
    bool ok() const noexcept { return status == Status::Success; }
};

} // namespace sa
