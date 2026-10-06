#pragma once
#include "Common.h"
#include <windows.h>
#include <wbemidl.h>
#include <string>
#include <vector>
#include <memory>

namespace sa {

class WmiConnection {
public:
    WmiConnection() = default;
    ~WmiConnection();
    WmiConnection(const WmiConnection&) = delete;
    WmiConnection& operator=(const WmiConnection&) = delete;

    Status Connect(const wchar_t* ns = L"ROOT\\CIMV2", std::wstring* reason = nullptr);
    // Returns a list of instances; caller must Release().
    Status Query(const wchar_t* wql, std::vector<IWbemClassObject*>& out,
                 std::wstring* reason = nullptr);
    IWbemServices* services() const noexcept { return svc_; }

private:
    IWbemLocator* loc_ = nullptr;
    IWbemServices* svc_ = nullptr;
};

// Convenience extractors — return false if property missing.
bool WmiGetString(IWbemClassObject* o, const wchar_t* name, std::wstring& out);
bool WmiGetUInt  (IWbemClassObject* o, const wchar_t* name, unsigned long long& out);
bool WmiGetBool  (IWbemClassObject* o, const wchar_t* name, bool& out);
// Reads a CIM integer array (e.g. uint32[]). Returns true if the property exists
// (an empty/NULL array yields true with an empty vector).
bool WmiGetUIntArray(IWbemClassObject* o, const wchar_t* name,
                     std::vector<unsigned long long>& out);

// RAII vector of instances
class WmiObjects {
public:
    WmiObjects() = default;
    ~WmiObjects() { clear(); }
    WmiObjects(const WmiObjects&) = delete;
    WmiObjects& operator=(const WmiObjects&) = delete;
    std::vector<IWbemClassObject*>& items() { return items_; }
    const std::vector<IWbemClassObject*>& items() const { return items_; }
    void clear() { for (auto* o : items_) if (o) o->Release(); items_.clear(); }
private:
    std::vector<IWbemClassObject*> items_;
};

} // namespace sa