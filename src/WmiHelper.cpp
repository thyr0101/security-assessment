#include "WmiHelper.h"
#include <comdef.h>          // <-- _bstr_t
#include <oleauto.h>
#include <wrl/client.h>
#include <cerrno>
#include <cwctype>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "comsuppw.lib")

namespace sa {

    static std::wstring HrText(HRESULT hr) {
        wchar_t b[32];
        swprintf_s(b, L"(0x%08X)", static_cast<unsigned>(hr));
        return b;
    }

    WmiConnection::~WmiConnection() {
        if (svc_) svc_->Release();
        if (loc_) loc_->Release();
    }

    Status WmiConnection::Connect(const wchar_t* ns, std::wstring* reason) {
        if (reason) reason->clear();
        if (svc_) { svc_->Release(); svc_ = nullptr; }
        if (loc_) { loc_->Release(); loc_ = nullptr; }

        HRESULT hr = ::CoCreateInstance(CLSID_WbemLocator, nullptr,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            reinterpret_cast<void**>(&loc_));
        if (FAILED(hr)) {
            if (reason) *reason = L"CoCreateInstance(WbemLocator) failed " + HrText(hr);
            return Status::Error;
        }

        _bstr_t nsBstr(ns);
        hr = loc_->ConnectServer(nsBstr, nullptr, nullptr, nullptr,
            0, nullptr, nullptr, &svc_);
        if (FAILED(hr)) {
            if (reason) *reason = std::wstring(L"ConnectServer(") + ns + L") failed " + HrText(hr);
            return (hr == static_cast<HRESULT>(WBEM_E_ACCESS_DENIED) || hr == E_ACCESSDENIED)
                ? Status::AccessDenied : Status::Unavailable;
        }

        hr = ::CoSetProxyBlanket(svc_,
            RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr, EOAC_NONE);
        if (FAILED(hr)) {
            if (reason) *reason = L"CoSetProxyBlanket failed " + HrText(hr);
            svc_->Release(); svc_ = nullptr;
            return Status::Error;
        }
        return Status::Success;
    }

    Status WmiConnection::Query(const wchar_t* wql,
        std::vector<IWbemClassObject*>& out,
        std::wstring* reason) {
        if (!svc_) { if (reason) *reason = L"not connected"; return Status::Error; }

        if (reason) reason->clear();
        Microsoft::WRL::ComPtr<IEnumWbemClassObject> en;
        _bstr_t lang(L"WQL");
        _bstr_t query(wql);
        HRESULT hr = svc_->ExecQuery(lang, query,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            nullptr, en.GetAddressOf());
        if (FAILED(hr) || !en) {
            if (reason) *reason = L"ExecQuery failed " + HrText(hr);
            return hr == E_ACCESSDENIED || hr == static_cast<HRESULT>(WBEM_E_ACCESS_DENIED)
                ? Status::AccessDenied : Status::Unavailable;
        }

        // A provider that has to start up (Defender, for one) can take longer than
        // a short timeout to return its first row. WBEM_S_TIMEDOUT is a *success*
        // code with zero rows, so it must be retried, not treated as end-of-data.
        std::vector<Microsoft::WRL::ComPtr<IWbemClassObject>> pending;
        HRESULT lastFail = S_OK;
        int timeouts = 0;
        for (;;) {
            IWbemClassObject* objs[8] = {};
            ULONG ret = 0;
            hr = en->Next(2000, 8, objs, &ret);
            Microsoft::WRL::ComPtr<IWbemClassObject> owned[8];
            for (ULONG i = 0; i < ret; ++i) owned[i].Attach(objs[i]);
            for (ULONG i = 0; i < ret; ++i) pending.push_back(std::move(owned[i]));
            if (hr == static_cast<HRESULT>(WBEM_S_TIMEDOUT)) {
                if (++timeouts >= 10) { lastFail = HRESULT_FROM_WIN32(ERROR_TIMEOUT); break; }
                continue;
            }
            if (FAILED(hr)) { lastFail = hr; break; }
            if (hr == static_cast<HRESULT>(WBEM_S_FALSE) || ret == 0) break;
        }
        if (FAILED(lastFail)) {
            if (reason) *reason = L"query failed " + HrText(lastFail);
            return lastFail == E_ACCESSDENIED || lastFail == static_cast<HRESULT>(WBEM_E_ACCESS_DENIED)
                ? Status::AccessDenied : Status::Unavailable;
        }
        out.reserve(out.size() + pending.size());
        for (auto& obj : pending) out.push_back(obj.Detach());
        return Status::Success;
    }

    static bool ParseUInt(BSTR text, unsigned long long& out) {
        if (!text) return false;
        // BSTRs are length-delimited; reject embedded nulls before parsing.
        if (wcslen(text) != ::SysStringLen(text)) return false;
        while (iswspace(*text)) ++text;
        if (!*text || *text == L'-') return false;
        wchar_t* end = nullptr;
        errno = 0;
        const auto value = wcstoull(text, &end, 10);
        if (errno == ERANGE || end == text) return false;
        while (iswspace(*end)) ++end;
        if (*end) return false;
        out = value;
        return true;
    }

    bool WmiGetString(IWbemClassObject* o, const wchar_t* name, std::wstring& out) {
        _variant_t v;
        if (FAILED(o->Get(name, 0, &v, nullptr, nullptr))) return false;
        bool ok = false;
        if (v.vt == VT_BSTR && v.bstrVal) {
            out.assign(v.bstrVal, ::SysStringLen(v.bstrVal));
            ok = true;
        }
        return ok;
    }

    static bool VariantUInt(const VARIANT& v, CIMTYPE type, unsigned long long& out) {
        bool ok = false;
        switch (v.vt) {
        // Read the member that matches the VARIANT type; reading ulVal for a
        // 1- or 2-byte type picks up unrelated bytes of the union.
        case VT_I1:
            if (v.cVal < 0 && type != CIM_UINT8) return false;
            out = static_cast<unsigned char>(v.cVal); ok = true; break;
        case VT_UI1: out = v.bVal;                                   ok = true; break;
        case VT_I2:
            if (v.iVal < 0 && type != CIM_UINT16) return false;
            out = static_cast<unsigned short>(v.iVal); ok = true; break;
        case VT_UI2: out = v.uiVal;                                  ok = true; break;
        case VT_I4:
            // WMI also represents uint32 as VT_I4; preserve its high bit.
            if (v.lVal < 0 && type != CIM_UINT32) return false;
            out = static_cast<ULONG>(v.lVal); ok = true; break;
        case VT_UI4: out = v.ulVal;                                  ok = true; break;
        case VT_I8:
            if (v.llVal < 0 && type != CIM_UINT64) return false;
            out = static_cast<unsigned long long>(v.llVal); ok = true; break;
        case VT_UI8: out = v.ullVal;                                 ok = true; break;
        case VT_BSTR:
            ok = ParseUInt(v.bstrVal, out);
            break;
        default: break;
        }
        return ok;
    }

    bool WmiGetUInt(IWbemClassObject* o, const wchar_t* name, unsigned long long& out) {
        _variant_t v;
        CIMTYPE type = 0;
        return SUCCEEDED(o->Get(name, 0, &v, &type, nullptr)) && VariantUInt(v, type, out);
    }

    bool WmiGetUIntArray(IWbemClassObject* o, const wchar_t* name,
                         std::vector<unsigned long long>& out) {
        out.clear();
        _variant_t v;
        CIMTYPE type = 0;
        if (FAILED(o->Get(name, 0, &v, &type, nullptr))) return false;
        bool ok = false;
        if ((v.vt & VT_ARRAY) && !(v.vt & VT_BYREF) && v.parray && ::SafeArrayGetDim(v.parray) == 1) {
            SAFEARRAY* arr = v.parray;
            const VARTYPE et = static_cast<VARTYPE>(v.vt & VT_TYPEMASK);
            LONG lb = 0, ub = -1;
            if (SUCCEEDED(::SafeArrayGetLBound(arr, 1, &lb)) &&
                SUCCEEDED(::SafeArrayGetUBound(arr, 1, &ub))) {
                switch (et) {
                case VT_I1: case VT_UI1: case VT_I2: case VT_UI2:
                case VT_I4: case VT_UI4: case VT_I8: case VT_UI8: case VT_BSTR: break;
                default: return false;
                }
                std::vector<unsigned long long> values;
                for (LONGLONG index = lb; index <= ub; ++index) {
                    LONG i = static_cast<LONG>(index);
                    _variant_t item;
                    item.vt = et;
                    // All supported scalar members share the VARIANT union's address.
                    if (FAILED(::SafeArrayGetElement(arr, &i, &item.bVal))) return false;
                    unsigned long long value = 0;
                    if (!VariantUInt(item, type & ~CIM_FLAG_ARRAY, value)) return false;
                    values.push_back(value);
                }
                out = std::move(values);
                ok = true;
            }
        }
        return ok;
    }

    bool WmiGetBool(IWbemClassObject* o, const wchar_t* name, bool& out) {
        _variant_t v;
        if (FAILED(o->Get(name, 0, &v, nullptr, nullptr))) return false;
        bool ok = false;
        if (v.vt == VT_BOOL) { out = (v.boolVal != VARIANT_FALSE); ok = true; }
        else if (v.vt == VT_I4 || v.vt == VT_UI4) { out = (v.ulVal != 0); ok = true; }
        return ok;
    }

} // namespace sa
