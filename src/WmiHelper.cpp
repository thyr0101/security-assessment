#include "WmiHelper.h"
#include <comdef.h>          // <-- _bstr_t
#include <oleauto.h>

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
            return Status::Error;
        }
        return Status::Success;
    }

    Status WmiConnection::Query(const wchar_t* wql,
        std::vector<IWbemClassObject*>& out,
        std::wstring* reason) {
        if (!svc_) { if (reason) *reason = L"not connected"; return Status::Error; }

        IEnumWbemClassObject* en = nullptr;
        _bstr_t lang(L"WQL");
        _bstr_t query(wql);
        HRESULT hr = svc_->ExecQuery(lang, query,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            nullptr, &en);
        if (FAILED(hr) || !en) {
            if (reason) *reason = L"ExecQuery failed " + HrText(hr);
            return Status::Unavailable;
        }

        // A provider that has to start up (Defender, for one) can take longer than
        // a short timeout to return its first row. WBEM_S_TIMEDOUT is a *success*
        // code with zero rows, so it must be retried, not treated as end-of-data.
        const size_t before = out.size();
        HRESULT lastFail = S_OK;
        int timeouts = 0;
        for (;;) {
            IWbemClassObject* objs[8] = {};
            ULONG ret = 0;
            hr = en->Next(2000, 8, objs, &ret);
            for (ULONG i = 0; i < ret; ++i) out.push_back(objs[i]);
            if (hr == WBEM_S_TIMEDOUT) {
                if (++timeouts >= 10) break;
                continue;
            }
            if (FAILED(hr)) { lastFail = hr; break; }
            if (hr == WBEM_S_FALSE || ret == 0) break;
        }
        en->Release();
        if (FAILED(lastFail) && out.size() == before) {
            if (reason) *reason = L"query failed " + HrText(lastFail);
            return Status::Unavailable;
        }
        return Status::Success;
    }

    bool WmiGetString(IWbemClassObject* o, const wchar_t* name, std::wstring& out) {
        VARIANT v; ::VariantInit(&v);
        if (FAILED(o->Get(name, 0, &v, nullptr, nullptr))) return false;
        bool ok = false;
        if (v.vt == VT_BSTR && v.bstrVal) {
            out.assign(v.bstrVal, ::SysStringLen(v.bstrVal));
            ok = true;
        }
        else if (v.vt == VT_NULL || v.vt == VT_EMPTY) {
            out.clear(); ok = true;
        }
        ::VariantClear(&v);
        return ok;
    }

    bool WmiGetUInt(IWbemClassObject* o, const wchar_t* name, unsigned long long& out) {
        VARIANT v; ::VariantInit(&v);
        if (FAILED(o->Get(name, 0, &v, nullptr, nullptr))) return false;
        bool ok = false;
        switch (v.vt) {
        // Read the member that matches the VARIANT type; reading ulVal for a
        // 1- or 2-byte type picks up unrelated bytes of the union.
        case VT_I1:  out = static_cast<unsigned char>(v.cVal);       ok = true; break;
        case VT_UI1: out = v.bVal;                                   ok = true; break;
        case VT_I2:  out = static_cast<unsigned short>(v.iVal);      ok = true; break;
        case VT_UI2: out = v.uiVal;                                  ok = true; break;
        case VT_I4:  out = static_cast<ULONG>(v.lVal);               ok = true; break;
        case VT_UI4: out = v.ulVal;                                  ok = true; break;
        case VT_I8:  out = static_cast<unsigned long long>(v.llVal); ok = true; break;
        case VT_UI8: out = v.ullVal;                                 ok = true; break;
        case VT_BSTR:
            if (v.bstrVal) { out = wcstoull(v.bstrVal, nullptr, 10); ok = true; }
            break;
        default: break;
        }
        ::VariantClear(&v);
        return ok;
    }

    bool WmiGetUIntArray(IWbemClassObject* o, const wchar_t* name,
                         std::vector<unsigned long long>& out) {
        out.clear();
        VARIANT v; ::VariantInit(&v);
        if (FAILED(o->Get(name, 0, &v, nullptr, nullptr))) return false;
        bool ok = false;
        if (v.vt == VT_NULL || v.vt == VT_EMPTY) {
            ok = true;                              // property exists, no elements
        }
        else if ((v.vt & VT_ARRAY) && v.parray && ::SafeArrayGetDim(v.parray) == 1) {
            SAFEARRAY* arr = v.parray;
            const VARTYPE et = static_cast<VARTYPE>(v.vt & VT_TYPEMASK);
            LONG lb = 0, ub = -1;
            if (SUCCEEDED(::SafeArrayGetLBound(arr, 1, &lb)) &&
                SUCCEEDED(::SafeArrayGetUBound(arr, 1, &ub))) {
                ok = true;
                for (LONG i = lb; i <= ub; ++i) {
                    switch (et) {
                    case VT_UI1: { BYTE x = 0;   if (SUCCEEDED(::SafeArrayGetElement(arr, &i, &x))) out.push_back(x); break; }
                    case VT_I2:  { SHORT x = 0;  if (SUCCEEDED(::SafeArrayGetElement(arr, &i, &x))) out.push_back(static_cast<unsigned short>(x)); break; }
                    case VT_UI2: { USHORT x = 0; if (SUCCEEDED(::SafeArrayGetElement(arr, &i, &x))) out.push_back(x); break; }
                    case VT_I4:  { LONG x = 0;   if (SUCCEEDED(::SafeArrayGetElement(arr, &i, &x))) out.push_back(static_cast<ULONG>(x)); break; }
                    case VT_UI4: { ULONG x = 0;  if (SUCCEEDED(::SafeArrayGetElement(arr, &i, &x))) out.push_back(x); break; }
                    case VT_BSTR: {
                        BSTR x = nullptr;
                        if (SUCCEEDED(::SafeArrayGetElement(arr, &i, &x)) && x) out.push_back(wcstoull(x, nullptr, 10));
                        if (x) ::SysFreeString(x);
                        break;
                    }
                    default: break;
                    }
                }
            }
        }
        ::VariantClear(&v);
        return ok;
    }

    bool WmiGetBool(IWbemClassObject* o, const wchar_t* name, bool& out) {
        VARIANT v; ::VariantInit(&v);
        if (FAILED(o->Get(name, 0, &v, nullptr, nullptr))) return false;
        bool ok = false;
        if (v.vt == VT_BOOL) { out = (v.boolVal != VARIANT_FALSE); ok = true; }
        else if (v.vt == VT_I4 || v.vt == VT_UI4) { out = (v.ulVal != 0); ok = true; }
        ::VariantClear(&v);
        return ok;
    }

} // namespace sa