#include "AntivirusCollector.h"
#include "../Warnings.h"
#include "../ComHelpers.h"
#include <iwscapi.h>
#include <wscapi.h>
#include <wrl/client.h>
#include <algorithm>
#include <unordered_set>

#pragma comment(lib, "wscapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace sa {
namespace {
using Microsoft::WRL::ComPtr;

void Failure(AntivirusInfo& info, HRESULT hr, const wchar_t* operation) {
    info.status = ComStatus(hr);
    info.reason = warnings::ProviderFailure(operation, ErrorCode(hr));
}

bool IsDefender(const std::wstring& id, const std::wstring& name, const std::wstring& remediation) {
    // The built-in Windows Defender registration is stable across display languages.
    if (IEquals(id, L"{D68DDC3A-831F-4FAE-9E44-DA132C1ACF46}")) return true;
    if (IEquals(name, L"Windows Defender") || IEquals(name, L"Windows Defender Antivirus") ||
        IEquals(name, L"Microsoft Defender") || IEquals(name, L"Microsoft Defender Antivirus")) return true;
    return ToLower(remediation).starts_with(L"windowsdefender:");
}
} // namespace

AntivirusInfo CollectAntivirusInfo() {
    AntivirusInfo info;
    ComInit com;
    if (!com.ok()) { info.reason = warnings::comUnavailable; return info; }

    ComPtr<IWSCProductList> list;
    HRESULT hr = ::CoCreateInstance(__uuidof(WSCProductList), nullptr, CLSCTX_INPROC_SERVER,
        __uuidof(IWSCProductList), reinterpret_cast<void**>(list.GetAddressOf()));
    if (FAILED(hr)) { Failure(info, hr, L"Windows Security Center connection"); return info; }
    hr = list->Initialize(WSC_SECURITY_PROVIDER_ANTIVIRUS);
    if (FAILED(hr)) { Failure(info, hr, L"Antivirus enumeration"); return info; }
    LONG count = 0;
    hr = list->get_Count(&count);
    if (FAILED(hr) || count < 0) {
        Failure(info, FAILED(hr) ? hr : E_UNEXPECTED, L"Antivirus count"); return info;
    }

    info.status = Status::Success;
    std::unordered_set<std::wstring> seenIds;
    for (LONG i = 0; i < count; ++i) {
        ComPtr<IWscProduct> product;
        hr = list->get_Item(i, product.GetAddressOf());
        if (FAILED(hr) || !product) {
            Failure(info, FAILED(hr) ? hr : E_UNEXPECTED, L"Antivirus product read"); continue;
        }
        AntivirusProduct entry;
        Bstr name, id, remediation;
        const HRESULT nameStatus = product->get_ProductName(&name.value);
        if (SUCCEEDED(nameStatus)) entry.name = name.str();
        if (SUCCEEDED(product->get_ProductGuid(&id.value))) entry.id = id.str();
        if (entry.name.empty()) entry.name = L"Unnamed antivirus";
        if (!entry.id.empty() && !seenIds.insert(ToLower(entry.id)).second) continue;
        (void)product->get_RemediationPath(&remediation.value);
        entry.isDefender = IsDefender(entry.id, entry.name, remediation.str());

        WSC_SECURITY_PRODUCT_STATE state = WSC_SECURITY_PRODUCT_STATE_OFF;
        hr = product->get_ProductState(&state);
        if (SUCCEEDED(hr)) {
            switch (state) {
            case WSC_SECURITY_PRODUCT_STATE_ON: entry.state = AntivirusState::Enabled; break;
            case WSC_SECURITY_PRODUCT_STATE_OFF: entry.state = AntivirusState::Disabled; break;
            case WSC_SECURITY_PRODUCT_STATE_SNOOZED: entry.state = AntivirusState::Snoozed; break;
            case WSC_SECURITY_PRODUCT_STATE_EXPIRED: entry.state = AntivirusState::Expired; break;
            default: break;
            }
        }
        entry.status = SUCCEEDED(hr) && entry.state != AntivirusState::Unknown ? Status::Success : ComStatus(hr);
        if (entry.status != Status::Success || FAILED(nameStatus)) {
            info.status = Status::Unavailable;
            info.reason = warnings::antivirusPartial;
        }
        WSC_SECURITY_SIGNATURE_STATUS signature{};
        if (SUCCEEDED(product->get_SignatureStatus(&signature))) {
            if (signature == WSC_SECURITY_PRODUCT_UP_TO_DATE) entry.signaturesUpToDate = Tri::Yes;
            else if (signature == WSC_SECURITY_PRODUCT_OUT_OF_DATE) entry.signaturesUpToDate = Tri::No;
        }
        info.products.push_back(std::move(entry));
    }
    std::sort(info.products.begin(), info.products.end(), [](const auto& a, const auto& b) {
        const auto left = ToLower(a.name), right = ToLower(b.name);
        return left == right ? a.id < b.id : left < right;
    });
    return info;
}
} // namespace sa
