#include "FirewallCollector.h"
#include <windows.h>
#include <netfw.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace sa {

    static const wchar_t* ProfileName(int p) {
        switch (p) {
        case NET_FW_PROFILE2_DOMAIN:  return L"Domain";
        case NET_FW_PROFILE2_PRIVATE: return L"Private";
        case NET_FW_PROFILE2_PUBLIC:  return L"Public";
        default:                      return L"Unknown";
        }
    }

    FirewallInfo CollectFirewallInfo() {
        FirewallInfo fw;
        ComInit ci;
        if (!ci.ok()) { fw.status = Status::Error; return fw; }

        // Service state via SCM
        SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (scm) {
            SC_HANDLE svc = ::OpenServiceW(scm, L"MpsSvc", SERVICE_QUERY_STATUS);
            if (svc) {
                SERVICE_STATUS ss{};
                if (::QueryServiceStatus(svc, &ss))
                    fw.serviceRunning = (ss.dwCurrentState == SERVICE_RUNNING);
                ::CloseServiceHandle(svc);
            }
            ::CloseServiceHandle(scm);
        }

        INetFwPolicy2* policy = nullptr;
        HRESULT hr = ::CoCreateInstance(__uuidof(NetFwPolicy2), nullptr,
            CLSCTX_INPROC_SERVER,
            __uuidof(INetFwPolicy2),
            reinterpret_cast<void**>(&policy));
        if (FAILED(hr) || !policy) { fw.status = Status::Unavailable; return fw; }

        const NET_FW_PROFILE_TYPE2 profiles[] = {
            NET_FW_PROFILE2_DOMAIN,
            NET_FW_PROFILE2_PRIVATE,
            NET_FW_PROFILE2_PUBLIC
        };
        for (NET_FW_PROFILE_TYPE2 p : profiles) {
            FirewallProfile prof;
            prof.name = ProfileName(static_cast<int>(p));

            VARIANT_BOOL en = VARIANT_FALSE;
            if (SUCCEEDED(policy->get_FirewallEnabled(p, &en)))
                prof.enabled = (en != VARIANT_FALSE);

            NET_FW_ACTION inAction = NET_FW_ACTION_BLOCK;
            NET_FW_ACTION outAction = NET_FW_ACTION_BLOCK;
            if (SUCCEEDED(policy->get_DefaultInboundAction(p, &inAction)))
                prof.defaultInbound = static_cast<DWORD>(inAction);
            if (SUCCEEDED(policy->get_DefaultOutboundAction(p, &outAction)))
                prof.defaultOutbound = static_cast<DWORD>(outAction);

            // NotificationsEnabled is omitted — it is cosmetic and some SDK
            // revisions do not expose it in a way that compiles across configs.

            fw.profiles.push_back(std::move(prof));
        }

        policy->Release();
        fw.status = Status::Success;
        return fw;
    }

} // namespace sa