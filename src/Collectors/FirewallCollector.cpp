#include "FirewallCollector.h"
#include <windows.h>
#include <netfw.h>
#include <wrl/client.h>

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
        ServiceHandle scm(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (scm) {
            ServiceHandle svc(::OpenServiceW(scm.get(), L"MpsSvc", SERVICE_QUERY_STATUS));
            if (svc) {
                SERVICE_STATUS ss{};
                if (::QueryServiceStatus(svc.get(), &ss))
                {
                    fw.serviceRunning = (ss.dwCurrentState == SERVICE_RUNNING);
                    fw.serviceStatus = Status::Success;
                }
                else fw.serviceStatus = StatusFromWin32(::GetLastError());
            }
            else fw.serviceStatus = StatusFromWin32(::GetLastError());
        }
        else fw.serviceStatus = StatusFromWin32(::GetLastError());

        Microsoft::WRL::ComPtr<INetFwPolicy2> policy;
        HRESULT hr = ::CoCreateInstance(__uuidof(NetFwPolicy2), nullptr,
            CLSCTX_INPROC_SERVER,
            __uuidof(INetFwPolicy2),
            reinterpret_cast<void**>(policy.GetAddressOf()));
        if (FAILED(hr) || !policy) { fw.status = Status::Unavailable; return fw; }

        const NET_FW_PROFILE_TYPE2 profiles[] = {
            NET_FW_PROFILE2_DOMAIN,
            NET_FW_PROFILE2_PRIVATE,
            NET_FW_PROFILE2_PUBLIC
        };
        fw.status = Status::Success;
        long active = 0;
        if (SUCCEEDED(policy->get_CurrentProfileTypes(&active))) {
            fw.activeProfiles = static_cast<DWORD>(active);
            fw.activeProfilesStatus = Status::Success;
        }
        for (NET_FW_PROFILE_TYPE2 p : profiles) {
            FirewallProfile prof;
            prof.name = ProfileName(static_cast<int>(p));

            VARIANT_BOOL en = VARIANT_FALSE;
            const HRESULT enabledResult = policy->get_FirewallEnabled(p, &en);
            if (SUCCEEDED(enabledResult))
                prof.enabled = (en != VARIANT_FALSE);

            NET_FW_ACTION inAction = NET_FW_ACTION_BLOCK;
            NET_FW_ACTION outAction = NET_FW_ACTION_BLOCK;
            const HRESULT inboundResult = policy->get_DefaultInboundAction(p, &inAction);
            const HRESULT outboundResult = policy->get_DefaultOutboundAction(p, &outAction);
            if (SUCCEEDED(inboundResult))
                prof.defaultInbound = static_cast<DWORD>(inAction);
            if (SUCCEEDED(outboundResult))
                prof.defaultOutbound = static_cast<DWORD>(outAction);

            VARIANT_BOOL disabled = VARIANT_FALSE;
            if (SUCCEEDED(policy->get_NotificationsDisabled(p, &disabled)))
                prof.notificationsEnabled = disabled == VARIANT_FALSE;
            prof.status = SUCCEEDED(enabledResult) && SUCCEEDED(inboundResult) && SUCCEEDED(outboundResult)
                ? Status::Success : Status::Unavailable;
            if (prof.status != Status::Success) fw.status = Status::Unavailable;

            fw.profiles.push_back(std::move(prof));
        }

        return fw;
    }

} // namespace sa
