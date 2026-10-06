// MUST come before anything that pulls in <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include "NetworkCollector.h"
#include "../Utilities.h"
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace sa {

    static std::wstring FormatMac(const BYTE* a, ULONG len) {
        if (len < 6) return L"";
        wchar_t buf[32]{};
        swprintf_s(buf, L"%02X:%02X:%02X:%02X:%02X:%02X",
            a[0], a[1], a[2], a[3], a[4], a[5]);
        return buf;
    }

    static std::wstring SockaddrToStr(const SOCKET_ADDRESS& sa) {
        if (!sa.lpSockaddr) return L"";
        wchar_t host[NI_MAXHOST]{};
        DWORD len = NI_MAXHOST;
        if (::WSAAddressToStringW(sa.lpSockaddr, sa.iSockaddrLength,
            nullptr, host, &len) == 0)
            return host;
        return L"";
    }

    static const wchar_t* IfTypeName(ULONG t) {
        switch (t) {
        case IF_TYPE_ETHERNET_CSMACD:   return L"Ethernet";
        case IF_TYPE_IEEE80211:         return L"Wi-Fi";
        case IF_TYPE_SOFTWARE_LOOPBACK: return L"Loopback";
        case IF_TYPE_TUNNEL:            return L"Tunnel";
        case IF_TYPE_PPP:               return L"PPP";
        case IF_TYPE_IEEE1394:          return L"FireWire";
        default:                        return L"Other";
        }
    }

    NetworkInfo CollectNetworkInfo() {
        NetworkInfo n;
        ULONG size = 16 * 1024;
        std::vector<BYTE> buf(size);
        const ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS
            | GAA_FLAG_SKIP_ANYCAST;

        ULONG ret = ::GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()),
            &size);
        if (ret == ERROR_BUFFER_OVERFLOW) {
            buf.resize(size);
            ret = ::GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()),
                &size);
        }
        if (ret != NO_ERROR) { n.status = Status::Error; return n; }

        for (IP_ADAPTER_ADDRESSES* a =
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
            a != nullptr;
            a = a->Next) {
            NetworkAdapterInfo ad;
            ad.name = a->FriendlyName ? a->FriendlyName : L"";
            ad.description = a->Description ? a->Description : L"";
            ad.up = (a->OperStatus == IfOperStatusUp);
            ad.ifType = IfTypeName(a->IfType);
            ad.dhcp = (a->Flags & IP_ADAPTER_DHCP_ENABLED) != 0;
            ad.dhcpServer = a->Dhcpv4Server.iSockaddrLength ? SockaddrToStr(a->Dhcpv4Server) : L"";

            // AdapterName is PCHAR (ANSI) — convert to wide.
            if (a->AdapterName) ad.guid = Utf8ToWide(a->AdapterName);

            if (a->PhysicalAddressLength)
                ad.macAddress = FormatMac(a->PhysicalAddress, a->PhysicalAddressLength);

            ad.isLoopback = (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK);
            ad.isVirtual = (a->IfType == IF_TYPE_TUNNEL) ||
                (ad.description.find(L"Virtual") != std::wstring::npos) ||
                (ad.description.find(L"Hyper-V") != std::wstring::npos);
            ad.isVpn = (ad.description.find(L"VPN") != std::wstring::npos) ||
                (ad.description.find(L"WireGuard") != std::wstring::npos) ||
                (ad.description.find(L"OpenVPN") != std::wstring::npos);

            for (IP_ADAPTER_UNICAST_ADDRESS* ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
                std::wstring s = SockaddrToStr(ua->Address);
                if (s.empty()) continue;
                if (ua->Address.lpSockaddr->sa_family == AF_INET)       ad.ipv4.push_back(s);
                else if (ua->Address.lpSockaddr->sa_family == AF_INET6) ad.ipv6.push_back(s);
            }
            for (IP_ADAPTER_GATEWAY_ADDRESS* g = a->FirstGatewayAddress; g; g = g->Next)
                ad.gateways.push_back(SockaddrToStr(g->Address));
            for (IP_ADAPTER_DNS_SERVER_ADDRESS* d = a->FirstDnsServerAddress; d; d = d->Next)
                ad.dns.push_back(SockaddrToStr(d->Address));

            n.adapters.push_back(std::move(ad));
        }
        n.status = Status::Success;
        return n;
    }

} // namespace sa