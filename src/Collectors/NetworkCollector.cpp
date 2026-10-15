// MUST come before anything that pulls in <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include "NetworkCollector.h"
#include "../Utilities.h"
#include <vector>
#include <algorithm>
#include <unordered_map>
#include <tuple>
#include <type_traits>
#include <comdef.h>
#include <wrl/client.h>
#include "../RegistryReader.h"
#include "../WmiHelper.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace sa {

    static std::wstring FormatMac(const BYTE* a, ULONG len) {
        std::wstring result;
        const wchar_t* hex = L"0123456789ABCDEF";
        result.reserve(len * 3);
        for (ULONG i = 0; i < len; ++i) {
            if (i) result += L':';
            result += hex[a[i] >> 4]; result += hex[a[i] & 15];
        }
        return result;
    }

    static std::wstring SockaddrToStr(const SOCKET_ADDRESS& sa) {
        if (!sa.lpSockaddr) return L"";
        wchar_t host[NI_MAXHOST]{};
        if (::GetNameInfoW(sa.lpSockaddr, sa.iSockaddrLength,
            host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST) == 0)
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

    static void CollectAdapters(NetworkInfo& n) {
        WSADATA data{};
        if (::WSAStartup(MAKEWORD(2, 2), &data) != 0) return;
        struct WinsockGuard { ~WinsockGuard() { ::WSACleanup(); } } winsock;
        ULONG size = 16 * 1024;
        std::vector<BYTE> buf(size);
        const ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS
            | GAA_FLAG_SKIP_ANYCAST;

        ULONG ret = ERROR_BUFFER_OVERFLOW;
        for (unsigned attempt = 0; attempt < 4 && ret == ERROR_BUFFER_OVERFLOW; ++attempt) {
            buf.resize(size);
            ret = ::GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()),
                &size);
        }
        if (ret == ERROR_NO_DATA) { n.status = Status::Success; return; }
        if (ret != NO_ERROR) { n.status = StatusFromWin32(ret); return; }

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
        return;
    }


namespace {
Status ReadDword(const wchar_t* path, const wchar_t* name, DWORD& value) {
    RegistryReader reader;
    auto status = reader.Open(HKEY_LOCAL_MACHINE, path);
    return status == Status::Success ? reader.GetDword(name, value) : status;
}
NetworkSetting RegistryFlag(const wchar_t* path, const wchar_t* name, bool inverted = false) {
    NetworkSetting result;
    result.source = std::wstring(L"HKLM\\") + path + L"\\" + name;
    DWORD value = 0;
    result.status = ReadDword(path, name, value);
    if (result.status == Status::Success) {
        if (value <= 1) result.enabled = ((value != 0) != inverted) ? Tri::Yes : Tri::No;
        else result.status = Status::Error;
    }
    if (result.status != Status::Success)
        result.reason = result.status == Status::NotFound ? L"Not configured; no effective state inferred."
            : L"Registry read failed or the value is invalid.";
    return result;
}
NetworkSetting RdpSetting(const wchar_t* name, const wchar_t* localPath, bool inverted = false) {
    auto result = RegistryFlag(L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services", name, inverted);
    if (result.status == Status::NotFound) result = RegistryFlag(localPath, name, inverted);
    return result;
}
Status HResultStatus(HRESULT hr) {
    return hr == E_ACCESSDENIED || hr == static_cast<HRESULT>(WBEM_E_ACCESS_DENIED)
        ? Status::AccessDenied : Status::Unavailable;
}
Status SmbConfiguration(WmiConnection& wmi, const wchar_t* className,
    Microsoft::WRL::ComPtr<IWbemClassObject>& configuration, std::wstring& reason) {
    // These classes expose a static read-only method, not enumerable singleton instances.
    Microsoft::WRL::ComPtr<IWbemClassObject> output;
    _bstr_t path(className), method(L"GetConfiguration");
    const HRESULT hr = wmi.services()->ExecMethod(path, method, 0, nullptr, nullptr, output.GetAddressOf(), nullptr);
    if (FAILED(hr) || !output) { reason = L"SMB GetConfiguration failed."; return HResultStatus(hr); }
    unsigned long long code = 0;
    if (!WmiGetUInt(output.Get(), L"ReturnValue", code)) {
        reason = L"SMB provider did not return a result code."; return Status::Unavailable;
    }
    if (code) {
        reason = L"SMB provider returned error " + std::to_wstring(code) + L".";
        return code <= MAXDWORD ? StatusFromWin32(static_cast<DWORD>(code)) : Status::Error;
    }
    _variant_t embedded;
    if (FAILED(output->Get(L"Output", 0, &embedded, nullptr, nullptr))) return Status::Unavailable;
    IUnknown* object = embedded.vt == VT_UNKNOWN ? embedded.punkVal
        : embedded.vt == VT_DISPATCH ? embedded.pdispVal : nullptr;
    if (!object || FAILED(object->QueryInterface(IID_PPV_ARGS(configuration.GetAddressOf())))) {
        reason = L"SMB provider did not return a configuration object."; return Status::Unavailable;
    }
    return Status::Success;
}
void CollectSmb(NetworkInfo& n) {
    WmiConnection wmi;
    std::wstring reason;
    const auto connected = wmi.Connect(L"ROOT\\Microsoft\\Windows\\SMB", &reason);
    auto read = [&](NetworkSetting& setting, IWbemClassObject* object, Status status,
                    const wchar_t* className, const wchar_t* property) {
        setting.source = std::wstring(L"SMB provider: ") + className + L"." + property;
        setting.status = status;
        setting.reason = reason;
        bool enabled = false;
        if (status == Status::Success) {
            if (WmiGetBool(object, property, enabled)) {
                setting.enabled = enabled ? Tri::Yes : Tri::No;
                setting.reason.clear();
            } else { setting.status = Status::Unavailable; setting.reason = L"Property is not available on this Windows version."; }
        }
    };
    Microsoft::WRL::ComPtr<IWbemClassObject> server, client;
    auto status = connected;
    if (connected == Status::Success) status = SmbConfiguration(wmi, L"MSFT_SmbServerConfiguration", server, reason);
    read(n.smb1Server, server.Get(), status, L"MSFT_SmbServerConfiguration", L"EnableSMB1Protocol");
    read(n.smbServerSigning, server.Get(), status, L"MSFT_SmbServerConfiguration", L"RequireSecuritySignature");
    read(n.smbEncryption, server.Get(), status, L"MSFT_SmbServerConfiguration", L"EncryptData");
    read(n.smbRejectUnencrypted, server.Get(), status, L"MSFT_SmbServerConfiguration", L"RejectUnencryptedAccess");
    if (connected == Status::Success) reason.clear();
    status = connected;
    if (connected == Status::Success) status = SmbConfiguration(wmi, L"MSFT_SmbClientConfiguration", client, reason);
    read(n.smbClientSigning, client.Get(), status, L"MSFT_SmbClientConfiguration", L"RequireSecuritySignature");
    read(n.smbGuestLogons, client.Get(), status, L"MSFT_SmbClientConfiguration", L"EnableInsecureGuestLogons");

    // SMB1 client availability is represented by the legacy redirector driver's start mode.
    n.smb1Client.source = L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10\\Start";
    DWORD start = 0;
    n.smb1Client.status = ReadDword(L"SYSTEM\\CurrentControlSet\\Services\\mrxsmb10", L"Start", start);
    if (n.smb1Client.status == Status::Success && start <= 4)
        n.smb1Client.enabled = start == 4 ? Tri::No : Tri::Yes;
    else if (n.smb1Client.status == Status::NotFound) {
        // A missing Start value in an existing driver key is not proof of absence.
        RegistryReader driver;
        if (driver.Open(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\mrxsmb10") == Status::NotFound) {
            n.smb1Client.status = Status::Success;
            n.smb1Client.enabled = Tri::No;
            n.smb1Client.reason = L"SMB1 client driver is not registered.";
        }
    } else if (n.smb1Client.status == Status::Success) n.smb1Client.status = Status::Error;
}
void CollectNetbios(NetworkInfo& n) {
    WmiConnection wmi;
    auto status = wmi.Connect();
    WmiObjects rows;
    if (status == Status::Success)
        status = wmi.Query(L"SELECT SettingID, TcpipNetbiosOptions FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE", rows.items());
    for (auto& adapter : n.adapters) {
        if (adapter.isLoopback || adapter.ipv4.empty()) { adapter.netbiosStatus = Status::Unsupported; continue; }
        adapter.netbiosStatus = status == Status::Success ? Status::Unavailable : status;
        if (status != Status::Success) continue;
        for (auto* row : rows.items()) {
            std::wstring id;
            if (!WmiGetString(row, L"SettingID", id) || !IEquals(id, adapter.guid)) continue;
            unsigned long long option = 0;
            if (WmiGetUInt(row, L"TcpipNetbiosOptions", option) && option <= 2) {
                adapter.netbiosOptions = static_cast<DWORD>(option);
                adapter.netbiosStatus = Status::Success;
            }
            break;
        }
    }
}

// Read a bounded local kernel endpoint snapshot; no probes, DNS lookups, or connections.
Status EndpointTable(ULONG family, bool tcp, std::vector<BYTE>& buffer, DWORD& bytes) {
    bytes = 16384;
    for (unsigned attempt = 0; attempt < 5; ++attempt) {
        if (bytes < sizeof(DWORD) || bytes > (16u << 20)) return Status::Error;
        buffer.resize(bytes);
        const DWORD error = tcp
            ? ::GetExtendedTcpTable(buffer.data(), &bytes, TRUE, family, TCP_TABLE_OWNER_PID_LISTENER, 0)
            : ::GetExtendedUdpTable(buffer.data(), &bytes, TRUE, family, UDP_TABLE_OWNER_PID, 0);
        if (error == ERROR_INSUFFICIENT_BUFFER) continue;
        return StatusFromWin32(error);
    }
    return Status::Unavailable;
}
void CollectEndpoints(NetworkInfo& n) {
    std::unordered_map<DWORD, std::pair<std::wstring, Status>> processes;
    auto process = [&](DWORD pid) {
        auto found = processes.find(pid);
        if (found != processes.end()) return found->second;
        std::pair<std::wstring, Status> result{L"Unknown", Status::Unavailable};
        if (pid == 4) result = {L"System", Status::Success};
        else {
            WinHandle handle(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
            if (!handle) result.second = StatusFromWin32(::GetLastError());
            else {
                std::wstring path(32768, L'\0');
                DWORD length = static_cast<DWORD>(path.size());
                if (::QueryFullProcessImageNameW(handle.get(), 0, path.data(), &length)) {
                    path.resize(length);
                    const auto slash = path.find_last_of(L"\\/");
                    result = {slash == std::wstring::npos ? path : path.substr(slash + 1), Status::Success};
                } else result.second = StatusFromWin32(::GetLastError());
            }
        }
        processes.emplace(pid, result);
        return result;
    };
    auto append = [&](ULONG family, bool tcp, const void* address, DWORD scope, DWORD port, DWORD pid) {
        const auto number = ntohs(static_cast<u_short>(port));
        if (!tcp && number != 69) return; // UDP is queried only for the legacy TFTP review.
        NetworkEndpoint endpoint;
        endpoint.protocol = tcp ? L"TCP" : L"UDP";
        endpoint.family = family == AF_INET ? L"IPv4" : L"IPv6";
        wchar_t text[INET6_ADDRSTRLEN]{};
        if (!::InetNtopW(static_cast<INT>(family), const_cast<void*>(address), text, _countof(text))) return;
        endpoint.address = text;
        if (family == AF_INET6 && scope) endpoint.address += L"%" + std::to_wstring(scope);
        bool loopback = false, wildcard = false;
        if (family == AF_INET) {
            const auto* bytes = static_cast<const BYTE*>(address);
            loopback = bytes[0] == 127;
            wildcard = *static_cast<const DWORD*>(address) == 0;
        } else {
            const auto* ip = static_cast<const IN6_ADDR*>(address);
            loopback = IN6_IS_ADDR_LOOPBACK(ip) != FALSE;
            wildcard = IN6_IS_ADDR_UNSPECIFIED(ip) != FALSE;
            if (IN6_IS_ADDR_V4MAPPED(ip)) loopback = ip->u.Byte[12] == 127;
        }
        endpoint.binding = loopback ? L"Loopback" : wildcard ? L"All interfaces" : L"Interface";
        endpoint.port = number;
        endpoint.processId = pid;
        auto [name, status] = process(pid);
        endpoint.processName = std::move(name);
        endpoint.processStatus = status;
        if (!loopback) {
            if (tcp && number == 21) endpoint.reviewNote = L"FTP port: review whether cleartext authentication is allowed.";
            else if (tcp && number == 23) endpoint.reviewNote = L"Telnet port: review legacy unencrypted remote access.";
            else if (!tcp && number == 69) endpoint.reviewNote = L"TFTP port: review unauthenticated file transfer.";
        }
        n.endpoints.push_back(std::move(endpoint));
    };
    for (const ULONG family : {ULONG{AF_INET}, ULONG{AF_INET6}}) {
        for (const bool tcp : {true, false}) {
            std::vector<BYTE> buffer;
            DWORD bytes = 0;
            auto status = EndpointTable(family, tcp, buffer, bytes);
            auto parse = [&]<typename Table>() {
                constexpr size_t offset = offsetof(Table, table);
                if (bytes < offset || bytes > buffer.size()) return false;
                const auto* table = reinterpret_cast<const Table*>(buffer.data());
                using Row = std::remove_cvref_t<decltype(table->table[0])>;
                if (table->dwNumEntries > (bytes - offset) / sizeof(Row)) return false;
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    const auto& row = table->table[i];
                    if constexpr (std::is_same_v<Table, MIB_TCPTABLE_OWNER_PID> || std::is_same_v<Table, MIB_UDPTABLE_OWNER_PID>)
                        append(family, tcp, &row.dwLocalAddr, 0, row.dwLocalPort, row.dwOwningPid);
                    else append(family, tcp, row.ucLocalAddr, row.dwLocalScopeId, row.dwLocalPort, row.dwOwningPid);
                }
                return true;
            };
            if (status == Status::Success) {
                const bool valid = family == AF_INET
                    ? (tcp ? parse.template operator()<MIB_TCPTABLE_OWNER_PID>() : parse.template operator()<MIB_UDPTABLE_OWNER_PID>())
                    : (tcp ? parse.template operator()<MIB_TCP6TABLE_OWNER_PID>() : parse.template operator()<MIB_UDP6TABLE_OWNER_PID>());
                if (!valid) status = Status::Error;
            }
            (tcp ? (family == AF_INET ? n.tcp4Status : n.tcp6Status)
                 : (family == AF_INET ? n.udp4Status : n.udp6Status)) = status;
        }
    }
    std::sort(n.endpoints.begin(), n.endpoints.end(), [](const auto& left, const auto& right) {
        return std::tie(left.protocol, left.port, left.processId, left.family, left.address)
             < std::tie(right.protocol, right.port, right.processId, right.family, right.address);
    });
}
} // namespace

NetworkInfo CollectNetworkInfo(bool includeInventory) {
    NetworkInfo n;
    ComInit com;
    n.llmnr = RegistryFlag(L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", L"EnableMulticast");
    n.rdp = RdpSetting(L"fDenyTSConnections", L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server", true);
    n.rdpNla = RdpSetting(L"UserAuthentication", L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp");
    DWORD port = 0;
    n.rdpPortStatus = ReadDword(L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", L"PortNumber", port);
    if (n.rdpPortStatus == Status::Success) {
        if (port && port <= 65535) n.rdpPort = port;
        else n.rdpPortStatus = Status::Error;
    }
    try { CollectSmb(n); } catch (...) { /* Individual settings retain Unknown. */ }
    try { CollectAdapters(n); } catch (...) { n.status = Status::Error; }
    try { CollectNetbios(n); } catch (...) { /* Preserve adapter inventory. */ }
    // InetNtop needs Winsock initialized independently of the adapter query's scope.
    WSADATA data{};
    if (includeInventory && ::WSAStartup(MAKEWORD(2, 2), &data) == 0) {
        struct Guard { ~Guard() { ::WSACleanup(); } } guard;
        try { CollectEndpoints(n); }
        catch (...) {
            // A partial snapshot must not erase independent configuration readings.
            n.tcp4Status = n.tcp6Status = n.udp4Status = n.udp6Status = Status::Error;
        }
    }
    return n;
}

} // namespace sa
