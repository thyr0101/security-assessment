// MUST come before anything that pulls in <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>

#include "NetworkCollector.h"
#include "../Utilities.h"
#include <vector>
#include <algorithm>
#include <comdef.h>
#include <wrl/client.h>
#include "../RegistryReader.h"
#include "../WmiHelper.h"

#pragma comment(lib, "iphlpapi.lib")

namespace sa {
namespace {
// Adapter addresses and identities are never stored in the assessment. GUIDs
// exist only long enough to match applicable active IPv4 adapters to policy.
void CollectAdapterPolicies(NetworkInfo& info) {
    ULONG size = 16384;
    std::vector<BYTE> buffer;
    ULONG result = ERROR_BUFFER_OVERFLOW;
    constexpr ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME;
    for (unsigned attempt = 0; attempt < 4 && result == ERROR_BUFFER_OVERFLOW; ++attempt) {
        buffer.resize(size);
        result = ::GetAdaptersAddresses(AF_INET, flags, nullptr,
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
    }
    if (result == ERROR_NO_DATA) { info.status = Status::Success; return; }
    if (result != NO_ERROR) { info.status = StatusFromWin32(result); return; }
    std::vector<std::wstring> ids;
    for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()); adapter; adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK || !adapter->FirstUnicastAddress)
            continue;
        info.adapters.emplace_back();
        ids.push_back(adapter->AdapterName ? Utf8ToWide(adapter->AdapterName) : L"");
    }
    info.status = Status::Success;
    if (ids.empty()) return;
    WmiConnection wmi;
    auto status = wmi.Connect();
    WmiObjects rows;
    if (status == Status::Success) {
        std::wstring query = L"SELECT SettingID,TcpipNetbiosOptions FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE AND (";
        bool first = true;
        for (const auto& id : ids) {
            if (id.empty() || id.find_first_of(L"'\\") != std::wstring::npos) continue;
            if (!first) query += L" OR ";
            query += L"SettingID='" + id + L"'";
            first = false;
        }
        if (first) status = Status::Unavailable;
        else { query += L")"; status = wmi.Query(query.c_str(), rows.items()); }
    }
    for (size_t i = 0; i < ids.size(); ++i) {
        auto& policy = info.adapters[i];
        policy.netbiosStatus = status == Status::Success ? Status::Unavailable : status;
        if (status != Status::Success) continue;
        for (auto* row : rows.items()) {
            std::wstring id;
            if (!WmiGetString(row, L"SettingID", id) || !IEquals(id, ids[i])) continue;
            unsigned long long value = 0;
            if (WmiGetUInt(row, L"TcpipNetbiosOptions", value) && value <= 2) {
                policy.netbiosOptions = static_cast<DWORD>(value);
                policy.netbiosStatus = Status::Success;
            }
            break;
        }
    }
}

Status ReadDword(const wchar_t* path, const wchar_t* name, DWORD& value) {
    RegistryReader reader;
    auto status = reader.Open(HKEY_LOCAL_MACHINE, path);
    return status == Status::Success ? reader.GetDword(name, value) : status;
}
NetworkSetting RegistryFlag(const wchar_t* path, const wchar_t* name, bool inverted = false) {
    NetworkSetting result;
    DWORD value = 0;
    result.status = ReadDword(path, name, value);
    if (result.status == Status::Success) {
        if (value <= 1) result.enabled = ((value != 0) != inverted) ? Tri::Yes : Tri::No;
        else result.status = Status::Error;
    }
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
    Microsoft::WRL::ComPtr<IWbemClassObject>& configuration) {
    // These classes expose a static read-only method, not enumerable singleton instances.
    Microsoft::WRL::ComPtr<IWbemClassObject> output;
    _bstr_t path(className), method(L"GetConfiguration");
    const HRESULT hr = wmi.services()->ExecMethod(path, method, 0, nullptr, nullptr, output.GetAddressOf(), nullptr);
    if (FAILED(hr) || !output) { return HResultStatus(hr); }
    unsigned long long code = 0;
    if (!WmiGetUInt(output.Get(), L"ReturnValue", code)) {
        return Status::Unavailable;
    }
    if (code) {
        return code <= MAXDWORD ? StatusFromWin32(static_cast<DWORD>(code)) : Status::Error;
    }
    _variant_t embedded;
    if (FAILED(output->Get(L"Output", 0, &embedded, nullptr, nullptr))) return Status::Unavailable;
    IUnknown* object = embedded.vt == VT_UNKNOWN ? embedded.punkVal
        : embedded.vt == VT_DISPATCH ? embedded.pdispVal : nullptr;
    if (!object || FAILED(object->QueryInterface(IID_PPV_ARGS(configuration.GetAddressOf())))) {
        return Status::Unavailable;
    }
    return Status::Success;
}
void CollectSmb(NetworkInfo& n) {
    WmiConnection wmi;
    const auto connected = wmi.Connect(L"ROOT\\Microsoft\\Windows\\SMB");
    auto read = [&](NetworkSetting& setting, IWbemClassObject* object, Status status,
                    const wchar_t* property) {
        setting.status = status;
        bool enabled = false;
        if (status == Status::Success) {
            if (WmiGetBool(object, property, enabled)) {
                setting.enabled = enabled ? Tri::Yes : Tri::No;
            } else setting.status = Status::Unavailable;
        }
    };
    Microsoft::WRL::ComPtr<IWbemClassObject> server, client;
    auto status = connected;
    if (connected == Status::Success) status = SmbConfiguration(wmi, L"MSFT_SmbServerConfiguration", server);
    read(n.smb1Server, server.Get(), status, L"EnableSMB1Protocol");
    read(n.smbServerSigning, server.Get(), status, L"RequireSecuritySignature");
    read(n.smbEncryption, server.Get(), status, L"EncryptData");
    read(n.smbRejectUnencrypted, server.Get(), status, L"RejectUnencryptedAccess");
    status = connected;
    if (connected == Status::Success) status = SmbConfiguration(wmi, L"MSFT_SmbClientConfiguration", client);
    read(n.smbClientSigning, client.Get(), status, L"RequireSecuritySignature");
    read(n.smbGuestLogons, client.Get(), status, L"EnableInsecureGuestLogons");

    // SMB1 client availability is represented by the legacy redirector driver's start mode.
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
        }
    } else if (n.smb1Client.status == Status::Success) n.smb1Client.status = Status::Error;
}
} // namespace

NetworkInfo CollectNetworkInfo() {
    NetworkInfo n;
    ComInit com;
    n.llmnr = RegistryFlag(L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", L"EnableMulticast");
    n.rdp = RdpSetting(L"fDenyTSConnections", L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server", true);
    n.rdpNla = RdpSetting(L"UserAuthentication", L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp");
    try { CollectSmb(n); } catch (...) { /* Individual settings retain Unknown. */ }
    try { CollectAdapterPolicies(n); } catch (...) { n.status = Status::Error; }
    return n;
}

} // namespace sa
