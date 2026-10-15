#include "StorageCollector.h"
#include "../WmiHelper.h"
#include "../Utilities.h"
#include <windows.h>
#include <winioctl.h>
#include <ntddstor.h>
#include <vector>
#include <algorithm>
#include <cstring>
#include <comdef.h>
#include <wrl/client.h>

namespace sa {

static std::wstring BusTypeName(STORAGE_BUS_TYPE t) {
    switch (t) {
    case BusTypeScsi: return L"SCSI";
    case BusTypeAtapi: return L"ATAPI";
    case BusTypeAta: return L"ATA";
    case BusType1394: return L"1394";
    case BusTypeSsa: return L"SSA";
    case BusTypeFibre: return L"Fibre";
    case BusTypeUsb: return L"USB";
    case BusTypeRAID: return L"RAID";
    case BusTypeiScsi: return L"iSCSI";
    case BusTypeSas: return L"SAS";
    case BusTypeSata: return L"SATA";
    case BusTypeSd: return L"SD";
    case BusTypeMmc: return L"MMC";
    case BusTypeVirtual: return L"Virtual";
    case BusTypeFileBackedVirtual: return L"FileBackedVirtual";
    case BusTypeSpaces: return L"StorageSpaces";
    case BusTypeNvme: return L"NVMe";
    case BusTypeSCM: return L"SCM";
    case BusTypeUfs: return L"UFS";
    default: return L"Other";
    }
}

static void CollectPhysicalDisks(StorageInfo& s) {
    std::vector<wchar_t> devices(32768);
    DWORD count = 0;
    while (!(count = ::QueryDosDeviceW(nullptr, devices.data(), static_cast<DWORD>(devices.size())))) {
        if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER || devices.size() >= (1u << 20)) return;
        devices.resize(devices.size() * 2);
    }
    std::vector<unsigned> indices;
    for (const wchar_t* name = devices.data(); *name; name += wcslen(name) + 1) {
        constexpr wchar_t prefix[] = L"PhysicalDrive";
        if (wcsncmp(name, prefix, _countof(prefix) - 1) != 0) continue;
        const wchar_t* number = name + _countof(prefix) - 1;
        wchar_t* end = nullptr;
        unsigned long index = wcstoul(number, &end, 10);
        if (end != number && !*end) indices.push_back(index);
    }
    std::sort(indices.begin(), indices.end());
    for (unsigned i : indices) {
        std::wstring path = L"\\\\.\\PhysicalDrive" + std::to_wstring(i);
        WinHandle h(::CreateFileW(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  nullptr, OPEN_EXISTING, 0, nullptr));
        if (!h.valid()) continue;

        STORAGE_PROPERTY_QUERY q{};
        q.PropertyId = StorageDeviceProperty;
        q.QueryType = PropertyStandardQuery;
        STORAGE_DESCRIPTOR_HEADER hdr{};
        DWORD ret = 0;
        if (!::DeviceIoControl(h.get(), IOCTL_STORAGE_QUERY_PROPERTY,
                               &q, sizeof(q), &hdr, sizeof(hdr), &ret, nullptr))
            continue;
        if (ret < sizeof(hdr) || hdr.Size < sizeof(STORAGE_DEVICE_DESCRIPTOR) || hdr.Size > (1u << 20))
            continue;
        std::vector<BYTE> buf(hdr.Size);
        if (!::DeviceIoControl(h.get(), IOCTL_STORAGE_QUERY_PROPERTY,
                               &q, sizeof(q), buf.data(), (DWORD)buf.size(), &ret, nullptr))
            continue;
        if (ret < sizeof(STORAGE_DEVICE_DESCRIPTOR) || ret > buf.size()) continue;
        auto* d = (STORAGE_DEVICE_DESCRIPTOR*)buf.data();
        StorageDisk disk;
        disk.index = i;
        auto readString = [&](DWORD offset) -> std::wstring {
            if (!offset || offset >= ret) return {};
            const char* start = reinterpret_cast<const char*>(buf.data() + offset);
            const char* end = static_cast<const char*>(std::memchr(start, 0, ret - offset));
            return end ? Trim(Utf8ToWide(std::string(start, end))) : std::wstring{};
        };
        disk.vendor = readString(d->VendorIdOffset);
        disk.model = readString(d->ProductIdOffset);
        disk.busType = BusTypeName(d->BusType);
        disk.mediaType = d->BusType == BusTypeNvme ? L"SSD" : L"Unknown";

        // Seek penalty reveals SSD vs HDD on many drives
        DEVICE_SEEK_PENALTY_DESCRIPTOR spd{};
        STORAGE_PROPERTY_QUERY q2{};
        q2.PropertyId = StorageDeviceSeekPenaltyProperty;
        q2.QueryType = PropertyStandardQuery;
        if (::DeviceIoControl(h.get(), IOCTL_STORAGE_QUERY_PROPERTY,
                              &q2, sizeof(q2), &spd, sizeof(spd), &ret, nullptr) && ret >= sizeof(spd)) {
            if (!spd.IncursSeekPenalty && disk.mediaType == L"Unknown") disk.mediaType = L"SSD";
            else if (spd.IncursSeekPenalty && disk.mediaType == L"Unknown") disk.mediaType = L"HDD";
        }

        // IOCTL_DISK_GET_LENGTH_INFO needs FILE_READ_ACCESS, and this handle was opened
        // with no access (enough for property queries), so it fails and leaves 0 bytes.
        // IOCTL_DISK_GET_DRIVE_GEOMETRY_EX is FILE_ANY_ACCESS and reports the disk size.
        std::vector<BYTE> geo(4096);
        DWORD geoRet = 0;
        if (::DeviceIoControl(h.get(), IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                              nullptr, 0, geo.data(), (DWORD)geo.size(), &geoRet, nullptr) &&
            geoRet >= sizeof(DISK_GEOMETRY_EX) &&
            reinterpret_cast<DISK_GEOMETRY_EX*>(geo.data())->DiskSize.QuadPart >= 0)
            disk.sizeBytes = (unsigned long long)
                reinterpret_cast<DISK_GEOMETRY_EX*>(geo.data())->DiskSize.QuadPart;

        s.disks.push_back(std::move(disk));
    }
}

static void CollectVolumeDisks(StorageVolume& volume) {
    std::wstring device = volume.volumeId;
    if (!device.empty() && device.back() == L'\\') device.pop_back();
    WinHandle handle(::CreateFileW(device.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr));
    if (!handle.valid()) {
        volume.diskMappingStatus = StatusFromWin32(::GetLastError());
        return;
    }
    std::vector<BYTE> buffer(sizeof(VOLUME_DISK_EXTENTS));
    // Extents can change while a removable/spanned volume is being queried.
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        DWORD returned = 0;
        const BOOL ok = ::DeviceIoControl(handle.get(), IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            nullptr, 0, buffer.data(), static_cast<DWORD>(buffer.size()), &returned, nullptr);
        const DWORD error = ok ? ERROR_SUCCESS : ::GetLastError();
        if (!ok && error != ERROR_MORE_DATA) {
            volume.diskMappingStatus = StatusFromWin32(error);
            return;
        }
        constexpr size_t offset = offsetof(VOLUME_DISK_EXTENTS, Extents);
        if (returned < offset || returned > buffer.size()) break;
        const auto* extents = reinterpret_cast<const VOLUME_DISK_EXTENTS*>(buffer.data());
        const DWORD count = extents->NumberOfDiskExtents;
        if (!count || count > ((1u << 20) - offset) / sizeof(DISK_EXTENT)) break;
        const size_t required = offset + static_cast<size_t>(count) * sizeof(DISK_EXTENT);
        if (!ok) {
            buffer.resize((std::max)(required, buffer.size() * 2));
            if (buffer.size() > (1u << 20)) break;
            continue;
        }
        if (required > returned) break;
        for (DWORD i = 0; i < count; ++i) volume.diskIndices.push_back(extents->Extents[i].DiskNumber);
        std::sort(volume.diskIndices.begin(), volume.diskIndices.end());
        volume.diskIndices.erase(std::unique(volume.diskIndices.begin(), volume.diskIndices.end()), volume.diskIndices.end());
        volume.diskMappingStatus = Status::Success;
        return;
    }
    volume.diskMappingStatus = Status::Error;
}

static Status CollectVolumes(StorageInfo& s) {
    // Don't pop "no disk in drive" dialogs for empty removable/optical drives.
    struct ErrorModeGuard {
        DWORD old = 0;
        bool changed = ::SetThreadErrorMode(::GetThreadErrorMode() | SEM_FAILCRITICALERRORS, &old) != FALSE;
        ~ErrorModeGuard() { if (changed) ::SetThreadErrorMode(old, nullptr); }
    } errorMode;

    wchar_t volName[MAX_PATH]{};
    HANDLE h = ::FindFirstVolumeW(volName, MAX_PATH);
    if (h == INVALID_HANDLE_VALUE) return StatusFromWin32(::GetLastError());
    struct VolumeGuard { HANDLE h; ~VolumeGuard() { ::FindVolumeClose(h); } } guard{h};
    Status status = Status::Success;

    do {
        // volName looks like \\?\Volume{GUID}\ . GetVolumePathNamesForVolumeNameW
        // REQUIRES that trailing backslash. The old code stripped it (that is only
        // needed when opening the volume as a device), so the call always failed and
        // no volume was ever listed - hence "NoVolumes" and no BitLocker result.
        std::vector<wchar_t> paths(1024);
        DWORD cch = static_cast<DWORD>(paths.size());
        BOOL gotPaths = ::GetVolumePathNamesForVolumeNameW(volName, paths.data(), cch, &cch);
        if (!gotPaths && ::GetLastError() == ERROR_MORE_DATA) {
            paths.resize(cch);
            gotPaths = ::GetVolumePathNamesForVolumeNameW(volName, paths.data(), cch, &cch);
        }
        if (!gotPaths) status = StatusFromWin32(::GetLastError());
        if (gotPaths && paths[0]) {
            StorageVolume mapping;
            mapping.volumeId = volName;
            CollectVolumeDisks(mapping);
            for (wchar_t* p = paths.data(); *p; p += wcslen(p) + 1) {
                StorageVolume v;
                v.volumeId = volName;
                v.mountPoint = p;
                v.diskIndices = mapping.diskIndices;
                v.diskMappingStatus = mapping.diskMappingStatus;

                wchar_t fsName[MAX_PATH]{};
                wchar_t volLabel[MAX_PATH]{};     // local, avoids the `label` macro issue
                DWORD serial = 0, maxLen = 0, flags = 0;
                if (::GetVolumeInformationW(p, volLabel, MAX_PATH, &serial,
                    &maxLen, &flags, fsName, MAX_PATH)) {
                    v.volumeLabel = volLabel;     // <-- renamed member
                    v.filesystem = fsName;
                }

                ULARGE_INTEGER freeAvail{}, total{}, totalFree{};
                if (::GetDiskFreeSpaceExW(p, &freeAvail, &total, &totalFree)) {
                    v.totalBytes = total.QuadPart;
                    v.freeBytes = freeAvail.QuadPart;
                }

                UINT dt = ::GetDriveTypeW(p);
                switch (dt) {
                case DRIVE_FIXED:     v.driveType = L"Fixed";     break;
                case DRIVE_REMOVABLE: v.driveType = L"Removable"; break;
                case DRIVE_REMOTE:    v.driveType = L"Network";   break;
                case DRIVE_CDROM:     v.driveType = L"CD-ROM";    break;
                case DRIVE_RAMDISK:   v.driveType = L"RAM";       break;
                default:              v.driveType = L"Unknown";   break;
                }
                v.bitLockerState = L"Unknown";
                s.volumes.push_back(std::move(v));
            }
        }
    } while (::FindNextVolumeW(h, volName, MAX_PATH));

    const DWORD error = ::GetLastError();
    if (error != ERROR_NO_MORE_FILES) status = StatusFromWin32(error);
    return status;
}

// Win32_EncryptableVolume.EncryptionMethod values.
static std::wstring EncryptionMethodName(unsigned long long m) {
    switch (m) {
    case 0: return L"";                         // not encrypted
    case 1: return L"AES 128 with Diffuser";
    case 2: return L"AES 256 with Diffuser";
    case 3: return L"AES 128";
    case 4: return L"AES 256";
    case 5: return L"Hardware encryption";
    case 6: return L"XTS-AES 128";
    case 7: return L"XTS-AES 256";
    default: return L"Unknown (" + std::to_wstring(m) + L")";
    }
}

// Calls a no-input WMI method on `obj` and reads one uint32 out-parameter.
// Fails if the call fails or the method's ReturnValue is non-zero.
static bool CallUIntMethod(IWbemServices* svc, IWbemClassObject* obj,
                           const wchar_t* method, const wchar_t* outName,
                           unsigned long long& out) {
    if (!svc) return false;
    _variant_t path;
    if (FAILED(obj->Get(L"__PATH", 0, &path, nullptr, nullptr)) ||
        path.vt != VT_BSTR || !path.bstrVal) {
        return false;
    }
    _bstr_t bm(method);
    Microsoft::WRL::ComPtr<IWbemClassObject> res;
    HRESULT hr = svc->ExecMethod(path.bstrVal, bm, 0, nullptr, nullptr, res.GetAddressOf(), nullptr);
    if (FAILED(hr) || !res) return false;
    unsigned long long rv = 0;
    bool ok = WmiGetUInt(res.Get(), L"ReturnValue", rv) && rv == 0 &&
              WmiGetUInt(res.Get(), outName, out);
    return ok;
}

static void CollectBitLocker(StorageInfo& s) {
    if (!IsElevated()) {
        for (auto& volume : s.volumes) {
            if (volume.driveType != L"Fixed") continue;
            volume.bitLockerStatus = Status::AccessDenied;
            volume.bitLockerNote = L"Administrator access is required to verify BitLocker protection.";
        }
        return;
    }
    ComInit ci;
    WmiConnection wmi;
    std::wstring why;
    const Status cs = wmi.Connect(L"ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption", &why);
    if (cs != Status::Success) {
        // This namespace is only accessible elevated.
        for (auto& v : s.volumes) {
            if (v.driveType != L"Fixed") continue;
            v.bitLockerStatus = (cs == Status::AccessDenied) ? Status::AccessDenied
                                                             : Status::Unavailable;
            v.bitLockerNote = why;
        }
        return;
    }
    WmiObjects objects;
    const Status queryStatus = wmi.Query(L"SELECT DeviceID,ProtectionStatus,EncryptionMethod FROM Win32_EncryptableVolume", objects.items(), &why);
    for (auto& v : s.volumes) {
        if (v.driveType != L"Fixed") continue;
        // Match the volume GUID so folder mount points resolve to their own volume.
        if (queryStatus != Status::Success) {
            v.bitLockerStatus = queryStatus;
            v.bitLockerNote = why;
            continue;
        }
        v.bitLockerStatus = Status::Unavailable;
        v.bitLockerNote = L"no Win32_EncryptableVolume instance";
        for (auto* o : objects.items()) {
            std::wstring deviceId;
            if (!WmiGetString(o, L"DeviceID", deviceId) || !IEquals(deviceId, v.volumeId)) continue;
            v.bitLockerNote.clear();
            unsigned long long ps = 2, em = 0;
            bool havePs = WmiGetUInt(o, L"ProtectionStatus", ps);
            if (!havePs)
                havePs = CallUIntMethod(wmi.services(), o, L"GetProtectionStatus",
                                        L"ProtectionStatus", ps);
            bool haveEm = WmiGetUInt(o, L"EncryptionMethod", em);
            if (!haveEm)
                haveEm = CallUIntMethod(wmi.services(), o, L"GetEncryptionMethod",
                                        L"EncryptionMethod", em);

            if (havePs) {
                v.bitLockerStatus = ps <= 1 ? Status::Success : Status::Unavailable;
                // ProtectionStatus: 0 = unprotected, 1 = protected, 2 = unknown
                v.bitLockerState = (ps == 1) ? L"On" : (ps == 0 ? L"Off" : L"Unknown");
            } else {
                v.bitLockerStatus = Status::Unavailable;
                v.bitLockerNote = L"ProtectionStatus could not be read";
            }
            if (haveEm) v.encryptionMethod = EncryptionMethodName(em);
            else if (havePs && ps == 1) v.encryptionMethod = L"Unknown";
            break;
        }
    }
}

StorageInfo CollectStorageInfo() {
    StorageInfo s;
    CollectPhysicalDisks(s);
    s.status = CollectVolumes(s);
    CollectBitLocker(s);
    return s;
}

} // namespace sa
