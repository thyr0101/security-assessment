#include "StorageCollector.h"
#include "../WmiHelper.h"
#include "../Utilities.h"
#include <windows.h>
#include <winioctl.h>
#include <ntddstor.h>
#include <setupapi.h>
#include <devguid.h>
#include <vector>
#pragma comment(lib, "setupapi.lib")

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
    for (int i = 0; i < 32; ++i) {
        std::wstring path = L"\\\\.\\PhysicalDrive" + std::to_wstring(i);
        WinHandle h(::CreateFileW(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  nullptr, OPEN_EXISTING, 0, nullptr));
        if (!h.valid()) break;

        STORAGE_PROPERTY_QUERY q{};
        q.PropertyId = StorageDeviceProperty;
        q.QueryType = PropertyStandardQuery;
        STORAGE_DESCRIPTOR_HEADER hdr{};
        DWORD ret = 0;
        if (!::DeviceIoControl(h.get(), IOCTL_STORAGE_QUERY_PROPERTY,
                               &q, sizeof(q), &hdr, sizeof(hdr), &ret, nullptr))
            continue;
        std::vector<BYTE> buf(hdr.Size);
        if (!::DeviceIoControl(h.get(), IOCTL_STORAGE_QUERY_PROPERTY,
                               &q, sizeof(q), buf.data(), (DWORD)buf.size(), &ret, nullptr))
            continue;
        auto* d = (STORAGE_DEVICE_DESCRIPTOR*)buf.data();
        StorageDisk disk;
        disk.index = i;
        if (d->VendorIdOffset) disk.vendor = Utf8ToWide((char*)buf.data() + d->VendorIdOffset);
        if (d->ProductIdOffset) disk.model = Utf8ToWide((char*)buf.data() + d->ProductIdOffset);
        if (d->ProductRevisionOffset) disk.firmware = Utf8ToWide((char*)buf.data() + d->ProductRevisionOffset);
        if (d->SerialNumberOffset) disk.serial = Utf8ToWide((char*)buf.data() + d->SerialNumberOffset);
        disk.busType = BusTypeName(d->BusType);
        disk.isNvme = (d->BusType == BusTypeNvme);
        disk.mediaType = disk.isNvme ? L"SSD" : L"Unknown";

        // Seek penalty reveals SSD vs HDD on many drives
        DEVICE_SEEK_PENALTY_DESCRIPTOR spd{};
        STORAGE_PROPERTY_QUERY q2{};
        q2.PropertyId = StorageDeviceSeekPenaltyProperty;
        q2.QueryType = PropertyStandardQuery;
        if (::DeviceIoControl(h.get(), IOCTL_STORAGE_QUERY_PROPERTY,
                              &q2, sizeof(q2), &spd, sizeof(spd), &ret, nullptr)) {
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
            geoRet >= sizeof(DISK_GEOMETRY_EX))
            disk.sizeBytes = (unsigned long long)
                reinterpret_cast<DISK_GEOMETRY_EX*>(geo.data())->DiskSize.QuadPart;

        s.disks.push_back(std::move(disk));
    }
}

static void CollectVolumes(StorageInfo& s) {
    // Don't pop "no disk in drive" dialogs for empty removable/optical drives.
    const UINT oldMode = ::SetErrorMode(SEM_FAILCRITICALERRORS);

    wchar_t volName[MAX_PATH]{};
    HANDLE h = ::FindFirstVolumeW(volName, MAX_PATH);
    if (h == INVALID_HANDLE_VALUE) { ::SetErrorMode(oldMode); return; }

    do {
        // volName looks like \\?\Volume{GUID}\ . GetVolumePathNamesForVolumeNameW
        // REQUIRES that trailing backslash. The old code stripped it (that is only
        // needed when opening the volume as a device), so the call always failed and
        // no volume was ever listed - hence "NoVolumes" and no BitLocker result.
        wchar_t paths[1024]{};
        DWORD cch = _countof(paths);
        if (::GetVolumePathNamesForVolumeNameW(volName, paths, cch, &cch) && paths[0]) {
            for (wchar_t* p = paths; *p; p += wcslen(p) + 1) {
                StorageVolume v;
                v.mountPoint = p;

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

    ::FindVolumeClose(h);
    ::SetErrorMode(oldMode);
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
    VARIANT path; ::VariantInit(&path);
    if (FAILED(obj->Get(L"__PATH", 0, &path, nullptr, nullptr)) ||
        path.vt != VT_BSTR || !path.bstrVal) {
        ::VariantClear(&path);
        return false;
    }
    BSTR bm = ::SysAllocString(method);
    IWbemClassObject* res = nullptr;
    HRESULT hr = svc->ExecMethod(path.bstrVal, bm, 0, nullptr, nullptr, &res, nullptr);
    ::SysFreeString(bm);
    ::VariantClear(&path);
    if (FAILED(hr) || !res) return false;
    unsigned long long rv = 0;
    bool ok = !(WmiGetUInt(res, L"ReturnValue", rv) && rv != 0) &&
              WmiGetUInt(res, outName, out);
    res->Release();
    return ok;
}

static void CollectBitLocker(StorageInfo& s) {
    ComInit ci;
    WmiConnection wmi;
    std::wstring why;
    const Status cs = wmi.Connect(L"ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption", &why);
    if (cs != Status::Success) {
        // This namespace is only accessible elevated.
        for (auto& v : s.volumes) {
            v.bitLockerStatus = (cs == Status::AccessDenied) ? Status::AccessDenied
                                                             : Status::Unavailable;
            v.bitLockerNote = why;
        }
        return;
    }
    for (auto& v : s.volumes) {
        if (v.driveType != L"Fixed") continue;
        // Win32_EncryptableVolume is addressed by drive letter ("C:"); a folder
        // mount point has no letter, so it cannot be queried this way.
        if (v.mountPoint.size() < 2 || v.mountPoint[1] != L':') {
            v.bitLockerStatus = Status::Unsupported;
            v.bitLockerNote = L"folder mount point (no drive letter)";
            continue;
        }
        // SELECT *: the previous query named ProtectionMethod and PercentageEncrypted,
        // which are not properties of Win32_EncryptableVolume (they are method outputs).
        // WMI rejects the whole query when a named property doesn't exist, so every
        // volume came back "Unknown".
        std::wstring wql = L"SELECT * FROM Win32_EncryptableVolume WHERE DriveLetter='"
                           + v.mountPoint.substr(0, 2) + L"'";
        std::vector<IWbemClassObject*> objs;
        std::wstring qwhy;
        if (wmi.Query(wql.c_str(), objs, &qwhy) != Status::Success || objs.empty()) {
            v.bitLockerStatus = Status::Unavailable;
            v.bitLockerNote = qwhy.empty() ? L"no Win32_EncryptableVolume instance" : qwhy;
            for (auto* o : objs) o->Release();
            continue;
        }
        for (auto* o : objs) {
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
                v.bitLockerStatus = Status::Success;
                // ProtectionStatus: 0 = unprotected, 1 = protected, 2 = unknown
                v.bitLockerState = (ps == 1) ? L"On" : (ps == 0 ? L"Off" : L"Unknown");
            } else {
                v.bitLockerStatus = Status::Unavailable;
                v.bitLockerNote = L"ProtectionStatus could not be read";
            }
            if (haveEm) v.encryptionMethod = EncryptionMethodName(em);
            else if (havePs && ps == 1) v.encryptionMethod = L"Unknown";
            o->Release();
        }
    }
}

StorageInfo CollectStorageInfo() {
    StorageInfo s;
    CollectPhysicalDisks(s);
    CollectVolumes(s);
    CollectBitLocker(s);
    s.status = Status::Success;
    return s;
}

} // namespace sa