#include "HardwareCollector.h"
#include "../WmiHelper.h"
#include "../RegistryReader.h"
#include <windows.h>
#include <intrin.h>
#include <vector>
#include <span>
#include <cstring>
#include <powrprof.h>
#pragma comment(lib, "powrprof.lib")

namespace sa {

// Documented by Microsoft but omitted from the Windows SDK headers.
// https://learn.microsoft.com/windows/win32/power/processor-power-information-str
struct ProcessorPowerInformation {
    ULONG Number, MaxMhz, CurrentMhz, MhzLimit, MaxIdleState, CurrentIdleState;
};

static void DoCpuId(int leaf, int subleaf, int regs[4]) {
    __cpuidex(regs, leaf, subleaf);
}

static void CollectCpuid(CpuInfo& c) {
    int r[4]{};
    DoCpuId(0, 0, r);
    const int maxLeaf = r[0];
    char vendor[13]{};
    memcpy(vendor + 0, &r[1], 4);
    memcpy(vendor + 4, &r[3], 4);
    memcpy(vendor + 8, &r[2], 4);
    c.vendor = Utf8ToWide(vendor);

    // Extended leaves (0x8000xxxx) are reported by their own max-leaf query. The
    // basic max leaf above says nothing about them, and the 0x8000xxxx values must be
    // compared as unsigned (as ints they are negative).
    DoCpuId(static_cast<int>(0x80000000u), 0, r);
    const unsigned maxExt = static_cast<unsigned>(r[0]);

    if (maxExt >= 0x80000004u) {
        char brand[49]{};
        DoCpuId(static_cast<int>(0x80000002u), 0, r); memcpy(brand + 0,  r, 16);
        DoCpuId(static_cast<int>(0x80000003u), 0, r); memcpy(brand + 16, r, 16);
        DoCpuId(static_cast<int>(0x80000004u), 0, r); memcpy(brand + 32, r, 16);
        c.brand = Trim(Utf8ToWide(brand));
    }
    if (maxExt >= 0x80000001u) {
        DoCpuId(static_cast<int>(0x80000001u), 0, r);
        const int ecx = r[2], edx = r[3];
        c.svm = (ecx & (1 << 2))  != 0;   // AMD SVM: CPUID 80000001h ECX[2]
        c.nx  = (edx & (1 << 20)) != 0;   // NX/XD:   CPUID 80000001h EDX[20]
    }

    if (maxLeaf >= 1) {
        DoCpuId(1, 0, r);
        const int ecx = r[2], edx = r[3];
        c.sse    = (edx & (1 << 25)) != 0;
        c.sse2   = (edx & (1 << 26)) != 0;
        c.sse3   = (ecx & (1 << 0))  != 0;
        c.ssse3  = (ecx & (1 << 9))  != 0;
        c.sse41  = (ecx & (1 << 19)) != 0;
        c.sse42  = (ecx & (1 << 20)) != 0;
        c.avx    = (ecx & (1 << 28)) != 0;
        c.aesni  = (ecx & (1 << 25)) != 0;
        c.vmx    = (ecx & (1 << 5))  != 0;                // Intel VMX
        c.hypervisorPresent = (ecx & (1 << 31)) != 0;     // running under a hypervisor
    }
    if (maxLeaf >= 7) {
        DoCpuId(7, 0, r);
        const int ebx = r[1];
        c.avx2    = (ebx & (1 << 5))  != 0;
        c.avx512f = (ebx & (1 << 16)) != 0;
        c.sha     = (ebx & (1 << 29)) != 0;
        // (leaf 7 ECX[2] is UMIP, not SVM - SVM lives in leaf 80000001h, read above)
    }
}

template<class Function>
static bool VisitTopologyRecords(std::span<const BYTE> bytes, Function&& visit) {
    constexpr size_t header = offsetof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Processor);
    while (!bytes.empty()) {
        if (bytes.size() < header) return false;
        const auto* record = reinterpret_cast<const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(bytes.data());
        if (record->Size < header || record->Size > bytes.size()) return false;
        visit(*record);
        bytes = bytes.subspan(record->Size);
    }
    return true;
}

CpuInfo CollectCpuInfo() {
    CpuInfo c;
    CollectCpuid(c);

    // core counts via GetLogicalProcessorInformationEx
    DWORD len = 0;
    ::GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &len);
    if (len) {
        std::vector<BYTE> buf(len);
        if (::GetLogicalProcessorInformationEx(RelationProcessorCore,
                (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)buf.data(), &len)) {
            unsigned cores = 0;
            if (len <= buf.size() && VisitTopologyRecords(std::span<const BYTE>(buf.data(), len), [&](const auto& record) {
                if (record.Relationship == RelationProcessorCore) ++cores;
            })) {
                c.physicalCores = cores;
            }
        }
    }
    // cache
    len = 0;
    ::GetLogicalProcessorInformationEx(RelationCache, nullptr, &len);
    if (len) {
        std::vector<BYTE> buf(len);
        if (::GetLogicalProcessorInformationEx(RelationCache,
                (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)buf.data(), &len)) {
            if (len <= buf.size()) VisitTopologyRecords(std::span<const BYTE>(buf.data(), len), [&](const auto& record) {
                constexpr size_t minimum = offsetof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Cache) +
                    offsetof(CACHE_RELATIONSHIP, CacheSize) + sizeof(DWORD);
                if (record.Relationship != RelationCache || record.Size < minimum) return;
                if (record.Cache.Level == 2) c.l2CacheKB += record.Cache.CacheSize / 1024;
                if (record.Cache.Level == 3) c.l3CacheKB += record.Cache.CacheSize / 1024;
            });
        }
    }

    c.logicalProcessors = ::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    c.processorGroups = ::GetActiveProcessorGroupCount();

    // Registry supplies the nominal frequency if the native power query is unavailable.
    if (auto v = RegReadDword(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"~MHz"))
        c.maxMhz = *v;
    // A nominal registry frequency cannot establish the current clock.
    std::vector<ProcessorPowerInformation> power(c.logicalProcessors);
    if (!power.empty() && ::CallNtPowerInformation(ProcessorInformation, nullptr, 0,
        power.data(), static_cast<ULONG>(power.size() * sizeof(ProcessorPowerInformation))) == 0) {
        c.currentMhz = power.front().CurrentMhz;
        c.maxMhz = power.front().MaxMhz;
    }

    c.status = Status::Success;
    return c;
}

MemoryInfo CollectMemoryInfo() {
    MemoryInfo m;
    MEMORYSTATUSEX ms{}; ms.dwLength = sizeof(ms);
    if (::GlobalMemoryStatusEx(&ms)) {
        m.totalBytes     = ms.ullTotalPhys;
        m.availableBytes = ms.ullAvailPhys;
        m.loadPercent    = ms.dwMemoryLoad;
        m.totalPageFile  = ms.ullTotalPageFile;
    } else {
        m.status = Status::Error;
        return m;
    }

    ComInit ci;
    WmiConnection wmi;
    if (wmi.Connect() == Status::Success) {
        WmiObjects objsOwner;
        auto& objs = objsOwner.items();
        if (wmi.Query(L"SELECT Capacity,Speed,ConfiguredClockSpeed,Manufacturer,"
                      L"PartNumber,SerialNumber,SMBIOSMemoryType,FormFactor,"
                      L"DataWidth,TotalWidth FROM Win32_PhysicalMemory", objs) == Status::Success) {
            for (auto* o : objs) {
                MemoryModule mm;
                unsigned long long v = 0;
                if (WmiGetUInt(o, L"Capacity", v))           mm.capacity = v;
                if (WmiGetUInt(o, L"Speed", v))              mm.speed = (unsigned)v;
                if (WmiGetUInt(o, L"ConfiguredClockSpeed", v)) mm.configuredSpeed = (unsigned)v;
                if (WmiGetUInt(o, L"SMBIOSMemoryType", v))   mm.memoryType = (unsigned)v;
                if (WmiGetUInt(o, L"FormFactor", v))         mm.formFactor = (unsigned)v;
                WmiGetString(o, L"Manufacturer", mm.manufacturer);
                WmiGetString(o, L"PartNumber", mm.partNumber);
                WmiGetString(o, L"SerialNumber", mm.serialNumber);
                unsigned long long dw = 0, tw = 0;
                if (WmiGetUInt(o, L"DataWidth", dw) && WmiGetUInt(o, L"TotalWidth", tw))
                    mm.ecc = (dw != 0 && dw != 0xffff && tw != 0xffff && tw > dw);
                m.modules.push_back(std::move(mm));
            }
        }
    }
    m.status = Status::Success;
    return m;
}

} // namespace sa
