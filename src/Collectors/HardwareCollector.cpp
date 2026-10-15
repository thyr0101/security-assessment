#include "HardwareCollector.h"
#include <windows.h>
#include <intrin.h>
#include <vector>
#include <span>
#include <cstring>

namespace sa {

static void DoCpuId(int leaf, int subleaf, int regs[4]) {
    __cpuidex(regs, leaf, subleaf);
}

static void CollectCpuid(CpuInfo& c) {
    int r[4]{};
    DoCpuId(0, 0, r);
    const int maxLeaf = r[0];
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
        c.virtualizationAvailable = (ecx & (1 << 2)) != 0;   // AMD SVM: CPUID 80000001h ECX[2]
        c.nx  = (edx & (1 << 20)) != 0;   // NX/XD:   CPUID 80000001h EDX[20]
    }

    if (maxLeaf >= 1) {
        DoCpuId(1, 0, r);
        const int ecx = r[2];
        c.aesni  = (ecx & (1 << 25)) != 0;
        c.virtualizationAvailable |= (ecx & (1 << 5)) != 0;                // Intel VMX
        c.virtualizationAvailable |= (static_cast<unsigned>(ecx) & (1u << 31)) != 0;     // running under a hypervisor
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
    c.logicalProcessors = ::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    c.status = Status::Success;
    return c;
}

MemoryInfo CollectMemoryInfo() {
    MemoryInfo m;
    MEMORYSTATUSEX ms{}; ms.dwLength = sizeof(ms);
    if (::GlobalMemoryStatusEx(&ms)) {
        m.totalBytes     = ms.ullTotalPhys;
        m.availableBytes = ms.ullAvailPhys;
    }
    return m;
}

} // namespace sa
