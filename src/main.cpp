#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <iostream>
#include <string>
#include <chrono>
#include <syncstream>
#include <array>
#include <atomic>
#include <functional>
#include <thread>
#include "Common.h"
#include "Utilities.h"
#include "Collectors/SystemCollector.h"
#include "Collectors/HardwareCollector.h"
#include "Collectors/SecurityCollector.h"
#include "Collectors/DefenderCollector.h"
#include "Collectors/AntivirusCollector.h"
#include "Collectors/FirewallCollector.h"
#include "Collectors/NetworkCollector.h"
#include "Collectors/HardeningCollector.h"
#include "Collectors/StorageCollector.h"
#include "Collectors/ApplicationCollector.h"
#include "Collectors/PrivacyCollector.h"
#include "Collectors/PersistenceCollector.h"
#include "Collectors/WindowsUpdateCollector.h"
#include "Security/ScoreEngine.h"
#include "Output/ConsoleRenderer.h"
#include "Output/JsonRenderer.h"

using namespace sa;

namespace {
class CollectionTimer {
    const wchar_t* label_;
    std::chrono::steady_clock::time_point start_ = std::chrono::steady_clock::now();
public:
    explicit CollectionTimer(const wchar_t* label) : label_(label) {}
    ~CollectionTimer() {
        wchar_t enabled[2]{};
        if (::GetEnvironmentVariableW(L"SA_TRACE_TIMINGS", enabled, _countof(enabled)))
            std::wosyncstream(std::wcerr) << L"[timing] " << label_ << L": "
                << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_).count()
                << L" ms\n";
    }
};
template<class Function>
auto Timed(const wchar_t* label, Function&& function) {
    CollectionTimer timer(label);
    return std::forward<Function>(function)();
}
}

int wmain(int argc, wchar_t** argv) {
    struct ConsoleCodePage {
        UINT original = ::GetConsoleOutputCP();
        bool changed = original != 0 && original != CP_UTF8 && ::SetConsoleOutputCP(CP_UTF8);
        ~ConsoleCodePage() { if (changed) ::SetConsoleOutputCP(original); }
    } consoleCodePage;

    bool json = false;
    bool noHash = false;
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--json")      json = true;
        else if (a == L"--no-hash") noHash = true;
        else if (a == L"--help" || a == L"-h") {
            std::wcout << L"Usage: SecurityAssessment [--json] [--no-hash]\n";
            return 0;
        }
        else {
            std::wcerr << L"Unknown option: " << a << L"\n"
                       << L"Usage: SecurityAssessment [--json] [--no-hash]\n";
            return 2;
        }
    }

    // Choose the stream mode ONCE, before any I/O on stdout.
    // Mixing std::cout (char) with a stream in _O_U8TEXT mode is what
    // tripped the UCRT fputc assertion.
    if (json) {
        if (_setmode(_fileno(stdout), _O_BINARY) == -1) return 1; // UTF-8 JSON bytes
    }
    else {
        if (_setmode(_fileno(stdout), _O_U8TEXT) == -1) return 1; // wide stream -> UTF-8
    }

    ComInit ci; // The main thread and every collector worker initialize COM separately.

    CollectionTimer totalTimer(L"total");
    AssessmentResult r;

    // Independent collectors write distinct result fields. Four COM-initialized
    // workers overlap provider waits while keeping output and scoring deterministic.
    const auto tasks = std::to_array<std::function<void()>>({
        [&] {
            try { r.os = Timed(L"os", [&] { return CollectOsInfo(); }); }
            catch (...) { r.os.status = Status::Error; }
        },
        [&] {
            try { r.cpu = Timed(L"cpu", [&] { return CollectCpuInfo(); }); }
            catch (...) { r.cpu.status = Status::Error; }
        },
        [&] {
            try { r.memory = Timed(L"memory", [&] { return CollectMemoryInfo(); }); }
            catch (...) { r.memory.status = Status::Error; }
        },
        [&] {
            try { r.security = Timed(L"security", [&] { return CollectSecurityInfo(); }); }
            catch (...) { r.security.tpm.status = Status::Error; }
        },
        [&] {
            try { r.defender = Timed(L"defender", [&] { return CollectDefenderInfo(); }); }
            catch (...) { r.defender.status = Status::Error; }
        },
        [&] {
            try { r.antivirus = Timed(L"antivirus", [&] { return CollectAntivirusInfo(); }); }
            catch (...) { r.antivirus.status = Status::Error; }
        },
        [&] {
            try { r.firewall = Timed(L"firewall", [&] { return CollectFirewallInfo(); }); }
            catch (...) { r.firewall.status = Status::Error; }
        },
        [&] {
            try { r.storage = Timed(L"storage", [&] { return CollectStorageInfo(); }); }
            catch (...) { r.storage.status = Status::Error; }
        },
        [&] {
            try { r.network = Timed(L"network", [&] { return CollectNetworkInfo(json); }); }
            catch (...) { r.network.status = Status::Error; }
        },
        [&] {
            try { r.hardening = Timed(L"hardening", [&] { return CollectHardeningInfo(); }); }
            catch (...) {}
        },
        [&] {
            try { r.services = Timed(L"services", [&] { return CollectSecurityServices(); }); }
            catch (...) { r.services.status = Status::Error; }
        },
        [&] {
            try { r.windowsUpdate = Timed(L"windowsUpdate", [&] { return CollectWindowsUpdateInfo(); }); }
            catch (...) { r.windowsUpdate.status = r.windowsUpdate.pendingStatus = Status::Error;
                              r.windowsUpdate.pendingReason = L"Windows Update collection failed."; }
        },
        [&] {
            try { r.applications = Timed(L"applications", [&] { return CollectApplications(DefaultApplicationList(), !noHash); }); }
            catch (...) {}
        },
        [&] {
            try { r.registryFindings = Timed(L"registryFindings", [&] { return RunRegistryScans(DefaultRegistryScans()); }); }
            catch (...) {}
        },
        [&] {
            try { r.directoryFindings = Timed(L"directoryFindings", [&] { return RunDirectoryScans(DefaultDirectoryScans()); }); }
            catch (...) {}
        },
        [&] {
            try { r.privacyFindings = Timed(L"privacyFindings", [&] { return CollectPrivacyFindings(); }); }
            catch (...) {}
        },
        [&] {
            try { r.persistence = Timed(L"persistence", [&] { return CollectPersistence(); }); }
            catch (...) {}
        }
    });
    {
        std::atomic_size_t next{0};
        auto work = [&] {
            ComInit workerCom;
            for (size_t index; (index = next.fetch_add(1, std::memory_order_relaxed)) < tasks.size();)
                tasks[index]();
        };
        std::array<std::jthread, 3> workers;
        try {
            for (auto& worker : workers) worker = std::jthread(work);
        } catch (const std::system_error&) {
            // Remaining work still runs if the OS cannot create every worker.
        }
        work();
    } // jthread joins before any collected fields are read for scoring/rendering.

    try { r.score = Timed(L"score", [&] { return ComputeScore(r); }); }
    catch (...) { r.score.total = 0; }

    if (json) {
        std::string out = RenderJson(r);
        std::cout << out << "\n";
        std::cout.flush();
        if (!std::cout) return 1;
    }
    else {
        RenderConsole(r);
        std::wcout.flush();
        if (!std::wcout) return 1;
    }
    return 0;
}