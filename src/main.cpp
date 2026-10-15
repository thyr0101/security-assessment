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
#include <optional>
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
#include "Collectors/PersistenceCollector.h"
#include "Collectors/WindowsUpdateCollector.h"
#include "Security/ScoreEngine.h"
#include "Output/ConsoleRenderer.h"
#include "Output/JsonRenderer.h"
#include "Output/JsonFile.h"

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

    constexpr auto usage = L"Usage: SecurityAssessment [--json [0|1] [output-file]]\n"
        L"       SecurityAssessment --json view <compact-report-file>\n"
        L"       0 = compact (viewable); 1 = readable text (not viewable). Omit to choose interactively.\n";
    bool json = false, viewJson = false, noHash = false;
    std::filesystem::path jsonPath;
    std::optional<JsonFormat> jsonFormat;
    auto invalid = [&](const wchar_t* reason) {
        std::wcerr << reason << L"\n" << usage;
        return 2;
    };
    for (int i = 1; i < argc; ++i) {
        const std::wstring_view argument = argv[i];
        if (argument == L"--json") {
            if (json) return invalid(L"Specify --json only once.");
            json = true;
            if (i + 1 < argc && std::wstring_view(argv[i + 1]) == L"view") {
                viewJson = true;
                ++i;
                if (i + 1 >= argc || std::wstring_view(argv[i + 1]).starts_with(L"-"))
                    return invalid(L"The JSON viewer requires a report filename.");
                jsonPath = argv[++i];
            } else {
                if (i + 1 < argc) {
                    const std::wstring_view mode = argv[i + 1];
                    if (mode == L"0" || mode == L"1") {
                        jsonFormat = mode == L"0" ? JsonFormat::Compact : JsonFormat::Readable;
                        ++i;
                    } else if (!mode.empty() && mode.find_first_not_of(L"0123456789") == mode.npos)
                        return invalid(L"JSON format must be 0 (compact) or 1 (readable).");
                }
                if (i + 1 < argc && !std::wstring_view(argv[i + 1]).starts_with(L"-")) jsonPath = argv[++i];
            }
        } else if (argument == L"--no-hash") noHash = true; // Legacy no-op: application hashing was removed.
        else if (argument == L"--help" || argument == L"-h") {
            std::wcout << usage;
            return 0;
        } else return invalid((L"Unknown option: " + std::wstring(argument)).c_str());
    }
    if (viewJson && noHash) return invalid(L"--no-hash applies to assessment, not to viewing a saved report.");
    // Both the report and file/view confirmations use wide UTF-8 console output.
    if (_setmode(_fileno(stdout), _O_U8TEXT) == -1) return 1;
    if (viewJson) {
        const auto saved = ReadJsonReport(jsonPath);
        if (!saved) { std::wcerr << saved.error() << L"\n"; return 1; }
        RenderConsole(*saved, ReportView::Export);
        std::wcout.flush();
        return std::wcout ? 0 : 1;
    }

    if (json && !jsonFormat) {
        std::wcout << L"Choose a JSON export format:\n"
            L"  0 - Compact: numbered fields, direct values and numeric states; opens in the backup viewer.\n"
            L"  1 - Readable: descriptive fields and state names; for manual inspection, cannot be viewed in the app.\n"
            L"Compact encoding is not encryption. Both formats contain system details.\n"
            L"Enter 0 or 1: " << std::flush;
        std::string choice;
        while (std::getline(std::cin, choice)) {
            const auto first = choice.find_first_not_of(" \t\r");
            const auto last = choice.find_last_not_of(" \t\r");
            if (first != choice.npos && first == last && (choice[first] == '0' || choice[first] == '1')) {
                jsonFormat = choice[first] == '0' ? JsonFormat::Compact : JsonFormat::Readable;
                break;
            }
            std::wcout << L"Please enter 0 (compact) or 1 (readable): " << std::flush;
        }
        if (!jsonFormat) { std::wcerr << L"No format selected. Use --json 0 or --json 1 for unattended exports.\n"; return 2; }
    }

    ComInit ci; // The main thread and every collector worker initialize COM separately.

    CollectionTimer totalTimer(L"total");
    AssessmentResult r;

    // Independent collectors write distinct result fields. Four COM-initialized
    // workers overlap provider waits while keeping output and scoring deterministic.
    // Start the slow update/antivirus providers first to reduce the final wait.
    const auto tasks = std::to_array<std::function<void()>>({
        [&] {
            try { r.windowsUpdate = Timed(L"windowsUpdate", [&] { return CollectWindowsUpdateInfo(); }); }
            catch (...) { r.windowsUpdate.status = r.windowsUpdate.pendingStatus = Status::Error;
                              r.windowsUpdate.pendingReason = L"Windows Update collection failed."; }
        },
        [&] {
            try { r.defender = Timed(L"defender", [&] { return CollectDefenderInfo(); }); }
            catch (...) { r.defender.status = Status::Error; }
        },
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
            try { r.registryFindings = Timed(L"registryFindings", [&] { return RunRegistryScans(DefaultRegistryScans()); }); }
            catch (...) {}
        },
        [&] {
            try { r.directoryFindings = Timed(L"directoryFindings", [&] { return RunDirectoryScans(DefaultDirectoryScans()); }); }
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
        const auto saved = SaveJsonReport(RenderJson(r, *jsonFormat), jsonPath);
        if (!saved) { std::wcerr << saved.error() << L"\n"; return 1; }
        std::wcout << L"JSON report saved to: " << saved->wstring() << L"\n";
        std::wcout.flush();
        if (!std::wcout) return 1;
    }
    else {
        RenderConsole(r);
        std::wcout.flush();
        if (!std::wcout) return 1;
    }
    return 0;
}