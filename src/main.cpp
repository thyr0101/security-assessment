#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <iostream>
#include <string>
#include "Common.h"
#include "Utilities.h"
#include "Collectors/SystemCollector.h"
#include "Collectors/HardwareCollector.h"
#include "Collectors/SecurityCollector.h"
#include "Collectors/DefenderCollector.h"
#include "Collectors/AntivirusCollector.h"
#include "Collectors/FirewallCollector.h"
#include "Collectors/NetworkCollector.h"
#include "Collectors/StorageCollector.h"
#include "Collectors/ApplicationCollector.h"
#include "Collectors/PrivacyCollector.h"
#include "Collectors/PersistenceCollector.h"
#include "Security/ScoreEngine.h"
#include "Output/ConsoleRenderer.h"
#include "Output/JsonRenderer.h"

using namespace sa;

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

    ComInit ci; // COM initialized once for the whole app

    AssessmentResult r;

    try { r.os = CollectOsInfo(); }
    catch (...) { r.os.status = Status::Error; }
    try { r.cpu = CollectCpuInfo(); }
    catch (...) { r.cpu.status = Status::Error; }
    try { r.memory = CollectMemoryInfo(); }
    catch (...) { r.memory.status = Status::Error; }
    try { r.security = CollectSecurityInfo(); }
    catch (...) { r.security.tpm.status = Status::Error; }
    try { r.defender = CollectDefenderInfo(); }
    catch (...) { r.defender.status = Status::Error; }
    try { r.antivirus = CollectAntivirusInfo(); }
    catch (...) { r.antivirus.status = Status::Error; }
    try { r.firewall = CollectFirewallInfo(); }
    catch (...) { r.firewall.status = Status::Error; }
    try { r.storage = CollectStorageInfo(); }
    catch (...) { r.storage.status = Status::Error; }
    try { r.network = CollectNetworkInfo(); }
    catch (...) { r.network.status = Status::Error; }
    try { r.services = CollectSecurityServices(); }
    catch (...) { r.services.status = Status::Error; }

    try {
        r.applications = CollectApplications(DefaultApplicationList(), !noHash);
    }
    catch (...) {}

    try { r.registryFindings = RunRegistryScans(DefaultRegistryScans()); }
    catch (...) {}
    try { r.directoryFindings = RunDirectoryScans(DefaultDirectoryScans()); }
    catch (...) {}
    try { r.privacyFindings = CollectPrivacyFindings(); }
    catch (...) {}
    try { r.persistence = CollectPersistence(); }
    catch (...) {}

    try { r.score = ComputeScore(r); }
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