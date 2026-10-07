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
    ::SetConsoleOutputCP(CP_UTF8);

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
        _setmode(_fileno(stdout), _O_BINARY);   // raw bytes, for UTF-8 JSON
    }
    else {
        _setmode(_fileno(stdout), _O_U8TEXT);   // wide stream -> UTF-8 on the way out
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
    try { r.firewall = CollectFirewallInfo(); }
    catch (...) { r.firewall.status = Status::Error; }
    try { r.storage = CollectStorageInfo(); }
    catch (...) { r.storage.status = Status::Error; }
    try { r.network = CollectNetworkInfo(); }
    catch (...) { r.network.status = Status::Error; }
    try { r.services = CollectSecurityServices(); }
    catch (...) { r.services.status = Status::Error; }

    try {
        auto apps = CollectApplications(DefaultApplicationList());
        if (noHash)
            for (auto& category : apps)
                for (auto& app : category.apps)
                    for (auto& loc : app.locations) loc.sha256.clear();
        r.applications = std::move(apps);
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
    }
    else {
        RenderConsole(r);
        std::wcout.flush();
    }
    return 0;
}