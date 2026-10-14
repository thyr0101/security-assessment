#include "Utilities.h"
#include "RegistryReader.h"
#include "Collectors/ApplicationCollector.h"
#include "Collectors/AntivirusCollector.h"
#include "Collectors/DefenderCollector.h"
#include "Collectors/PersistenceCollector.h"
#include "Output/JsonRenderer.h"
#include "Output/ConsoleRenderer.h"
#include "Security/ScoreEngine.h"
#include "WmiHelper.h"
#include <comdef.h>
#include <wrl/client.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <locale>
#include <numeric>
#include <stdexcept>

namespace fs = std::filesystem;
using namespace sa;

static void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

struct Fixture {
    fs::path dir = fs::current_path() / (L"sa-regression-" + std::to_wstring(::GetCurrentProcessId()));
    std::wstring keyName = L"Software\\SecurityAssessmentRegression_" + std::to_wstring(::GetCurrentProcessId());
    RegKey key;
    Fixture() {
        Check(!fs::exists(dir), "test directory already exists");
        fs::create_directory(dir);
        DWORD disposition = 0;
        Check(::RegCreateKeyExW(HKEY_CURRENT_USER, keyName.c_str(), 0, nullptr, REG_OPTION_VOLATILE,
            KEY_ALL_ACCESS, nullptr, key.put(), &disposition) == ERROR_SUCCESS && disposition == REG_CREATED_NEW_KEY,
            "cannot create isolated test registry key");
    }
    ~Fixture() {
        key.close();
        ::RegDeleteTreeW(HKEY_CURRENT_USER, keyName.c_str());
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};

static void TestRegistry(Fixture& fixture) {
    const wchar_t bad[] = {L'a', L'b'};
    Check(::RegSetValueExW(fixture.key.get(), L"bad", 0, REG_MULTI_SZ,
        reinterpret_cast<const BYTE*>(bad), sizeof(bad)) == ERROR_SUCCESS, "write malformed fixture");
    const wchar_t valid[] = L"alpha\0beta\0";
    Check(::RegSetValueExW(fixture.key.get(), L"valid", 0, REG_MULTI_SZ,
        reinterpret_cast<const BYTE*>(valid), sizeof(valid)) == ERROR_SUCCESS, "write multi-string fixture");
    Check(::RegSetValueExW(fixture.key.get(), L"text", 0, REG_SZ,
        reinterpret_cast<const BYTE*>(bad), sizeof(bad)) == ERROR_SUCCESS, "write unterminated string");
    RegistryReader reader;
    Check(reader.Open(fixture.key.get(), L"", 0) == Status::Success, "open registry fixture");
    std::vector<std::wstring> strings{L"old"};
    Check(reader.GetMultiSz(L"bad", strings) == Status::Error, "unterminated multi-string must fail safely");
    Check(reader.GetMultiSz(L"valid", strings) == Status::Success && strings == std::vector<std::wstring>{L"alpha", L"beta"},
          "multi-string output must replace previous contents");
    std::wstring text;
    Check(reader.GetString(L"text", text) == Status::Success && text == L"ab", "bounded unterminated REG_SZ");
    Check(reader.GetString(L"missing", text) == Status::NotFound, "missing registry value status");
    DWORD number = 0;
    Check(reader.GetDword(L"text", number) == Status::Unsupported, "registry type mismatch");
    auto findings = RunRegistryScans({{L"fixture", fixture.key.get(), L"", 2, 0}});
    Check(findings.size() == 1 && findings[0].status == Status::Success && findings[0].valueCount == 3 && findings[0].exceeded,
          "registry threshold counts");
    for (const auto& definition : DefaultRegistryScans())
        Check(!definition.name.empty() && definition.root && !definition.subkey.empty(), "no empty default registry definitions");
    const wchar_t empty[] = L"";
    Check(::RegSetValueExW(fixture.key.get(), L"empty", 0, REG_MULTI_SZ,
        reinterpret_cast<const BYTE*>(empty), sizeof(empty)) == ERROR_SUCCESS, "write empty multi-string");
    strings = {L"previous"};
    Check(reader.GetMultiSz(L"empty", strings) == Status::Success && strings.empty(), "single-null empty REG_MULTI_SZ is valid");
}

static void TestFiles(Fixture& fixture) {
    const fs::path app = fixture.dir / L"app.exe";
    std::ofstream(app, std::ios::binary) << "abc";
    fs::create_directory(fixture.dir / L"nested");
    std::ofstream(fixture.dir / L"nested" / L"second.exe", std::ios::binary) << "";
    fs::create_directory(fixture.dir / L"directory.exe");
    const std::wstring digest = L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    Check(FileSha256(app.wstring()) == digest, "SHA-256 known vector");
    Check(!FileSha256((fixture.dir / L"missing").wstring()), "missing hash input");
    const std::vector<ApplicationDefinition> definitions{{L"fixture", {
        L"Example|" + (fixture.dir / L"*.exe").wstring(), L"Example|" + app.wstring()}}};
    const auto apps = CollectApplications(definitions);
    Check(apps.size() == 1 && apps[0].apps.size() == 1 && apps[0].apps[0].locations.size() == 1,
          "deduplicate app paths and exclude directories");
    Check(apps[0].apps[0].locations[0].sha256 == digest, "application hash");
    Check(CollectApplications(definitions, false)[0].apps[0].locations[0].sha256.empty(), "hash suppression");
    const auto relative = CollectApplications({{L"relative", {L"Example|" + fs::relative(app).wstring(),
        L"Example|" + app.wstring()}}}, false);
    Check(relative[0].apps.size() == 1 && relative[0].apps[0].locations.size() == 1,
          "relative and absolute paths must identify one executable");
    const auto scans = RunDirectoryScans({{L"flat", fixture.dir.wstring(), 1, false},
        {L"recursive", fixture.dir.wstring(), 1, true}, {L"missing", (fixture.dir / L"missing").wstring(), 0, false}});
    Check(scans[0].fileCount == 1 && !scans[0].exceeded, "flat directory scan");
    Check(scans[1].fileCount == 2 && scans[1].dirCount == 2 && scans[1].exceeded, "recursive directory scan");
    Check(scans[2].status == Status::NotFound, "missing directory status");
}

static const ScoreRuleResult& Rule(const ScoreReport& score, const std::string& id) {
    for (const auto& rule : score.rules) if (rule.id == id) return rule;
    throw std::runtime_error("missing score rule");
}

static void TestScoreAndJson() {
    AssessmentResult result;
    auto empty = ComputeScore(result);
    Check(empty.total == 0 && empty.maximum == 1000, "unknown assessment must not earn points");
    Check(Rule(empty, "mp.rtp").category == "Malware Protection", "failed rules keep their category");
    result.os.status = result.cpu.status = Status::Success;
    result.os.build = 26100; result.os.ubr = 1;
    result.cpu.vmx = result.cpu.aesni = result.cpu.nx = true;
    auto& s = result.security;
    s.tpm.status = Status::Success; s.tpm.present = s.tpm.ready = true; s.tpm.specVersion = L"2.0";
    s.secureBoot.enabled = Tri::Yes;
    s.secureBoot.status = Status::Success;
    s.virt.status = Status::Success;
    s.virt.runningServicesKnown = s.virt.vbsEnabled = s.virt.hvciEnabled = true;
    s.uac.status = Status::Success; s.uac.enabled = s.uac.consentPromptAdmin = true;
    s.dep.depEnabled = s.dep.sehopEnabled = Tri::Yes;
    s.smartAppControlOn = s.isElevated = s.windowsHelloAvailable = true;
    auto& d = result.defender;
    d.status = Status::Success;
    d.enabledStatus = d.realTimeProtectionStatus = d.behaviorMonitorStatus = d.ioavStatus =
        d.cloudProtectionStatus = d.tamperProtectionStatus = Status::Success;
    d.installed = d.enabled = d.realTimeProtection = d.behaviorMonitor = d.ioav = true;
    d.cloudProtection = d.tamperProtection = d.threatsKnown = true;
    result.firewall.status = Status::Success; result.firewall.serviceRunning = true;
    result.firewall.serviceStatus = Status::Success;
    for (const auto* name : {L"Domain", L"Private", L"Public"}) {
        FirewallProfile p; p.name = name; p.enabled = true; p.defaultInbound = 0; p.status = Status::Success;
        result.firewall.profiles.push_back(p);
    }
    StorageVolume volume; volume.driveType = L"Fixed"; volume.bitLockerState = L"On";
    volume.bitLockerStatus = Status::Success;
    result.storage.status = Status::Success;
    result.storage.volumes.push_back(volume);
    result.persistence.status = Status::Success;
    ApplicationFinding app; app.status = Status::NotFound; result.applications.push_back(app);
    auto healthy = ComputeScore(result);
    Check(healthy.total == 1000 && healthy.maximum == 1000, "fully satisfied rules retain 1000-point scale");
    Check(Rule(healthy, "os.sac").awardedPoints == 50 && Rule(healthy, "os.sac").maxPoints == 50,
          "enforcing Smart App Control earns 50 points");
    Check(Rule(healthy, "mp.threats").awardedPoints == 20 && Rule(healthy, "mp.threats").maxPoints == 20 &&
          Rule(healthy, "mp.threats").state == "Clear", "no active threats earns 20 points with a meaningful state");
    s.smartAppControlOn = false; s.smartAppControlEvaluation = true; s.smartAppControlState = Tri::No;
    const auto evaluation = ComputeScore(result);
    Check(evaluation.total == 975 && evaluation.maximum == 1000 &&
          Rule(evaluation, "os.sac").awardedPoints == 25 && Rule(evaluation, "os.sac").state == "Evaluation",
          "evaluation mode earns 25 of 50 points on the 1000-point scale");
    result.score = evaluation;
    std::ofstream("evaluation-output.json", std::ios::binary) << RenderJson(result);
    s.smartAppControlEvaluation = false;
    Check(Rule(ComputeScore(result), "os.sac").awardedPoints == 0 && Rule(ComputeScore(result), "os.sac").state == "Off",
          "disabled Smart App Control earns zero");
    s.smartAppControlState = Tri::Unknown;
    Check(Rule(ComputeScore(result), "os.sac").awardedPoints == 0 && Rule(ComputeScore(result), "os.sac").state == "Unknown",
          "unreadable Smart App Control earns zero");
    s.smartAppControlOn = true; s.smartAppControlState = Tri::Yes;
    d.threatsCount = 1;
    Check(Rule(ComputeScore(result), "mp.threats").awardedPoints == 0 &&
          Rule(ComputeScore(result), "mp.threats").state == "Threats found", "active threats earn zero with a clear state");
    d.threatsCount = 0;
    for (const auto* id : {"hw.tpm2", "hw.virt", "hw.aes", "hw.nx", "hw.vbs", "hw.hvci", "os.win11",
                           "os.patch", "mp.defender", "mp.threats", "net.in", "net.svc", "enc.bl", "enc.tpm",
                           "acc.uac2", "acc.elev", "acc.hello", "hyg.startup", "hyg.appinv"}) {
        Check(Rule(healthy, id).state != "Enabled", "capabilities, facts, and scan results do not use Enabled");
    }
    int sum = 0; for (const auto& rule : healthy.rules) sum += rule.awardedPoints;
    Check(sum == healthy.total, "rule sum matches score");
    s.tpm.specVersion = L"1.2";
    Check(Rule(ComputeScore(result), "hw.tpm2").awardedPoints == 20, "TPM 1.2 must not earn TPM 2.0 points");
    s.tpm.specVersion = L"12.0";
    Check(Rule(ComputeScore(result), "hw.tpm2").awardedPoints == 20, "TPM version matching must use the complete version");
    s.tpm.specVersion = L"2.0, 0, 1.59";
    Check(Rule(ComputeScore(result), "hw.tpm2").awardedPoints == 50, "TPM 2.0 with revision metadata earns full credit");
    result.firewall.profiles[0].defaultInbound = 2;
    Check(Rule(ComputeScore(result), "net.in").awardedPoints == 0, "unknown firewall action must not count as blocked");
    s.virt.runningServicesKnown = false;
    Check(Rule(ComputeScore(result), "hw.hvci").state == "Unknown", "configured HVCI is not running evidence");
    result.privacyFindings.push_back({L"quoted \"name\"", L"C:\\path\nnext", Category::Privacy,
        Severity::Informational, L"tabs\tand\nnewlines"});
    result.score = ComputeScore(result);
    const auto json = RenderJson(result);
    Check(json.find("quoted \\\"name\\\"") != std::string::npos, "score strings are JSON escaped");
    Check(json.find("tabs\\tand\\nnewlines") != std::string::npos, "control characters are JSON escaped");
    // The smoke harness independently parses this output using Python's JSON parser.
    std::ofstream("regression-output.json", std::ios::binary) << json;
}

static void TestComAndWmi() {
    Check(SUCCEEDED(::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED)), "initialize STA");
    struct ComGuard { ~ComGuard() { ::CoUninitialize(); } } outer;
    { ComInit nested; Check(nested.ok(), "existing STA supports COM helper"); }
    APTTYPE type{}; APTTYPEQUALIFIER qualifier{};
    Check(SUCCEEDED(::CoGetApartmentType(&type, &qualifier)), "changed-mode helper must not uninitialize caller COM");
    WmiConnection wmi;
    Check(wmi.Connect() == Status::Success, "connect WMI for conversion regression");
    Microsoft::WRL::ComPtr<IWbemClassObject> object;
    Check(SUCCEEDED(wmi.services()->GetObject(nullptr, 0, nullptr, object.GetAddressOf(), nullptr)), "create in-memory WMI class");
    _variant_t invalid(L"not a number");
    Check(SUCCEEDED(object->Put(L"Probe", 0, &invalid, CIM_STRING)), "set in-memory property");
    unsigned long long number = 123;
    Check(!WmiGetUInt(object.Get(), L"Probe", number) && number == 123, "malformed WMI number must fail");
    _variant_t valid(L"18446744073709551615");
    Check(SUCCEEDED(object->Put(L"Probe", 0, &valid, CIM_STRING)), "set maximum integer");
    Check(WmiGetUInt(object.Get(), L"Probe", number) && number == ULLONG_MAX, "parse full uint64 range");
    _variant_t overflow(L"18446744073709551616");
    Check(SUCCEEDED(object->Put(L"Probe", 0, &overflow, CIM_STRING)), "set overflowing integer");
    Check(!WmiGetUInt(object.Get(), L"Probe", number), "reject overflowing uint64");
    number = 123;
    _variant_t negative(static_cast<long>(-1));
    Check(SUCCEEDED(object->Put(L"SignedProbe", 0, &negative, CIM_SINT32)), "set signed negative property");
    Check(!WmiGetUInt(object.Get(), L"SignedProbe", number) && number == 123, "negative signed WMI values must not become huge unsigned values");
    Check(SUCCEEDED(object->Put(L"UnsignedProbe", 0, &negative, CIM_UINT32)), "set unsigned high-bit property");
    Check(WmiGetUInt(object.Get(), L"UnsignedProbe", number) && number == ULONG_MAX, "CIM uint32 retains its full range despite VT_I4 representation");
    _variant_t nullText; nullText.vt = VT_NULL;
    Check(SUCCEEDED(object->Put(L"Probe", 0, &nullText, CIM_STRING)), "set NULL string");
    std::wstring text = L"unchanged";
    Check(!WmiGetString(object.Get(), L"Probe", text) && text == L"unchanged", "NULL string is unavailable and preserves caller output");
    _variant_t array;
    array.vt = VT_ARRAY | VT_I4;
    array.parray = ::SafeArrayCreateVector(VT_I4, 5, 2);
    Check(array.parray != nullptr, "allocate numeric array");
    LONG index = 5, value = 1;
    Check(SUCCEEDED(::SafeArrayPutElement(array.parray, &index, &value)), "first array element");
    index = 6; value = 2;
    Check(SUCCEEDED(::SafeArrayPutElement(array.parray, &index, &value)), "second array element");
    Check(SUCCEEDED(object->Put(L"Services", 0, &array, CIM_UINT32 | CIM_FLAG_ARRAY)), "set numeric WMI array");
    std::vector<unsigned long long> services;
    Check(WmiGetUIntArray(object.Get(), L"Services", services) && services == std::vector<unsigned long long>{1, 2},
          "read WMI integer array with nonzero lower bound");
    _variant_t nullValue; nullValue.vt = VT_NULL;
    Check(SUCCEEDED(object->Put(L"Services", 0, &nullValue, CIM_UINT32 | CIM_FLAG_ARRAY)), "set NULL WMI array");
    Check(!WmiGetUIntArray(object.Get(), L"Services", services), "NULL running services must remain unknown");
    WmiObjects rows;
    Check(wmi.Query(L"SELECT * FROM ClassThatDoesNotExist_SARegression", rows.items()) != Status::Success && rows.items().empty(),
          "failed WMI query must not return success");
}

static void TestPartialCollection() {
    AssessmentResult result;
    auto& d = result.defender;
    d.status = Status::Success;
    d.installed = d.enabled = d.cloudProtection = true;
    d.enabledStatus = Status::Success;
    auto score = ComputeScore(result);
    Check(Rule(score, "mp.defender").awardedPoints == 40, "known Defender status survives missing optional properties");
    Check(Rule(score, "mp.cloud").state == "Unknown" && Rule(score, "mp.cloud").awardedPoints == 0,
          "unknown cloud preference cannot be disabled or earn credit from a stale value");
    Check(Rule(score, "mp.rtp").state == "Unknown", "missing real-time status is not disabled");
    d.cloudProtectionStatus = Status::Success;
    Check(Rule(ComputeScore(result), "mp.cloud").awardedPoints == 20, "known cloud preference retains its credit");
    d.cloudProtection = false;
    Check(Rule(ComputeScore(result), "mp.cloud").state == "Disabled", "explicitly disabled cloud preference stays disabled");

    StorageVolume volume;
    volume.driveType = L"Fixed"; volume.bitLockerState = L"On"; volume.bitLockerStatus = Status::AccessDenied;
    result.storage.status = Status::Success;
    result.storage.volumes = {volume};
    Check(Rule(ComputeScore(result), "enc.bl").awardedPoints == 0 && Rule(ComputeScore(result), "enc.bl").state == "Unknown",
          "unreadable BitLocker status must not earn points from stale On state");
    result.storage.volumes[0].bitLockerStatus = Status::Success;
    Check(Rule(ComputeScore(result), "enc.bl").awardedPoints == 100, "complete encrypted inventory receives full credit");
    result.storage.status = Status::AccessDenied;
    Check(Rule(ComputeScore(result), "enc.bl").awardedPoints == 50, "partial volume enumeration cannot receive full credit");
    result.storage.volumes.clear();
    Check(Rule(ComputeScore(result), "enc.bl").state == "Unknown", "failed empty inventory does not mean no fixed volumes");
    result.storage.status = Status::Success;
    result.storage.volumes = {volume}; result.storage.volumes[0].bitLockerStatus = Status::Success;
    result.storage.volumes.push_back(StorageVolume{});
    Check(Rule(ComputeScore(result), "enc.bl").awardedPoints == 50, "unknown volume type prevents full encryption coverage credit");
    result.security.secureBoot.enabled = Tri::Yes;
    Check(Rule(ComputeScore(result), "hw.secureboot").awardedPoints == 0, "failed Secure Boot read cannot earn stale credit");
    result.security.virt.runningServicesKnown = result.security.virt.hvciEnabled = true;
    Check(Rule(ComputeScore(result), "hw.hvci").awardedPoints == 0, "failed virtualization read cannot earn stale HVCI credit");
    result.applications.push_back(ApplicationFinding{});
    result.applications[0].name = L"Blocked app inventory"; result.applications[0].status = Status::AccessDenied;
    result.score = ComputeScore(result);
    std::wostringstream captured;
    auto* old = std::wcout.rdbuf(captured.rdbuf());
    try { RenderConsole(result); } catch (...) { std::wcout.rdbuf(old); throw; }
    std::wcout.rdbuf(old);
    Check(captured.str().find(L"Incomplete (AccessDenied)") != std::wstring::npos, "blocked application scan is displayed as incomplete");
    std::ofstream("partial-output.json", std::ios::binary) << RenderJson(result);
}

static void TestRegisteredAntivirus() {
    AssessmentResult result;
    result.antivirus.status = Status::Success;
    AntivirusProduct first;
    first.name = L"Example \"Antivirus\" A"; first.id = L"first";
    first.state = AntivirusState::Enabled; first.status = Status::Success;
    first.signaturesUpToDate = Tri::No; // Enabled status alone determines credit.
    AntivirusProduct second = first;
    second.name = L"Example Antivirus B"; second.id = L"second"; second.state = AntivirusState::Disabled;
    AntivirusProduct defender = second;
    defender.name = L"Microsoft Defender Antivirus"; defender.id = L"defender"; defender.isDefender = true;
    result.antivirus.products = {first, second, defender};
    result.defender.periodicScanning = Tri::Yes;
    result.defender.amRunningMode = L"SxS Passive Mode";
    result.score = ComputeScore(result);
    Check(result.score.registeredAntivirusScoring, "third-party AV selects registration scoring");
    Check(result.score.total == 195 && result.score.maximum == 1000, "enabled third-party AV earns malware section only");
    Check(result.score.antivirusScores.size() == 3 && result.score.antivirusScores[0].awardedPoints == 195 &&
          result.score.antivirusScores[1].awardedPoints == 0 && result.score.antivirusScores[2].awardedPoints == 0,
          "independent product scores when Defender is inactive");
    Check(Rule(result.score, "mp.registered").awardedPoints == 195, "Defender WMI failure must not erase WSC credit");
    std::ofstream("antivirus-output.json", std::ios::binary) << RenderJson(result);
    std::wostringstream captured;
    auto* old = std::wcout.rdbuf(captured.rdbuf());
    try { RenderConsole(result); } catch (...) { std::wcout.rdbuf(old); throw; }
    std::wcout.rdbuf(old);
    Check(captured.str().find(first.name) != std::wstring::npos && captured.str().find(second.name) != std::wstring::npos,
          "console names both third-party products");
    Check(captured.str().find(L"195 / 195") != std::wstring::npos && captured.str().find(L"0 / 195") != std::wstring::npos,
          "console shows each antivirus score");
    Check(captured.str().find(L"Periodic scanning") != std::wstring::npos && captured.str().find(L"Real-Time") == std::wstring::npos,
          "fallback replaces inactive Defender detail and shows periodic scanning");
    for (Tri periodic : {Tri::No, Tri::Yes, Tri::Unknown}) {
        result.defender.periodicScanning = periodic;
        Check(ComputeScore(result).total == 195, "periodic scanning must never affect score");
    }
    result.antivirus.products[1].state = AntivirusState::Enabled;
    auto both = ComputeScore(result);
    Check(both.total == 195 && both.antivirusScores[0].awardedPoints == 195 && both.antivirusScores[1].awardedPoints == 195,
          "two enabled AVs score separately without inflating total");
    result.security.smartAppControlEvaluation = true;
    const auto evaluatedWithAv = ComputeScore(result);
    Check(evaluatedWithAv.total == 220 && evaluatedWithAv.maximum == 1000 &&
          Rule(evaluatedWithAv, "mp.registered").maxPoints == 195,
          "registered antivirus and SAC evaluation preserve the 1000-point scale");
    result.security.smartAppControlEvaluation = false;
    result.antivirus.products[1].state = AntivirusState::Disabled;
    for (auto state : {AntivirusState::Disabled, AntivirusState::Snoozed, AntivirusState::Expired, AntivirusState::Unknown}) {
        result.antivirus.products[0].state = state;
        Check(ComputeScore(result).total == 0, "inactive or unknown antivirus earns zero");
    }
    result.antivirus.products[0].state = AntivirusState::Enabled;
    result.antivirus.products[0].status = Status::AccessDenied;
    Check(ComputeScore(result).total == 0, "unreadable enabled field cannot earn points");
    result.antivirus.products = {defender};
    result.antivirus.products[0].state = AntivirusState::Enabled;
    Check(ComputeScore(result).total == 195, "registered Defender fallback works when its WMI provider is unavailable");
    result.defender.status = Status::Success; result.defender.enabled = result.defender.installed = true;
    result.defender.enabledStatus = Status::Success;
    auto defenderOnly = ComputeScore(result);
    Check(!defenderOnly.registeredAntivirusScoring && Rule(defenderOnly, "mp.defender").awardedPoints == 40,
          "normal Defender-only scoring is preserved");
    Check(PeriodicScanningFromMode(L"SxS Passive Mode") == Tri::Yes, "SxS periodic scanning enabled");
    Check(PeriodicScanningFromMode(L" normal ") == Tri::No && PeriodicScanningFromMode(L"Passive Mode") == Tri::No &&
          PeriodicScanningFromMode(L"EDR Block Mode") == Tri::No, "other documented modes are not limited periodic scanning");
    Check(PeriodicScanningFromMode(L"") == Tri::Unknown && PeriodicScanningFromMode(L"future mode") == Tri::Unknown,
          "unrecognized periodic scanning state remains unknown");
}

int main() {
    try {
        Fixture fixture;
        TestRegistry(fixture);
        TestFiles(fixture);
        TestScoreAndJson();
        TestRegisteredAntivirus();
        TestPartialCollection();
        TestComAndWmi();
        std::cout << "All native regressions passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Regression failed: " << error.what() << '\n';
        return 1;
    }
}
