#include "Utilities.h"
#include "RegistryReader.h"
#include "Collectors/AntivirusCollector.h"
#include "Collectors/DefenderCollector.h"
#include <ranges>
#include <algorithm>
#include "Collectors/PersistenceCollector.h"
#include "Output/JsonRenderer.h"
#include "Output/JsonFile.h"
#include "Output/JsonCompact.h"
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

static WindowsUpdateInfo HealthyWindowsUpdate() {
    WindowsUpdateInfo update;
    update.status = update.pendingStatus = update.historyStatus = update.services.status = Status::Success;
    update.rebootRequired = Tri::No;
    update.lastInstallationSucceeded = Tri::Yes;
    update.lastInstallationResult = L"Succeeded";
    update.lastSearchUtc = L"2026-10-14T10:00:00Z";
    for (const auto* name : {L"wuauserv", L"BITS", L"UsoSvc"}) {
        ServiceEntry service;
        service.name = name; service.state = L"Stopped"; service.startType = L"Manual"; service.status = Status::Success;
        update.services.entries.push_back(service);
    }
    return update;
}

static void TestScoreAndJson() {
    AssessmentResult result;
    auto empty = ComputeScore(result);
    Check(empty.total == 0 && empty.maximum == 1000, "unknown assessment must not earn points");
    Check(Rule(empty, "mp.rtp").category == "Malware Protection", "failed rules keep their category");
    result.os.status = result.cpu.status = Status::Success;
    result.os.build = 26100; result.os.ubr = 1;
    result.windowsUpdate = HealthyWindowsUpdate();
    result.cpu.vmx = result.cpu.aesni = result.cpu.nx = true;
    auto& s = result.security;
    s.tpm.status = Status::Success; s.tpm.present = s.tpm.ready = true; s.tpm.specVersion = L"2.0";
    s.secureBoot.enabled = Tri::Yes;
    s.secureBoot.status = Status::Success;
    s.virt.status = Status::Success;
    s.virt.runningServicesKnown = s.virt.vbsEnabled = s.virt.hvciEnabled = s.virt.credentialGuardRunning = true;
    s.uac.status = Status::Success; s.uac.enabled = s.uac.consentPromptAdmin = true; s.uac.promptOnSecureDesktop = 1;
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
    result.network.status = Status::Success;
    for (auto* setting : {&result.network.smb1Server, &result.network.smb1Client,
                          &result.network.smbGuestLogons, &result.network.llmnr, &result.network.rdp}) {
        setting->enabled = Tri::No; setting->status = Status::Success;
    }
    for (auto* setting : {&result.network.smbServerSigning, &result.network.smbClientSigning}) {
        setting->enabled = Tri::Yes; setting->status = Status::Success;
    }
    auto& hardening = result.hardening;
    for (auto* setting : {&hardening.lsaProtection, &hardening.noLmHash, &hardening.autoPlayDisabled,
                          &hardening.guestDisabled, &hardening.remoteAssistanceDisabled}) {
        setting->status = Status::Success; setting->enabled = Tri::Yes;
    }
    hardening.inactivityStatus = hardening.lmCompatibilityStatus = hardening.lockoutStatus = Status::Success;
    hardening.inactivitySeconds = 900; hardening.lmCompatibility = 5;
    hardening.lockoutThreshold = 10; hardening.lockoutDuration = hardening.lockoutWindow = 900;
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
                           "acc.uac2", "acc.elev", "acc.hello", "hyg.startup"}) {
        Check(Rule(healthy, id).state != "Enabled", "capabilities, facts, and scan results do not use Enabled");
    }
    int sum = 0; for (const auto& rule : healthy.rules) sum += rule.awardedPoints;
    Check(sum == healthy.total, "rule sum matches score");
    s.tpm.specVersion = L"1.2";
    Check(Rule(ComputeScore(result), "hw.tpm2").awardedPoints == 15, "TPM 1.2 must not earn TPM 2.0 points");
    s.tpm.specVersion = L"12.0";
    Check(Rule(ComputeScore(result), "hw.tpm2").awardedPoints == 15, "TPM version matching must use the complete version");
    s.tpm.specVersion = L"2.0, 0, 1.59";
    Check(Rule(ComputeScore(result), "hw.tpm2").awardedPoints == 30, "TPM 2.0 with revision metadata earns full credit");
    result.firewall.profiles[0].defaultInbound = 2;
    Check(Rule(ComputeScore(result), "net.in").awardedPoints == 0, "unknown firewall action must not count as blocked");
    s.virt.runningServicesKnown = false;
    Check(Rule(ComputeScore(result), "hw.hvci").state == "Unknown", "configured HVCI is not running evidence");
    result.os.productName = L"quoted \"name\"";
    result.hardening.lsaProtection.reason = L"tabs\tand\nnewlines";
    result.score = ComputeScore(result);
    const auto json = RenderJson(result);
    Check(json.find("quoted \\\"name\\\"") != std::string::npos, "score strings are JSON escaped");
    Check(json.find("tabs\\tand\\nnewlines") != std::string::npos, "control characters are JSON escaped");
    // The smoke harness independently parses this output using Python's JSON parser.
    std::ofstream("regression-output.json", std::ios::binary) << json;
}

static void TestWindowsUpdate() {
    AssessmentResult result;
    result.os.status = Status::Success; result.os.build = 26100; result.os.ubr = 1;
    result.windowsUpdate = HealthyWindowsUpdate();
    auto score = ComputeScore(result);
    Check(score.maximum == 1000, "Windows Update category preserves the 1000-point maximum");
    Check(Rule(score, "os.patch").category == "Windows Update" && Rule(score, "os.patch").maxPoints == 0,
          "update metadata retain their stable ID without earning security points");
    int categoryMax = 0, categoryAward = 0;
    for (const auto& rule : score.rules) if (rule.category == "Windows Update") {
        categoryMax += rule.maxPoints; categoryAward += rule.awardedPoints;
    }
    Check(categoryMax == 60 && categoryAward == 60, "healthy Windows Update receives all 60 scored points");
    const int baselineScore = score.total;
    for (unsigned count : {0u, 1u, 2u, 3u, 7u, 8u, 9u, UINT_MAX}) {
        result.windowsUpdate.pendingCount = count;
        const auto report = ComputeScore(result);
        const auto& rule = Rule(report, "wu.pending");
        Check(rule.awardedPoints == 0 && rule.maxPoints == 0 && report.total == baselineScore,
              "pending counts through overflow boundaries are informational and never change score");
    }
    result.windowsUpdate.pendingCount = 1;
    result.windowsUpdate.optionalCount = 12;
    Check(ComputeScore(result).total == baselineScore, "pending and optional updates do not reduce score");
    result.windowsUpdate.pendingStatus = Status::AccessDenied;
    Check(Rule(ComputeScore(result), "wu.pending").state == "Unknown" &&
          ComputeScore(result).total == baselineScore, "failed pending search stays unknown without changing score");
    result.windowsUpdate.pendingStatus = Status::Success;
    auto& service = result.windowsUpdate.services.entries[0];
    Check(Rule(ComputeScore(result), "wu.service.wuauserv").awardedPoints == 10, "idle manual update service is available on demand");
    service.startType = L"Disabled";
    Check(Rule(ComputeScore(result), "wu.service.wuauserv").awardedPoints == 0, "disabled update service earns no readiness credit");
    service.startType = L"Manual"; service.status = Status::AccessDenied;
    Check(Rule(ComputeScore(result), "wu.service.wuauserv").state == "Unknown", "unreadable service is unknown");
    service.status = Status::Success;
    result.windowsUpdate.rebootRequired = Tri::Yes;
    Check(Rule(ComputeScore(result), "wu.restart").awardedPoints == 0 &&
          Rule(ComputeScore(result), "wu.restart").state == "Restart required", "pending restart reduces update completion score");
    result.windowsUpdate.rebootRequired = Tri::Unknown;
    Check(Rule(ComputeScore(result), "wu.restart").state == "Unknown", "unavailable restart status is unknown");
    result.windowsUpdate.rebootRequired = Tri::No;
    result.windowsUpdate.lastInstallationSucceeded = Tri::No;
    Check(Rule(ComputeScore(result), "wu.history").awardedPoints == 0, "failed latest update installation earns no history credit");
    result.windowsUpdate.lastInstallationSucceeded = Tri::Yes; result.windowsUpdate.historyStatus = Status::AccessDenied;
    Check(Rule(ComputeScore(result), "wu.history").state == "Unknown", "unreadable history cannot earn stale credit");
    result.windowsUpdate = HealthyWindowsUpdate();
    result.windowsUpdate.pendingCount = 1;
    WindowsUpdateItem item;
    item.title = L"Pending \"Windows\" update"; item.id = L"update-id"; item.kbArticles = {L"1234567"};
    item.optional = Tri::No; item.downloaded = Tri::Yes;
    item.updateType = L"Software"; item.classifications = {L"Security Updates"};
    item.products = {L"Microsoft .NET Framework"}; item.severity = L"Critical";
    result.windowsUpdate.updates.push_back(item);
    WindowsUpdateItem optional = item;
    optional.id = L"optional-id"; optional.title = L"Optional driver"; optional.optional = Tri::Yes;
    optional.updateType = L"Driver"; optional.classifications.clear(); optional.products.clear(); optional.severity.clear();
    result.windowsUpdate.updates.push_back(optional); result.windowsUpdate.optionalCount = 1;
    result.windowsUpdate.services.entries[0].displayName = L"Windows Update";
    result.score = ComputeScore(result);
    std::ofstream("windows-update-output.json", std::ios::binary) << RenderJson(result);
    std::wostringstream captured;
    auto* old = std::wcout.rdbuf(captured.rdbuf());
    try { RenderConsole(result); } catch (...) { std::wcout.rdbuf(old); throw; }
    std::wcout.rdbuf(old);
    Check(captured.str().find(item.title) != std::wstring::npos && captured.str().find(L"KB1234567") != std::wstring::npos,
          "pending update title and KB are shown in console output");
    Check(captured.str().find(L"|- Pending \"Windows\" update  [Security Updates; Severity: Critical]") != std::wstring::npos &&
          captured.str().find(L"Products: Microsoft .NET Framework") != std::wstring::npos &&
          captured.str().find(L"`- Optional driver  [Optional; Driver]") != std::wstring::npos,
          "pending update tree includes API classifications, products, severity, and optional driver types");
    Check(captured.str().find(L"|- wuauserv - Windows Update") != std::wstring::npos &&
          captured.str().find(L"`- UsoSvc") != std::wstring::npos, "update services form a tree with service key names first");
    const size_t scoreStart = captured.str().find(L"Rule breakdown");
    const size_t updateGroup = captured.str().find(L"Windows Update", scoreStart);
    const size_t metadata = captured.str().find(L"Windows update details available", scoreStart);
    Check(scoreStart != std::wstring::npos && updateGroup != std::wstring::npos && metadata == std::wstring::npos,
          "informational update metadata do not appear in the scored breakdown");
    result.windowsUpdate.updates.clear(); result.windowsUpdate.pendingCount = result.windowsUpdate.optionalCount = 0;
    captured.str(L""); captured.clear(); old = std::wcout.rdbuf(captured.rdbuf());
    try { RenderConsole(result); } catch (...) { std::wcout.rdbuf(old); throw; }
    std::wcout.rdbuf(old);
    const size_t pendingStart = captured.str().find(L"Pending Updates  (None)");
    const size_t pendingEnd = captured.str().find(L"Update Services", pendingStart);
    Check(pendingStart != std::wstring::npos && pendingEnd != std::wstring::npos &&
          captured.str().substr(pendingStart, pendingEnd - pendingStart).find(L"|-") == std::wstring::npos &&
          captured.str().substr(pendingStart, pendingEnd - pendingStart).find(L"`-") == std::wstring::npos,
          "no pending updates prints None without an empty tree");
    result.windowsUpdate.pendingStatus = Status::Unavailable;
    result.score = ComputeScore(result);
    std::ofstream("windows-update-unknown.json", std::ios::binary) << RenderJson(result);
    const auto apiServices = CollectServices({L"WuAuSeRv"});
    Check(apiServices.entries.size() == 1 && apiServices.entries[0].status == Status::Success &&
          apiServices.entries[0].name == L"wuauserv", "SCM supplies the canonical service key name instead of echoing the requested casing");
}

static void TestComAndWmi() {
    std::wstring missingString;
    unsigned long long missingNumber = 0;
    bool missingBool = false;
    std::vector<unsigned long long> missingArray{1};
    Check(!WmiGetString(nullptr, L"Probe", missingString) && !WmiGetUInt(nullptr, L"Probe", missingNumber) &&
          !WmiGetBool(nullptr, L"Probe", missingBool) && !WmiGetUIntArray(nullptr, L"Probe", missingArray) && missingArray.empty(),
          "missing WMI objects fail safely without dereferencing null");
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
    Check(Rule(ComputeScore(result), "enc.bl").awardedPoints == 50, "complete encrypted inventory receives full credit");
    result.storage.status = Status::AccessDenied;
    Check(Rule(ComputeScore(result), "enc.bl").awardedPoints == 25, "partial volume enumeration cannot receive full credit");
    result.storage.volumes.clear();
    Check(Rule(ComputeScore(result), "enc.bl").state == "Unknown", "failed empty inventory does not mean no fixed volumes");
    result.storage.status = Status::Success;
    result.storage.volumes = {volume}; result.storage.volumes[0].bitLockerStatus = Status::Success;
    result.storage.volumes.push_back(StorageVolume{});
    Check(Rule(ComputeScore(result), "enc.bl").awardedPoints == 25, "unknown volume type prevents full encryption coverage credit");
    result.security.secureBoot.enabled = Tri::Yes;
    Check(Rule(ComputeScore(result), "hw.secureboot").awardedPoints == 0, "failed Secure Boot read cannot earn stale credit");
    result.security.virt.runningServicesKnown = result.security.virt.hvciEnabled = true;
    Check(Rule(ComputeScore(result), "hw.hvci").awardedPoints == 0, "failed virtualization read cannot earn stale HVCI credit");
    result.score = ComputeScore(result);
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
    Check(result.score.total == 180 && result.score.maximum == 1000, "enabled third-party AV earns malware section only");
    Check(result.score.antivirusScores.size() == 3 && result.score.antivirusScores[0].awardedPoints == 180 &&
          result.score.antivirusScores[1].awardedPoints == 0 && result.score.antivirusScores[2].awardedPoints == 0,
          "independent product scores when Defender is inactive");
    Check(Rule(result.score, "mp.registered").awardedPoints == 180, "Defender WMI failure must not erase WSC credit");
    std::ofstream("antivirus-output.json", std::ios::binary) << RenderJson(result);
    std::wostringstream captured;
    auto* old = std::wcout.rdbuf(captured.rdbuf());
    try { RenderConsole(result); } catch (...) { std::wcout.rdbuf(old); throw; }
    std::wcout.rdbuf(old);
    Check(captured.str().find(first.name) != std::wstring::npos && captured.str().find(second.name) != std::wstring::npos,
          "console names both third-party products");
    Check(captured.str().find(L"180 / 180") != std::wstring::npos && captured.str().find(L"0 / 180") != std::wstring::npos,
          "console shows each antivirus score");
    Check(captured.str().find(L"Periodic scanning") != std::wstring::npos && captured.str().find(L"Real-Time") == std::wstring::npos,
          "fallback replaces inactive Defender detail and shows periodic scanning");
    for (Tri periodic : {Tri::No, Tri::Yes, Tri::Unknown}) {
        result.defender.periodicScanning = periodic;
        Check(ComputeScore(result).total == 180, "periodic scanning must never affect score");
    }
    result.antivirus.products[1].state = AntivirusState::Enabled;
    auto both = ComputeScore(result);
    Check(both.total == 180 && both.antivirusScores[0].awardedPoints == 180 && both.antivirusScores[1].awardedPoints == 180,
          "two enabled AVs score separately without inflating total");
    result.security.smartAppControlEvaluation = true;
    const auto evaluatedWithAv = ComputeScore(result);
    Check(evaluatedWithAv.total == 205 && evaluatedWithAv.maximum == 1000 &&
          Rule(evaluatedWithAv, "mp.registered").maxPoints == 180,
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
    Check(ComputeScore(result).total == 180, "registered Defender fallback works when its WMI provider is unavailable");
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

static std::wstring CaptureConsole(const AssessmentResult& result, ReportView view = ReportView::Live) {
    std::wostringstream captured;
    auto* original = std::wcout.rdbuf(captured.rdbuf());
    try { RenderConsole(result, view); } catch (...) { std::wcout.rdbuf(original); throw; }
    std::wcout.rdbuf(original);
    return captured.str();
}
static void TestHardeningAndWarnings() {
    AssessmentResult result;
    auto score = ComputeScore(result);
    Check(score.maximum == 1000 && score.total == 0, "unknown expanded assessment earns zero on the 1000-point scale");
    Check(std::ranges::all_of(score.warnings, [](const auto& warning) { return warning.verificationOnly && warning.severity == Severity::Low; }),
          "missing data produce verification gaps rather than vulnerability claims");
    auto& hardening = result.hardening;
    hardening.lockoutStatus = Status::Success;
    hardening.lockoutThreshold = 10; hardening.lockoutDuration = hardening.lockoutWindow = 900;
    Check(Rule(ComputeScore(result), "acc.lockout").awardedPoints == 25,
          "verified local lockout policy earns its exact weight");
    for (const auto attempts : {0u, 1u, 10u, 11u, MAXDWORD}) {
        hardening.lockoutThreshold = attempts;
        Check(Rule(ComputeScore(result), "acc.lockout").awardedPoints == (attempts >= 1 && attempts <= 10 ? 25 : 0),
              "lockout attempt thresholds do not overflow or reward disabled lockout");
    }
    hardening.lockoutThreshold = 5; hardening.lockoutDuration = 899;
    Check(Rule(ComputeScore(result), "acc.lockout").awardedPoints == 12, "short lockout receives partial credit");
    hardening.lockoutDuration = MAXDWORD;
    Check(Rule(ComputeScore(result), "acc.lockout").awardedPoints == 25, "administrator-only unlocking qualifies for lockout duration");
    hardening.lsaProtection.enabled = Tri::Yes; hardening.lsaProtection.status = Status::AccessDenied;
    Check(Rule(ComputeScore(result), "os.lsa").awardedPoints == 0, "unreadable LSA status cannot earn stale credit");
    hardening.guestDisabled.status = Status::Success; hardening.guestDisabled.enabled = Tri::No;
    result.defender.status = Status::Success; result.defender.installed = result.defender.threatsKnown = true;
    result.defender.threatsCount = 1;
    score = ComputeScore(result);
    const auto critical = std::ranges::find(score.warnings, std::string("mp.threats"), &SecurityWarning::ruleId);
    Check(critical != score.warnings.end() && critical->severity == Severity::Critical && !critical->verificationOnly,
          "confirmed active threats generate a critical warning");
    Check(std::ranges::is_sorted(score.warnings, std::greater{}, &SecurityWarning::severity), "warnings are sorted by severity");
    result.security.tpm.status = Status::Success; result.security.tpm.present = true; result.security.tpm.specVersion = L"2.0";
    const auto nativeTpm = ComputeScore(result);
    Check(Rule(nativeTpm, "hw.tpm2").state == "Readiness unknown" && Rule(nativeTpm, "enc.tpm").awardedPoints == 40,
          "native TPM presence does not invent verified readiness");
    result.network.adapters.push_back(NetworkAdapterInfo{}); result.network.adapters.back().name = L"PRIVATE_ADAPTER_SENTINEL";
    result.network.adapters.back().up = true;
    result.score = ComputeScore(result);
    const auto console = CaptureConsole(result);
    Check(console.find(L"Rule breakdown") < console.find(L"SECURITY SCORE") && console.find(L"SECURITY SCORE") < console.find(L"-- Warnings"),
          "report ends with breakdown, score, then warnings");
    for (const auto* hidden : {L"Active Network Adapters", L"PRIVATE_ADAPTER_SENTINEL", L"Local TCP Listeners", L"UDP Port 69", L"Configured RDP port", L"RDP scope"})
        Check(console.find(hidden) == std::wstring::npos, "removed console inventories stay hidden");
    Check(console.find(L"Critical") != std::wstring::npos && console.find(L"verification gap") != std::wstring::npos,
          "console distinguishes critical findings from unverified coverage");
    std::ofstream("warnings-output.json", std::ios::binary) << RenderJson(result);
}
static void TestNetworkSignIn() {
    AssessmentResult result;
    for (DWORD level = 0; level <= 6; ++level) {
        result.hardening.lmCompatibilityStatus = Status::Success;
        result.hardening.lmCompatibility = level;
        const auto rule = Rule(ComputeScore(result), "net.ntlm");
        Check(rule.awardedPoints == (level >= 3 && level <= 5 ? 20 : 0), "only supported modern sign-in levels receive credit");
        Check(rule.state != "Unknown", "valid or invalid configured policy has a specific state");
    }
    for (const auto status : {Status::NotFound, Status::AccessDenied, Status::Unsupported, Status::Error, Status::Unavailable}) {
        result.hardening.lmCompatibilityStatus = status;
        result.hardening.lmCompatibility = 0;
        result.score = ComputeScore(result);
        const auto& rule = Rule(result.score, "net.ntlm");
        Check(rule.state != "Unknown" && rule.awardedPoints == 0 && !rule.reason.empty(), "policy absence and read errors have explanations");
        const auto console = CaptureConsole(result);
        Check(console.find(NetworkSignInState(result.hardening)) != std::wstring::npos &&
              console.find(L"Unknown / not configured") == std::wstring::npos, "console distinguishes absent and failed sign-in policy reads");
        Check(std::ranges::none_of(result.score.warnings, [](const auto& warning) { return warning.ruleId == "net.ntlm"; }),
              "unverified sign-in policy does not invent a confirmed legacy weakness");
    }
}

static void TestJsonFiles(Fixture& fixture) {
    AssessmentResult result;
    result.os.productName = L"quoted \"name\" with [braces] and \\slashes";
    result.score = ComputeScore(result);
    result.os.computerName = L"SAVED_COMPUTER";
    result.os.build = 26100;
    result.cpu.brand = L"SAVED_CPU";
    result.cpu.hypervisorPresent = true;
    result.memory.totalBytes = 32ull << 30;
    result.memory.availableBytes = 12ull << 30;
    result.windowsUpdate = HealthyWindowsUpdate();
    WindowsUpdateItem update;
    update.title = L"SAVED_SECURITY_UPDATE"; update.classifications = {L"Security Updates"};
    update.products = {L"Microsoft .NET"}; update.kbArticles = {L"1234567"}; update.optional = Tri::No;
    result.windowsUpdate.updates.push_back(update); result.windowsUpdate.pendingCount = 1;
    StorageDisk disk; disk.index = 3; disk.model = L"SAVED_DISK"; disk.sizeBytes = 1ull << 40;
    result.storage.disks.push_back(disk);
    StorageVolume volume; volume.mountPoint = L"Z:\\"; volume.diskIndices = {3}; volume.bitLockerState = L"On";
    volume.totalBytes = 1ull << 40; volume.freeBytes = 1ull << 39;
    result.storage.volumes.push_back(volume);
    FirewallProfile profile; profile.name = L"Domain"; profile.status = Status::Success;
    profile.enabled = true; profile.defaultInbound = 0; profile.defaultOutbound = 1;
    result.firewall.profiles.push_back(profile);
    result.score.total = 321; // A recorded score must never be recomputed during viewing.
    Check(!result.score.warnings.empty(), "fixture has live warnings to exclude");
    const auto text = RenderJson(result);
    const auto compact = RenderJson(result, JsonFormat::Compact);
    Check(compact.size() < text.size(), "compact reports reduce field names and omit default values");
    Check(compact.find("\"s\":") == std::string::npos && compact.find("\"1\":\"quoted") != std::string::npos,
          "compact fields store literal values without a string table");
    Check(compact.find("\"2\":26100") != std::string::npos, "build has decimal field ID 2");
    Check(text.find("\"warnings\"") == std::string::npos, "JSON exports omit warnings by default");
    Check(text.find("\"applications\"") == std::string::npos, "JSON exports omit removed applications");
    Check(std::ranges::none_of(result.score.rules, [](const auto& rule) { return rule.id == "hyg.appinv"; }),
          "removed application inventory does not create scoring rules or verification gaps");
    const auto path = fixture.dir / L"saved report \u03a9.json";
    const auto saved = SaveJsonReport(compact, path);
    Check(saved.has_value() && fs::exists(path), "save JSON to a Unicode path with spaces");
    const auto viewed = ReadJsonReport(path);
    Check(viewed.has_value(), "native Windows parser restores a saved report");
    Check(RenderJson(*viewed) == text, "all serialized report fields round trip without recomputing scores");
    Check(viewed->score.total == 321 && viewed->score.warnings.empty(), "saved scores are preserved and warnings are not restored");
    const auto console = CaptureConsole(*viewed, ReportView::Export);
    const auto live = CaptureConsole(result);
    const auto banner = console.find(L"Windows Security Assessment");
    const auto warning = console.find(L"[!] BACKUP REPORT");
    const auto system = console.find(L"-- System");
    Check(banner < warning && warning < system, "boxed backup warning appears between title and System");
    Check(console.find(L"+------------------------------------------------------------+") != std::wstring::npos &&
          console.find(L"current system state.") != std::wstring::npos, "backup warning has a plain-text box and explains stale data");
    Check(live.find(L"BACKUP REPORT") == std::wstring::npos && console.find(L"-- Applications") == std::wstring::npos,
          "live reports have no backup box and applications are removed");
    Check(console.substr(system, console.find(L"-- Warnings") - system) ==
          live.substr(live.find(L"-- System"), live.find(L"-- Warnings") - live.find(L"-- System")),
          "saved report uses the same display as the live report before warnings");
    Check(console.find(L"Warnings are disabled when viewing an export") != std::wstring::npos &&
          console.find(L"verification gap") == std::wstring::npos, "export viewer explicitly disables security warnings");
    Check(CaptureConsole(result, ReportView::Export).find(L"verification gap") == std::wstring::npos,
          "export context suppresses even populated warning lists");
    Check(!SaveJsonReport("replacement", path), "exports do not overwrite existing files");
    Check(fs::file_size(path) == compact.size() + 1, "failed overwrite preserves original file");
    Check(!SaveJsonReport(text, fixture.dir / L"missing" / L"report.json"), "unavailable output directories fail clearly");
    Check(!ReadJsonReport(fixture.dir / L"missing.json"), "missing reports cannot be viewed");
    const auto bad = fixture.dir / L"bad.json";
    for (const auto* invalid : {"", "{\"system\":", "[]", "{}", "{\"system\":{},\"score\":{\"rules\":[],\"total\":101,\"maximum\":100}}", "\xff\xfe"}) {
        std::ofstream(bad, std::ios::binary) << invalid;
        Check(!ReadJsonReport(bad), "empty, malformed, non-report and invalid UTF-8 files are rejected");
    }
    std::ofstream(bad, std::ios::binary) << compact << '\0';
    Check(!ReadJsonReport(bad), "raw NUL characters cannot hide trailing report data");
    std::ofstream(bad, std::ios::binary) << "\xef\xbb\xbf" << compact;
    Check(ReadJsonReport(bad).has_value(), "UTF-8 BOM reports remain viewable");
    std::ofstream(bad, std::ios::binary) << R"({"v":1,"s":["Disabled","Enabled","Unknown","N/A","Legacy OS"],"d":{"4":{"5":4,"7":26100},"5w":{"5x":7,"5y":10,"60":[]}}})";
    const auto previousCompact = ReadJsonReport(bad);
    Check(previousCompact && previousCompact->os.productName == L"Legacy OS" && previousCompact->os.build == 26100 &&
          previousCompact->score.total == 7, "previous compact backups remain viewable");
    auto legacy = text;
    legacy.insert(legacy.size() - 2, ",\"warnings\":[{\"title\":\"OLD_WARNING_SENTINEL\"}]");
    std::ofstream(bad, std::ios::binary) << legacy;
    legacy.insert(legacy.size() - 1, ",\"applications\":[{\"name\":\"OLD_APPLICATION_SENTINEL\"}]");
    std::ofstream(bad, std::ios::binary) << legacy;
    auto old = ReadJsonReport(bad);
    Check(!old && old.error().find(L"compact exports only") != std::wstring::npos, "readable and legacy exports are not viewable");
    std::ofstream(bad, std::ios::binary) << CompactJson(R"({"system":{"productName":"\u001b[2J\nspoof"},"score":{"total":7,"maximum":10,"rules":[]}})");
    auto controls = ReadJsonReport(bad);
    Check(controls && controls->os.productName == L"\\u001B[2J\\u000Aspoof", "imported controls cannot inject terminal escapes");
    for (const auto* invalid : {
        R"({"system":{},"score":{"total":0,"maximum":2147483648,"rules":[]}})",
        R"({"system":{},"score":{"total":0,"maximum":10,"rules":[{"maxPoints":5,"awardedPoints":6}]}})",
        R"({"system":{},"score":{"total":0,"maximum":10,"rules":[{"maxPoints":-1}]}})",
        R"({"system":{"build":"bad"},"score":{"total":0,"maximum":10,"rules":[]}})",
        R"({"system":{"uptimeSeconds":18446744073709551616},"score":{"total":0,"maximum":10,"rules":[]}})"}) {
        std::string encoded;
        try { encoded = CompactJson(invalid); }
        catch (const std::runtime_error&) { continue; } // Invalid readable types cannot be compacted.
        std::ofstream(bad, std::ios::binary) << encoded;
        Check(!ReadJsonReport(bad), "out-of-range numbers and impossible compact rule scores are rejected");
    }
    // Exercise every native status/tri-state and numeric/text arrays independently
    // of the default fixture values. Text that resembles a state stays text.
    for (const auto status : {Status::Success, Status::NotFound, Status::AccessDenied, Status::Unsupported, Status::Unavailable, Status::Error}) {
        auto coded = result;
        coded.os.status = status;
        coded.defender.enabledStatus = status;
        coded.firewall.activeProfilesStatus = status;
        coded.network.rdp.status = status;
        coded.os.computerName = L"Enabled";
        NetworkAdapterInfo adapter; adapter.netbiosOptions = 0; adapter.ipv4 = {L"192.0.2.1", L"192.0.2.2"}; adapter.dns = {L"192.0.2.53"};
        coded.network.adapters.push_back(adapter);
        for (const auto tri : {Tri::Yes, Tri::No, Tri::Unknown, Tri::NotApplicable}) {
            coded.security.secureBoot.enabled = tri;
            coded.network.rdp.enabled = tri;
            coded.defender.periodicScanning = tri;
            std::ofstream(bad, std::ios::binary) << RenderJson(coded, JsonFormat::Compact);
            const auto restored = ReadJsonReport(bad);
            Check(restored && RenderJson(*restored) == RenderJson(coded), "all compact states and arrays restore exactly");
        }
    }
    for (const auto state : {AntivirusState::Unknown, AntivirusState::Enabled, AntivirusState::Disabled, AntivirusState::Snoozed, AntivirusState::Expired}) {
        auto coded = result;
        AntivirusProduct product; product.name = L"State fixture"; product.state = state;
        coded.antivirus.products.push_back(product);
        std::ofstream(bad, std::ios::binary) << RenderJson(coded, JsonFormat::Compact);
        const auto restored = ReadJsonReport(bad);
        Check(restored && restored->antivirus.products[0].state == state, "antivirus codes restore independently of rule-state text");
    }
    auto oversized = result;
    oversized.score.rules.front().description.assign(16385, 'x');
    std::ofstream(bad, std::ios::binary) << RenderJson(oversized, JsonFormat::Compact);
    Check(!ReadJsonReport(bad), "oversized rule labels cannot multiply console padding without bound");
    std::ofstream(bad, std::ios::binary) << std::string(129, '[') << std::string(129, ']');
    Check(!ReadJsonReport(bad), "deeply nested inputs are rejected before parsing");
}

int main() {
    try {
        Check(::SetEnvironmentVariableW(L"NO_COLOR", L"1") != FALSE, "use deterministic ASCII tree rendering in regressions");
        Fixture fixture;
        TestRegistry(fixture);
        TestFiles(fixture);
        TestScoreAndJson();
        TestRegisteredAntivirus();
        TestWindowsUpdate();
        TestPartialCollection();
        TestHardeningAndWarnings();
        TestJsonFiles(fixture);
        TestNetworkSignIn();
        TestComAndWmi();
        std::cout << "All native regressions passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Regression failed: " << error.what() << '\n';
        return 1;
    }
}
