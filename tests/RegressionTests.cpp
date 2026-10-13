#include "Utilities.h"
#include "RegistryReader.h"
#include "Collectors/ApplicationCollector.h"
#include "Collectors/PersistenceCollector.h"
#include "Output/JsonRenderer.h"
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
    s.virt.status = Status::Success;
    s.virt.runningServicesKnown = s.virt.vbsEnabled = s.virt.hvciEnabled = true;
    s.uac.status = Status::Success; s.uac.enabled = s.uac.consentPromptAdmin = true;
    s.dep.depEnabled = s.dep.sehopEnabled = Tri::Yes;
    s.smartAppControlOn = s.isElevated = s.windowsHelloAvailable = true;
    auto& d = result.defender;
    d.status = Status::Success;
    d.installed = d.enabled = d.realTimeProtection = d.behaviorMonitor = d.ioav = true;
    d.cloudProtection = d.tamperProtection = d.threatsKnown = true;
    result.firewall.status = Status::Success; result.firewall.serviceRunning = true;
    result.firewall.serviceStatus = Status::Success;
    for (const auto* name : {L"Domain", L"Private", L"Public"}) {
        FirewallProfile p; p.name = name; p.enabled = true; p.defaultInbound = 0; p.status = Status::Success;
        result.firewall.profiles.push_back(p);
    }
    StorageVolume volume; volume.driveType = L"Fixed"; volume.bitLockerState = L"On";
    result.storage.volumes.push_back(volume);
    result.persistence.status = Status::Success;
    ApplicationFinding app; app.status = Status::NotFound; result.applications.push_back(app);
    auto healthy = ComputeScore(result);
    Check(healthy.total == 1000 && healthy.maximum == 1000, "fully satisfied rules retain 1000-point scale");
    int sum = 0; for (const auto& rule : healthy.rules) sum += rule.awardedPoints;
    Check(sum == healthy.total, "rule sum matches score");
    s.tpm.specVersion = L"1.2";
    Check(Rule(ComputeScore(result), "hw.tpm2").awardedPoints == 20, "TPM 1.2 must not earn TPM 2.0 points");
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

int main() {
    try {
        Fixture fixture;
        TestRegistry(fixture);
        TestFiles(fixture);
        TestScoreAndJson();
        TestComAndWmi();
        std::cout << "All native regressions passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Regression failed: " << error.what() << '\n';
        return 1;
    }
}
