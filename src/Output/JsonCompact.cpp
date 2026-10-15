#include "JsonCompact.h"
#include "../Utilities.h"
#include <wrl/client.h>
#include <wrl/wrappers/corewrappers.h>
#include <algorithm>
#include <array>
#include <charconv>
#include <stdexcept>
#include <unordered_map>
#include <vector>

namespace sa {
namespace {
using Microsoft::WRL::ComPtr;
using Microsoft::WRL::Wrappers::HString;
using Microsoft::WRL::Wrappers::HStringReference;
using namespace ABI::Windows::Data::Json;
constexpr size_t kExpandedLimit = 128u << 20;
// Version 1 key order is part of the file format. Append only; never reorder.
constexpr std::string_view keys[] = {
    "enabled", "status", "source", "reason", "system", "productName", "displayVersion",
    "build", "ubr", "architecture", "computerName", "userName", "timeZone", "locale",
    "uptimeSeconds", "windowsUpdate", "cachedOnly", "pendingStatus", "pendingReason", "pendingCount", "optionalCount",
    "lastSearchUtc", "rebootRequired", "historyStatus", "lastInstallationUtc", "lastInstallationTitle", "lastInstallationResult", "lastInstallationError",
    "lastInstallationSucceeded", "updates", "title", "id", "optional", "downloaded", "updateType",
    "severity", "classifications", "products", "kbArticles", "servicesStatus", "services", "name",
    "displayName", "state", "startType", "hardware", "cpu", "vendor", "brand",
    "logicalProcessors", "physicalCores", "processorGroups", "maxMhz", "features", "sse", "sse2",
    "sse3", "ssse3", "sse41", "sse42", "avx", "avx2", "avx512f",
    "aesni", "sha", "vmx", "hypervisorPresent", "svm", "nx", "memory",
    "totalBytes", "availableBytes", "loadPercent", "modules", "capacity", "speed", "configuredSpeed",
    "manufacturer", "partNumber", "ecc", "security", "tpm", "present", "ready",
    "readinessKnown", "specVersion", "manufacturerId", "secureBoot", "firmwareIsUefi", "virtualization", "vbsEnabled",
    "hvciEnabled", "credentialGuardRunning", "hvciConfigured", "runningServicesKnown", "uac", "smartAppControl", "smartAppControlEvaluation",
    "elevated", "defender", "installed", "enabledStatus", "realTimeProtection", "realTimeProtectionStatus", "behaviorMonitor",
    "behaviorMonitorStatus", "ioav", "ioavStatus", "cloudProtection", "cloudProtectionStatus", "threatsKnown", "threatsCount",
    "tamperProtection", "tamperProtectionStatus", "amEngineVersion", "amRunningMode", "periodicScanning", "antivirusSignatureVersion", "antivirus",
    "hasThirdParty", "isDefender", "signaturesUpToDate", "firewall", "serviceRunning", "serviceStatus", "activeProfiles",
    "activeProfilesStatus", "profiles", "defaultInbound", "defaultOutbound", "storage", "disks", "index",
    "model", "sizeBytes", "busType", "mediaType", "isNvme", "volumes", "volumeId",
    "diskMappingStatus", "diskIndices", "mountPoint", "volumeLabel", "filesystem", "freeBytes", "driveType",
    "bitLockerState", "bitLockerStatus", "bitLockerNote", "encryptionMethod", "protectionMethod", "encryptionPercentage", "network",
    "adapters", "description", "mac", "up", "ifType", "guid", "dhcpServer",
    "netbiosOptions", "netbiosStatus", "dhcp", "ipv4", "ipv6", "gateways", "dns",
    "rdpPort", "rdpPortStatus", "tcp4Status", "tcp6Status", "udp4Status", "udp6Status", "endpointScope",
    "endpoints", "protocol", "family", "address", "port", "processId", "processName",
    "processStatus", "binding", "reviewNote", "hardening", "lsaProtection", "noLmHash", "autoPlayDisabled",
    "guestDisabled", "remoteAssistanceDisabled", "inactivitySeconds", "inactivityStatus", "lmCompatibility", "lmCompatibilityStatus", "lockoutThreshold",
    "lockoutDuration", "lockoutWindow", "lockoutStatus", "registryFindings", "path", "valueCount", "subkeyCount",
    "threshold", "exceeded", "directoryFindings", "fileCount", "dirCount", "persistence", "location",
    "command", "persistenceStatus", "score", "total", "maximum", "registeredAntivirusScoring", "rules",
    "maxPoints", "awardedPoints", "category", "antivirusScores", "smb1Server", "smb1Client", "smbServerSigning",
    "smbClientSigning", "smbGuestLogons", "smbEncryption", "smbRejectUnencrypted", "llmnr", "rdp", "rdpNla",
};
constexpr std::string_view tri[] = {"No", "Yes", "Unknown", "N/A"};
constexpr std::string_view status[] = {"Error", "Success", "Unavailable", "NotFound", "AccessDenied", "Unsupported"};
constexpr std::string_view antivirus[] = {"Disabled", "Enabled", "Unknown", "Snoozed", "Expired"};
enum class Kind { Text, Number, Boolean, Tri, Status, Antivirus };
Kind Type(std::string_view path) {
    const auto dot = path.rfind('.');
    const auto name = dot == path.npos ? path : path.substr(dot + 1);
    const auto parent = dot == path.npos ? std::string_view{} : path.substr(0, dot);
    if (name == "status" || name.ends_with("Status")) return Kind::Status;
    if (path == "antivirus.products.state") return Kind::Antivirus;
    if (name == "enabled") {
        if (parent == "security.tpm" || parent == "security.uac" || parent == "defender" || parent == "firewall.profiles")
            return Kind::Boolean;
        return Kind::Tri;
    }
    constexpr std::string_view tris[] = {"firmwareIsUefi", "smartAppControl", "hvciConfigured", "periodicScanning",
        "signaturesUpToDate", "rebootRequired", "lastInstallationSucceeded", "optional", "downloaded"};
    if (std::ranges::find(tris, name) != std::end(tris)) return Kind::Tri;
    constexpr std::string_view booleans[] = {"cachedOnly", "sse", "sse2", "sse3", "ssse3", "sse41", "sse42",
        "avx", "avx2", "avx512f", "aesni", "sha", "vmx", "svm", "nx", "hypervisorPresent", "ecc", "present",
        "ready", "readinessKnown", "vbsEnabled", "hvciEnabled", "credentialGuardRunning", "runningServicesKnown",
        "smartAppControlEvaluation", "elevated", "installed", "realTimeProtection", "behaviorMonitor", "ioav",
        "cloudProtection", "threatsKnown", "tamperProtection", "hasThirdParty", "isDefender", "serviceRunning",
        "isNvme", "up", "dhcp", "exceeded", "registeredAntivirusScoring"};
    if (std::ranges::find(booleans, name) != std::end(booleans)) return Kind::Boolean;
    constexpr std::string_view numbers[] = {"build", "ubr", "uptimeSeconds", "pendingCount", "optionalCount",
        "logicalProcessors", "physicalCores", "processorGroups", "maxMhz", "totalBytes", "availableBytes",
        "loadPercent", "capacity", "speed", "configuredSpeed", "threatsCount", "activeProfiles", "defaultInbound",
        "defaultOutbound", "index", "sizeBytes", "diskIndices", "freeBytes", "netbiosOptions", "rdpPort", "port",
        "processId", "inactivitySeconds", "lmCompatibility", "lockoutThreshold", "lockoutDuration", "lockoutWindow",
        "valueCount", "subkeyCount", "threshold", "fileCount", "dirCount", "total", "maximum", "maxPoints", "awardedPoints"};
    return std::ranges::find(numbers, name) != std::end(numbers) ? Kind::Number : Kind::Text;
}
std::string ShortKey(size_t index) {
    char buffer[16];
    const auto [end, error] = std::to_chars(std::begin(buffer), std::end(buffer), index, 36);
    if (error != std::errc{}) throw std::runtime_error("Invalid compact key");
    return {buffer, end};
}
size_t Integer(std::string_view value, int base = 10) {
    size_t index = 0;
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), index, base);
    if (error != std::errc{} || end != value.data() + value.size()) throw std::runtime_error("Invalid compact index");
    return index;
}
std::string Quote(std::string_view value) { return "\"" + std::string(value) + "\""; }

// Native JSON parsing validates imported syntax first. This bounded transformer
// preserves number tokens while applying the versioned schema to primitive values.
class Transform {
public:
    explicit Transform(bool encode) : encode_(encode), strings_{"\"Disabled\"", "\"Enabled\"", "\"Unknown\"", "\"N/A\""} {
        for (size_t i = 0; i < strings_.size(); ++i) indices_.emplace(strings_[i], i);
    }
    std::vector<std::string>& Strings() { return strings_; }
    std::string Run(std::string_view source) {
        source_ = source;
        position_ = 0;
        output_.clear();
        Value({}, 0);
        Space();
        if (position_ != source_.size()) throw std::runtime_error("Trailing JSON data");
        return std::move(output_);
    }
private:
    bool encode_;
    std::vector<std::string> strings_;
    std::unordered_map<std::string, size_t> indices_;
    std::string_view source_;
    size_t position_ = 0;
    std::string output_;
    void Add(std::string_view value) {
        if (value.size() > kExpandedLimit - output_.size()) throw std::runtime_error("Expanded report too large");
        output_ += value;
    }
    void Space() { while (position_ < source_.size() && std::string_view(" \r\n\t").contains(source_[position_])) ++position_; }
    bool Take(char c) {
        Space();
        if (position_ == source_.size() || source_[position_] != c) return false;
        ++position_; return true;
    }
    void Need(char c) { if (!Take(c)) throw std::runtime_error("Invalid JSON structure"); }
    std::string_view String() {
        Space();
        const size_t start = position_;
        Need('"');
        bool escaped = false;
        while (position_ < source_.size()) {
            const char c = source_[position_++];
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') return source_.substr(start, position_ - start);
        }
        throw std::runtime_error("Unterminated JSON string");
    }
    std::string_view Token() {
        Space();
        const size_t start = position_;
        while (position_ < source_.size() && !std::string_view(",]} \r\n\t").contains(source_[position_])) ++position_;
        if (start == position_) throw std::runtime_error("Missing JSON value");
        return source_.substr(start, position_ - start);
    }
    template<size_t N> void Enum(std::string_view value, const std::string_view (&table)[N]) {
        if (encode_) {
            const auto raw = value.substr(1, value.size() - 2);
            const auto entry = std::ranges::find(table, raw);
            if (entry == std::end(table)) throw std::runtime_error("Invalid state");
            Add(std::to_string(entry - std::begin(table)));
        } else {
            const size_t index = Integer(value);
            if (index >= N) throw std::runtime_error("Invalid state code");
            Add(Quote(table[index]));
        }
    }
    void Value(const std::string& path, size_t depth) {
        if (depth > 128) throw std::runtime_error("Nesting limit");
        if (Take('{')) {
            Add("{");
            if (!Take('}')) {
                do {
                    const auto token = String();
                    const auto key = token.substr(1, token.size() - 2);
                    std::string longKey;
                    if (encode_) {
                        const auto found = std::ranges::find(keys, key);
                        if (found == std::end(keys)) throw std::runtime_error("Unknown schema key");
                        longKey = *found;
                        Add(Quote(ShortKey(found - std::begin(keys))));
                    } else {
                        const size_t index = Integer(key, 36);
                        if (index >= std::size(keys) || ShortKey(index) != key) throw std::runtime_error("Invalid schema key");
                        longKey = keys[index]; Add(Quote(longKey));
                    }
                    Need(':'); Add(":");
                    Value(path.empty() ? longKey : path + "." + longKey, depth + 1);
                    if (!Take(',')) break;
                    Add(",");
                } while (true);
                Need('}');
            }
            Add("}"); return;
        }
        if (Take('[')) {
            Add("[");
            if (!Take(']')) {
                do {
                    Value(path, depth + 1);
                    if (!Take(',')) break;
                    Add(",");
                } while (true);
                Need(']');
            }
            Add("]"); return;
        }
        Space();
        const bool quoted = position_ < source_.size() && source_[position_] == '"';
        const auto value = quoted ? String() : Token();
        if (value == "null") { Add(value); return; }
        const auto kind = Type(path);
        if (kind == Kind::Tri) Enum(value, tri);
        else if (kind == Kind::Status) Enum(value, status);
        else if (kind == Kind::Antivirus) Enum(value, antivirus);
        else if (kind == Kind::Boolean) {
            if (encode_ && (value == "true" || value == "false")) Add(value == "true" ? "1" : "0");
            else if (!encode_ && (value == "0" || value == "1")) Add(value == "1" ? "true" : "false");
            else throw std::runtime_error("Invalid Boolean code");
        } else if (kind == Kind::Text) {
            if (encode_) {
                if (!quoted) throw std::runtime_error("Expected text");
                const auto [entry, inserted] = indices_.emplace(std::string(value), strings_.size());
                if (inserted) strings_.emplace_back(value);
                Add(std::to_string(entry->second));
            } else {
                const auto index = Integer(value);
                if (index >= strings_.size()) throw std::runtime_error("Invalid text reference");
                Add(strings_[index]);
            }
        } else {
            if (quoted || value == "true" || value == "false") throw std::runtime_error("Expected number");
            Add(value);
        }
    }
};
} // namespace

std::string CompactJson(std::string_view readable) {
    Transform codec(true);
    auto data = codec.Run(readable);
    std::string output = "{\"v\":1,\"s\":[";
    bool comma = false;
    for (const auto& text : codec.Strings()) {
        if (comma) output += ',';
        output += text;
        comma = true;
    }
    return output + "],\"d\":" + data + "}";
}

std::expected<std::wstring, std::wstring> ExpandCompactJson(IJsonObject* root) {
    double version = 0;
    if (FAILED(root->GetNamedNumber(HStringReference(L"v").Get(), &version)))
        return std::unexpected(L"The viewer supports compact exports only. Export again using --json 0; readable/plain-text reports cannot be viewed.");
    if (version != 1) return std::unexpected(L"This compact report version is not supported.");
    try {
        ComPtr<IJsonArray> strings;
        ComPtr<ABI::Windows::Foundation::Collections::IVector<IJsonValue*>> array;
        ComPtr<IJsonObject> data;
        if (FAILED(root->GetNamedArray(HStringReference(L"s").Get(), strings.GetAddressOf())) ||
            FAILED(strings.As(&array)) || FAILED(root->GetNamedObject(HStringReference(L"d").Get(), data.GetAddressOf())))
            throw std::runtime_error("Invalid compact envelope");
        UINT32 size = 0;
        if (FAILED(array->get_Size(&size)) || size < 4 || size > 100000) throw std::runtime_error("Invalid text table");
        Transform codec(false);
        auto& table = codec.Strings();
        const auto seed = table;
        table.clear(); table.reserve(size);
        for (UINT32 i = 0; i < size; ++i) {
            ComPtr<IJsonValue> item;
            JsonValueType type{};
            HString text;
            if (FAILED(array->GetAt(i, item.GetAddressOf())) || FAILED(item->get_ValueType(&type)) ||
                type != JsonValueType_String || FAILED(item->Stringify(text.GetAddressOf())))
                throw std::runtime_error("Invalid text table entry");
            table.push_back(WideToUtf8(::WindowsGetStringRawBuffer(text.Get(), nullptr)));
            if (i < seed.size() && table.back() != seed[i]) throw std::runtime_error("Invalid state dictionary");
        }
        ComPtr<IJsonValue> value;
        HString text;
        if (FAILED(data.As(&value)) || FAILED(value->Stringify(text.GetAddressOf()))) throw std::runtime_error("Invalid data");
        return Utf8ToWide(codec.Run(WideToUtf8(::WindowsGetStringRawBuffer(text.Get(), nullptr))));
    } catch (const std::runtime_error&) {
        return std::unexpected(L"The compact report contains invalid keys, values or text references, or exceeds the display limits.");
    }
}
} // namespace sa
