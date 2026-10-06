#include "PrivacyCollector.h"
#include "../RegistryReader.h"

namespace sa {

static PrivacyFinding Info(std::wstring name, std::wstring value,
                           std::wstring expl, Category c = Category::Privacy) {
    PrivacyFinding f;
    f.name = std::move(name);
    f.value = std::move(value);
    f.explanation = std::move(expl);
    f.category = c;
    f.severity = Severity::Informational;
    return f;
}

std::vector<PrivacyFinding> CollectPrivacyFindings() {
    std::vector<PrivacyFinding> out;

    // Telemetry (AllowTelemetry) — 0=Security,1=Basic,2=Enhanced,3=Full
    if (auto v = RegReadDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", L"AllowTelemetry")) {
        const wchar_t* s = L"Unknown";
        switch (*v) {
        case 0: s = L"Security (minimum)"; break;
        case 1: s = L"Basic"; break;
        case 2: s = L"Enhanced"; break;
        case 3: s = L"Full"; break;
        }
        out.push_back(Info(L"Diagnostic data level", s,
            L"Windows diagnostic data transmitted to Microsoft.", Category::Privacy));
    } else {
        out.push_back(Info(L"Diagnostic data level", L"Default (not policy-configured)",
            L"No explicit telemetry policy override is set.", Category::Privacy));
    }

    // Advertising ID
    if (auto v = RegReadDword(HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo", L"Enabled")) {
        out.push_back(Info(L"Advertising ID",
            *v ? L"Enabled" : L"Disabled",
            L"Controls whether apps can use the advertising identifier.",
            Category::Privacy));
    }

    // Location
    if (auto v = RegReadDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location",
        L"Value")) {
        out.push_back(Info(L"Location services", *v ? L"Allowed" : L"Denied",
            L"Global location access policy.", Category::Privacy));
    }

    // Camera (per-user)
    if (auto v = RegReadDword(HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam",
        L"Value")) {
        out.push_back(Info(L"Camera access", *v ? L"Allowed" : L"Denied",
            L"Per-user camera access policy.", Category::Privacy));
    }

    // Microphone
    if (auto v = RegReadDword(HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone",
        L"Value")) {
        out.push_back(Info(L"Microphone access", *v ? L"Allowed" : L"Denied",
            L"Per-user microphone access policy.", Category::Privacy));
    }

    // Activity history publishing
    if (auto v = RegReadDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", L"PublishUserActivities")) {
        out.push_back(Info(L"Publish user activities",
            *v ? L"Enabled" : L"Disabled",
            L"Controls whether Windows publishes activity history.", Category::Privacy));
    }

    // Windows Update delivery optimization (P2P) — informational only
    if (auto v = RegReadDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config",
        L"DODownloadMode")) {
        out.push_back(Info(L"Delivery Optimization mode", std::to_wstring(*v),
            L"Controls peer-to-peer update sharing.", Category::Privacy));
    }

    return out;
}

} // namespace sa