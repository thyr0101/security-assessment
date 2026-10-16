#include "Warnings.h"
#include <algorithm>
#include <ranges>

namespace sa::warnings {
void BuildWarnings(const AssessmentResult& assessment, ScoreReport& report) {
    std::vector<std::string> unverified;
    for (const auto& rule : report.rules) {
        if (!rule.maxPoints || rule.awardedPoints >= rule.maxPoints) continue;
        const auto state = ToLower(Utf8ToWide(rule.state));
        bool verification = state.find(L"unknown") != std::wstring::npos || state == L"unavailable" ||
            state == L"version unverified" || state == L"dhcp controlled" || state == L"no fixed drives" ||
            (state == L"not configured" && rule.id != "acc.lockout" && rule.id != "os.autolock");
        if (rule.id == "net.ntlm" && (assessment.hardening.lmCompatibilityStatus != Status::Success ||
            assessment.hardening.lmCompatibility > 5)) verification = true;
        if (rule.id == "net.fw" && !std::ranges::any_of(assessment.firewall.profiles,
            [](const auto& profile) { return profile.status == Status::Success && !profile.enabled; })) verification = true;
        if (rule.id == "enc.bl" && !std::ranges::any_of(assessment.storage.volumes,
            [](const auto& volume) { return volume.driveType == L"Fixed" && volume.bitLockerStatus == Status::Success && volume.bitLockerState == L"Off"; })) verification = true;
        if (verification) { unverified.push_back(rule.description + " [" + rule.state + "]"); continue; }
        const auto policy = std::ranges::find(policies, rule.id, &WarningPolicy::id);
        SecurityWarning warning;
        warning.ruleId = rule.id;
        warning.title = rule.description;
        warning.detail = rule.state + ": " + rule.reason;
        warning.severity = policy == std::end(policies) ? Severity::Medium : policy->severity;
        warning.recommendation = policy == std::end(policies)
            ? contextReviewThisSettingInWindowsSecurityOr
            : std::string(policy->recommendation);
        report.warnings.push_back(std::move(warning));
    }
    if (!unverified.empty()) {
        SecurityWarning coverage;
        coverage.ruleId = "assessment.coverage";
        coverage.severity = Severity::Low;
        coverage.title = contextSomeSecurityChecksCouldNotBeVerified;
        coverage.verificationOnly = true;
        for (const auto& check : unverified) {
            if (!coverage.detail.empty()) coverage.detail += "; ";
            coverage.detail += check;
        }
        coverage.recommendation = assessment.security.isElevated
            ? contextReviewMissingPoliciesProviderSupportAndAccess
            : contextRunAsAdministratorToVerifyRestrictedChecks;
        report.warnings.push_back(std::move(coverage));
    }
    std::ranges::stable_sort(report.warnings, std::greater{}, &SecurityWarning::severity);
}
} // namespace sa::warnings

namespace sa {
std::wstring NetworkSignInReason(const HardeningInfo& info) {
    switch (info.lmCompatibilityStatus) {
    case Status::NotFound: return warnings::signInNotConfigured;
    case Status::AccessDenied: return warnings::signInDenied;
    case Status::Unsupported: return warnings::signInWrongType;
    case Status::Unavailable: return warnings::signInUnavailable;
    case Status::Error:
        return info.lmCompatibility > 5 ? warnings::signInInvalidValue
            : warnings::signInReadError;
    case Status::Success:
        if (info.lmCompatibility > 5) return warnings::signInRecordedInvalid;
        return info.lmCompatibility >= 3
            ? warnings::signInModernPrefix + std::to_wstring(info.lmCompatibility) + warnings::signInModernSuffix
            : warnings::signInLegacyPrefix + std::to_wstring(info.lmCompatibility) + warnings::signInLegacySuffix;
    }
    return warnings::signInUnverified;
}
} // namespace sa
