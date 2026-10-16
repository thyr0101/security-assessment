#pragma once
#include "Models.h"
#include <string_view>

// Edit user-facing warning text here. Dynamic states and names are supplied by
// the collected report; notice text, rule context and recommendations live here.
namespace sa::warnings {
struct WarningPolicy {
    std::string_view id;
    Severity severity;
    std::string_view recommendation;
};
inline constexpr WarningPolicy policies[] = {
        {"mp.threats", Severity::Critical, "Open Windows Security and review/remediate the reported active threats."},
        {"mp.registered", Severity::Critical, "Enable a trusted antivirus and verify its state in Windows Security."},
        {"mp.defender", Severity::Critical, "Verify that a trusted antivirus is actively protecting the device."},
        {"mp.rtp", Severity::High, "Enable real-time antivirus protection."},
        {"mp.tamper", Severity::High, "Enable tamper protection in Windows Security when supported."},
        {"net.fw", Severity::High, "Enable the firewall for every network profile."},
        {"net.in", Severity::High, "Use default inbound blocking and narrowly scoped allow rules."},
        {"net.svc", Severity::High, "Restore the Windows Firewall service and verify firewall operation."},
        {"net.smb1.server", Severity::High, "Disable the legacy SMB1 server after checking file-sharing compatibility."},
        {"net.smb1.client", Severity::High, "Remove or disable the legacy SMB1 client when no longer needed."},
        {"net.smb.sign.server", Severity::High, "Require signing for incoming SMB connections after checking compatibility."},
        {"net.smb.sign.client", Severity::High, "Require signing for outgoing SMB connections after checking compatibility."},
        {"net.smb.guest", Severity::High, "Use authenticated SMB access and block insecure guest logons."},
        {"net.rdp", Severity::High, "Require Network Level Authentication for RDP, or disable RDP when unused."},
        {"net.ntlm", Severity::High, "Use modern network sign-in responses and check compatibility with older devices."},
        {"enc.bl", Severity::High, "Review unprotected fixed volumes and enable BitLocker where appropriate; retain recovery keys."},
        {"os.uac", Severity::High, "Enable User Account Control."},
        {"os.lsa", Severity::High, "Enable protection for the Windows sign-in service and confirm that it is running in protected mode."},
        {"os.lmhash", Severity::High, "Disable old password-hash storage; this takes effect when existing account passwords change."},
        {"acc.guest", Severity::High, "Disable the built-in Guest account if it is not explicitly required."},
        {"acc.lockout", Severity::Medium, "Use a local account lockout threshold of 1-10 attempts with lockout/reset windows of at least 15 minutes."},
        {"acc.securedesktop", Severity::Medium, "Require UAC prompts on the secure desktop."},
        {"acc.assistance", Severity::Low, "Block solicited Remote Assistance invitations when the feature is unused."},
        {"os.autolock", Severity::Medium, "Review device and user locking policies; configure an inactivity limit of 15 minutes or less."},
        {"os.autoplay", Severity::Low, "Disable AutoPlay for all drive types through device policy."},
        {"hw.credentialguard", Severity::Medium, "Enable Credential Guard when supported by the Windows edition and hardware."},
        {"hw.hvci", Severity::Medium, "Enable Memory integrity if drivers and hardware support it."},
        {"os.sac", Severity::Medium, "Review Smart App Control in Windows Security; evaluation mode does not block apps."},
        {"wu.restart", Severity::Medium, "Restart Windows to finish applying updates."},
        {"wu.history", Severity::Medium, "Review Windows Update installation history and resolve the latest recorded failure."}
    };

inline constexpr auto backupTitle = L"[!] BACKUP REPORT";
inline constexpr auto backup = L"You are viewing a backup. These results do not represent the current system state.";
inline constexpr auto nonAdminTitle = L"[!] LIMITED ACCESS";
inline constexpr auto nonAdmin = L"This application is not running with administrator privileges. Restricted checks may be unavailable. Run as administrator for the fullest assessment.";
inline constexpr auto thresholdTitle = "Review threshold exceeded: ";
inline constexpr auto thresholdValues = " registry values; review threshold: ";
inline constexpr auto thresholdFiles = " files; review threshold: ";
inline constexpr auto thresholdPartial = " Partial count; query status: ";
inline constexpr auto thresholdRecommendation = "Review this location for unexpected entries. A high count alone is not evidence of malware; this warning does not affect the score.";
inline constexpr auto verificationGap = L" (verification gap)";
inline constexpr auto action = L"Action: ";
inline constexpr auto exported = L"Warnings are disabled when viewing an export";
inline constexpr auto clear = L"No warnings from the evaluated checks.";
inline constexpr auto disclaimer = L"This is a hardening posture score. It does not guarantee security.";
inline constexpr auto periodicUnknown = L"Defender did not report a recognized running mode.";
inline constexpr auto defenderExcluded = L"Not scored (third-party antivirus registered)";
inline constexpr auto contextSecureBootIsEnabledAndUEFIIs = "Secure Boot is enabled and UEFI is the firmware.";
inline constexpr auto contextSecureBootIsNotEnabledOrCould = "Secure Boot is not enabled or could not be verified.";
inline constexpr auto contextTPM20IsPresentAndReady = "TPM 2.0 is present and ready.";
inline constexpr auto contextTPMIsReadyButVersion20 = "TPM is ready, but version 2.0 could not be confirmed.";
inline constexpr auto contextTPMPresenceIsConfirmedReadinessIsNot = "TPM presence is confirmed; readiness is not confirmed.";
inline constexpr auto contextNoUsableTPMDetected = "No usable TPM detected.";
inline constexpr auto contextWindowsUsesVirtualizationToIsolateSecurityFunctions = "Windows uses virtualization to isolate security functions.";
inline constexpr auto contextVBSNotDetectedAsRunning = "VBS not detected as running.";
inline constexpr auto contextMemoryIntegrityProtectsWindowsKernelCodeUsing = "Memory integrity protects Windows kernel code using virtualization.";
inline constexpr auto contextHVCIIsNotEnabled = "HVCI is not enabled.";
inline constexpr auto contextTheInstalledOperatingSystemIsWindows11 = "The installed operating system is Windows 11 or newer.";
inline constexpr auto contextTheInstalledWindowsVersionIsOlderThan = "The installed Windows version is older than Windows 11.";
inline constexpr auto contextUserAccountControlIsEnabled = "User Account Control is enabled.";
inline constexpr auto contextUACIsDisabled = "UAC is disabled.";
inline constexpr auto contextDataExecutionPreventionIsActive = "Data Execution Prevention is active.";
inline constexpr auto contextDEPIsNotEnforced = "DEP is not enforced.";
inline constexpr auto contextWindowsProtectsExceptionHandlingDataAgainstMemory = "Windows protects exception handling data against memory overwrite attacks.";
inline constexpr auto contextSEHOPIsNotEnabled = "SEHOP is not enabled.";
inline constexpr auto contextSmartAppControlIsEnforcing = "Smart App Control is enforcing.";
inline constexpr auto contextSmartAppControlIsEvaluatingApplicationsWithout = "Smart App Control is evaluating applications without blocking them.";
inline constexpr auto contextSmartAppControlNotEnforcing = "Smart App Control not enforcing.";
inline constexpr auto contextTheUpdateServiceSStateAndConfiguration = "The update service's state and configuration could not be verified.";
inline constexpr auto contextTheUpdateServiceIsDisabled = "The update service is disabled.";
inline constexpr auto contextTheUpdateServiceIsPausedOrStopping = "The update service is paused or stopping.";
inline constexpr auto contextTheServiceIsEnabledWindowsUpdateServices = "The service is enabled. Windows update services can stop when idle and start on demand.";
inline constexpr auto contextTheUpdateServiceConfigurationCouldNotBe = "The update service configuration could not be interpreted.";
inline constexpr auto contextWindowsUpdateDoesNotRequireARestart = "Windows Update does not require a restart.";
inline constexpr auto contextRestartWindowsToFinishApplyingUpdates = "Restart Windows to finish applying updates.";
inline constexpr auto contextUpdateRestartStatusCouldNotBeRead = "Update restart status could not be read.";
inline constexpr auto contextTheLatestRecordedUpdateInstallationSucceeded = "The latest recorded update installation succeeded.";
inline constexpr auto contextTheLatestInstallationFailedWasIncompleteOr = "The latest installation failed, was incomplete, or its result could not be verified.";
inline constexpr auto contextDefenderIsNotScoredWhileAThird = "Defender is not scored while a third-party antivirus is registered.";
inline constexpr auto contextWindowsSecurityCenterReportsThisAntivirusEnabled = "Windows Security Center reports this antivirus enabled.";
inline constexpr auto contextWindowsSecurityCenterDoesNotReportThis = "Windows Security Center does not report this antivirus actively protecting the computer.";
inline constexpr auto contextWindowsSecurityCenterCouldNotReportThis = "Windows Security Center could not report this antivirus state.";
inline constexpr auto contextAtLeastOneRegisteredAntivirusIsEnabled = "At least one registered antivirus is enabled. Independent product scores are shown separately.";
inline constexpr auto contextNoRegisteredAntivirusCouldBeConfirmedEnabled = "No registered antivirus could be confirmed enabled.";
inline constexpr auto contextMicrosoftDefenderIsActive = "Microsoft Defender is active.";
inline constexpr auto contextDefenderCouldNotBeConfirmedActive = "Defender could not be confirmed active.";
inline constexpr auto contextRealTimeProtectionIsEnabled = "Real-time protection is enabled.";
inline constexpr auto contextRealTimeProtectionIsOff = "Real-time protection is off.";
inline constexpr auto contextBehaviorMonitoringEnabled = "Behavior monitoring enabled.";
inline constexpr auto contextBehaviorMonitoringNotEnabled = "Behavior monitoring not enabled.";
inline constexpr auto contextDownloadedFileScanningEnabled = "Downloaded-file scanning enabled.";
inline constexpr auto contextIOAVScanningNotEnabled = "IOAV scanning not enabled.";
inline constexpr auto contextCloudDeliveredProtectionEnabled = "Cloud-delivered protection enabled.";
inline constexpr auto contextCloudDeliveredProtectionNotEnabled = "Cloud-delivered protection not enabled.";
inline constexpr auto contextDefenderProtectsItsSecuritySettingsAgainstUnauthorized = "Defender protects its security settings against unauthorized changes.";
inline constexpr auto contextDefenderSettingsProtectionIsDisabledOrUnavailable = "Defender settings protection is disabled or unavailable.";
inline constexpr auto contextNoActiveThreatsReportedByDefender = "No active threats reported by Defender.";
inline constexpr auto contextActiveThreatsReportedByDefender = "Active threats reported by Defender.";
inline constexpr auto contextThreatStatusCouldNotBeRead = "Threat status could not be read.";
inline constexpr auto contextFirewallEnabledOnDomainPrivateAndPublic = "Firewall enabled on Domain, Private, and Public profiles.";
inline constexpr auto contextFirewallEnabledOnSomeButNotAll = "Firewall enabled on some but not all profiles.";
inline constexpr auto contextFirewallNotEnabledOnAnyProfile = "Firewall not enabled on any profile.";
inline constexpr auto contextIncomingTrafficIsBlockedByDefaultUnless = "Incoming traffic is blocked by default unless a firewall rule allows it.";
inline constexpr auto contextNotAllProfilesDefaultBlockInbound = "Not all profiles default-block inbound.";
inline constexpr auto contextTheWindowsFirewallServiceIsRunning = "The Windows Firewall service is running.";
inline constexpr auto contextFirewallServiceNotRunning = "Firewall service not running.";
inline constexpr auto contextTheRequiredConfigurationCouldNotBeVerified = "The required configuration could not be verified; no default is assumed.";
inline constexpr auto contextSMB1ServerConfigurationDisablingThisLegacyProtocol = "SMB1 server configuration; disabling this legacy protocol reduces file-sharing attack surface.";
inline constexpr auto contextSMB1ClientDriverAvailabilityAnAbsentOr = "SMB1 client driver availability; an absent or disabled redirector cannot be used for legacy SMB1 connections.";
inline constexpr auto contextRequiringSMBServerSigningProtectsTheIntegrity = "Requiring SMB server signing protects the integrity of incoming file-sharing traffic.";
inline constexpr auto contextRequiringSMBClientSigningProtectsTheIntegrity = "Requiring SMB client signing protects the integrity of outgoing file-sharing traffic.";
inline constexpr auto contextInsecureGuestLogonsBypassNormalSMBAuthentication = "Insecure guest logons bypass normal SMB authentication.";
inline constexpr auto contextDisablingMulticastNameResolutionFallbackReducesLocal = "Disabling multicast name-resolution fallback reduces local name-spoofing opportunities.";
inline constexpr auto contextNotEveryApplicableAdapterSNetBIOSConfiguration = "Not every applicable adapter's NetBIOS configuration could be read.";
inline constexpr auto contextAtLeastOneActiveIPv4AdapterExplicitly = "At least one active IPv4 adapter explicitly enables NetBIOS.";
inline constexpr auto contextDHCPControlledSettingsDoNotProveNetBIOS = "DHCP-controlled settings do not prove NetBIOS is disabled.";
inline constexpr auto contextNetBIOSIsExplicitlyDisabledOnEveryActive = "NetBIOS is explicitly disabled on every active IPv4 adapter.";
inline constexpr auto contextNoActiveNonLoopbackIPv4AdaptersRequire = "No active non-loopback IPv4 adapters require this check.";
inline constexpr auto contextRemoteDesktopConnectionsAreDisabledByConfiguration = "Remote Desktop connections are disabled by configuration.";
inline constexpr auto contextRemoteDesktopIsConfiguredToRequireNetwork = "Remote Desktop is configured to require Network Level Authentication; firewall scope is a separate control.";
inline constexpr auto contextEnabledRemoteDesktopMustRequireNetworkLevel = "Enabled Remote Desktop must require Network Level Authentication to receive these points.";
inline constexpr auto contextNoFixedVolumesCouldBeVerified = "No fixed volumes could be verified.";
inline constexpr auto contextAllDetectedFixedDrivesHaveBitLockerProtection = "All detected fixed drives have BitLocker protection active.";
inline constexpr auto contextBitLockerProtectionConfirmedOnSomeVolumesFull = "BitLocker protection confirmed on some volumes; full coverage could not be verified.";
inline constexpr auto contextBitLockerStatusCouldNotBeReadNeeds = "BitLocker status could not be read (needs elevation).";
inline constexpr auto contextBitLockerNotEnabledOnAnyFixedVolume = "BitLocker not enabled on any fixed volume.";
inline constexpr auto contextATPMSecurityChipIsAvailableTo = "A TPM security chip is available to store and protect encryption keys.";
inline constexpr auto contextNoTPMAvailableForKeyProtection = "No TPM available for key protection.";
inline constexpr auto contextAdministratorActionsRequireAUACConsentOr = "Administrator actions require a UAC consent or credentials prompt.";
inline constexpr auto contextUACPromptNotRequiredForAdminActions = "UAC prompt not required for admin actions.";
inline constexpr auto contextCredentialGuardIsolatesSignInSecretsUsing = "Credential Guard isolates sign-in secrets using virtualization.";
inline constexpr auto contextReportsTheRunningLSASSProcessProtectionLevel = "Reports the running LSASS process protection level, not merely a registry configuration.";
inline constexpr auto contextNoLMHashPreventsLMHashesBeingStoredAt = "NoLMHash prevents LM hashes being stored at the next password change; it does not prove older hashes were removed.";
inline constexpr auto contextTheDeviceAutoPlayPolicyMustCoverAll = "The device AutoPlay policy must cover all drive types.";
inline constexpr auto contextAnExplicitDeviceInactivityPolicyLocksSessions = "An explicit device inactivity policy locks sessions within 15 minutes.";
inline constexpr auto contextChecksTheDeviceInactivityPolicyUserScreen = "Checks the device inactivity policy; user screen-saver policies can impose additional locking.";
inline constexpr auto contextUACPromptsShouldRunOnTheIsolated = "UAC prompts should run on the isolated secure desktop.";
inline constexpr auto contextIdentifiesTheBuiltInGuestAccountBy = "Identifies the built-in Guest account by RID 501, even if it was renamed.";
inline constexpr auto contextChecksPolicyLocalPermissionForSolicitedRemote = "Checks policy/local permission for solicited Remote Assistance invitations, not third-party remote support tools.";
inline constexpr auto contextLocalSAMLockoutPolicyCouldNotBe = "Local SAM lockout policy could not be read.";
inline constexpr auto contextLocalAccountsLockAfter110Failed = "Local accounts lock after 1-10 failed attempts, with a lockout and reset window of at least 15 minutes.";
inline constexpr auto contextTheLocalLockoutDurationOrResetWindow = "The local lockout duration or reset window is shorter than 15 minutes.";
inline constexpr auto contextTheLocalAccountLockoutThresholdIsAbsent = "The local account lockout threshold is absent or exceeds 10 failed attempts.";
inline constexpr auto contextTheRequiredSystemDataCouldNotBe = "The required system data could not be read reliably.";
inline constexpr auto contextReviewThisSettingInWindowsSecurityOr = "Review this setting in Windows Security or the applicable device policy.";
inline constexpr auto contextSomeSecurityChecksCouldNotBeVerified = "Some security checks could not be verified";
inline constexpr auto contextReviewMissingPoliciesProviderSupportAndAccess = "Review missing policies, provider support, and access permissions. Unverified checks are not confirmed vulnerabilities.";
inline constexpr auto contextRunAsAdministratorToVerifyRestrictedChecks = "Run as administrator to verify restricted checks. Missing policies or unsupported features can remain unknown; they are not confirmed vulnerabilities.";

inline constexpr auto signInNotConfigured = L"The network sign-in policy is not explicitly configured (LmCompatibilityLevel is absent). Windows defaults were not verified; this does not mean older sign-in methods are active.";

inline constexpr auto signInDenied = L"Windows denied access while reading the network sign-in policy. Run as administrator and try again.";

inline constexpr auto signInWrongType = L"The network sign-in policy has an invalid registry type; a DWORD value from 0 to 5 is required.";

inline constexpr auto signInUnavailable = L"The network sign-in policy could not be queried on this system.";

inline constexpr auto signInInvalidValue = L"The network sign-in policy contains an invalid value (expected 0 to 5).";

inline constexpr auto signInReadError = L"Windows returned an error while reading the network sign-in policy; its configuration could not be verified.";

inline constexpr auto signInRecordedInvalid = L"The recorded network sign-in policy is outside the supported range (0 to 5).";

inline constexpr auto signInModernPrefix = L"The configured policy sends modern NTLMv2 responses only (level ";

inline constexpr auto signInModernSuffix = L"). This does not prove that all incoming older sign-in methods are blocked.";

inline constexpr auto signInLegacyPrefix = L"The configured policy permits older network sign-in responses (level ";

inline constexpr auto signInLegacySuffix = L").";

inline constexpr auto signInUnverified = L"The network sign-in policy could not be verified.";

inline constexpr auto defenderQueryPrefix = L"Defender status could not be read: ";
inline constexpr auto antivirusPartial = L"Some registered antivirus details could not be read.";

inline std::wstring ProviderFailure(std::wstring_view operation, std::wstring_view code) {
    return std::wstring(operation) + L" failed (" + std::wstring(code) + L").";
}

inline constexpr auto defenderSchemaUnavailable = L"No supported status properties were available.";

inline constexpr auto bitLockerElevation = L"Administrator access is required to verify BitLocker protection.";

inline constexpr auto updateSearchTimeout = L"Local update search timed out after 45 seconds; pending updates are unknown.";

inline constexpr auto comUnavailable = L"COM initialization failed.";

void BuildWarnings(const AssessmentResult& assessment, ScoreReport& report);
} // namespace sa::warnings
