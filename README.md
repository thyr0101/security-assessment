# Windows Security \& Privacy Assessment

A read only app built on C++ extracting all the security information from your computer. It uses natve windows APIs to extract information all without the use of `cmd.exe`, PowerShell, `wmic.exe`, `sc.exe`, `reg.exe`and any third party software. 



## What it does



- Enumerates OS, CPU, memory, storage, network, TPM, Secure Boot, VBS, HVCI,Defender, Firewall, BitLocker, UAC, DEP/SEHOP, services, applications, persistence locations, privacy-related registry settings.

- Runs configurable registry and directory threshold scans.

- Emits a deterministic, rule-based security-posture score.

- Shows installation state of installed apps.

## Current state

### Implemented

- [x] System Information
- [x] Hardware security enumeration
- [x] Windows Defender enumeration
- [x] Bitlocker status
- [x] Basic app scanning
- [x] Basic privacy scanner
### To-do

- [ ] Enhanced app scanning (Multiple apps in one category, more app support)
- [ ] Threshold scanning (Logic implemented already)
- [ ] Enhanced privacy scanner
## What it does NOT do



- It is **not** an antivirus or malware detector.

- It does not modify any system state.

- Use the internet

# Requirements

- Windows 10 or newer

# Usage 

- Open a command prompt window, elevated or not[^1]

- Run the binary

[^1]: Without elevation, some restricted security checks remain unverified.

## Build

### Requirements


- An MSVC toolset supporting C++23. The Visual Studio project selects v143 for Debug and v145 for Release; an installed toolset can be selected with `/p:PlatformToolset=...`. CMake selects one toolset for all configurations.

- Windows SDK 10.0.26100.

### MSBuild / Visual Studio

Open `SecurityAssessment.sln`, select `x64 | Release`, and build.



### CMake

```
cmake -S . -B build -A x64

cmake --build build --config Release
```

## Command-line options

`SecurityAssessment [--json] [--no-hash]`

- `--json`: writes a UTF-8 JSON report instead of the console report.
- `--no-hash`: skips executable hashing and leaves application SHA-256 fields empty.
- `--help` / `-h`: prints usage.

Unrecognized options return exit code 2 with a usage message.

Collection uses native Windows APIs, COM/WMI, and the C++ standard library. No external commands, network services, or third-party runtime libraries are required. WMI and registry access can be restricted without elevation; unavailable checks are reported as unknown. HVCI configuration is distinguished from confirmed running state, and Smart App Control evaluation does not count as enforcement.

Defender JSON fields have individual status companions (for example, `cloudProtectionStatus`) because optional property reads can fail even when the main status query succeeds. `servicesStatus` and `persistenceStatus` describe inventory completeness. Full BitLocker coverage credit requires complete volume enumeration and successful protection-status reads.

## Scoring

Smart App Control earns 25/50 points in evaluation mode and 50/50 when enabled. Disabled or unavailable states earn zero. Defender's no-active-threats check contributes 20 points. The OS category totals 200 points and malware protection totals 180. Windows Update has its own 60-point category, keeping the overall maximum at 1000. Score states describe each result, such as Supported, Available, Clear, Running, or Complete.

### Windows Update

The report uses the native Windows Update Agent COM API to read locally cached pending updates, titles, KB references, download state, restart requirements, the last successful search time, and the latest installation result. Pending updates appear in a tree under `Pending Updates`, with API-reported classifications (such as Security Updates or Critical Updates), product names (including .NET products when reported), optional status, and security severity. Empty results show `Pending Updates (None)` without a tree. Pending and optional updates are informational and never affect the score. Unreadable counts display Unknown (JSON `null`).

Seven related services appear in an `Update Services` tree, each prefixed with its canonical service key name resolved through the Service Control Manager, followed by its display name and state. If the name mapping cannot be read, the requested service name is retained as a fallback. The update search stays offline and has a 45-second completion timeout; no updates are downloaded or installed. Cached results reflect Windows' last scan, so they can differ from a fresh online check.

The console uses blue for service identifiers, white for display names, and cyan for service states; startup types are omitted. Update source, search time, restart status, and latest-installation details are hidden from the console and remain available in JSON. Colors distinguish identifiers, values, and secondary details throughout the report. Redirected output and `NO_COLOR` remain plain text.

| Check | Maximum | Scoring |
| --- | ---: | --- |
| Windows update details available | 0 | Informational metadata; readability does not establish security. |
| Pending Windows updates | 0 | Informational only; counts and types never change the score. |
| Update service readiness | 30 | 10 each for Windows Update, BITS, and Update Orchestrator when enabled and available; idle services that start on demand qualify. |
| Update restart completed | 15 | No update restart is required. |
| Latest update installation | 15 | The latest recorded installation succeeded. |

The existing update-details rule retains its `os.patch` ID in Windows Update. Service readiness, restart completion, and installation history now carry the Windows Update score. Pending updates remain informational. Following the network-hardening expansion, TPM key-protection availability is worth 40 points; assessment administrator access is informational. The overall maximum remains 1000. JSON includes classification, product, type, and severity fields for each update. Failed or incomplete reads do not earn credit for scored checks.

## Registered antivirus fallback

The app reads antivirus registrations through the native Windows Security Center COM API. When a third-party antivirus is registered, the console lists every registered product and its reported state instead of the inactive Defender feature list. Each product receives an independent score of 180/180 when Windows reports it enabled, or 0/180 otherwise. Disabled, snoozed, expired, and unreadable states receive no credit. Signature currency is informational.

The malware category contributes at most 180 points to the overall 1000-point score: any confirmed enabled product satisfies this category. Multiple enabled products do not multiply the overall score. Normal Defender-only operation retains the existing detailed scoring; registration scoring also provides a fallback when Defender's own status is unavailable or inactive.

When a third-party antivirus is registered, Defender periodic scanning is shown separately and never affects scoring. Its state comes from Defender's `AMRunningMode` (`SxS Passive Mode` means enabled); unavailable or unrecognized modes display Unknown. JSON includes registration details under `antivirus`, separate product scores under `score.antivirusScores`, and `defender.periodicScanning`.

## Regression checks (optional)

```
cmake -S . -B build-tests -A x64 -DSA_BUILD_TESTS=ON
cmake --build build-tests --config Release
ctest --test-dir build-tests -C Release --output-on-failure
python tests/smoke.py build-tests/Release
```

The native tests use temporary files and a private volatile registry key, which they remove afterward, plus an in-memory WMI object. They require local WMI access. The optional smoke harness uses only Python's standard library to parse reports and check the CLI; Python is not an application dependency.

See [REVIEW.md](REVIEW.md) for the fixes, compatibility notes, and validation scope.

## Compact console layout and storage mapping

The console uses short headings, paired facts when the terminal is wide enough, and nested storage trees. Values are never truncated; narrow consoles fall back to separate fact rows. Each mounted volume appears beneath its physical disk, using [IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_volume_get_volume_disk_extents). Spanned volumes appear beneath every referenced disk with an explicit span annotation. Unmapped volumes remain visible with a mapping status, and missing disk descriptors do not hide mapped volumes. JSON retains its disk and volume arrays and adds volume GUIDs, disk numbers, and mapping statuses.

No pictographic icons are added: console font coverage and Unicode hardware symbols are inconsistent. Tree characters, restrained colors, and aligned labels provide the visual structure. Redirected output and `NO_COLOR` use plain ASCII structure.

## Privacy configuration

Privacy collection uses native registry reads; replacing these with undocumented NT entry points would not provide a more authoritative view of configuration. The report includes diagnostic policy, advertising ID, personalization, online speech consent, typing/inking policy, app permission defaults, clipboard history and sync preferences/policies, Remote Assistance, activity publishing, and named Delivery Optimization modes. Known policy restrictions take precedence over preferences where applicable. Missing settings are shown as **Not configured**, rather than assumed enabled or disabled; read failures remain **Unknown**.

Every entry identifies its scope. App permissions describe defaults, not active access: individual app overrides, desktop-app exceptions, Windows edition/version support, and other restrictions can affect actual behavior. Clipboard policy permission does not prove that sync is active, and stored speech consent does not override device restrictions. Expanded JSON privacy entries include status, scope, and group alongside their existing fields. Privacy remains informational and does not change the 1000-point score.

Policy mappings follow Microsoft's [Privacy policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy) and [System policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-system), together with Windows' installed ADMX definitions.

## Security checks and report layout

Selected checks were inspired by [Apotrope](https://github.com/hexorcist404/apotrope) and implemented independently with native Windows interfaces. The app does not run Apotrope, PowerShell, external tools, or network probes.

The compact console groups firewall controls, SMB protection, remote access, credential/device protection, and local account policies. Related values share rows when they fit; long values are preserved. Adapter inventory, local TCP listeners, UDP port 69 inventory, configured RDP port, and explanatory RDP scope metadata are omitted from the console. Existing JSON inventories remain available.

New security checks include:

- Credential Guard's running state and the actual protection level of the LSASS process.
- Blocking legacy LM password-hash storage and requiring NTLMv2-only outgoing responses by explicit policy. LM hash policy applies at the next password change and does not establish whether old hashes already exist.
- Device AutoPlay policy covering all drive types and an explicit device inactivity lock within 15 minutes. User screen-saver policies can impose additional locking.
- UAC prompts on the secure desktop, the built-in Guest account identified by RID 501, and blocking solicited Remote Assistance invitations when unused.
- Local SAM minimum password length (12+ characters for full credit; 8-11 for half) and account lockout (1-10 attempts, lockout/reset windows at least 15 minutes; shorter windows receive half). Domain and Microsoft accounts may use different policies. These are this app's selected hardening thresholds, not a compliance certification.

SMB configuration comes from the Windows SMB provider's read-only `GetConfiguration` methods through COM/WMI. LLMNR and Remote Desktop policies take precedence where applicable; missing configuration is not silently treated as secure or insecure. DHCP-controlled NetBIOS does not establish that NetBIOS is disabled. Listeners and encryption settings do not prove internet reachability; an individual SMB share can require encryption independently of global settings.

### Score allocation

| Category | Maximum |
| --- | ---: |
| Hardware Security | 150 |
| Operating System | 200 |
| Windows Update | 60 |
| Malware Protection | 180 |
| Network Security | 200 |
| Encryption | 90 |
| Account Security | 120 |
| Software inventory and privacy | 0 (informational) |
| **Total** | **1000** |

BitLocker is now **50 points (5%)**, with 25 points for verified partial coverage. TPM availability is 40 points. Smart App Control remains 50 when enforcing and 25 in evaluation. Defender real-time protection is 45 points; all granular malware checks total 180. Registered antivirus scores independently earn 180 or zero based on the state Windows reports, with the overall category capped at 180. Existing stable rule IDs remain, including zero-weight informational rules. Update metadata readability and assessment elevation no longer earn security points. Unknown data never become full credit; native TPM presence can earn partial hardware credit while readiness remains explicitly unverified.

### Warnings

The report ends with **rule breakdown, total score, then warnings**, ordered Critical, High, Medium, Low. Warnings give the finding, context, and an action to review; they do not apply additional point deductions. Confirmed weaknesses are distinguished from missing settings, access failures, and unsupported checks. Unverified checks are grouped in one Low-severity verification-gap notice and are not described as confirmed vulnerabilities. JSON includes `score.warnings` with severity, rule ID, title, detail, recommendation, and `verificationOnly`, plus native readings under `hardening`.

### Collection performance

Independent collectors use four COM-initialized workers, joined before scoring and rendering. Non-admin TPM presence/version use [TPM Base Services](https://learn.microsoft.com/en-us/windows/win32/api/tbs/nf-tbs-tbsi_getdeviceinfo), keeping readiness unverified. Non-admin BitLocker checks return AccessDenied directly because their WMI namespace requires elevation. Console runs skip endpoint enumeration that is no longer displayed; JSON retains the inventory. No timeout is interpreted as a successful or secure state.

For optional local profiling, set `SA_TRACE_TIMINGS=1` before running the app. Collector durations go to stderr; ordinary report output is unchanged. On the development machine, a non-admin baseline took 10.994 seconds, including roughly five seconds each for restricted TPM and BitLocker WMI connections. Five optimized Release `--json --no-hash` runs took 0.779, 0.784, 0.802, 0.817, and 0.808 seconds (median 0.802). These are local warm-run observations, not a speed guarantee for every machine or provider.

The C++23 cleanup uses `std::expected` for typed registry read failures, `std::out_ptr` with owned native API buffers, and ranges algorithms. Joined worker lifetimes and bounded `std::span` topology traversal avoid detached work and unbounded native-record iteration. WMI extractors reject null objects and preserve unavailable states.

Native references: [SMB configuration](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/smb/getconfiguration-msft-smbserverconfiguration), [LSA process protection](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_protection_level_information), [local account policy](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusermodalsget), [LAN Manager authentication levels](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level), and [Remote Desktop policies](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-remotedesktopservices).
