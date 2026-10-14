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

- Open a command prompt window, elevated or notÃƒâ€šÃ‚Â¹

- Run the binary

Ãƒâ€šÃ‚Â¹ If not elevated, the app is unable to load all information.

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

Smart App Control earns 25/50 points in evaluation mode and 50/50 when enabled. Disabled or unavailable states earn zero. Defender's no-active-threats check contributes 20 points. The OS category totals 145 points and malware protection totals 195. Windows Update has its own 60-point category, keeping the overall maximum at 1000. Score states describe each result, such as Supported, Available, Clear, Running, or Complete.

### Windows Update

The report uses the native Windows Update Agent COM API to read locally cached pending updates, titles, KB references, download state, restart requirements, the last successful search time, and the latest installation result. Pending updates appear in a tree under `Pending Updates`, with API-reported classifications (such as Security Updates or Critical Updates), product names (including .NET products when reported), optional status, and security severity. Empty results show `Pending Updates (None)` without a tree. Pending and optional updates are informational and never affect the score. Unreadable counts display Unknown (JSON `null`).

Seven related services appear in an `Update Services` tree, each prefixed with its canonical service key name resolved through the Service Control Manager, followed by its display name and state. If the name mapping cannot be read, the requested service name is retained as a fallback. The update search stays offline and has a 45-second completion timeout; no updates are downloaded or installed. Cached results reflect Windows' last scan, so they can differ from a fresh online check.

The console uses blue for service identifiers, white for display names, and cyan for service states; startup types are omitted. Update source, search time, restart status, and latest-installation details are hidden from the console and remain available in JSON. Colors distinguish identifiers, values, and secondary details throughout the report. Redirected output and `NO_COLOR` remain plain text.

| Check | Maximum | Scoring |
| --- | ---: | --- |
| Windows update details available | 30 | Installed update revision can be read; this does not prove Windows is up to date. |
| Pending Windows updates | 0 | Informational only; counts and types never change the score. |
| Update service readiness | 15 | 5 each for Windows Update, BITS, and Update Orchestrator when enabled and available; idle services that start on demand qualify. |
| Update restart completed | 10 | No update restart is required. |
| Latest update installation | 5 | The latest recorded installation succeeded. |

The existing update-details rule retains its `os.patch` ID in Windows Update. Service, restart, and history weights remain unchanged. Pending updates remain informational. Following the network-hardening expansion, TPM key-protection availability is worth 60 points; assessment administrator access remains 5 points. The overall maximum remains 1000. JSON includes classification, product, type, and severity fields for each update. Failed or incomplete reads do not earn credit for scored checks.

## Registered antivirus fallback

The app reads antivirus registrations through the native Windows Security Center COM API. When a third-party antivirus is registered, the console lists every registered product and its reported state instead of the inactive Defender feature list. Each product receives an independent score of 195/195 when Windows reports it enabled, or 0/195 otherwise. Disabled, snoozed, expired, and unreadable states receive no credit. Signature currency is informational.

The malware category contributes at most 195 points to the overall 1000-point score: any confirmed enabled product satisfies this category. Multiple enabled products do not multiply the overall score. Normal Defender-only operation retains the existing detailed scoring; registration scoring also provides a fallback when Defender's own status is unavailable or inactive.

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

## Network Security

The network section was expanded after reviewing [Apotrope's network, SMB, and Remote Desktop checks](https://github.com/hexorcist404/apotrope). Only relevant checks were selected, with independent native implementations: the app does not run Apotrope, PowerShell, external tools, or network probes.

- Firewall service, Domain/Private/Public enablement, active profile markers, and default inbound/outbound actions.
- SMB1 server configuration and legacy client-driver availability, incoming/outgoing signing requirements, insecure guest logons, global server encryption, and rejection of unencrypted access. SMB settings come from the Windows SMB provider's read-only `GetConfiguration` methods through COM/WMI, rather than guesses based on registry defaults. An absent SMB1 redirector service is treated as unavailable for use; an unreadable driver setting is unknown.
- LLMNR policy and NetBIOS configuration on active, non-loopback IPv4 adapters. Missing LLMNR policy is **Not configured**, not proof that multicast resolution is disabled. DHCP-controlled NetBIOS configuration does not prove the effective state is disabled.
- Remote Desktop enablement, Network Level Authentication requirement, and configured RDP port. Registry policy takes precedence over local configuration. The score accepts disabled RDP or enabled RDP with verified NLA; configuration is not proof of reachability.
- Only adapters reported Up are shown in the console, excluding all loopback interfaces. Their addresses, gateways, DNS servers, MAC addresses, DHCP information, and NetBIOS settings are grouped under Active Network Adapters. Disconnected and loopback adapters remain available in the JSON inventory. IPv6 presence, DNS provider, and VPN-name heuristics do not affect scoring.
- Local TCP listeners across IPv4 and IPv6 remain available in JSON and are omitted from the console. UDP enumeration is restricted in the report to port 69 for TFTP review. FTP/Telnet/TFTP ports bound beyond loopback receive review notes; the port alone does not identify the protocol. Process lookup is cached by PID, requires only limited query access, and retains unknown names when access is denied or a process exits.

Listeners and SMB encryption settings are informational. The app does not probe connectivity or claim that a listener is internet-accessible. Individual shares can require encryption independently of global settings. Failed endpoint reads are marked incomplete instead of reported as no listeners. JSON adds network security configuration, per-setting status/source/reason, adapter NetBIOS status, endpoint owner/binding information, and separate IPv4/IPv6 query statuses; existing fields remain available.

### Revised score allocation

| Category | Maximum |
| --- | ---: |
| Hardware Security | 180 |
| Operating System | 145 |
| Windows Update | 60 |
| Malware Protection | 195 |
| Network Security | 180 |
| Encryption | 160 |
| Account Security | 80 |
| Software inventory and privacy | 0 (informational) |
| **Total** | **1000** |

Network retains 60 points for firewall profile coverage, 20 for default inbound blocking, and 20 for the firewall service. Eight additional checks are worth 10 each: SMB1 server disabled, SMB1 client disabled/absent, incoming SMB signing required, outgoing SMB signing required, insecure SMB guests blocked, LLMNR explicitly disabled, NetBIOS disabled on all active IPv4 adapters, and RDP disabled or NLA required. NetBIOS is satisfied as not applicable when adapter enumeration succeeds and no active non-loopback IPv4 adapter exists. Unknown readings earn no credit.

The 80 new points replace 40 inventory-completion points, 35 CPU-capability points (virtualization, AES acceleration, NX), and 5 TPM-availability points. These capabilities and inventory results remain visible as information; they do not by themselves establish an enforced security configuration. Stable rule IDs remain in JSON with zero maximum for informational checks. Scores from earlier versions are therefore not directly comparable without considering the changed weights.

Native sources: Microsoft's [SMB configuration provider](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/smb/getconfiguration-msft-smbserverconfiguration), [IP Helper TCP table API](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable), [network adapter configuration](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-networkadapterconfiguration), [DNS Client policies](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-dnsclient), and [Remote Desktop policies](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-remotedesktopservices).

The console separates categories with section rules, uses spaced `[+]` headings for groups, and indented middle dots for facts (plain dots when redirected or `NO_COLOR` is set). Name Resolution, Remote Desktop, SMB hardening, and informational SMB encryption have separate headings. Active adapter counts exclude disconnected and loopback interfaces. These display changes do not change scoring.
