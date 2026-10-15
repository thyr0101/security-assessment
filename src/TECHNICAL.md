# Technical reference

## Build

The project targets Windows 10 or newer and C++23 with MSVC. The current development toolchain is Visual Studio 18, v145, and Windows SDK 10.0.26100. The Visual Studio project defaults to v143 for Debug and v145 for Release; override the toolset when needed.

```powershell
cmake -S . -B build -G "Visual Studio 18 2026" -A x64 -T v145
cmake --build build --config Release
```

Or open `SecurityAssessment.sln`. For a Debug build with the installed toolset:

```powershell
msbuild SecurityAssessment.vcxproj /p:Configuration=Debug /p:Platform=x64 /p:PlatformToolset=v145
```

All runtime dependencies are Windows components or the C++ runtime. No Python packages, command-line tools, or third-party libraries are required by the application. Python is used only by the optional development smoke harness.

## Source map and data flow

| Location | Responsibility |
| --- | --- |
| `Output/JsonCompact` | Versioned short-key encoding, numeric states, direct field values and bounded expansion. |
| `Output/JsonReportReader.h` | Restores typed saved report fields through Windows JSON interfaces, without collection or rescoring. |
| `main.cpp` | Validates CLI arguments, coordinates collectors, and selects console/export/view mode. |
| `Models.h`, `Common.h` | Typed assessment data, read statuses, score rules, and warnings. |
| `Collectors/SystemCollector`, `HardwareCollector`, `SecurityCollector` | OS, processor/memory, TPM, Secure Boot, VBS, memory integrity, UAC, and memory protection. |
| `Collectors/DefenderCollector`, `AntivirusCollector`, `FirewallCollector` | Defender status, registered antivirus products, and firewall controls. |
| `Collectors/NetworkCollector`, `HardeningCollector` | SMB/remote-access configuration, local account lockout, Guest identity, and device/credential safeguards. |
| `Collectors/StorageCollector` | Physical disks, volume extents, and BitLocker status. |
| `Collectors/WindowsUpdateCollector` | Offline cached updates, service readiness, restart status, and installation history. |
| `Collectors/PersistenceCollector` | Startup locations and threshold scans. |
| `RegistryReader`, `WmiHelper`, `Utilities` | Native resource ownership, typed extraction, hashing, and shared helpers. |
| `Security/ScoreEngine` | Applies rules, totals weights, and generates ranked warnings. |
| `Output/ConsoleRenderer`, `JsonRenderer` | Human-readable presentation and UTF-8 JSON serialization. |
| `Output/JsonFile` | Safe file creation, native JSON validation, and terminal formatting of saved reports. |

Four COM-initialized workers run independent collectors and write distinct result fields. Workers join before scoring and rendering. Provider failures preserve unknown/unavailable states rather than inventing disabled or secure results. Privacy collection and minimum-password-length collection have been removed from the data model, collectors, renderers, and scoring.

## Windows interfaces

- Registry configuration uses Win32 registry APIs. Explicit policy takes precedence where applicable; absence is not automatically treated as secure or insecure.
- Defender, Device Guard, SMB configuration, and elevated TPM/BitLocker use COM/WMI. SMB uses the provider's read-only `GetConfiguration` methods.
- Non-admin TPM presence/version use TPM Base Services (`Tbsi_GetDeviceInfo`). Readiness remains explicitly unverified. Non-admin BitLocker checks retain AccessDenied without waiting on its restricted namespace.
- Windows Security Center provides antivirus registrations. Every product receives an independent 180-point score when Windows confirms it enabled; the overall category remains capped at 180. Defender periodic scanning is informational.
- IP Helper supplies adapter/endpoint data. The console omits adapter and listener inventory; JSON preserves it. DHCP-controlled NetBIOS does not establish that it is disabled.
- `GetProcessInformation(ProcessProtectionLevelInfo)` reads actual LSASS protection. Native local SAM APIs read lockout and identify Guest by RID 501, including renamed accounts. Domain and Microsoft accounts can have different policies.
- `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` maps mounted volumes to physical disks. Spanned volumes appear under every referenced disk with a span note; unmapped volumes remain visible.
- Windows Update Agent searches offline with service self-upgrade disabled and a 45-second completion timeout. Search failures are not interpreted as no pending updates. Startup types, search timestamps, and installation metadata are retained in JSON where collected.
- `Windows.Data.Json` validates viewed files through the Windows Runtime. No external viewer or executable is launched.

Source references: [TPM Base Services](https://learn.microsoft.com/en-us/windows/win32/api/tbs/nf-tbs-tbsi_getdeviceinfo), [SMB configuration](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/smb/getconfiguration-msft-smbserverconfiguration), [process protection levels](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_protection_level_information), [local account policy](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusermodalsget), and [Windows JSON validation](https://learn.microsoft.com/en-us/uwp/api/windows.data.json.jsonobject.tryparse).

## Score allocation

| Category | Maximum | Main weights |
| --- | ---: | --- |
| Hardware Security | 150 | Secure Boot 40; TPM readiness 30; VBS 30; memory integrity 30; Credential Guard 20. |
| Operating System | 200 | Windows version 10; UAC 20; DEP 20; SEHOP 15; Smart App Control 50; LSASS protection 25; LM-hash policy 20; AutoPlay 20; inactivity locking 20. |
| Windows Update | 60 | Three key services at 10 each; restart completion 15; latest installation 15. |
| Malware Protection | 180 | Defender active 40; real-time 45; behavior 20; downloaded-file scanning 15; cloud 20; tamper protection 20; no active threats 20. Registration fallback replaces these with a capped 180-point rule. |
| Network Security | 200 | Firewall coverage 60, inbound defaults 20, firewall service 20; eight SMB/name-resolution/RDP checks at 10 each; modern sign-in policy 20. |
| Encryption | 90 | BitLocker 50; TPM availability 40. |
| Account Security | 120 | Admin permission prompt 20; secure desktop 25; Guest disabled 30; Remote Assistance invitations blocked 20; account lockout 25. |
| Inventory | 0 | Selected software/startup scans and hardware capabilities are informational. |
| **Total** | **1000** | |

Removing the 20-point password-length rule reallocates five points each to secure desktop, Guest, Remote Assistance, and account lockout. Lockout with shorter-than-15-minute lock/reset windows receives 12 of 25 points; full credit requires 1-10 attempts with both windows at least 15 minutes. These are selected hardening thresholds, not compliance certification.

Smart App Control earns 50 when enforcing and 25 in evaluation. Verified partial BitLocker coverage earns 25 of 50. Verified TPM presence can receive partial hardware credit while readiness remains unknown. Unknown readings never become full credit. Pending updates, inventory completion, assessment elevation, and update-metadata readability do not change the score.

Stable IDs such as `net.ntlm` remain machine-facing identifiers; user-facing labels use plain descriptions such as “Modern network sign-in protection.” The privacy category, `priv.*` rules, `acc.password`, and related JSON fields are removed rather than retained as hidden checks. Scores from older versions must be compared with their original weights in mind.

## CLI, export, and viewer

```text
SecurityAssessment [--json [0|1] [output-file]]
SecurityAssessment --json view <report-file>
```

- Default mode renders the console assessment.
- `--json` prompts for mode 0 (compact and viewable) or 1 (descriptive JSON, not viewable) before collection. EOF without a choice exits with code 2. `--json 0 [file]` and `--json 1 [file]` bypass the prompt. Both modes run the assessment and create a UTF-8 file without a BOM. A generated `security-assessment-YYYYMMDD-HHMMSS-mmm-PID.json` filename uses the system's local clock and current folder.
- An explicit destination is resolved from the current folder. Parents must exist. `CREATE_NEW` prevents replacement of existing files, including links. Writes are exclusive and flushed before success is reported; failed writes mark the owned handle for deletion where possible.
- Export prints only a confirmation/path. It no longer emits JSON on stdout. This intentionally changes the old CLI contract.
- `--json view <file>` reads a saved report without running collectors. It accepts UTF-8 with or without a BOM, validates JSON, checks the compact format version and expands its numbered fields, direct values and numeric states with strict code/reference bounds. It validates the restored system/score/rules structure with Windows' parser, then restores the typed assessment model and renders the regular console report with a red backup warning box between the title and System section. Saved scores and rules are preserved without calling collectors or the score engine. Validation checks report structure, not provenance or authenticity.
- The viewer accepts up to 64 MiB input, nesting up to 128 levels, 100,000 items per array, and 4,096 score rules with descriptions up to 16,384 UTF-8 bytes. Typed fields, numeric ranges, and rule score bounds are validated; imported terminal control characters are displayed as visible Unicode escapes. Invalid encoding, malformed JSON, unrelated JSON, unavailable files, and excessive input fail with an error.
- `--no-hash` remains accepted as a legacy no-op for assessment scripts and cannot be combined with view mode. Application collection and executable hashing no longer run. Unexpected arguments and duplicate `--json` are rejected before collecting data.
- Exit codes: 0 for success/help, 1 for file/runtime output errors, 2 for invalid arguments. The score does not control the exit code.

JSON retains the `system`, `hardware`, `security`, `defender`, `antivirus`, `firewall`, `storage`, `network`, `hardening`, `services`, `registryFindings`, `directoryFindings`, `persistence`, `windowsUpdate`, and `score` report data. Native boolean readings must be interpreted with their accompanying status fields. Warnings are omitted from exports and disabled in the backup viewer. The viewer explicitly displays “Warnings are disabled when viewing an export”. Both current numbered-field and previous compact exports are supported by the viewer; descriptive and legacy plain-text JSON is intentionally rejected. See [JSON_FORMAT.md](JSON_FORMAT.md) for the encoding contract.

## Console and warnings

The console ends with breakdown, score, then warnings. Colors supplement explicit states; redirected output and `NO_COLOR` use plain ASCII structure. Related facts share rows only when full values fit. Hardware pictograms are not used because console font coverage is inconsistent.

Warnings are ordered Critical, High, Medium, Low and include context and a recommendation. They do not deduct extra points. Unknown, inaccessible, or unconfigured evidence is distinguished from confirmed weaknesses and grouped in a Low-severity verification-gap notice. Recommendations are displayed only; the app does not apply them.

## Debugging and regression checks

```powershell
cmake -S . -B build-tests -G "Visual Studio 18 2026" -A x64 -T v145 -DSA_BUILD_TESTS=ON
cmake --build build-tests --config Release
ctest --test-dir build-tests -C Release --output-on-failure
python tests/smoke.py build-tests/Release
```

Native fixtures use private temporary files and registry data. They cover parsing, ownership, rule boundaries, partial readings, score sums, antivirus fallback, hidden console fields, and JSON save/view behavior. Smoke checks cover file export, automatic filenames, compact viewer round trips, numeric states, readable-file rejection, interactive choices, no-overwrite behavior, invalid arguments, legacy CLI compatibility, removed application inventory, help, and redirected console output.

Optional MSVC `/analyze` and AddressSanitizer builds can check static and memory errors. The previous review passed Debug/Release regressions, live non-admin smoke runs, static analysis, and AddressSanitizer; elevated TPM/BitLocker provider collection was not run live. Synthetic tests cover how those provider results affect scoring.

Set `SA_TRACE_TIMINGS=1` to emit per-collector durations to stderr. Prior measured non-admin runs dropped from a 10.994-second profiled baseline to a median of 0.802 seconds over five warm Release JSON runs after avoiding restricted WMI waits and overlapping collectors. Different machines/provider cache states will differ. C++23 typed errors (`std::expected`), owned output pointers (`std::out_ptr`), ranges, joined workers, and bounded topology traversal support safer collection without third-party dependencies.

## Local archive

`archived/ApplicationCollector.cpp` and `archived/ApplicationCollector.h` preserve the removed collector locally. `/archived/` is ignored by Git and is outside the build source tree; builds and tests do not depend on these files. New JSON exports omit applications, and removed application fields are not restored. Removing the informational application rule does not change the 1000-point scale.

## Network sign-in policy reporting

`LmCompatibilityLevel` is read directly from `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`. Missing values are reported as **Not configured**, without inferring an effective default. Read failures distinguish denied access, invalid registry types, unavailable data, invalid values and general read errors. Configured levels 0–2 allow legacy responses; 3–5 send NTLMv2 responses only and receive the existing 20 points. Unsupported values never earn credit. The console and rule reasons explain missing/failed readings, which remain verification gaps in warning classification.

Reference: [Microsoft's LAN Manager authentication policy documentation](https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level).
