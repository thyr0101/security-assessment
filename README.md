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

- Open a command prompt window, elevated or not¹

- Run the binary

¹ If not elevated, the app is unable to load all information.

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

## Registered antivirus fallback

The app reads antivirus registrations through the native Windows Security Center COM API. When a third-party antivirus is registered, the console lists every registered product and its reported state instead of the inactive Defender feature list. Each product receives an independent score of 200/200 when Windows reports it enabled, or 0/200 otherwise. Disabled, snoozed, expired, and unreadable states receive no credit. Signature currency is informational.

The malware category contributes at most 200 points to the overall 1000-point score: any confirmed enabled product satisfies this category. Multiple enabled products do not multiply the overall score. Normal Defender-only operation retains the existing detailed scoring; registration scoring also provides a fallback when Defender's own status is unavailable or inactive.

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
