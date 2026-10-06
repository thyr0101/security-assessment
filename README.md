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


- Visual Studio 2022 / 2026 with MSVC v14.51, or any MSVC toolset supporting C++20.

- Windows SDK 10.0.26100.

### MSBuild / Visual Studio

Open `SecurityAssessment.sln`, select `x64 | Release`, and build.



### CMake

```
cmake -S . -B build -A x64

cmake --build build --config Release
```
