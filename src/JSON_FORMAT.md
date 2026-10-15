# Compact JSON format, version 1

CLI mode `--json 0` writes a compact report. Mode `--json 1` writes the descriptive schema and cannot be opened by the viewer. The choice prompt appears when the mode is omitted. Filenames remain optional.

## Envelope

```json
{"v":1,"s":["Disabled","Enabled","Unknown","N/A","additional text..."],"d":{}}
```

- `v`: exact schema version. Unknown versions are rejected.
- `s`: shared text table. The first four strings must match the example exactly. Additional strings (names, rule descriptions, reasons, titles, categories and other text) are stored once and referenced by zero-based numeric index.
- `d`: assessment data. Field keys use the fixed table below. Objects and arrays keep their descriptive-schema structure; measured numbers and nulls remain numbers and nulls.
- Compact encoding is not encryption or authentication. System details remain recoverable, and a file's score is recorded evidence, not a live assessment.

## State codes

| Value kind | Codes |
| --- | --- |
| Boolean | 0=false/disabled; 1=true/enabled |
| Tri-state | 0=No/disabled; 1=Yes/enabled; 2=Unknown; 3=N/A |
| Collection status | 0=Error; 1=Success; 2=Unavailable; 3=NotFound; 4=AccessDenied; 5=Unsupported |
| Antivirus state | 0=Disabled; 1=Enabled; 2=Unknown; 3=Snoozed; 4=Expired |
| Other text, including rule states | Index into `s`; Disabled=0, Enabled=1 and Unknown=2. Other labels use the report's text table. |

`enabled` is Boolean for TPM, UAC, Defender and firewall profiles; it is tri-state for Secure Boot and general security settings. Arrays of text contain text-table indexes; numeric arrays such as disk indexes retain their numeric values. Empty text also has a table entry. Native JSON booleans and quoted primitive values are not used in `d`.

Warnings and application inventory are not exported. Scores are restored without rescoring. Input is limited to 64 MiB, nesting to 128 levels, expanded JSON to 128 MiB, and the text table to 100,000 entries. Unknown keys, invalid codes and invalid text references are rejected. Terminal control characters are escaped for display after import.

## Fixed key table

Key IDs are base-36 strings. This order is part of version 1: do not reorder it. New keys may only be appended; incompatible changes require a new version. The value-type rules are defined in `JsonCompact.cpp::Type`.

| Key | Descriptive field |
| --- | --- |
| `0` | `enabled` |
| `1` | `status` |
| `2` | `source` |
| `3` | `reason` |
| `4` | `system` |
| `5` | `productName` |
| `6` | `displayVersion` |
| `7` | `build` |
| `8` | `ubr` |
| `9` | `architecture` |
| `a` | `computerName` |
| `b` | `userName` |
| `c` | `timeZone` |
| `d` | `locale` |
| `e` | `uptimeSeconds` |
| `f` | `windowsUpdate` |
| `g` | `cachedOnly` |
| `h` | `pendingStatus` |
| `i` | `pendingReason` |
| `j` | `pendingCount` |
| `k` | `optionalCount` |
| `l` | `lastSearchUtc` |
| `m` | `rebootRequired` |
| `n` | `historyStatus` |
| `o` | `lastInstallationUtc` |
| `p` | `lastInstallationTitle` |
| `q` | `lastInstallationResult` |
| `r` | `lastInstallationError` |
| `s` | `lastInstallationSucceeded` |
| `t` | `updates` |
| `u` | `title` |
| `v` | `id` |
| `w` | `optional` |
| `x` | `downloaded` |
| `y` | `updateType` |
| `z` | `severity` |
| `10` | `classifications` |
| `11` | `products` |
| `12` | `kbArticles` |
| `13` | `servicesStatus` |
| `14` | `services` |
| `15` | `name` |
| `16` | `displayName` |
| `17` | `state` |
| `18` | `startType` |
| `19` | `hardware` |
| `1a` | `cpu` |
| `1b` | `vendor` |
| `1c` | `brand` |
| `1d` | `logicalProcessors` |
| `1e` | `physicalCores` |
| `1f` | `processorGroups` |
| `1g` | `maxMhz` |
| `1h` | `features` |
| `1i` | `sse` |
| `1j` | `sse2` |
| `1k` | `sse3` |
| `1l` | `ssse3` |
| `1m` | `sse41` |
| `1n` | `sse42` |
| `1o` | `avx` |
| `1p` | `avx2` |
| `1q` | `avx512f` |
| `1r` | `aesni` |
| `1s` | `sha` |
| `1t` | `vmx` |
| `1u` | `hypervisorPresent` |
| `1v` | `svm` |
| `1w` | `nx` |
| `1x` | `memory` |
| `1y` | `totalBytes` |
| `1z` | `availableBytes` |
| `20` | `loadPercent` |
| `21` | `modules` |
| `22` | `capacity` |
| `23` | `speed` |
| `24` | `configuredSpeed` |
| `25` | `manufacturer` |
| `26` | `partNumber` |
| `27` | `ecc` |
| `28` | `security` |
| `29` | `tpm` |
| `2a` | `present` |
| `2b` | `ready` |
| `2c` | `readinessKnown` |
| `2d` | `specVersion` |
| `2e` | `manufacturerId` |
| `2f` | `secureBoot` |
| `2g` | `firmwareIsUefi` |
| `2h` | `virtualization` |
| `2i` | `vbsEnabled` |
| `2j` | `hvciEnabled` |
| `2k` | `credentialGuardRunning` |
| `2l` | `hvciConfigured` |
| `2m` | `runningServicesKnown` |
| `2n` | `uac` |
| `2o` | `smartAppControl` |
| `2p` | `smartAppControlEvaluation` |
| `2q` | `elevated` |
| `2r` | `defender` |
| `2s` | `installed` |
| `2t` | `enabledStatus` |
| `2u` | `realTimeProtection` |
| `2v` | `realTimeProtectionStatus` |
| `2w` | `behaviorMonitor` |
| `2x` | `behaviorMonitorStatus` |
| `2y` | `ioav` |
| `2z` | `ioavStatus` |
| `30` | `cloudProtection` |
| `31` | `cloudProtectionStatus` |
| `32` | `threatsKnown` |
| `33` | `threatsCount` |
| `34` | `tamperProtection` |
| `35` | `tamperProtectionStatus` |
| `36` | `amEngineVersion` |
| `37` | `amRunningMode` |
| `38` | `periodicScanning` |
| `39` | `antivirusSignatureVersion` |
| `3a` | `antivirus` |
| `3b` | `hasThirdParty` |
| `3c` | `isDefender` |
| `3d` | `signaturesUpToDate` |
| `3e` | `firewall` |
| `3f` | `serviceRunning` |
| `3g` | `serviceStatus` |
| `3h` | `activeProfiles` |
| `3i` | `activeProfilesStatus` |
| `3j` | `profiles` |
| `3k` | `defaultInbound` |
| `3l` | `defaultOutbound` |
| `3m` | `storage` |
| `3n` | `disks` |
| `3o` | `index` |
| `3p` | `model` |
| `3q` | `sizeBytes` |
| `3r` | `busType` |
| `3s` | `mediaType` |
| `3t` | `isNvme` |
| `3u` | `volumes` |
| `3v` | `volumeId` |
| `3w` | `diskMappingStatus` |
| `3x` | `diskIndices` |
| `3y` | `mountPoint` |
| `3z` | `volumeLabel` |
| `40` | `filesystem` |
| `41` | `freeBytes` |
| `42` | `driveType` |
| `43` | `bitLockerState` |
| `44` | `bitLockerStatus` |
| `45` | `bitLockerNote` |
| `46` | `encryptionMethod` |
| `47` | `protectionMethod` |
| `48` | `encryptionPercentage` |
| `49` | `network` |
| `4a` | `adapters` |
| `4b` | `description` |
| `4c` | `mac` |
| `4d` | `up` |
| `4e` | `ifType` |
| `4f` | `guid` |
| `4g` | `dhcpServer` |
| `4h` | `netbiosOptions` |
| `4i` | `netbiosStatus` |
| `4j` | `dhcp` |
| `4k` | `ipv4` |
| `4l` | `ipv6` |
| `4m` | `gateways` |
| `4n` | `dns` |
| `4o` | `rdpPort` |
| `4p` | `rdpPortStatus` |
| `4q` | `tcp4Status` |
| `4r` | `tcp6Status` |
| `4s` | `udp4Status` |
| `4t` | `udp6Status` |
| `4u` | `endpointScope` |
| `4v` | `endpoints` |
| `4w` | `protocol` |
| `4x` | `family` |
| `4y` | `address` |
| `4z` | `port` |
| `50` | `processId` |
| `51` | `processName` |
| `52` | `processStatus` |
| `53` | `binding` |
| `54` | `reviewNote` |
| `55` | `hardening` |
| `56` | `lsaProtection` |
| `57` | `noLmHash` |
| `58` | `autoPlayDisabled` |
| `59` | `guestDisabled` |
| `5a` | `remoteAssistanceDisabled` |
| `5b` | `inactivitySeconds` |
| `5c` | `inactivityStatus` |
| `5d` | `lmCompatibility` |
| `5e` | `lmCompatibilityStatus` |
| `5f` | `lockoutThreshold` |
| `5g` | `lockoutDuration` |
| `5h` | `lockoutWindow` |
| `5i` | `lockoutStatus` |
| `5j` | `registryFindings` |
| `5k` | `path` |
| `5l` | `valueCount` |
| `5m` | `subkeyCount` |
| `5n` | `threshold` |
| `5o` | `exceeded` |
| `5p` | `directoryFindings` |
| `5q` | `fileCount` |
| `5r` | `dirCount` |
| `5s` | `persistence` |
| `5t` | `location` |
| `5u` | `command` |
| `5v` | `persistenceStatus` |
| `5w` | `score` |
| `5x` | `total` |
| `5y` | `maximum` |
| `5z` | `registeredAntivirusScoring` |
| `60` | `rules` |
| `61` | `maxPoints` |
| `62` | `awardedPoints` |
| `63` | `category` |
| `64` | `antivirusScores` |
| `65` | `smb1Server` |
| `66` | `smb1Client` |
| `67` | `smbServerSigning` |
| `68` | `smbClientSigning` |
| `69` | `smbGuestLogons` |
| `6a` | `smbEncryption` |
| `6b` | `smbRejectUnencrypted` |
| `6c` | `llmnr` |
| `6d` | `rdp` |
| `6e` | `rdpNla` |
