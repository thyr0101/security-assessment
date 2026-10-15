# Compact JSON format, version 2

CLI mode `--json 0` writes a compact report. Mode `--json 1` writes the descriptive schema and cannot be opened by the viewer. The choice prompt appears when the mode is omitted. Filenames remain optional.

## Version 2 layout

New exports use numbered fields with their actual values directly beside them. Text is not stored in a lookup table. The following abbreviated example illustrates the System group (`7`), OS name (`1`), build (`2`) and Defender group (`100`) with enabled (`3`):

```json
{"v":2,"d":{"7":{"1":"Windows 11 Pro","2":26100},"100":{"3":1}}}
```

- `v`: schema version.
- `d`: assessment data. Objects and arrays keep the descriptive schema's hierarchy.
- Decimal field IDs are fixed by the table below. OS name is `1`, and build is `2`.
- Text values such as OS names, update titles and rule descriptions remain directly in their fields. Measured numbers and nulls remain numbers and nulls.
- Empty text properties and optional empty arrays are omitted and restored from model defaults. Zero or unavailable numeric properties with zero defaults are also omitted. Required score totals and fields with nonzero defaults remain explicit. Within the selected display snapshot, Boolean/state properties and array elements are retained; compact default omission does not remove them.
- There is no string dictionary or text-reference encoding in version 2.

## State codes

| Value kind | Codes |
| --- | --- |
| Boolean | 0=false/disabled; 1=true/enabled |
| Tri-state | 0=No/disabled; 1=Yes/enabled; 2=Unknown; 3=N/A |
| Collection status | 0=Error; 1=Success; 2=Unavailable; 3=NotFound; 4=AccessDenied; 5=Unsupported |
| Antivirus state | 0=Disabled; 1=Enabled; 2=Unknown; 3=Snoozed; 4=Expired |
| Rule/service `state` | Disabled=0; Enabled=1; Unknown=2. Other descriptive states (such as Running, Evaluation or Modern responses only) remain literal text. |
| BitLocker state | Off=0; On=1; Unknown=2 |
| Score category | 0=Hardware Security; 1=OS Security; 2=Windows Update; 3=Malware Protection; 4=Network Security; 5=Encryption; 6=Account Security; 7=Hardening; 8=Software Hygiene; 9=Informational |

`enabled` is Boolean for UAC, Defender and firewall profiles (and for the reserved TPM field in older backups); it is tri-state for Secure Boot and general security settings. Text arrays contain actual strings, and numeric arrays such as disk indexes retain actual numbers. Native JSON booleans are not used in `d`.

Exports contain only console display inputs and recorded rule results. Hidden inventories, raw scoring-only evidence, provenance strings, rule reasons and non-exceeded successful threshold scans are omitted. Warnings and application inventory are not exported. The backup viewer displays a stale-data notice and disables warnings. Scores are restored without rescoring. Input is limited to 64 MiB, nesting to 128 levels, expanded JSON to 128 MiB. Unknown keys and invalid state codes are rejected. Terminal control characters are escaped for display after import.

## Previous compact backups

The viewer continues to read version 1 compact backups with base-36 keys and the shared `s` text table, using their original mapping. The old table's 100,000-entry limit remains enforced. New exports always use version 2. Descriptive/plain-text JSON is not viewable.

Compact encoding is not encryption or authentication. System details remain recoverable, and recorded scores are not a live assessment.

## Fixed key table

Key IDs are decimal strings starting at 1. This order is part of version 2: do not reorder it. New keys may only be appended; incompatible changes require a new version. Keys for retired fields remain reserved for older backups and are never reused. Their presence in this table does not mean new exports contain them. The value-type rules are defined in `JsonCompact.cpp::Type`.

| Key | Descriptive field |
| --- | --- |
| `1` | `productName` |
| `2` | `build` |
| `3` | `enabled` |
| `4` | `status` |
| `5` | `source` |
| `6` | `reason` |
| `7` | `system` |
| `8` | `displayVersion` |
| `9` | `ubr` |
| `10` | `architecture` |
| `11` | `computerName` |
| `12` | `userName` |
| `13` | `timeZone` |
| `14` | `locale` |
| `15` | `uptimeSeconds` |
| `16` | `windowsUpdate` |
| `17` | `cachedOnly` |
| `18` | `pendingStatus` |
| `19` | `pendingReason` |
| `20` | `pendingCount` |
| `21` | `optionalCount` |
| `22` | `lastSearchUtc` |
| `23` | `rebootRequired` |
| `24` | `historyStatus` |
| `25` | `lastInstallationUtc` |
| `26` | `lastInstallationTitle` |
| `27` | `lastInstallationResult` |
| `28` | `lastInstallationError` |
| `29` | `lastInstallationSucceeded` |
| `30` | `updates` |
| `31` | `title` |
| `32` | `id` |
| `33` | `optional` |
| `34` | `downloaded` |
| `35` | `updateType` |
| `36` | `severity` |
| `37` | `classifications` |
| `38` | `products` |
| `39` | `kbArticles` |
| `40` | `servicesStatus` |
| `41` | `services` |
| `42` | `name` |
| `43` | `displayName` |
| `44` | `state` |
| `45` | `startType` |
| `46` | `hardware` |
| `47` | `cpu` |
| `48` | `vendor` |
| `49` | `brand` |
| `50` | `logicalProcessors` |
| `51` | `physicalCores` |
| `52` | `processorGroups` |
| `53` | `maxMhz` |
| `54` | `features` |
| `55` | `sse` |
| `56` | `sse2` |
| `57` | `sse3` |
| `58` | `ssse3` |
| `59` | `sse41` |
| `60` | `sse42` |
| `61` | `avx` |
| `62` | `avx2` |
| `63` | `avx512f` |
| `64` | `aesni` |
| `65` | `sha` |
| `66` | `vmx` |
| `67` | `hypervisorPresent` |
| `68` | `svm` |
| `69` | `nx` |
| `70` | `memory` |
| `71` | `totalBytes` |
| `72` | `availableBytes` |
| `73` | `loadPercent` |
| `74` | `modules` |
| `75` | `capacity` |
| `76` | `speed` |
| `77` | `configuredSpeed` |
| `78` | `manufacturer` |
| `79` | `partNumber` |
| `80` | `ecc` |
| `81` | `security` |
| `82` | `tpm` |
| `83` | `present` |
| `84` | `ready` |
| `85` | `readinessKnown` |
| `86` | `specVersion` |
| `87` | `manufacturerId` |
| `88` | `secureBoot` |
| `89` | `firmwareIsUefi` |
| `90` | `virtualization` |
| `91` | `vbsEnabled` |
| `92` | `hvciEnabled` |
| `93` | `credentialGuardRunning` |
| `94` | `hvciConfigured` |
| `95` | `runningServicesKnown` |
| `96` | `uac` |
| `97` | `smartAppControl` |
| `98` | `smartAppControlEvaluation` |
| `99` | `elevated` |
| `100` | `defender` |
| `101` | `installed` |
| `102` | `enabledStatus` |
| `103` | `realTimeProtection` |
| `104` | `realTimeProtectionStatus` |
| `105` | `behaviorMonitor` |
| `106` | `behaviorMonitorStatus` |
| `107` | `ioav` |
| `108` | `ioavStatus` |
| `109` | `cloudProtection` |
| `110` | `cloudProtectionStatus` |
| `111` | `threatsKnown` |
| `112` | `threatsCount` |
| `113` | `tamperProtection` |
| `114` | `tamperProtectionStatus` |
| `115` | `amEngineVersion` |
| `116` | `amRunningMode` |
| `117` | `periodicScanning` |
| `118` | `antivirusSignatureVersion` |
| `119` | `antivirus` |
| `120` | `hasThirdParty` |
| `121` | `isDefender` |
| `122` | `signaturesUpToDate` |
| `123` | `firewall` |
| `124` | `serviceRunning` |
| `125` | `serviceStatus` |
| `126` | `activeProfiles` |
| `127` | `activeProfilesStatus` |
| `128` | `profiles` |
| `129` | `defaultInbound` |
| `130` | `defaultOutbound` |
| `131` | `storage` |
| `132` | `disks` |
| `133` | `index` |
| `134` | `model` |
| `135` | `sizeBytes` |
| `136` | `busType` |
| `137` | `mediaType` |
| `138` | `isNvme` |
| `139` | `volumes` |
| `140` | `volumeId` |
| `141` | `diskMappingStatus` |
| `142` | `diskIndices` |
| `143` | `mountPoint` |
| `144` | `volumeLabel` |
| `145` | `filesystem` |
| `146` | `freeBytes` |
| `147` | `driveType` |
| `148` | `bitLockerState` |
| `149` | `bitLockerStatus` |
| `150` | `bitLockerNote` |
| `151` | `encryptionMethod` |
| `152` | `protectionMethod` |
| `153` | `encryptionPercentage` |
| `154` | `network` |
| `155` | `adapters` |
| `156` | `description` |
| `157` | `mac` |
| `158` | `up` |
| `159` | `ifType` |
| `160` | `guid` |
| `161` | `dhcpServer` |
| `162` | `netbiosOptions` |
| `163` | `netbiosStatus` |
| `164` | `dhcp` |
| `165` | `ipv4` |
| `166` | `ipv6` |
| `167` | `gateways` |
| `168` | `dns` |
| `169` | `rdpPort` |
| `170` | `rdpPortStatus` |
| `171` | `tcp4Status` |
| `172` | `tcp6Status` |
| `173` | `udp4Status` |
| `174` | `udp6Status` |
| `175` | `endpointScope` |
| `176` | `endpoints` |
| `177` | `protocol` |
| `178` | `family` |
| `179` | `address` |
| `180` | `port` |
| `181` | `processId` |
| `182` | `processName` |
| `183` | `processStatus` |
| `184` | `binding` |
| `185` | `reviewNote` |
| `186` | `hardening` |
| `187` | `lsaProtection` |
| `188` | `noLmHash` |
| `189` | `autoPlayDisabled` |
| `190` | `guestDisabled` |
| `191` | `remoteAssistanceDisabled` |
| `192` | `inactivitySeconds` |
| `193` | `inactivityStatus` |
| `194` | `lmCompatibility` |
| `195` | `lmCompatibilityStatus` |
| `196` | `lockoutThreshold` |
| `197` | `lockoutDuration` |
| `198` | `lockoutWindow` |
| `199` | `lockoutStatus` |
| `200` | `registryFindings` |
| `201` | `path` |
| `202` | `valueCount` |
| `203` | `subkeyCount` |
| `204` | `threshold` |
| `205` | `exceeded` |
| `206` | `directoryFindings` |
| `207` | `fileCount` |
| `208` | `dirCount` |
| `209` | `persistence` |
| `210` | `location` |
| `211` | `command` |
| `212` | `persistenceStatus` |
| `213` | `score` |
| `214` | `total` |
| `215` | `maximum` |
| `216` | `registeredAntivirusScoring` |
| `217` | `rules` |
| `218` | `maxPoints` |
| `219` | `awardedPoints` |
| `220` | `category` |
| `221` | `antivirusScores` |
| `222` | `smb1Server` |
| `223` | `smb1Client` |
| `224` | `smbServerSigning` |
| `225` | `smbClientSigning` |
| `226` | `smbGuestLogons` |
| `227` | `smbEncryption` |
| `228` | `smbRejectUnencrypted` |
| `229` | `llmnr` |
| `230` | `rdp` |
| `231` | `rdpNla` |
| `232` | `virtualizationAvailable` |
| `233` | `promptOnSecureDesktop` |
