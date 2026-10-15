# Correctness and performance review

Reviewed all source/header files, both build definitions, and the README. The application remains a native Windows console program with no third-party runtime dependency and no external command execution.

## Changes

| Area | Corrections |
| --- | --- |
| CLI / application inventory | `--no-hash` now bypasses hashing. Fixed concatenated Firefox/Brave paths, Signal's install path, and Discord's versioned locations. Directory matches are excluded, wildcard results are sorted, duplicate detection uses a hash set, and enumeration failures propagate. |
| Registry | Bounded multi-string parsing rejects malformed data. Reads retry when a value grows and recheck type after reading. Integer reads validate size and use `memcpy`. Enumeration preserves the actual default value name. |
| COM / WMI | COM cleanup balances only successful initialization calls. WMI enumerators, property variants, and collected objects have automatic cleanup. Failed or timed-out queries no longer masquerade as successful empty/partial results. Numeric strings and arrays are validated. |
| File metadata / hashing | Version resources use their declared languages/code pages with fixed-version fallback. PE header reads are bounded and avoid mapping whole executables. BCrypt property failures are checked; file hashing uses sequential-read hints. |
| OS / hardware | Counts logical processors across groups, sums cache instances, reads current CPU frequency through the native power API, rejects unknown ECC widths, and reads the system UI language. |
| Security | Correct TPM manufacturer conversion and failure states. Restores the temporary firmware privilege. Separates configured HVCI from observed running services, fixes UAC credential-prompt detection, and distinguishes SAC evaluation from enforcement. Removes the unrelated Winlogon key as evidence for Hello. Individual security checks preserve other successful results on failure. |
| Defender / firewall | Registry read failures no longer imply enabled Defender features. Missing threat properties leave the count unknown. Firewall actions default to unknown, profile/service errors are retained, and failed reads cannot earn default-block points. |
| Storage | Enumerates existing physical-drive names instead of stopping at the first missing index. Bounds descriptor strings. Uses dynamic mount-path buffers and restores thread error mode. Queries BitLocker instances once and matches volume GUIDs, including folder mounts; checks method return codes and reads encryption percentage. |
| Network | Initializes Winsock correctly, formats complete hardware addresses, formats numeric IP addresses without port suffixes, retries adapter-buffer growth, and handles an empty adapter list. |
| Persistence / thresholds | Fixes the escaped MUI path, removes an empty registry scan and duplicate firewall service, checks count failures, honors recursive scans without following reparse points, preserves enumeration errors, and includes machine 32-bit RunOnce entries. Service handles have automatic cleanup. |
| Privacy | Reads camera/microphone consent as strings and labels Remote Assistance accurately. |
| Scoring | Keeps categories consistent for failing/partial rules, prevents TPM 1.2 receiving TPM 2.0 credit, and avoids awarding completed-inventory points on failed collection. Derives totals and maximum from the same rules; the current weights still sum to 1000. Missing required inputs produce unknown states. |
| Output | Escapes all JSON rule strings, uses locale-independent JSON numbers, and adds collection-status fields. Console output distinguishes several unavailable checks from disabled features and displays scan errors. Restores the console code page and returns failure on stdout errors. |

## Compatibility

### Windows Update category

Added a native, offline Windows Update Agent collector and a 60-point Windows Update category. The existing 30-point `os.patch` rule moves category without changing ID. Scored checks cover three service-readiness checks totaling 15 points, restart completion (10), and the latest installation result (5). Pending updates are informational (zero-weight `wu.pending` rule). Seven update services are displayed, and stopped services configured to start on demand are not treated as disabled.

The extra 30 scored points come from TPM key-protection availability (75 to 65) and assessment administrator access (25 to 5); maximum remains 1000 in both Defender and registered-antivirus modes. Removing the former pending-update score restores 40 points to TPM key availability. Console grouping uses the category field. JSON includes update details, separate optional counts, history, service states, and explicit null counts on failed reads. Offline search has a 45-second completion timeout; cache timestamps, restart state, installation details, and service startup types remain in JSON while the console shows the simplified pending-update and service trees.

Pending updates and update services use tree layouts. Update types come from WUA classification/product categories, software/driver type, optional status, and MSRC severity, with no title-based classification guesses. Empty pending lists show `(None)` without branches. Service labels show the SCM-resolved canonical key name before the display name. Native regressions cover informational counts through overflow boundaries, unknown reads, disabled and idle services, restart states, installation errors, both tree layouts, empty lists, category placement, output escaping, canonical service-name lookup, and the 1000-point scale.

API references: [offline search setting](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-put_online), [update search criteria](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-search), and [asynchronous search guidance](https://learn.microsoft.com/en-us/windows/win32/wua_sdk/guidelines-for-asynchronous-wua-operations).

Tree metadata references: [update categories](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdate-get_categories), [security severity](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdate-get_msrcseverity), and [service key names](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-getservicekeynamew).

Console styling uses blue identifiers, white names, cyan values and service states, and muted secondary details. Security outcomes retain green/yellow/red, with unknown results shown in yellow. A live pseudoconsole check confirmed service colors, hidden update metadata, and omitted startup types; regression and smoke checks confirmed plain redirected output.

### Follow-up bug review

- Defender fields now retain individual read statuses. Missing real-time, behavior, IOAV, cloud, and tamper properties are reported as unknown and cannot earn points from stale values. A running service alone does not establish active antivirus protection.
- BitLocker full-coverage scoring requires complete volume enumeration and successful per-volume status reads. Unknown volume types prevent full credit. Failed Secure Boot/HVCI collection cannot earn stale credit, and TPM version matching uses the complete version token.
- Startup folders are resolved through the native known-folder API, including redirected folders. Directories, `desktop.ini`, and non-string Run values are excluded. Unreadable Run commands and service reads preserve incomplete inventory status; JSON exposes the aggregate statuses.
- WMI unsigned extraction rejects negative signed values while preserving the full CIM uint32 range. NULL string properties are unavailable. Registry reads accept the documented single-null empty multi-string, and enumeration errors are retained.
- Application resolution normalizes absolute paths before deduplication. Incomplete application scans display their status. Windows directory queries resize their buffers, storage descriptor reads validate returned lengths, and unknown CLI options return an error.

Validation: CMake Release and native MSBuild Debug builds passed; native MSBuild Release with `/analyze` reported no warnings. Native regressions and the live smoke harness passed, including partial-data scoring, WMI signed/unsigned conversion, empty registry lists, path deduplication, JSON parsing, both hash modes, invalid options, and redirected console output. Live checks ran without elevation; encryption failures and multiple-antivirus scenarios use synthetic fixtures.

References: [WMI numeric representations](https://learn.microsoft.com/en-us/windows/win32/wmisdk/numbers), [registry string formats](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types), [known-folder resolution](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath), and [Windows directory buffer sizing](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectoryw).

### Registered antivirus support

Added native Windows Security Center product enumeration, independent 195-point product scores, and a capped 195-point malware category fallback. Defender-only detailed scoring remains available. Defender periodic scanning is informational and uses its reported running mode; missing evidence stays unknown. Both console and JSON expose the results. Synthetic coverage includes multiple enabled/disabled products, inaccessible states, Defender provider failure, and periodic-scanning score independence.

- Existing CLI options, report sections, and JSON keys remain. New JSON status/context fields are additive.
- Corrected readings and rules can change scores. Full credit remains 1000. Smart App Control earns 25/50 in evaluation mode and 50/50 when enforcing; the no-active-threats check earns 20 points. Registration fallback replaces the granular malware rules with `mp.registered` (195 points). Rule IDs remain stable; descriptions and states use clearer user-facing wording.
- Application definitions and threshold definitions remain configured in C++.
- The tool still reports a security posture, not malware detection or proof of security. Boolean model fields may need their accompanying status/context to distinguish unavailable data.

## Validation

For the registered-antivirus update, CMake Release, native MSBuild Debug, and MSBuild Release with `/analyze` compiled successfully with no reported analyzer warnings. After fixing the malformed multi-string reader to require the double-null terminator, all native regressions passed, including the antivirus scenarios. The smoke harness also passed live JSON, hashing, help, and redirected-console checks without elevation. Multiple-product behavior passed synthetic fixtures but has not been confirmed on a machine running multiple registered antivirus products.

- Native MSBuild Release and Debug builds; Debug uses the installed v145 toolset override because the project defaults to v143.
- CMake-generated Release application and native regression targets.
- Regression fixtures exercise malformed/unterminated registry strings, registry type mismatches, thresholds, recursive directory counts, application deduplication, SHA-256 known vectors, disabled hashing, unknown/healthy score scenarios, JSON escaping, COM apartment ownership, WMI numeric conversion, and failed queries.
- The smoke harness parses synthetic and live JSON, exercises both hash modes, help, and redirected console output, checks score sums and original report sections, and confirms service names are unique.
- Live checks run without elevation. Elevated-only BitLocker paths, other Windows versions, unusual storage topologies, and unavailable hardware need validation on matching systems.

One local run observed 10.283 seconds for the updated `--json --no-hash` and 18.611 seconds for the original binary. The updated hashing run took 10.530 seconds. These are individual runs affected by WMI/provider warm-up, not a controlled performance benchmark.

## API references

- [COM initialization and balancing cleanup](https://learn.microsoft.com/en-us/windows/win32/api/objbase/nf-objbase-coinitialize)
- [Windows Security Center product states](https://learn.microsoft.com/en-us/windows/win32/api/iwscapi/ne-iwscapi-wsc_security_product_state)
- [Defender running modes](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows#check-the-state-of-microsoft-defender-antivirus-on-your-device)
- [Smart App Control evaluation and enforcement](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/overview)
- [Native processor power information structure omitted from SDK headers](https://learn.microsoft.com/en-us/windows/win32/power/processor-power-information-str)

## 2026-10-15: hardening, warnings, and latency review

### Connections and changes

`main.cpp` runs independent collectors through a bounded group of joined workers. Each initializes COM on its own thread and writes a distinct assessment field. `HardeningCollector` adds native LSA-process, account-policy, and registry-policy readings to `AssessmentResult::hardening`. `ScoreEngine` evaluates the rebalanced rules and derives severity-ranked warnings without further deductions. `ConsoleRenderer` groups relevant controls and ends with breakdown, score, and warnings; `JsonRenderer` preserves existing inventories and adds the hardening/warning fields. `PrivacyCollector` separates metadata from small typed read/precedence helpers, with injectable registry roots for isolated tests.

The initial non-admin profile identified two five-second restricted WMI connections. TPM Base Services now supply non-admin presence/version without inventing readiness; BitLocker explicitly retains AccessDenied. Collection work overlaps with a four-worker limit. Optional timing output is stderr-only. Console runs avoid unused endpoint inventory. Existing WUA offline behavior and its bounded search timeout are preserved.

The review also added null checks to all WMI extraction helpers and bounded native CPU topology traversal to prevent a malformed size from causing a non-advancing or out-of-bounds loop. C++23 features were used where they improve ownership, error handling, or traversal; providers and hardware limitations remain explicit.

### Validation and limits

- CMake Release and Debug application/regression builds succeeded.
- Release and Debug native regressions passed, including complete/unknown/partial scoring, local-policy thresholds, warning severity/order, privacy precedence using private volatile registry roots, hidden console inventories, antivirus fallback, registry parsing, WMI conversions/null objects, storage coverage, and hashing fixtures.
- MSBuild Release `/analyze` completed without reported warnings.
- AddressSanitizer Debug native regressions and live smoke checks passed, including JSON parsing, both hashing modes, invalid arguments/help, redirected console output, warning metadata, and all score sums.
- A live pseudoconsole check confirmed ANSI colors, the final breakdown/score/warnings order, and absence of the removed console inventories.
- Five Release non-admin JSON runs had a median of 0.802 seconds, versus a single profiled baseline of 10.994 seconds before the changes. Different provider cache states and machines can produce different results.
- Live runs used a non-admin token. Elevated TPM/BitLocker provider collection was not exercised live; synthetic fixtures validate scoring for their results and for multiple antivirus products. No security settings were changed. This is broad regression/static/memory coverage, not proof that every possible Windows configuration is defect-free.

Current weights and console behavior are described in README.md; earlier notes above describe their historical versions.
