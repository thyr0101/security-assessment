# Changelog

## Unreleased

Changes since the first-release changelog.

### Added

- A warning box above live assessments when the app is running without administrator privileges.
- Additional threshold checks for startup registry locations and user/shared Startup folders, with descriptions for each location.
- A centralized warning catalog for warning text, severity, context and recommendations.

### Changed

- **Antivirus scoring:** When a third-party antivirus is registered, Microsoft Defender is marked **Not scored**, regardless of either product's state. Enabled third-party products earn credit; disabled or unknown products earn none. The overall antivirus contribution remains capped at **180 points**.
- **Threshold warnings:** Only locations exceeding their review thresholds appear, alongside other warnings at **Medium** severity. Findings include the location, count, threshold and description. Partial counts are identified explicitly. These warnings do not affect the score.
- **JSON exports:** Omit threshold scan records and skip warning-only scans and warning generation during export. Older compact backups remain viewable with their recorded scores; warnings remain disabled in the backup viewer.
- **Purple accents:** Use purple for `[+]` markers, disk names and category names in the rule breakdown.
- **Disk identifiers:** Display identifiers such as `Disk0` in light yellow, including references to disks in spanned volumes.
- **Category score colors:** Use green for full marks, orange for scores above 50% but below full marks, and yellow for scores at or below 50%.
- **Orange highlights:** Use orange for Smart App Control's `[Evaluation]` state and Medium warnings.
- **Collection and cleanup:** Use direct Win32 directory enumeration, deduplicate equivalent scan paths and separate threshold scans from update-service queries. Remove obsolete navigation, hyperlink handling and startup-readability code.

### Removed

- The standalone **Threshold Findings** category. Exceeded thresholds now appear only in warnings.
- The **Inventory Coverage (informational)** section and its obsolete zero-point rule.
- Clickable Settings shortcuts and the `--settings` command-line argument.

### Validation

- Passed Debug and Release regression and smoke checks, AddressSanitizer and MSVC static analysis after the threshold and navigation cleanup.
- Successfully built the subsequent console color changes in Release configuration.

## First release

Changes introduced since third-party antivirus support was added.

### Added

- **Third-party antivirus support:** Read antivirus registrations and protection states through Windows Security Center. Each registered product receives a separate score: **180/180** when confirmed enabled, or **0/180** otherwise. The overall malware-protection contribution is capped at **180 points**, even with multiple enabled products.
- **Defender periodic scanning:** Show whether periodic scanning is enabled when a third-party antivirus is registered. This is informational and does not affect the score.
- **Windows Update assessment:** Check update-service readiness, restart requirements and the latest recorded installation result. List pending updates in a tree with their classifications, severity, products, KB references and download status where available. Pending updates are informational and do not reduce the score; results come from Windows' local update cache.
- **Expanded network security checks:** Assess firewall profiles and inbound defaults, legacy SMB support, file-sharing integrity requirements, guest access, older name-discovery protocols, modern network sign-in policy and Remote Desktop authentication. Show additional SMB encryption settings for context.
- **Device and account safeguards:** Check sign-in service protection, older password storage, AutoPlay restrictions, automatic locking, the built-in Guest account, Remote Assistance invitations and local account lockout.
- **Ranked warnings:** Show findings and review suggestions grouped as Critical, High, Medium or Low, after the rule breakdown and total score. Distinguish verification gaps from confirmed weaknesses.
- **JSON report files and backup viewer:** Export a compact report with numbered fields and numeric state codes using `--json 0`, or a descriptive report using `--json 1`. Run `--json` to choose interactively. Only compact reports can be opened in the app with `--json view <file>`; descriptive reports remain readable in external tools.
- **Backup notice:** Display a red warning above saved report data to explain that it does not represent the current system state. Warnings are not exported and are disabled in the backup viewer.

### Changed

- Put report categories, rule breakdown, score and warnings in individual boxes, with restrained colors, wrapped text and ASCII borders for redirected output.
- Group volumes beneath their physical disks and update services beneath a shared heading. Display service names, display names and current states without startup-type clutter.
- Use clearer check names and states such as **Clear**, **Available**, **Not configured** and **Readiness unknown** where “Enabled” would be misleading.
- Keep the score out of **1000**, with rebalanced weights. Smart App Control earns **25/50** in evaluation and **50/50** when enforcing; no active threats earns **20** points; BitLocker contributes up to **50** points.
- Limit JSON exports to displayed information and recorded scores. Stop collecting unused inventories and metadata, including network endpoints, adapter addresses, startup commands and general service inventory.
- Reduce delays without administrator access and overlap independent collectors. Consolidate shared helpers in focused headers and reduce formatting overhead.
- Reduce the measured Release executable from **728 KiB to 499.5 KiB** (**31.4% smaller**) during the final layout and helper cleanup. Sizes depend on build settings.

### Fixed

- Improve Defender and registered-antivirus handling so unavailable provider data is distinguished from confirmed disabled protection.
- Distinguish missing network sign-in policy from denied access, invalid data and other read errors.
- Improve TPM, Device Guard and BitLocker collection, volume matching and handling of restricted or partial readings.
- Preserve saved scores without rerunning collectors or recalculating results. Correct UAC secure-desktop display in newly exported backups.
- Validate imported reports, escape terminal control characters and prevent exports from overwriting existing files.

### Removed

- The **Privacy (informational)** category and privacy collector.
- The **Applications** category and application collector from the build. Historical application-collector sources are kept only in the local, Git-ignored `archived/` directory.
- The local minimum-password-length check and executable hashing.
- Adapter and TCP/UDP listener inventories, configured RDP-port details and hidden metadata that did not contribute to the visible report or scoring.

Privacy and application inventory are outside the scope of this release. They may return in a future version.

For usage, see [README.md](README.md). Build instructions, score weights and implementation details are in [src/TECHNICAL.md](src/TECHNICAL.md); the compact JSON contract is in [src/JSON_FORMAT.md](src/JSON_FORMAT.md).
