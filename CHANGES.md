# Changelog

## Unreleased

### Added

- Settings shortcuts beside relevant headings and checks, plus `--settings <page>` navigation and `--settings` to list pages.
- A prominent warning above live assessments running without administrator privileges.
- Expanded threshold scans with descriptions, full paths, counts and read statuses. Added startup registration/approval locations and user/shared startup folders.
- A shared warning catalog in `src/Warnings.h` for notices, rule context, severity and recommendations.

### Changed

- Exclude Defender from product scoring whenever a third-party antivirus is registered, regardless of either product's state. Defender displays **Not scored**. Third-party products earn credit only when confirmed enabled; the category cap remains **180/1000**.
- Enumerate directory entries directly through Win32, normalize/deduplicate scan paths and retain displayed threshold descriptions in JSON backups.
- Separate threshold and update-service collectors and remove obsolete startup-readability collection and its zero-point rule.

### Removed

- The **Inventory Coverage (informational)** section.

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
