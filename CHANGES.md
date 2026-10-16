# Changelog

## Changes since `936bbf8`

### Added

- A prominent warning box when a live assessment runs without administrator privileges.
- Additional threshold checks for user and machine startup registry locations, including 32-bit registrations, startup approval records and user/shared Startup folders.
- Descriptions for threshold locations, explaining what each registry key or directory contains.
- A centralized warning catalog for notices, warning text, severity, context and recommendations.

### Changed

- **Third-party antivirus scoring:** Exclude Microsoft Defender from scoring whenever a third-party antivirus is registered, regardless of either product's state. Defender displays **Not scored**. Confirmed enabled third-party protection earns credit; disabled or unknown protection earns none. The antivirus contribution remains capped at **180/1000**.
- **Threshold findings:** Display only exceeded thresholds alongside other warnings, all at **Medium** severity. Include each location's path, count, review threshold and description. These findings do not affect the score.
- **JSON exports:** Omit threshold records and skip threshold scans and warning generation during export. Older compact backups remain viewable with their recorded scores; warnings remain disabled in the backup viewer.
- **Directory enumeration:** Use direct Win32 enumeration, reuse returned file attributes and deduplicate equivalent scan paths. Separate threshold collection from Windows Update service queries.
- **Purple accents:** Display `[+]` markers, disk names and category names in the rule breakdown in purple.
- **Disk identifiers:** Display identifiers such as `Disk0` in light yellow, including references for spanned volumes.
- **Category score colors:** Display full marks in green, scores above 50% but below full marks in orange, and scores at or below 50% in yellow.
- **Orange highlights:** Display Smart App Control's `[Evaluation]` state and Medium warnings in orange.
- Refresh usage and technical documentation to match the current report, export and command-line behavior.

### Fixed

- Prevent disabled or passive Defender registrations from appearing as a separate scoring failure when a third-party antivirus is present.
- Preserve partial directory counts when enumeration fails, and explicitly identify partial counts that already exceed a review threshold.
- Keep backup notices separate from live privilege warnings, so saved elevation data does not describe the viewer's current privileges.

### Removed

- The standalone **Threshold Findings** category; exceeded items now appear only in warnings.
- The **Inventory Coverage (informational)** section, its zero-point rule and obsolete startup-readability collection.
- Clickable Settings shortcuts and the `--settings` argument.
- Unused Settings navigation helpers, hyperlink formatting and threshold export/import code.
