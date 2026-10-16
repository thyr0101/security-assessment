# Windows Security Assessment

A local Windows security auditor that checks how your computer is protected, gives it a score out of **1000**, and highlights settings that need attention.

See [CHANGES.md](CHANGES.md) for the first-release changelog.

It uses built-in Windows interfaces. It does not contact online services, run external commands, install software, or change security settings.

## What it checks

- **Hardware protection:** Secure Boot, the TPM security chip, memory integrity, and protection for sign-in secrets.
- **Windows protection:** permission prompts, protection against memory attacks, Smart App Control, protected sign-in services, automatic locking, and AutoPlay restrictions.
- **Antivirus:** Microsoft Defender protection or antivirus products registered with Windows Security Center. Registered products receive separate scores, capped at 180 points overall. Defender periodic scanning is informational.
- **Network protection:** firewall profiles, file-sharing safeguards, remote access authentication, and protection against older sign-in methods.
- **Drive encryption:** BitLocker coverage across fixed volumes, grouped beneath their physical disks.
- **Account protection:** secure permission prompts, the built-in Guest account, account lockout, and Remote Assistance invitations.
- **Windows Update:** pending updates from the local cache, update-service readiness, restart requirements and the latest recorded installation result. Pending updates are listed without affecting the score.

Threshold findings show registry and directory counts, review thresholds, paths and descriptions. They are informational and do not affect the score; high counts are not evidence of malware. Privacy settings and minimum password length are not collected.

## Run an assessment

The documented build configuration targets **64-bit Windows 10 or newer**. Open a terminal in the folder containing the executable:

```powershell
.\SecurityAssessment.exe
```

Run the terminal **as administrator** for the fullest assessment. A warning box identifies live assessments without administrator access. Restricted checks remain unverified instead of being reported as disabled.

Each category appears in its own box, with long values wrapping inside the border. The console ends with the **rule breakdown**, **total score**, and **warnings**, in that order. Warnings are grouped as Critical, High, Medium, or Low and include an action to review. Missing evidence is clearly identified as a verification gap.

## Open Windows settings

Relevant headings and checks have Settings shortcuts in an interactive console. In Windows Terminal, use **Ctrl+click** on `[Settings]`; the terminal may ask you to confirm opening the URI. Other terminals show an identifier such as `[Settings: update]`.

Use `SecurityAssessment.exe --settings update` to open Windows Update directly, or `SecurityAssessment.exe --settings` to list supported pages. Navigation does not collect an assessment. System opens **System > About**. Checks without a dedicated modern Settings page use their relevant parent page; availability depends on Windows version and edition.

Shortcuts always open settings on this computer, including when viewing a backup. No security setting is changed automatically. Redirected reports omit buttons and terminal control sequences.

## Save a JSON report

Choose the export format interactively:

```powershell
.\SecurityAssessment.exe --json
```

The prompt explains both formats. For scripts, specify the format directly (no prompt):

```powershell
.\SecurityAssessment.exe --json 0 "assessment.json"
.\SecurityAssessment.exe --json 1 "readable-assessment.json"
```

| Mode | Contents | Opens in the app viewer |
| --- | --- | --- |
| `0` Compact | Numbered field keys and numeric states. Booleans use 0/1; tri-state readings also support 2 = unknown and 3 = not applicable. | Yes |
| `1` Readable | Descriptive field names and text states for manual inspection or other tools. | No |

Omit the filename to generate one in the current folder. The destination folder must exist, and existing files are never overwritten. The command prints the saved file's path. Both formats save the displayed report and recorded scores, excluding hidden inventories and internal evidence. Compact encoding is **not encryption**; both formats contain system details.

### View a saved JSON report

```powershell
.\SecurityAssessment.exe --json view "assessment.json"
```

This opens the regular console report using the saved data and scores. A red warning box below the title states that you are viewing a backup and the results do not represent the current system state. It does not run another assessment.

Warnings are omitted from JSON exports. The saved report viewer displays **“Warnings are disabled when viewing an export”**. The viewer accepts only compact mode `0` reports. Readable mode `1` reports and older plain-text JSON exports are rejected with an explanation.

For command help:

```powershell
.\SecurityAssessment.exe --help
```

## Understanding the results

- The maximum score remains **1000**; BitLocker contributes up to **50** points.
- When any third-party antivirus is registered, Defender is **Not scored**, regardless of either product's state. The antivirus category uses third-party products only: confirmed enabled protection earns credit; disabled or unknown protection earns zero. The category cap remains **180** points.
- Network sign-in protection distinguishes an unconfigured policy, denied access, invalid data and read errors. An absent policy is not assumed to be enabled or disabled.
- Only verified results receive the corresponding credit. Unreadable or missing configuration is distinguished from a confirmed weakness.
- Warnings explain the findings and do not apply extra score deductions.
- Cached update results can differ from a fresh Windows Update scan.
- Saved reports contain machine and configuration details; review them before sharing.

This is a security configuration assessment, not an antivirus scanner or a guarantee that a computer is secure.

## Build and development

See [src/TECHNICAL.md](src/TECHNICAL.md) for build instructions, architecture, APIs, score weights and debugging details, and [src/JSON_FORMAT.md](src/JSON_FORMAT.md) for the compact JSON format.
