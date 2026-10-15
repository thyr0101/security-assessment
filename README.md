# Windows Security Assessment

A local Windows security auditor that checks how your computer is protected, gives it a score out of **1000**, and highlights settings that need attention.

It uses built-in Windows interfaces. It does not contact online services, run external commands, install software, or change security settings.

## What it checks

- **Hardware protection:** Secure Boot, the TPM security chip, memory integrity, and protection for sign-in secrets.
- **Windows protection:** permission prompts, protection against memory attacks, Smart App Control, protected sign-in services, automatic locking, and AutoPlay restrictions.
- **Antivirus:** Microsoft Defender protection or antivirus products registered with Windows, including separate product scores.
- **Network protection:** firewall profiles, file-sharing safeguards, remote access authentication, and protection against older sign-in methods.
- **Drive encryption:** BitLocker coverage across fixed volumes, grouped beneath their physical disks.
- **Account protection:** secure permission prompts, the built-in Guest account, account lockout, and Remote Assistance invitations.
- **Windows Update:** pending updates, update services, restart requirements, and installation results. Pending updates are listed without affecting the score.

The report also includes startup and threshold scan results. Privacy settings and minimum password length are not collected.

## Run an assessment

Windows 10 or newer is required. Open a terminal in the folder containing the executable:

```powershell
.\SecurityAssessment.exe
```

Run the terminal **as administrator** for the fullest assessment. Without elevation, restricted checks remain unverified instead of being reported as disabled.

The console ends with the **rule breakdown**, **total score**, and **warnings**, in that order. Warnings are grouped as Critical, High, Medium, or Low and include an action to review. Missing evidence is clearly identified as a verification gap.

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
| `0` Compact | Numbered field keys with actual values; Boolean states use 0/1. Disabled = 0, enabled = 1, unknown = 2. | Yes |
| `1` Readable | Descriptive field names and text states for manual inspection or other tools. | No |

Omit the filename to generate one in the current folder. The destination folder must exist, and existing files are never overwritten. The command prints the saved file's path. Compact encoding is **not encryption**; both formats contain system details.

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
- Network sign-in protection distinguishes an unconfigured policy, denied access, invalid data and read errors. An absent policy is not assumed to be enabled or disabled.
- Only verified results receive the corresponding credit. Unreadable or missing configuration is distinguished from a confirmed weakness.
- Warnings explain the findings and do not apply extra score deductions.
- Cached update results can differ from a fresh Windows Update scan.
- Saved reports contain machine and configuration details; review them before sharing.

This is a security configuration assessment, not an antivirus scanner or a guarantee that a computer is secure.

## Build and development

See [src/TECHNICAL.md](src/TECHNICAL.md) for build instructions, architecture, APIs, score weights, report format, and debugging details.
