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

The report also includes selected installed applications and startup/threshold scan results. Privacy settings and minimum password length are not collected.

## Run an assessment

Windows 10 or newer is required. Open a terminal in the folder containing the executable:

```powershell
.\SecurityAssessment.exe
```

Run the terminal **as administrator** for the fullest assessment. Without elevation, restricted checks remain unverified instead of being reported as disabled.

To skip executable hashing:

```powershell
.\SecurityAssessment.exe --no-hash
```

The console ends with the **rule breakdown**, **total score**, and **warnings**, in that order. Warnings are grouped as Critical, High, Medium, or Low and include an action to review. Missing evidence is clearly identified as a verification gap.

## Save a JSON report

Generate a report with an automatic filename in the current folder:

```powershell
.\SecurityAssessment.exe --json
```

Or choose a filename:

```powershell
.\SecurityAssessment.exe --json "reports\assessment.json"
.\SecurityAssessment.exe --json "assessment.json" --no-hash
```

The destination folder must exist. Existing files are never overwritten. The command prints the saved file's path, rather than the report contents.

### View a saved JSON report

```powershell
.\SecurityAssessment.exe --json view "assessment.json"
```

This opens the regular console report using the saved data and scores. A notice at the top states that you are viewing a file and the results are not live. It does not run another assessment.

Warnings are omitted from JSON exports. The saved report viewer displays **“Warnings are disabled when viewing an export”**, including when opening older reports that contain warnings. Older reports with the expected system and score structure remain supported; fields absent from those files cannot be restored.

For command help:

```powershell
.\SecurityAssessment.exe --help
```

## Understanding the results

- The maximum score remains **1000**; BitLocker contributes up to **50** points.
- Only verified results receive the corresponding credit. Unreadable or missing configuration is distinguished from a confirmed weakness.
- Warnings explain the findings and do not apply extra score deductions.
- Cached update results can differ from a fresh Windows Update scan.
- Saved reports contain machine and configuration details; review them before sharing.

This is a security configuration assessment, not an antivirus scanner or a guarantee that a computer is secure.

## Build and development

See [src/TECHNICAL.md](src/TECHNICAL.md) for build instructions, architecture, APIs, score weights, report format, and debugging details.
