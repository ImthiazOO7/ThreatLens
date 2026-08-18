# IR-001: Encoded PowerShell Execution & Correlated File Creation

**Status:** Investigated — controlled lab activity
**Detection:** [`detections/powershell/`](../../detections/powershell/README.md) — Rule `92057`, Level 12
**MITRE:** T1059.001 – PowerShell (Execution)

## Summary

Wazuh detected a PowerShell process executing a base64-encoded command on `IMTHIAZ-WIN11`. Rather than treating the alert in isolation, this investigation traced the process telemetry, identified the parent/child relationship, correlated a related file-creation event, and built a short timeline of the activity.

## Affected Endpoint

| Field | Value |
|---|---|
| Agent | IMTHIAZ-WIN11 |
| Agent ID | 001 |
| User | TPCX1\Imthiaz |

## Step 1 — Alert Identification

```
Rule:        92057
Description: PowerShell.exe spawned a PowerShell process which executed
             a base64 encoded command
Level:       12
```

## Step 2 — Raw Event Examination

```
Image:          C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine:    powershell.exe -EncodedCommand ...
User:           TPCX1\Imthiaz
IntegrityLevel: High
ParentImage:    powershell.exe
ProcessId:      23924
```

The process is running at **High** integrity under a standard user context, launched from a parent PowerShell process — consistent with an interactive or scripted PowerShell session rather than a privileged system process.

## Step 3 — Surrounding Activity / Correlation

Searching Sysmon telemetry around the same timestamp surfaced a related **Event ID 11 (File Creation)**:

```
Image:          C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetFilename: C:\Users\Imthiaz\AppData\Local\Temp\__PSScriptPolicyTest_....ps1
```

This is a `.ps1` file created directly by the PowerShell process itself in the user's Temp directory — the kind of artifact worth flagging for review, and exactly the sort of pivot a SOC analyst should make instead of stopping at the initial alert.

Full evidence interpretation: [`evidence.md`](evidence.md)

## Step 4 — Timeline

See [`timeline.md`](timeline.md) for the full reconstructed sequence.

## Step 5 — MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Technique | T1059.001 – PowerShell |
| Tactic | Execution |

## Step 6 — Context & False-Positive Assessment

Encoded PowerShell and `.ps1` temp-file creation are both things legitimate tooling does (installers, config management, `__PSScriptPolicyTest_*.ps1` in particular is a filename pattern Windows itself generates when checking PowerShell script-execution policy — not automatically evidence of anything malicious). What matters is the combination and context:

- ✅ Encoded command executed
- ✅ Correlated file creation immediately after
- ⚠️ No evidence in this lab of network exfiltration, lateral movement, or additional payload execution
- ⚠️ Activity was intentionally generated in a controlled lab session, not observed "in the wild"

## Step 7 — Analyst Conclusion

The telemetry supports a confirmed case of **encoded PowerShell execution with a directly correlated file-creation event**, which is exactly the pattern an analyst should escalate for further review in a production environment. In this lab, the activity was intentionally generated to exercise the detection and investigation workflow. It is documented as **observed in a controlled lab environment** — not a real intrusion — and its value is demonstrating the investigation methodology itself: alert → raw event → correlation → timeline → MITRE mapping → context-based conclusion.

## Evidence

- `evidence/powershell-event-details.png`
- `evidence/correlated-file-creation.png`
