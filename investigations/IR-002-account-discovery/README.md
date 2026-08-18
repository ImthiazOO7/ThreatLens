# IR-002: `net.exe` Account Discovery Activity

**Status:** Investigated — controlled lab activity
**Detection:** [`detections/account-discovery/`](../../detections/account-discovery/README.md) — Rule `100100` (custom), Level 15
**MITRE:** T1087 – Account Discovery (Discovery)

## Summary

Wazuh's custom Rule `100100` fired on `net1.exe` execution consistent with `net user` account enumeration, spawned from `net.exe`, running under `NT AUTHORITY\SYSTEM`. This investigation confirms the process relationship is expected Windows behavior for the `net user` command and evaluates whether the activity is consistent with legitimate use or reconnaissance.

## Affected Endpoint

| Field | Value |
|---|---|
| Agent | IMTHIAZ-WIN11 |
| Agent ID | 001 |
| Executing context | NT AUTHORITY\SYSTEM |

## Step 1 — Alert Identification

```
Rule:        100100 (custom)
Description: Custom Detection - net.exe Discovery
Level:       15
```

## Step 2 — Raw Event Examination

```
CommandLine:    C:\WINDOWS\System32\net1 user
Image:          C:\Windows\SysWOW64\net1.exe
ParentImage:    C:\Windows\SysWOW64\net.exe
IntegrityLevel: System
User:           NT AUTHORITY\SYSTEM
```

`net1.exe` is a legitimate Windows helper binary that `net.exe` spawns internally to execute commands — this parent/child pairing is expected and is not itself a red flag.

## Step 3 — Context

Execution under `NT AUTHORITY\SYSTEM` at `System` integrity indicates this ran with the highest level of local privilege available on Windows. In this lab, the command was executed deliberately to exercise the detection; in a production environment, `SYSTEM`-level account enumeration would warrant checking:

- What parent process or service triggered this (was it a scheduled task, a remote-management tool, an interactive session, or something else)?
- Whether this matches a known administrative or monitoring routine
- Whether it's followed by further discovery, credential-access, or lateral-movement activity

## Step 4 — MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Technique | T1087 – Account Discovery |
| Tactic | Discovery |

## Step 5 — False-Positive Assessment

`net user` is a routine administrative command. Running as `SYSTEM` raises the bar for scrutiny but is not unusual for scheduled tasks, monitoring agents, or management tooling that legitimately runs under that context. No corroborating evidence of malicious follow-on activity was observed in this lab session.

## Step 6 — Analyst Conclusion

The detection reliably identifies `net.exe`/`net1.exe`-based account enumeration and correctly captured the full process lineage and privilege context needed for triage. The activity in this case is documented as **observed in a controlled lab environment**; the investigation demonstrates the questions an analyst should ask before escalating a discovery alert — specifically, evaluating *what triggered the command* and *what happened afterward*, not just the command itself.

## Evidence

- `evidence/account-discovery-event.png`
