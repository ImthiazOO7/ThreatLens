# Detection Engineering Methodology

This document explains *how* the custom detections in this repository were built, not just what they detect.

## The general pipeline

Every custom detection followed the same process:

```
1. Identify a behavior worth detecting (based on MITRE ATT&CK technique)
        ↓
2. Determine the Sysmon event type that captures it
   (Event ID 1 - Process Creation, Event ID 11 - File Creation, Event ID 13 - Registry)
        ↓
3. Generate the behavior in the lab to see the raw event structure
        ↓
4. Identify the specific fields that reliably distinguish the behavior
   (Image, ParentImage, CommandLine, TargetObject, etc.)
        ↓
5. Write a custom Wazuh rule matching those fields
        ↓
6. Assign a severity level and MITRE ATT&CK tag
        ↓
7. Re-generate the behavior and confirm the rule fires correctly
        ↓
8. Document the rule, the evidence, and known false-positive conditions
```

## Rule numbering

Custom rules in this lab use IDs in the `100100`–`100199` range, which is the standard local/custom rule ID space in Wazuh (reserved outside the default ruleset to avoid collisions with built-in rules).

| Rule ID | Purpose | Status |
|---|---|---|
| `100100` | `net.exe` account discovery | ✅ Validated |
| `100102` | Registry Run Key persistence | ✅ Validated |
| `100103` | Scheduled task detection | ⛔ Parked (see [limitations.md](limitations.md)) |

## Severity levels used

| Level | Meaning in this lab |
|---|---|
| 12 | Notable execution behavior worth review (e.g. encoded PowerShell) |
| 15 | High-confidence, high-impact behavior (discovery, persistence) requiring analyst attention |

## Detection engineering vs. investigation

These are treated as two distinct skills throughout this repository:

**Detection engineering** asks: *"Can I reliably detect this behavior?"*
```
Behavior (e.g. net.exe discovery) → Custom rule → Alert fires reliably
```

**Investigation** asks: *"What does this specific alert actually mean?"*
```
Alert → Raw event → Command line → Parent process → User → Related events → Timeline → Conclusion
```

Building a rule that fires is only half the work — every detection in [`detections/`](../detections/) is paired with an investigation write-up in [`investigations/`](../investigations/) that demonstrates the second half.

## Why only three detections are presented as validated

Two additional detection efforts (Active Response `firewall-drop`, and Rule `100103` for scheduled tasks) were built and tested but did not reliably produce the expected result. Rather than include unverified behavior in the validated capability list, they are documented separately as parked work. See [`limitations.md`](limitations.md).
