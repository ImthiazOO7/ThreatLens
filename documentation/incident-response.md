# Incident Response Methodology

This document describes the investigation methodology used across every case in [`investigations/`](../investigations/). It's the repeatable process ThreatLens follows any time an alert needs to be turned into a documented finding.

## The 8-Step Process

### Step 1 — Alert Identification
Record the rule ID, description, and severity level exactly as generated (e.g. `Rule 92057, Encoded PowerShell, Level 12`).

### Step 2 — Determine the Affected Endpoint
Confirm which agent generated the event (`IMTHIAZ-WIN11`, Agent ID `001`) — never assume; always verify against the raw event.

### Step 3 — Examine the Raw Event
Pull the full Sysmon/Wazuh event and record every relevant field:
- Timestamp
- Image (executable path)
- Command line
- User
- Process ID
- Parent process

### Step 4 — Examine Surrounding Activity
Search adjacent telemetry for related events:
- Related process creation
- File creation
- Registry changes
- Authentication events
- Other alerts around the same time window

### Step 5 — Build a Timeline
Place every related event in chronological order to understand the sequence of activity, not just the isolated alert.

### Step 6 — Map to MITRE ATT&CK
Identify the specific technique and tactic the behavior represents.

### Step 7 — Determine Context
Ask, for every case, before concluding anything:
- Was this expected?
- Was it user-generated or system-generated?
- Was it administrative activity?
- Is there evidence supporting malicious intent?
- Are there related indicators elsewhere in the environment?

### Step 8 — Analyst Conclusion
State a conclusion grounded in the evidence collected — never in the severity level alone.

**Wrong:** *"Level 15 = definitely malware."*
**Right:** *"The telemetry indicates [specific behavior]. The observed context [does / does not] support malicious activity, for the following reasons: ..."*

## Detection Engineering vs. Investigation

These are two distinct skills, both demonstrated across this repository:

| | Detection Engineering | Investigation |
|---|---|---|
| Core question | *Can I reliably detect this behavior?* | *What does this specific alert actually mean?* |
| Example | `net.exe` execution → Rule `100100` → Level 15 alert | Alert → raw event → command line → parent process → user → related events → timeline → conclusion |
| Output | A rule that fires consistently | A documented, evidence-based finding |

## Evidence Sources Used

| Source | Provides |
|---|---|
| Wazuh | Alert, rule ID, severity, agent, MITRE tag, event details |
| Sysmon | Process creation, parent process, command line, file creation, registry modification, hashes, process IDs |
| Windows Event Viewer | Direct validation of the underlying Sysmon event on the endpoint itself |
| Microsoft Defender | Endpoint protection validation |

Using multiple, independent sources — rather than a single screenshot — is what makes a finding defensible.
