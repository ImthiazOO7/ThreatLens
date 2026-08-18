# Hunting Methodology

## Process

```
Collect telemetry
      ↓
Define hypothesis
      ↓
Query / search
      ↓
Identify anomalies
      ↓
Pivot into events
      ↓
Correlate
      ↓
Validate
```

## Step-by-step

### 1. Collect telemetry
Ensure Sysmon and Wazuh Agent telemetry is flowing reliably from `IMTHIAZ-WIN11` before hunting — a hunt is only as good as the data underneath it.

### 2. Define a hypothesis
Start from a specific, testable question about attacker behavior rather than an open-ended "look for anything weird" search. See [`hypotheses.md`](hypotheses.md) for the hypotheses used in this project.

### 3. Query / search
Use the Wazuh Dashboard's event/discover view with targeted filters (e.g. `manager.name`, `rule.mitre.id: exists`, specific process image paths, or command-line substrings) to narrow down to relevant events.

### 4. Identify anomalies
Look for events that stand out relative to a baseline — unusual parent/child process relationships, unexpected users, uncommon execution paths, or rare command-line patterns.

### 5. Pivot into events
Once something interesting is found, pivot into the full raw event to examine every available field — not just the summary shown in the alert list.

### 6. Correlate
Search adjacent telemetry (same host, same process, close timestamp) for related process, file, or registry events, the same approach used in [IR-001](../investigations/IR-001-encoded-powershell/README.md).

### 7. Validate
Determine whether the pattern found is expected/benign or warrants escalation, and document the conclusion either way — including when the hunt turns up nothing notable, since a documented "no findings" hunt is still a valid and useful outcome.

## Why this matters

This process is what separates a SOC analyst who reacts to whatever a SIEM happens to alert on from one who can proactively identify gaps in detection coverage and find activity that existing rules don't yet catch.
