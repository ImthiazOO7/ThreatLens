# False-Positive Analysis

A detection isn't automatically "good" just because it generates alerts. Every detection in ThreatLens is paired with an explicit assessment of what *legitimate* activity could trigger it — this is what separates a mature detection portfolio from a noisy one.

## Why This Matters

All three core detections in this project are built on **legitimate Windows tools and mechanisms**:

- `net.exe` / `net1.exe` — a signed, built-in Windows utility
- PowerShell — a core Windows administration and automation tool
- Registry Run keys — a standard, widely used autostart mechanism

None of these are inherently malicious. The analyst's job is to evaluate **context**, not just presence.

## The Context-Evaluation Chain

```
Detection
   ↓
Context
   ↓
Process / user / path
   ↓
Parent process
   ↓
Command line
   ↓
Timestamp
   ↓
Related events
   ↓
Analyst conclusion
```

## Per-Detection False-Positive Notes

### PowerShell (Rule 92057 — Encoded Command)

| Legitimate triggers | Suspicious context |
|---|---|
| Administrator scripts | Encoded commands specifically (obfuscation is itself a mild signal) |
| Windows management automation | Unusual parent process |
| Software installation | Unusual execution path |
| Security tools (some encode their own calls) | Unexpected user account |
| | Related payload/file activity immediately following |

### `net.exe` (Rule 100100 — Account Discovery)

| Legitimate triggers | Suspicious context |
|---|---|
| Administrator troubleshooting | Unexpected account enumeration pattern |
| System/inventory management scripts | Unusual execution chain |
| Help-desk verification | Suspicious parent process |

### Registry Run Key (Rule 100102 — Persistence)

| Legitimate triggers | Suspicious context |
|---|---|
| Application installation | Unknown or unsigned executable referenced |
| Software updates | Unusual file path (e.g. `%TEMP%`, randomized names) |
| Application configuration | Persistence write following another suspicious event |
|  | Unexpected process performing the write |

## Guiding Principle

> A detection firing tells you *what happened*. It does not, by itself, tell you *what it means*. Every conclusion in this repository is based on the full context available — not the rule's severity level alone.
