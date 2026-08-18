# IR-001 — Timeline

| Time | Event | Source |
|---|---|---|
| 21:50:01 | `powershell.exe` executes with `-EncodedCommand`, spawned from a parent `powershell.exe` process, under user `TPCX1\Imthiaz` | Sysmon Event ID 1 (Process Creation) |
| 21:50:02 | The same `powershell.exe` process creates a `.ps1` file: `C:\Users\Imthiaz\AppData\Local\Temp\__PSScriptPolicyTest_....ps1` | Sysmon Event ID 11 (File Creation) |
| 21:50:03 | Wazuh generates Rule `92057` alert (Level 12) for the encoded PowerShell execution | Wazuh Manager |

```
21:50:01                21:50:02                     21:50:03
   │                        │                             │
   ▼                        ▼                             ▼
Encoded PowerShell   →  .ps1 file created in       →  Wazuh alert
execution begins        user Temp directory           generated
(Process ID 23924)      (correlated child event)      (Rule 92057, Level 12)
```

## Why this sequence matters

Three seconds separates process execution from the correlated file-creation event, and the file creation is attributed to the **same process image** (`powershell.exe`) — a tight enough correlation to treat these as a single unit of activity rather than two unrelated events. This is the core of event correlation: connecting telemetry across event types (process + file) using shared identifiers (image path, timestamp proximity, process ID) rather than relying on any single alert in isolation.
