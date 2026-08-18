# IR-002 — Timeline

| Time | Event | Source |
|---|---|---|
| T0 | `net.exe` invoked, internally spawns `net1.exe` to execute `net1 user` under `NT AUTHORITY\SYSTEM` | Sysmon Event ID 1 (Process Creation) |
| T0 + Δ | Wazuh generates custom Rule `100100` alert (Level 15) | Wazuh Manager |

```
T0                                          T0 + Δ
 │                                             │
 ▼                                             ▼
net.exe → net1.exe                    Wazuh custom rule fires
"net1 user" executed as SYSTEM        (Rule 100100, Level 15)
```

This is a short-duration, single-action event rather than a multi-step chain — the timeline here is primarily used to record exact execution context (privilege level, parent process) for the record, rather than to correlate multiple stages of activity as in IR-001.
