# Detection: Registry Run Key Persistence

**Rule ID:** `100102` (custom)
**Level:** 15
**Status:** ✅ Validated

## 1. Detection Name

CRITICAL: Registry Run Key Persistence Detected

## 2. Security Objective

Detect modifications to Windows Registry "Run" keys, which are commonly used to launch a program automatically at user logon.

## 3. Why This Behavior Matters

```
Attacker executes payload
        ↓
Persistence mechanism installed
        ↓
Registry Run key modified
        ↓
User logs in again
        ↓
Payload launches automatically
```

Registry Run keys are one of the oldest and most common Windows persistence mechanisms because they're simple, reliable, and don't require special privileges in most cases. That said, the mere presence of a Run key change is **not** proof of compromise — many legitimate applications register themselves this way.

## 4. Data Source

Sysmon **Event ID 13 — Registry Value Set**, forwarded via Wazuh Agent.

## 5. Observed Telemetry

```
RuleName:      T1060,RunKey
EventType:     SetValue
Image:         msedge.exe
TargetObject:  ...\Software\Microsoft\Windows\CurrentVersion\Run\...
```

## 6. Detection Logic

The rule matches Sysmon registry SetValue events where the target object path falls under a `...CurrentVersion\Run` (or `RunOnce`) key, flagging the modification at a critical severity level for analyst review.

Full rule definition: [`rule-100102.xml`](rule-100102.xml)

## 7. MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Technique | T1547.001 – Registry Run Keys / Startup Folder |
| Tactic | Persistence |

## 8. Alert Evidence

- `evidence/registry-persistence-alert.png` — the alert list for Rule `100102` in Wazuh (12 hits over the monitoring period)
- `evidence/registry-event-details.png` — the full raw Sysmon Event ID 13 record behind the alert, including `ProcessGuid`, `ProcessId`, `TargetObject`, and the modifying image (`msedge.exe`)

## 9. Investigation Steps

1. Identify the modifying process image (`msedge.exe` in this case) and its parent
2. Determine whether the process/user is expected to write to this key
3. Inspect the full `TargetObject` value and the data written
4. Check for related process creation or file creation events around the same timestamp
5. Determine whether the registered value points to a known, expected executable

## 10. False-Positive Considerations

Legitimate Run key activity includes:
- Application installation
- Software auto-update mechanisms
- Application configuration/preferences being set (e.g. a browser registering a startup helper)

Suspicious context that would raise confidence:
- An unrecognized or unsigned executable referenced in the value
- An unusual file path (e.g. `%TEMP%`, `%APPDATA%` with a randomized name)
- Registry write immediately following another suspicious event (e.g. an encoded PowerShell execution or a file drop)
- A process not normally expected to write to `Run` performing the write

## 11. Analyst Conclusion

The rule reliably detects Run key modification. In this lab, the observed event (`msedge.exe` writing to a Run key) is consistent with **normal browser behavior** and is documented as **observed in a controlled lab environment** — it demonstrates the detection firing correctly, not an actual persistence incident. This is an important example of why every registry-persistence alert must be evaluated in context rather than treated as inherently malicious.
