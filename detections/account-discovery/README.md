# Detection: Account Discovery via `net.exe`

**Rule ID:** `100100` (custom)
**Level:** 15
**Status:** ✅ Validated

## 1. Detection Name

Custom Detection — `net.exe` Discovery

## 2. Security Objective

Detect the use of `net.exe` (via `net1.exe`) to enumerate local or domain user accounts — a common early-stage reconnaissance action.

## 3. Why This Behavior Matters

An attacker who gains a foothold on a Windows system frequently needs to answer:

- What user accounts exist on this system?
- Are there privileged/administrative accounts?
- Who are potential lateral-movement or privilege-escalation targets?

`net user`, executed through `net.exe`/`net1.exe`, is one of the simplest and most common ways to answer that question — which is exactly why it's a legitimate Windows utility *and* a common discovery tool.

```
Execution
   ↓
Discovery (net.exe user enumeration)
   ↓
Who exists on this system?
   ↓
Could this support privilege escalation / lateral movement?
```

## 4. Data Source

Sysmon **Event ID 1 — Process Creation**, forwarded via Wazuh Agent to the Wazuh Manager.

## 5. Observed Telemetry

```
CommandLine:   C:\WINDOWS\System32\net1 user
Image:         C:\Windows\SysWOW64\net1.exe
ParentImage:   C:\Windows\SysWOW64\net.exe
IntegrityLevel: System
User:          NT AUTHORITY\SYSTEM
```

Note the parent/child relationship: `net.exe` spawns `net1.exe` as a helper process — this is normal Windows behavior for the `net user` command and is expected in the process tree.

## 6. Detection Logic

The rule matches on `net1.exe` execution with a command line consistent with account enumeration (`net1 user`), tagged at a high severity level given the reconnaissance implications.

Full rule definition: [`rule-100100.xml`](rule-100100.xml)

## 7. MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Technique | T1087 – Account Discovery |
| Tactic | Discovery |

## 8. Alert Evidence

- `evidence/rule-100100.png` — the custom rule as configured in Wazuh
- `evidence/account-discovery-alert.png` — the alert firing against the observed event

## 9. Investigation Steps

See [IR-002 — Account Discovery Activity](../../investigations/IR-002-account-discovery/README.md) for the full investigation walkthrough of this detection firing.

## 10. False-Positive Considerations

`net.exe`/`net1.exe` is a **legitimate, signed Windows utility**. This detection does **not** mean malware was found — it means account-enumeration activity occurred and should be evaluated in context.

Legitimate triggers include:
- Administrator troubleshooting
- System/inventory management scripts
- Help-desk account verification

Suspicious context that would raise confidence:
- Unexpected parent process (e.g. spawned from a script host, Office app, or browser instead of a normal admin session)
- Execution by a non-administrative user
- Immediately followed by further discovery or lateral-movement commands
- Off-hours execution with no corresponding ticket/change record

## 11. Analyst Conclusion

The rule reliably detects `net.exe`-based account discovery. In this lab, the activity was intentionally generated to exercise the detection; it is documented as **observed in a controlled lab environment**, not a real compromise. The analyst's job in a live environment would be to evaluate the surrounding context (user, parent process, timing, follow-on activity) before escalating.
