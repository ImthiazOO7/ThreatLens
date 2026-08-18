# Detection: Encoded PowerShell Execution

**Rule ID:** `92057` (built-in Wazuh rule)
**Level:** 12
**Status:** ✅ Validated

## 1. Detection Name

PowerShell.exe spawned a PowerShell process which executed a base64-encoded command

## 2. Security Objective

Detect PowerShell execution using the `-EncodedCommand` parameter, which base64-encodes the actual command being run.

## 3. Why This Behavior Matters

PowerShell itself is a legitimate, heavily used Windows administration tool — which is precisely why attackers abuse it:

- It's already installed on virtually every Windows system
- It can execute arbitrary commands and interact directly with the Windows API
- Encoding the command makes plain-text command-line inspection significantly harder

So the presence of PowerShell is not suspicious on its own. What raises the bar is:

```
PowerShell
  + encoded command
  + unusual parent/child relationship
  + suspicious execution context
  = worth investigating
```

## 4. Data Source

Sysmon **Event ID 1 — Process Creation**, forwarded via Wazuh Agent.

## 5. Observed Telemetry

```
Image:          C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine:    powershell.exe -EncodedCommand ...
User:           TPCX1\Imthiaz
IntegrityLevel: High
ParentImage:    powershell.exe
ProcessId:      23924
```

## 6. Detection Logic

This is a **built-in** Wazuh rule (ID `92057`) that matches PowerShell process creation events where the command line contains `-EncodedCommand` (or equivalent shortened forms such as `-enc`). ThreatLens demonstrates triggering, tuning severity awareness, and investigating this rule rather than authoring it from scratch.

## 7. MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Technique | T1059.001 – PowerShell |
| Tactic | Execution |

## 8. Alert Evidence

- `evidence/encoded-powershell-alert.png` — the Wazuh alert as generated

## 9. Investigation Steps

This detection was investigated in full, including correlation with a related file-creation event, in [IR-001 — Encoded PowerShell Execution](../../investigations/IR-001-encoded-powershell/README.md).

## 10. False-Positive Considerations

Encoded PowerShell is used legitimately by:
- Administrator scripts and automation tooling
- Software installers and configuration management tools
- Security tools themselves (some EDR/AV agents encode their own PowerShell calls)

Context that increases suspicion:
- Unusual parent process (e.g. spawned from Office, a browser, or a script host instead of a terminal or scheduled task)
- Unexpected user account
- Unusual execution path or working directory
- Related file-creation, network, or registry activity immediately following execution

## 11. Analyst Conclusion

The rule reliably fires on `-EncodedCommand` usage. In this lab the encoded command was generated intentionally to exercise the detection and correlation workflow — it is documented as **observed in a controlled lab environment**, not a real compromise. The value of this detection is in demonstrating how an analyst investigates *encoded* PowerShell specifically, since obfuscation is itself a signal worth tracking down.
