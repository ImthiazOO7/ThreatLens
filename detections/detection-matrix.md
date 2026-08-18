# Detection Matrix

Summary of every detection validated in ThreatLens. Only detections with confirmed, reproducible alerts are listed here — see [`documentation/limitations.md`](../documentation/limitations.md) for attempts that did not meet this bar.

| Detection | Rule ID | Type | Level | Data Source | MITRE Technique | Tactic | Status |
|---|---|---|---|---|---|---|---|
| [Account Discovery](account-discovery/README.md) | `100100` | Custom | 15 | Sysmon Event ID 1 (Process Creation) | T1087 – Account Discovery | Discovery | ✅ Validated |
| [Encoded PowerShell Execution](powershell/README.md) | `92057` | Built-in Wazuh | 12 | Sysmon Event ID 1 (Process Creation) | T1059.001 – PowerShell | Execution | ✅ Validated |
| [Registry Run Key Persistence](registry-persistence/README.md) | `100102` | Custom | 15 | Sysmon Event ID 13 (Registry Value Set) | T1547.001 – Registry Run Keys / Startup Folder | Persistence | ✅ Validated |
| Active Response (`firewall-drop`) | — | Custom (response) | — | — | — | — | ⛔ Parked — not reliably validated |
| Scheduled Task Detection | `100103` | Custom | — | Sysmon | T1053 – Scheduled Task/Job | Execution / Persistence | ⛔ Parked — alert not reliably returned |

## How to read "Custom" vs "Built-in"

- **Custom** rules were authored specifically for this lab and live in this repository as `.xml` files (e.g. `rule-100100.xml`).
- **Built-in** rules (e.g. `92057`) ship with the Wazuh ruleset itself — ThreatLens demonstrates *tuning, triggering, and investigating* them rather than authoring them from scratch.

## Detection engineering pipeline

Every custom detection in this repo followed the same pipeline:

```
Raw Sysmon event
       ↓
Wazuh decoder
       ↓
Rule matching (custom XML rule)
       ↓
Severity level assigned
       ↓
MITRE ATT&CK tag applied
       ↓
Alert generated in Wazuh Dashboard
```
