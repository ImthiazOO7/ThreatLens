# MITRE ATT&CK Matrix

ThreatLens maps every validated detection to a MITRE ATT&CK technique and tactic, turning custom rules into behavior that's understood in an established, industry-standard adversary framework.

## Coverage Summary

| Tactic | Technique | Technique ID | Detection |
|---|---|---|---|
| Discovery | Account Discovery | T1087 | [`net.exe` Account Discovery](../detections/account-discovery/README.md) — Rule `100100` |
| Execution | PowerShell | T1059.001 | [Encoded PowerShell Execution](../detections/powershell/README.md) — Rule `92057` |
| Persistence | Registry Run Keys / Startup Folder | T1547.001 | [Registry Run Key Persistence](../detections/registry-persistence/README.md) — Rule `100102` |
| Credential Access | Password Guessing | T1110.001 | [SSH Authentication Attack](../kali-attacker/attack-scenarios.md#scenario-1--ssh-authentication-attack) — Rule `5710` |
| Lateral Movement | Remote Services: SSH | T1021.004 | [SSH Authentication Attack](../kali-attacker/attack-scenarios.md#scenario-1--ssh-authentication-attack) — Rule `5710` |

## Why MITRE mapping matters

Without MITRE context, a detection is just an arbitrary rule number:

```
Rule 100100
net.exe detected
```

With MITRE context, it becomes part of a recognized adversary behavior model:

```
Rule 100100
       ↓
Account Discovery
       ↓
Discovery tactic
       ↓
T1087
```

This makes the detection immediately understandable to anyone familiar with the ATT&CK framework — including recruiters, hiring managers, and other analysts — without needing to read the rule logic itself.

## Kill-chain view

The three endpoint-side detections in ThreatLens span three different tactics on the Windows 11 endpoint, giving a small but genuine cross-section of the ATT&CK matrix rather than repeated coverage of a single stage. The Kali-originated SSH activity against the Ubuntu server adds a fourth and fifth technique from a different vantage point — credential access and lateral movement, observed from the *target* side rather than the endpoint side:

```
Execution (T1059.001)  →  Discovery (T1087)  →  Persistence (T1547.001)
   PowerShell               net.exe                Registry Run Key

Credential Access (T1110.001)  →  Lateral Movement (T1021.004)
   Password Guessing (SSH)          Remote Services: SSH
```

Note: the credential-access/lateral-movement pair represents **failed** authentication attempts only — no successful login or lateral movement is claimed or supported by the collected telemetry.

Further technique-level detail: [`technique-mapping.md`](technique-mapping.md)

## Evidence

- `evidence/mitre-attack-events.png` — Wazuh's MITRE ATT&CK Events view, filtered to `manager.name: ubuntu-server` and `rule.mitre.id: exists`, showing 2,729 MITRE-tagged hits across the monitoring period with technique ID, tactic, and rule description columns visible
