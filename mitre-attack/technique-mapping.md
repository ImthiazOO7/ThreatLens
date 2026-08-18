# Technique Mapping — Detail

## T1059.001 — PowerShell

**Tactic:** Execution
**Detection:** Rule `92057` — Encoded PowerShell Execution

```
Encoded PowerShell
       ↓
T1059.001
       ↓
PowerShell
       ↓
Execution
```

Adversaries use PowerShell to execute commands, download and run payloads, and interact directly with the Windows API. Encoding commands is a common technique to evade simple string-based command-line inspection. ThreatLens detects this pattern and correlates it with follow-on file-creation activity (see [IR-001](../investigations/IR-001-encoded-powershell/README.md)).

---

## T1087 — Account Discovery

**Tactic:** Discovery
**Detection:** Rule `100100` (custom) — `net.exe` Discovery

```
net.exe user discovery
       ↓
T1087
       ↓
Account Discovery
       ↓
Discovery
```

Adversaries enumerate local and domain accounts to identify privileged targets and plan lateral movement or privilege escalation. `net user` (via `net.exe`/`net1.exe`) is one of the most common living-off-the-land tools used for this purpose. See [IR-002](../investigations/IR-002-account-discovery/README.md).

---

## T1547.001 — Registry Run Keys / Startup Folder

**Tactic:** Persistence
**Detection:** Rule `100102` (custom) — Registry Run Key Persistence

```
Registry Run key modification
       ↓
T1547.001
       ↓
Registry Run Keys / Startup Folder
       ↓
Persistence
```

Adversaries add entries to Registry Run/RunOnce keys so that a program executes automatically at user logon, providing a simple and durable persistence mechanism. ThreatLens detects writes to these keys and documents the false-positive considerations required to distinguish legitimate application behavior from actual persistence. See the [registry-persistence detection](../detections/registry-persistence/README.md).

---

## Coverage note

This is a small, honest slice of the ATT&CK matrix — three techniques across three tactics — not a claim of comprehensive coverage. Expanding technique coverage (e.g. credential access, lateral movement, defense evasion) is a natural next step for the project, tracked informally as future work rather than presented as already implemented.
