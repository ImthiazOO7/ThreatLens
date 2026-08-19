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

## T1110.001 — Password Guessing

**Tactic:** Credential Access
**Detection:** Rule `5710` (built-in) — SSH non-existent-user login attempt

```
Repeated SSH authentication attempts
       ↓
T1110.001
       ↓
Password Guessing
       ↓
Credential Access
```

Adversaries attempt repeated authentication against a service using guessed or brute-forced credentials. In this lab, the Kali attacker/test workstation (`192.168.234.128`) generated repeated SSH login attempts against the Ubuntu server (`192.168.234.130`), which Wazuh captured as failed-authentication telemetry (Rule `5710` — non-existent user, and Rule `5503` — PAM login failure). Every observed event is a **failed** attempt; no successful authentication is present in the collected telemetry, and none is claimed. Full write-up: [`kali-attacker/attack-scenarios.md`](../kali-attacker/attack-scenarios.md#scenario-1--ssh-authentication-attack).

---

## T1021.004 — Remote Services: SSH

**Tactic:** Lateral Movement

```
SSH used as the transport for the attempted authentication
       ↓
T1021.004
       ↓
Remote Services: SSH
       ↓
Lateral Movement
```

SSH is a standard remote-access protocol that adversaries abuse to move between hosts once valid credentials are obtained. This technique is mapped here because SSH was the protocol used for the credential-testing activity in this lab — it does **not** imply that lateral movement was achieved. No credentials were successfully validated, and no session was established as a result of this activity.

---

## Coverage note

This is a small, honest slice of the ATT&CK matrix — five techniques across four tactics (Execution, Discovery, Persistence, Credential Access, Lateral Movement) — not a claim of comprehensive coverage. The credential-access and lateral-movement techniques reflect **failed** authentication activity only. Expanding technique coverage further (e.g. defense evasion, collection, exfiltration) remains a natural next step for the project, tracked informally as future work rather than presented as already implemented.
