# Kali Attack Scenarios

Detailed breakdown of the two lab exercises involving the Kali attacker/test workstation. Both are documented against actual, observed Wazuh telemetry — nothing here is inferred or assumed.

---

## Scenario 1 — SSH Authentication Attack

### Objective

Generate controlled failed SSH authentication activity against the Ubuntu server and validate that Wazuh detects and logs it correctly.

### Source

Kali Linux — `192.168.234.128`

### Target

Ubuntu Server — `192.168.234.130` (SSH service)

### Observed Telemetry

```
srcip:      192.168.234.128
srcuser:    wronguser
decoder:    sshd
full_log:   sshd[5022]: Failed password for invalid user wronguser
            from 192.168.234.128 port 47812 ssh2
```

### Detection

| Rule | Description | Level |
|---|---|---|
| `5710` | sshd: Attempt to login using a non-existent user | 5 |
| `5503` | PAM: User login failed | — |

**Rule groups observed:** `syslog`, `sshd`, `authentication_failed`, `invalid_login`

13 hits were recorded for Rule `5710` over the monitoring period, all originating from Kali's IP.

### MITRE ATT&CK

| Field | Value |
|---|---|
| Technique | T1110.001 – Password Guessing |
| Technique | T1021.004 – SSH |
| Tactics | Credential Access, Lateral Movement |

### Result

**Detection successful.** The source IP (`192.168.234.128`) was visible in Wazuh telemetry, and the failed authentication activity was fully recorded across multiple attempts.

**This was not a successful compromise.** Every observed event is a *failed* login attempt against a non-existent username. No event in this lab's telemetry shows a successful authentication from Kali, and no such claim is made.

### Evidence

- [`evidence/ssh-bruteforce-alert.png`](evidence/ssh-bruteforce-alert.png) — Rule `5710` alert list (13 hits)
- [`evidence/ssh-bruteforce-event-details.png`](evidence/ssh-bruteforce-event-details.png) — full raw event for a single attempt

---

## Scenario 2 — Persistence Validation

### Objective

Validate the registry Run Key persistence detection on the monitored Windows endpoint, using Kali as the controlled attacker/test workstation for the exercise.

### Attacker / Test Workstation

Kali Linux — `192.168.234.128`

### Monitored Endpoint

Windows 11 — `IMTHIAZ-WIN11`, running Wazuh Agent + Sysmon

### Detection

Registry Run Key Persistence — Rule `100102` (see [`detections/registry-persistence/README.md`](../detections/registry-persistence/README.md) for the full detection write-up)

### Result

Persistence telemetry was detected and documented using the existing registry-persistence evidence, which shows the modification occurring on the Windows endpoint (`msedge.exe` writing to a `CurrentVersion\Run` key).

**Important distinction:** No Wazuh event in this lab explicitly attributes the registry modification to Kali as its source. The telemetry proves *what happened on the Windows endpoint* — it does not prove *what triggered it*. Per this project's documentation standard, that causal link is not claimed.

Instead, the accurate relationship is:

> Kali served as the controlled attacker/test workstation used during the lab exercise, while the resulting persistence behavior was validated on the Windows endpoint through Wazuh telemetry.

### Evidence

This scenario does not have its own evidence folder — it references the existing detection evidence directly rather than duplicating it:

- [`detections/registry-persistence/evidence/registry-persistence-alert.png`](../detections/registry-persistence/evidence/registry-persistence-alert.png)
- [`detections/registry-persistence/evidence/registry-event-details.png`](../detections/registry-persistence/evidence/registry-event-details.png)

---

## What's Explicitly Out of Scope

An Nmap/network-scanning experiment was run separately from these two scenarios during lab testing. It did not produce a Wazuh or Suricata detection and has been intentionally excluded from ThreatLens. It is not referenced, alluded to, or "parked" anywhere in this repository — it simply isn't part of the documented project.
