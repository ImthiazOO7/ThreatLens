# Kali Attacker Workstation

## Overview

Kali Linux is used as the controlled attacker/test workstation within the ThreatLens laboratory environment. It is **not** a monitored asset and does **not** run a Wazuh Agent — it exists solely to generate controlled security activity against the monitored environment (the Ubuntu server and the Windows 11 endpoint), so that the detection and investigation workflow documented elsewhere in this repository has real, observable telemetry to work from.

## Network Identity

| Component | Address | Role |
|---|---|---|
| Kali Linux | `192.168.234.128` | Attacker / test workstation (not a Wazuh agent) |
| Ubuntu Server | `192.168.234.130` | Wazuh Manager / Indexer / Dashboard — monitored Linux host |
| Windows 11 Endpoint | `IMTHIAZ-WIN11` | Wazuh Agent + Sysmon — monitored endpoint |

## Activities

### SSH Authentication Testing → Ubuntu Server

Kali generated controlled SSH authentication attempts against the Ubuntu server (`192.168.234.130`). Wazuh observed and recorded the resulting failed-authentication telemetry originating from Kali's IP (`192.168.234.128`).

| Rule | Description | Level |
|---|---|---|
| `5710` | sshd: Attempt to login using a non-existent user | 5 |
| `5503` | PAM: User login failed | — |

**MITRE ATT&CK:** T1110.001 – Password Guessing, T1021.004 – SSH

Full scenario write-up: [`attack-scenarios.md`](attack-scenarios.md#scenario-1--ssh-authentication-attack)

### Persistence Testing → Windows 11 Endpoint

Kali served as the controlled attacker/test workstation during the persistence-testing exercise. The actual persistence behavior — a registry Run Key modification — was observed and validated **on the Windows endpoint**, not on Kali or Ubuntu, via the existing [Registry Persistence detection](../detections/registry-persistence/README.md) (Rule `100102`).

Full scenario write-up: [`attack-scenarios.md`](attack-scenarios.md#scenario-2--persistence-validation)

## Telemetry Flow

```
Kali Linux (192.168.234.128)
  Attacker / Test Workstation
        │
        │ Controlled attack / test activity
        │
        ├──────────────────────────────┐
        ▼                              ▼
Ubuntu Server (192.168.234.130)   Windows 11 Endpoint
  SSH authentication attempts       Persistence testing
        │                              │
        ▼                              ▼
        └──────────── Wazuh Telemetry ─┘
                         │
                         ▼
                  Wazuh Manager
                         │
                         ▼
                  SOC Investigation
                         │
                         ▼
                  MITRE ATT&CK Mapping
```

## Evidence

- `evidence/ssh-bruteforce-alert.png` — Wazuh alert(s) for the SSH authentication-failure activity originating from Kali

The registry persistence evidence remains in its original location — [`detections/registry-persistence/evidence/`](../detections/registry-persistence/evidence/) — and is referenced here rather than duplicated.

## Scope & Honesty Notes

- Kali is documented **only** for activity that produced genuine, observable Wazuh telemetry.
- This does **not** represent a successful compromise — the SSH activity produced authentication **failures**, not a successful login. No claim of successful compromise is made anywhere in this repository.
- Kali does not run a Wazuh Agent; it is intentionally outside the monitored asset inventory.
- An earlier Nmap/network-scanning experiment was tested separately, did not produce a Wazuh or Suricata detection, and has been intentionally excluded from project scope. It is not documented here or elsewhere in the repository.
- Kali is not claimed to have directly caused the Windows registry persistence event unless a specific piece of telemetry proves that relationship — it did not, so that relationship is described only as "Kali was the attacker/test workstation used during the exercise; the persistence behavior was independently validated on the Windows endpoint."
