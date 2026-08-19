# Architecture

This directory documents how the ThreatLens lab environment was built, before any detection engineering or investigation work began.

## Why the environment came first

Detections depend entirely on telemetry, and telemetry depends entirely on a working monitoring pipeline:

```
No environment → No telemetry → No event → No detection → No investigation
```

So the first phase of ThreatLens was standing up and validating the monitoring pipeline itself — not attacks, not rules, just proving that data flows correctly from endpoint to SIEM.

## Components

### Kali Linux — Attacker / Security Tester Machine
- Used as the controlled attacker/test workstation, connecting over the network to both the Ubuntu server and the Windows 11 endpoint
- Source of two categories of controlled activity: (1) SSH authentication attempts against the Ubuntu server, and (2) endpoint-side test activity investigated on the Windows 11 endpoint (encoded PowerShell execution, `net.exe` account discovery, registry Run key modification)
- Not part of the monitored/defended environment itself — Kali does **not** run a Wazuh Agent and generates no defensive telemetry of its own. It only appears in telemetry indirectly, as the *source* of activity observed by monitored hosts (e.g. as `srcip` in the Ubuntu server's SSH logs)

### Ubuntu Server — Wazuh backend
- Wazuh Manager — receives agent telemetry, applies decoders/rules, generates alerts
- Wazuh Indexer — stores and indexes events
- Wazuh Dashboard — visualization, event search, MITRE views
- Also a monitored asset in its own right — its SSH service was the target of the Kali authentication-testing scenario (see [`kali-attacker/`](../kali-attacker/README.md))

### Windows 11 Endpoint — `IMTHIAZ-WIN11`
- Wazuh Agent v4.14.6 (Agent ID `001`) — ships telemetry to the manager
- Sysmon — high-fidelity process, file, and registry telemetry (`Microsoft-Windows-Sysmon/Operational`)
- Microsoft Defender — native endpoint protection, used for validation testing

## Data flow

```
Kali Linux (Attacker / Test Workstation)
192.168.234.128
        │
        │ Controlled attack/test activity
        │
        ├───────────────────────────┬──────────────────────────────┐
        ▼                           ▼
Ubuntu Server                Windows 11 (IMTHIAZ-WIN11)
192.168.234.130               Sysmon observes: process creation,
SSH authentication attempts   file writes, registry changes
        │                           │
        ▼                           ▼
Wazuh Manager decodes        Wazuh Agent forwards events
+ applies detection rules            │
        │                           ▼
        └──────────────┬────────────┘
                        ▼
              Wazuh Indexer stores events
                        │
                        ▼
              Wazuh Dashboard surfaces alerts
                        │
                        ▼
     SOC Analyst investigates, correlates, maps to MITRE ATT&CK, documents
```

**Important distinction:** Kali is the source of the *activity being detected* on both hosts — it is not itself a monitored asset. Its SSH activity against the Ubuntu server **does** appear directly in Wazuh telemetry (as `srcip: 192.168.234.128` in the SSH authentication-failure events — see [`kali-attacker/`](../kali-attacker/README.md)). Its endpoint-side test activity on the Windows 11 endpoint is observed indirectly, through Sysmon/Wazuh Agent telemetry on that endpoint, which is standard for host-based detection engineering. In neither case is Kali claimed to have successfully compromised a host, and Kali is never treated as a monitored asset in this repository.

## Environment validation

Before any detection work, two things were confirmed:

1. **Agent connectivity** — `IMTHIAZ-WIN11`, Agent ID `001`, Windows 11 Pro, Wazuh Agent v4.14.6, status `active`.
2. **Sysmon telemetry flow** — the `Microsoft-Windows-Sysmon/Operational` channel was confirmed to be generating and forwarding events (Process Creation – Event ID 1, File Creation – Event ID 11, Registry – Event ID 13).

Only after this baseline was confirmed did detection engineering begin.

## Diagrams

- `threatlens-architecture.png` — full component + data-flow diagram
- `network-topology.png` — server/endpoint network layout

## Environment Validation Evidence

- `evidence/windows-agent-active.png` — Wazuh "Explore agent" view confirming `IMTHIAZ-WIN11` (Agent ID `001`) is registered, running Agent v4.14.6 on Windows 11 Pro, status `active`
- `evidence/sysmon-operational.png` — Windows Event Viewer confirming the `Microsoft-Windows-Sysmon/Operational` channel is live and generating Process Creation / File Creation events

These two screenshots are the environment baseline proof referenced in Step "Environment validation" above — confirmed *before* any detection engineering work began.
