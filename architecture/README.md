# Architecture

This directory documents how the ThreatLens lab environment was built, before any detection engineering or investigation work began.

## Why the environment came first

Detections depend entirely on telemetry, and telemetry depends entirely on a working monitoring pipeline:

```
No environment → No telemetry → No event → No detection → No investigation
```

So the first phase of ThreatLens was standing up and validating the monitoring pipeline itself — not attacks, not rules, just proving that data flows correctly from endpoint to SIEM.

## Components

### Ubuntu Server — Wazuh backend
- Wazuh Manager — receives agent telemetry, applies decoders/rules, generates alerts
- Wazuh Indexer — stores and indexes events
- Wazuh Dashboard — visualization, event search, MITRE views

### Windows 11 Endpoint — `IMTHIAZ-WIN11`
- Wazuh Agent v4.14.6 (Agent ID `001`) — ships telemetry to the manager
- Sysmon — high-fidelity process, file, and registry telemetry (`Microsoft-Windows-Sysmon/Operational`)
- Microsoft Defender — native endpoint protection, used for validation testing

## Data flow

```
Windows 11 (IMTHIAZ-WIN11)
   Sysmon observes: process creation, file writes, registry changes
        ↓
   Wazuh Agent forwards events
        ↓
Ubuntu Server
   Wazuh Manager decodes + applies detection rules
        ↓
   Wazuh Indexer stores events
        ↓
   Wazuh Dashboard surfaces alerts
        ↓
SOC Analyst investigates, correlates, maps to MITRE ATT&CK, documents
```

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
