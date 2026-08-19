# Environment Setup

This document describes how the ThreatLens lab environment was built, in the order it was actually built — environment first, detections second.

## 1. Prerequisites

- Ubuntu Server (host for Wazuh Manager, Indexer, Dashboard)
- Windows 11 Pro VM/host (monitored endpoint)
- Kali Linux VM/host (attacker/test workstation — not monitored, no Wazuh Agent)
- Network connectivity between all three hosts (agent-to-manager communication, plus Kali's reachability to both other hosts for test activity)

## 2. Ubuntu Server — Wazuh Backend

Install and start the three Wazuh components:

- **Wazuh Indexer** — stores and indexes all events
- **Wazuh Manager** — receives agent telemetry, applies decoders/rules, generates alerts
- **Wazuh Dashboard** — web UI for visualization, event search, and MITRE views

Network identity: `192.168.234.130`

## 3. Windows 11 Endpoint — Agent + Telemetry

1. **Install the Wazuh Agent** (v4.14.6) on the Windows 11 host and register it against the Ubuntu Manager.
2. **Install Sysmon** with a detection-oriented configuration to capture:
   - Event ID 1 — Process Creation
   - Event ID 11 — File Creation
   - Event ID 13 — Registry Value Set
   (plus the standard broader Sysmon event set)
3. Confirm the Sysmon operational log channel is active:
   ```
   Microsoft-Windows-Sysmon/Operational
   ```
4. Confirm **Microsoft Defender** real-time protection is enabled (used later for endpoint validation testing).

## 4. Kali Linux — Attacker/Test Workstation

Kali Linux (`192.168.234.128`) is deployed as a standard, unmodified Kali install with network connectivity to both the Ubuntu server and the Windows 11 endpoint. No Wazuh Agent is installed on it — it is intentionally excluded from the monitored asset inventory, since its purpose is to generate the controlled activity that the *monitored* hosts observe, not to be monitored itself.

Kali is used for two activities in this lab:

- SSH authentication testing against the Ubuntu server
- Endpoint-side test activity against the Windows 11 endpoint (encoded PowerShell, `net.exe` discovery, registry Run key modification)

Full detail on both activities: [`kali-attacker/README.md`](../kali-attacker/README.md)

## 5. Validate the Pipeline

Before any detection engineering work, two checks were performed:

1. **Agent connectivity** — in the Wazuh Dashboard, confirm the agent shows:
   ```
   Name:    IMTHIAZ-WIN11
   ID:      001
   OS:      Windows 11 Pro
   Version: Wazuh Agent v4.14.6
   Status:  active
   ```
2. **Telemetry flow** — generate a benign process (e.g. open Notepad) on the Windows endpoint and confirm a corresponding Sysmon Event ID 1 appears in the Wazuh Dashboard's event/discover view within a few seconds.

Only once both checks passed did detection engineering (custom rules) begin.

## 6. Where to Go Next

- Custom detection rules: [`detections/`](../detections/)
- How rules were engineered: [`documentation/detection-engineering.md`](detection-engineering.md)
- Kali's role and attack scenarios: [`kali-attacker/`](../kali-attacker/README.md)
