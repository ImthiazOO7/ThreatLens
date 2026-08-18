# Environment Setup

This document describes how the ThreatLens lab environment was built, in the order it was actually built — environment first, detections second.

## 1. Prerequisites

- Ubuntu Server (host for Wazuh Manager, Indexer, Dashboard)
- Windows 11 Pro VM/host (monitored endpoint)
- Network connectivity between the two (agent-to-manager communication)

## 2. Ubuntu Server — Wazuh Backend

Install and start the three Wazuh components:

- **Wazuh Indexer** — stores and indexes all events
- **Wazuh Manager** — receives agent telemetry, applies decoders/rules, generates alerts
- **Wazuh Dashboard** — web UI for visualization, event search, and MITRE views

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

## 4. Validate the Pipeline

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

## 5. Where to Go Next

- Custom detection rules: [`detections/`](../detections/)
- How rules were engineered: [`documentation/detection-engineering.md`](detection-engineering.md)
